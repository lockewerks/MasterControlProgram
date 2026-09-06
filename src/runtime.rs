use anyhow::{bail, Context, Result};
use std::cell::RefCell;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, OnceLock,
};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::timeout_at;

const MAX_TIMEOUT_MS: u64 = 3_600_000;

struct Cancellation {
    cancelled: AtomicBool,
    deadline: Instant,
    wake: Condvar,
    sleeping: Mutex<()>,
}

#[derive(Clone)]
pub(crate) struct OperationContext(Arc<Cancellation>);

impl OperationContext {
    fn new(duration: Duration) -> Self {
        Self(Arc::new(Cancellation {
            cancelled: AtomicBool::new(false),
            deadline: Instant::now() + duration,
            wake: Condvar::new(),
            sleeping: Mutex::new(()),
        }))
    }

    pub(crate) fn checkpoint(&self) -> Result<()> {
        if self.0.cancelled.load(Ordering::Acquire) {
            bail!("Operation cancelled; an already accepted action may have taken effect");
        }
        if Instant::now() >= self.0.deadline {
            bail!("Operation deadline exceeded; an already accepted action may have taken effect");
        }
        Ok(())
    }

    pub(crate) fn remaining(&self) -> Result<Duration> {
        self.checkpoint()?;
        Ok(self.0.deadline.saturating_duration_since(Instant::now()))
    }

    pub(crate) fn sleep(&self, duration: Duration) -> Result<()> {
        let end = Instant::now()
            .checked_add(duration)
            .context("Sleep duration overflow")?;
        let mut guard = self
            .0
            .sleeping
            .lock()
            .map_err(|_| anyhow::anyhow!("Cancellation lock poisoned"))?;
        loop {
            let remaining = self.remaining()?;
            let delay = end.saturating_duration_since(Instant::now());
            if delay.is_zero() {
                return Ok(());
            }
            guard = self
                .0
                .wake
                .wait_timeout(guard, delay.min(remaining))
                .map_err(|_| anyhow::anyhow!("Cancellation lock poisoned"))?
                .0;
        }
    }

    fn cancel(&self) {
        // Pair the notification with the sleeping lock so cancellation cannot
        // be lost between the sleeper's checkpoint and its wait.
        let _guard = self.0.sleeping.lock().unwrap_or_else(|e| e.into_inner());
        self.0.cancelled.store(true, Ordering::Release);
        self.0.wake.notify_all();
    }
}

thread_local! {
    static CURRENT: RefCell<Option<OperationContext>> = const { RefCell::new(None) };
}

pub(crate) fn current_context() -> Option<OperationContext> {
    CURRENT.with(|slot| slot.borrow().clone())
}

pub(crate) fn checkpoint() -> Result<()> {
    match current_context() {
        Some(context) => context.checkpoint(),
        None => Ok(()),
    }
}

pub(crate) fn sleep(duration: Duration) -> Result<()> {
    match current_context() {
        Some(context) => context.sleep(duration),
        None => {
            std::thread::sleep(duration);
            Ok(())
        }
    }
}

struct ContextScope(Option<OperationContext>);

impl ContextScope {
    fn enter(context: OperationContext) -> Self {
        Self(CURRENT.with(|slot| slot.replace(Some(context))))
    }
}

impl Drop for ContextScope {
    fn drop(&mut self) {
        CURRENT.with(|slot| slot.replace(self.0.take()));
    }
}

struct Running<T: Send + 'static> {
    context: OperationContext,
    task: Option<JoinHandle<Result<T>>>,
    reaper: tokio::runtime::Handle,
}

impl<T: Send + 'static> Drop for Running<T> {
    fn drop(&mut self) {
        self.context.cancel();
        if let Some(task) = self.task.take() {
            // Abort prevents work still queued in Tokio from starting. Running
            // native work is cooperative and keeps its permits until it exits.
            task.abort();
            self.reaper.spawn(async move {
                match task.await {
                    Ok(Err(error)) => tracing::warn!(%error, "cancelled native operation finished"),
                    Err(error) if !error.is_cancelled() => {
                        tracing::error!(%error, "cancelled native operation panicked");
                    }
                    _ => {}
                }
            });
        }
    }
}

struct Runtime {
    capacity: Arc<Semaphore>,
    desktop: Arc<Semaphore>,
    acquire_timeout: Duration,
    execution_timeout: Duration,
    pulse: Arc<dyn Fn() + Send + Sync>,
}

fn setting(name: &str, default: u64, max: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => parse_setting(name, &value, max),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("Invalid {name}")),
    }
}

fn parse_setting(name: &str, value: &str, max: u64) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|ch| ch.is_ascii_digit()) {
        bail!("{name} must be an integer in 1..={max}");
    }
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("Invalid {name}"))?;
    if !(1..=max).contains(&parsed) {
        bail!("{name} must be in 1..={max}");
    }
    Ok(parsed)
}

impl Runtime {
    fn from_env() -> Result<Self> {
        Ok(Self {
            capacity: Arc::new(Semaphore::new(
                setting("MCP_NATIVE_CONCURRENCY", 8, 64)? as usize
            )),
            desktop: Arc::new(Semaphore::new(1)),
            acquire_timeout: Duration::from_millis(setting(
                "MCP_NATIVE_ACQUIRE_TIMEOUT_MS",
                30_000,
                MAX_TIMEOUT_MS,
            )?),
            execution_timeout: Duration::from_millis(setting(
                "MCP_NATIVE_TIMEOUT_MS",
                30_000,
                MAX_TIMEOUT_MS,
            )?),
            pulse: Arc::new(crate::overlay::pulse),
        })
    }

    async fn run<T, F>(&self, interactive: bool, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        self.run_with_timeout(interactive, self.execution_timeout, work)
            .await
    }

    async fn run_with_timeout<T, F>(
        &self,
        interactive: bool,
        duration: Duration,
        work: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let acquire_deadline = tokio::time::Instant::now() + self.acquire_timeout;
        // Desktop waiters must not consume all capacity needed by unrelated
        // reads. Both permits move into the blocking closure, never its caller.
        let desktop = if interactive {
            Some(
                timeout_at(acquire_deadline, self.desktop.clone().acquire_owned())
                    .await
                    .context("Timed out waiting for desktop input")??,
            )
        } else {
            None
        };
        let capacity = timeout_at(acquire_deadline, self.capacity.clone().acquire_owned())
            .await
            .context("Timed out waiting for native operation capacity")??;
        let context = OperationContext::new(duration);
        let deadline = tokio::time::Instant::from_std(context.0.deadline);
        let operation = context.clone();
        let pulse = self.pulse.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _capacity = capacity;
            let _desktop = desktop;
            let _scope = ContextScope::enter(operation.clone());
            operation.checkpoint()?;
            if interactive {
                pulse();
            }
            let result = work()?;
            operation.checkpoint()?;
            Ok(result)
        });
        let mut running = Running {
            context,
            task: Some(task),
            reaper: tokio::runtime::Handle::current(),
        };
        match timeout_at(deadline, running.task.as_mut().expect("owned blocking task")).await {
            Ok(joined) => {
                running.task.take();
                joined.context("Native operation task failed")?
            }
            Err(_) => bail!("Native operation deadline exceeded; running work is being cancelled, and an already accepted action may have taken effect"),
        }
    }
}

fn shared() -> Result<&'static Runtime> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| Runtime::from_env().map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

pub(crate) async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    shared()?.run(false, work).await
}

pub(crate) async fn interactive<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    shared()?.run(true, work).await
}

#[allow(dead_code)]
pub(crate) async fn blocking_with_timeout<T, F>(timeout_ms: u64, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let duration = operation_timeout(timeout_ms)?;
    shared()?.run_with_timeout(false, duration, work).await
}

#[allow(dead_code)]
pub(crate) async fn interactive_with_timeout<T, F>(timeout_ms: u64, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let duration = operation_timeout(timeout_ms)?;
    shared()?.run_with_timeout(true, duration, work).await
}

#[allow(dead_code)]
fn operation_timeout(timeout_ms: u64) -> Result<Duration> {
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        bail!("timeout_ms must be in 1..={MAX_TIMEOUT_MS}");
    }
    Ok(Duration::from_millis(timeout_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::oneshot;

    fn runtime(capacity: usize, pulses: Arc<AtomicUsize>) -> Arc<Runtime> {
        Arc::new(Runtime {
            capacity: Arc::new(Semaphore::new(capacity)),
            desktop: Arc::new(Semaphore::new(1)),
            acquire_timeout: Duration::from_secs(1),
            execution_timeout: Duration::from_secs(2),
            pulse: Arc::new(move || {
                pulses.fetch_add(1, Ordering::SeqCst);
            }),
        })
    }

    #[test]
    fn configuration_rejects_invalid_limits() {
        for value in [
            "",
            "0",
            "-1",
            "+1",
            " 1",
            "1.5",
            "NaN",
            "65",
            "18446744073709551616",
        ] {
            assert!(parse_setting("limit", value, 64).is_err(), "{value}");
        }
        assert_eq!(parse_setting("limit", "64", 64).unwrap(), 64);
        assert!(operation_timeout(0).is_err());
        assert!(operation_timeout(MAX_TIMEOUT_MS + 1).is_err());
        assert_eq!(
            operation_timeout(MAX_TIMEOUT_MS).unwrap().as_millis(),
            MAX_TIMEOUT_MS as u128
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_work_keeps_executor_responsive_and_passive_reads_dark() {
        let pulses = Arc::new(AtomicUsize::new(0));
        let runtime = runtime(2, pulses.clone());
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_runtime = runtime.clone();
        let first = tokio::spawn(async move {
            first_runtime
                .run(false, move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(1)
                })
                .await
        });
        started_rx.await.unwrap();
        assert_eq!(runtime.run(false, || Ok(2)).await.unwrap(), 2);
        assert_eq!(pulses.load(Ordering::SeqCst), 0);
        release_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);
    }

    #[tokio::test]
    async fn cancellation_retains_desktop_lock_and_capacity_until_work_exits() {
        let pulses = Arc::new(AtomicUsize::new(0));
        let runtime = runtime(2, pulses.clone());
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_runtime = runtime.clone();
        let first = tokio::spawn(async move {
            first_runtime
                .run(true, move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    checkpoint()
                })
                .await
        });
        started_rx.await.unwrap();
        first.abort();
        let _ = first.await;
        assert_eq!(runtime.capacity.available_permits(), 1);
        assert_eq!(runtime.desktop.available_permits(), 0);
        assert_eq!(pulses.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.run(false, || Ok(7)).await.unwrap(), 7);
        let next_runtime = runtime.clone();
        let next = tokio::spawn(async move { next_runtime.run(true, || Ok(9)).await });
        tokio::task::yield_now().await;
        assert_eq!(pulses.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        assert_eq!(next.await.unwrap().unwrap(), 9);
        assert_eq!(pulses.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deadline_wakes_cooperative_sleep_and_cleans_up() {
        let pulses = Arc::new(AtomicUsize::new(0));
        let mut runtime = runtime(1, pulses);
        Arc::get_mut(&mut runtime).unwrap().execution_timeout = Duration::from_millis(30);
        let (finished_tx, finished_rx) = oneshot::channel();
        let result = runtime
            .run(true, move || {
                let result = sleep(Duration::from_secs(10));
                finished_tx.send(result.is_err()).unwrap();
                result
            })
            .await;
        assert!(result.is_err());
        assert!(tokio::time::timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap());
        let permit = runtime.capacity.clone().acquire_owned().await.unwrap();
        assert_eq!(runtime.desktop.available_permits(), 1);
        drop(permit);
    }

    #[tokio::test]
    async fn cancelled_waiter_never_runs_or_pulses() {
        let pulses = Arc::new(AtomicUsize::new(0));
        let runtime = runtime(1, pulses.clone());
        let permit = runtime.desktop.clone().acquire_owned().await.unwrap();
        let next_runtime = runtime.clone();
        let next = tokio::spawn(async move {
            next_runtime
                .run(true, || -> Result<()> { panic!("cancelled work ran") })
                .await
        });
        tokio::task::yield_now().await;
        next.abort();
        let _ = next.await;
        drop(permit);
        assert_eq!(pulses.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn capacity_wait_has_a_deadline_and_does_not_run_work() {
        let pulses = Arc::new(AtomicUsize::new(0));
        let mut runtime = runtime(1, pulses.clone());
        Arc::get_mut(&mut runtime).unwrap().acquire_timeout = Duration::from_millis(20);
        let permit = runtime.capacity.clone().acquire_owned().await.unwrap();
        let result = runtime
            .run(true, || -> Result<()> { panic!("capacity waiter ran") })
            .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("capacity"));
        assert_eq!(runtime.desktop.available_permits(), 1);
        assert_eq!(pulses.load(Ordering::SeqCst), 0);
        drop(permit);
    }
}
