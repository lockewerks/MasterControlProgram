use std::{
    fs::File,
    io::Write,
    os::windows::io::{AsHandle, OwnedHandle},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{sync_channel, SyncSender, TrySendError},
        Arc, Condvar, Mutex,
    },
    time::Duration,
};

use anyhow::Context;
use serde::Serialize;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use windows::Win32::{
    Foundation::{ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED},
    System::IO::CancelSynchronousIo,
};

use super::MAX_INPUT_BYTES;
use crate::context::raw;

struct WriteRequest {
    id: u64,
    bytes: Vec<u8>,
    canceled: Arc<AtomicBool>,
    written: Arc<AtomicUsize>,
    result: oneshot::Sender<InputResult>,
}

#[derive(Debug, Serialize)]
pub struct InputResult {
    pub outcome: String,
    pub requested_bytes: usize,
    pub bytes_written: usize,
    pub write_completion_uncertain: bool,
    pub error: Option<String>,
    pub semantics: String,
}

pub(super) struct InputWriter {
    sender: SyncSender<WriteRequest>,
    pending_bytes: Arc<AtomicUsize>,
    activity: Arc<WriterActivity>,
    next_id: AtomicU64,
    thread: OwnedHandle,
}

struct ActiveWrite {
    id: u64,
    canceled: Arc<AtomicBool>,
    reported_error: Option<i32>,
    #[cfg(test)]
    cancellation_attempts: usize,
}

impl ActiveWrite {
    fn cancel_io(&mut self, thread: &OwnedHandle) {
        let result = unsafe { CancelSynchronousIo(raw(thread)) };
        #[cfg(test)]
        {
            self.cancellation_attempts += 1;
        }
        if let Err(error) = result {
            if error.code() != ERROR_NOT_FOUND.to_hresult()
                && self.reported_error != Some(error.code().0)
            {
                tracing::warn!(request_id = self.id, %error, "terminal input cancellation failed");
                self.reported_error = Some(error.code().0);
            }
        }
    }
}

#[derive(Default)]
struct ActivityState {
    active: Option<ActiveWrite>,
    stopped: bool,
}

#[derive(Default)]
struct WriterActivity {
    state: Mutex<ActivityState>,
    changed: Condvar,
    #[cfg(test)]
    before_write: Mutex<Option<Arc<tests::SubmissionGate>>>,
}

struct WriterStopped(Arc<WriterActivity>);

impl Drop for WriterStopped {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().expect("input activity mutex poisoned");
        state.active = None;
        state.stopped = true;
        self.0.changed.notify_one();
    }
}

fn cancel_until_completed(activity: Arc<WriterActivity>, thread: OwnedHandle) {
    let mut state = activity
        .state
        .lock()
        .expect("input activity mutex poisoned");
    while !state.stopped {
        if let Some(active) = &mut state.active {
            if active.canceled.load(Ordering::Acquire) {
                // Keep retrying through late WriteFile submission. The same lock guards
                // active-ID changes, so cancellation cannot reach the next request.
                active.cancel_io(&thread);
                state = activity
                    .changed
                    .wait_timeout(state, Duration::from_millis(2))
                    .expect("input activity mutex poisoned")
                    .0;
                continue;
            }
        }
        state = activity
            .changed
            .wait(state)
            .expect("input activity mutex poisoned");
    }
}

struct CancelWrite<'a> {
    writer: &'a InputWriter,
    canceled: Arc<AtomicBool>,
    id: u64,
    armed: bool,
}

impl Drop for CancelWrite<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self
                .writer
                .activity
                .state
                .lock()
                .expect("input activity mutex poisoned");
            self.canceled.store(true, Ordering::Release);
            if let Some(active) = &mut state.active {
                if active.id == self.id {
                    active.cancel_io(&self.writer.thread);
                }
            }
            self.writer.activity.changed.notify_one();
        }
    }
}

impl InputWriter {
    pub fn new(mut file: File, name: &str) -> anyhow::Result<Self> {
        let (sender, receiver) = sync_channel::<WriteRequest>(8);
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let pending = pending_bytes.clone();
        let activity = Arc::new(WriterActivity::default());
        let writer_activity = activity.clone();
        let thread = std::thread::Builder::new().name(format!("mcp-input-{name}")).spawn(move || {
            let _stopped = WriterStopped(writer_activity.clone());
            while let Ok(request) = receiver.recv() {
                writer_activity.state.lock().expect("input activity mutex poisoned").active = Some(ActiveWrite {
                    id: request.id,
                    canceled: request.canceled.clone(),
                    reported_error: None,
                    #[cfg(test)]
                    cancellation_attempts: 0,
                });
                writer_activity.changed.notify_one();
                let mut written = 0;
                let mut error = None;
                let mut uncertain = false;
                while written < request.bytes.len() && !request.canceled.load(Ordering::Acquire) {
                    let end = (written + 4096).min(request.bytes.len());
                    #[cfg(test)]
                    {
                        let gate = writer_activity.before_write.lock().unwrap().clone();
                        if let Some(gate) = gate {
                            if let Err(failure) = gate.pause(request.id) {
                                error = Some(failure.to_string());
                                break;
                            }
                        }
                    }
                    match file.write(&request.bytes[written..end]) {
                        Ok(0) => {
                            error = Some("WriteFile accepted zero bytes".into());
                            break;
                        }

                        Ok(count) => {
                            written += count;
                            request.written.store(written, Ordering::Release);
                        }
                        Err(failure) => {
                            uncertain = true;
                            if failure.raw_os_error() != Some(ERROR_OPERATION_ABORTED.0 as i32)
                                || !request.canceled.load(Ordering::Acquire)
                            {
                                error = Some(failure.to_string());
                            }
                            break;
                        }
                    }
                }
                writer_activity.state.lock().expect("input activity mutex poisoned").active = None;
                writer_activity.changed.notify_one();
                pending.fetch_sub(request.bytes.len(), Ordering::AcqRel);
                let _ = request.result.send(InputResult {
                    outcome: if error.is_some() { "failed" }
                        else if written == request.bytes.len() { "written" } else { "canceled" }.into(),
                    requested_bytes: request.bytes.len(),
                    bytes_written: written,
                    write_completion_uncertain: uncertain,
                    error,
                    semantics: if uncertain {
                        "bytes_written counts confirmed writes; the interrupted chunk may have delivered additional bytes. Do not replay input automatically"
                    } else {
                        "bytes written to the ConPTY input pipe, not an application postcondition"
                    }.into(),
                });
            }
        })?;
        let handle = thread.as_handle().try_clone_to_owned()?;
        drop(thread);
        let cancel_activity = activity.clone();
        let cancel_target = handle.try_clone()?;
        std::thread::Builder::new()
            .name(format!("mcp-input-cancel-{name}"))
            .spawn(move || cancel_until_completed(cancel_activity, cancel_target))?;
        Ok(Self {
            sender,
            pending_bytes,
            activity,
            next_id: AtomicU64::new(1),
            thread: handle,
        })
    }

    pub async fn write(
        &self,
        bytes: Vec<u8>,
        timeout: Duration,
        cancel: CancellationToken,
    ) -> anyhow::Result<InputResult> {
        anyhow::ensure!(
            !cancel.is_cancelled(),
            "terminal input canceled before queueing"
        );
        let count = bytes.len();
        self.pending_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending
                    .checked_add(count)
                    .filter(|&total| total <= MAX_INPUT_BYTES)
            })
            .map_err(|_| {
                anyhow::anyhow!("terminal pending input exceeds {MAX_INPUT_BYTES} bytes")
            })?;
        let canceled = Arc::new(AtomicBool::new(false));
        let written = Arc::new(AtomicUsize::new(0));
        let (result, receive) = oneshot::channel();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = WriteRequest {
            id,
            bytes,
            canceled: canceled.clone(),
            written: written.clone(),
            result,
        };
        if let Err(error) = self.sender.try_send(request) {
            self.pending_bytes.fetch_sub(count, Ordering::AcqRel);
            return Err(match error {
                TrySendError::Full(_) => anyhow::anyhow!("terminal input queue is full"),
                TrySendError::Disconnected(_) => anyhow::anyhow!("terminal input pipe is closed"),
            });
        }
        let mut guard = CancelWrite {
            writer: self,
            canceled,
            id,
            armed: true,
        };
        let outcome = tokio::select! {
            result = receive => {
                guard.armed = false;
                return result.context("terminal input writer stopped without a result");
            }
            _ = cancel.cancelled() => "canceled",
            _ = tokio::time::sleep(timeout) => "timed_out",
        };
        Ok(InputResult {
            outcome: outcome.into(),
            requested_bytes: count,
            bytes_written: written.load(Ordering::Acquire),
            write_completion_uncertain: true,
            error: None,
            semantics: "write cancellation requested; an in-flight chunk may have completed. Do not replay input automatically".into(),
        })
    }
}

impl Drop for InputWriter {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .state
            .lock()
            .expect("input activity mutex poisoned");
        if let Some(active) = &mut state.active {
            active.canceled.store(true, Ordering::Release);
            active.cancel_io(&self.thread);
        }
        self.activity.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use windows::Win32::{Foundation::HANDLE, System::Pipes::CreatePipe};

    pub(super) struct SubmissionGate {
        entered: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl SubmissionGate {
        fn install(writer: &InputWriter) -> (oneshot::Receiver<()>, SyncSender<()>) {
            let (entered, reached) = oneshot::channel();
            let (release, receive) = sync_channel(1);
            *writer.activity.before_write.lock().unwrap() = Some(Arc::new(Self {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(receive),
            }));
            (reached, release)
        }

        pub(super) fn pause(&self, id: u64) -> anyhow::Result<()> {
            if id == 1 {
                if let Some(entered) = self.entered.lock().unwrap().take() {
                    entered
                        .send(())
                        .map_err(|_| anyhow::anyhow!("submission gate receiver closed"))?;
                    self.release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))?;
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn canceled_late_submission_finishes_and_next_write_progresses() -> anyhow::Result<()> {
        for drop_handler in [false, true] {
            let mut read = HANDLE::default();
            let mut write = HANDLE::default();
            unsafe { CreatePipe(&mut read, &mut write, None, 4096)? };
            let mut read = File::from(unsafe { crate::context::own(read) });
            let mut write = File::from(unsafe { crate::context::own(write) });
            write.write_all(&[b'p'; 4096])?;
            let writer = Arc::new(InputWriter::new(write, "late-submission-test")?);
            let (reached, release) = SubmissionGate::install(&writer);
            let cancel = CancellationToken::new();
            let request_cancel = cancel.clone();
            let first_writer = writer.clone();
            let first = tokio::spawn(async move {
                first_writer
                    .write(vec![b'a'; 16], Duration::from_secs(5), request_cancel)
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), reached).await??;
            if drop_handler {
                first.abort();
                assert!(first.await.unwrap_err().is_cancelled());
            } else {
                cancel.cancel();
                let result = first.await??;
                assert_eq!(result.outcome, "canceled");
                assert_eq!(result.bytes_written, 0);
                assert!(result.write_completion_uncertain);
            }
            assert!(
                writer
                    .activity
                    .state
                    .lock()
                    .unwrap()
                    .active
                    .as_ref()
                    .unwrap()
                    .cancellation_attempts
                    > 0
            );
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(5), async {
                while writer.pending_bytes.load(Ordering::Acquire) != 0 {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .context("late native write was not canceled under backpressure")?;

            let reader = tokio::task::spawn_blocking(move || {
                let mut bytes = vec![0; 4100];
                read.read_exact(&mut bytes)?;
                anyhow::Ok(bytes)
            });
            let next = writer
                .write(
                    b"next".to_vec(),
                    Duration::from_secs(5),
                    CancellationToken::new(),
                )
                .await?;
            assert_eq!(next.outcome, "written");
            assert_eq!(next.bytes_written, 4);
            assert!(!next.write_completion_uncertain);
            let bytes = tokio::time::timeout(Duration::from_secs(5), reader).await???;
            assert_eq!(&bytes[..4096], &[b'p'; 4096]);
            assert_eq!(&bytes[4096..], b"next");
            let activity = writer.activity.clone();
            drop(writer);
            tokio::time::timeout(Duration::from_secs(5), async {
                while !activity.state.lock().unwrap().stopped {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .context("input writer did not stop after its last owner dropped")?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn canceling_queued_input_does_not_cancel_another_write() -> anyhow::Result<()> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        unsafe { CreatePipe(&mut read, &mut write, None, 4096)? };
        let mut read = File::from(unsafe { crate::context::own(read) });
        let write = File::from(unsafe { crate::context::own(write) });
        let writer = Arc::new(InputWriter::new(write, "cancel-isolation-test")?);
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            first_writer
                .write(
                    vec![b'a'; 32768],
                    Duration::from_secs(5),
                    CancellationToken::new(),
                )
                .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while writer.pending_bytes.load(Ordering::Acquire) != 32768 {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "first input did not queue"
            );
            tokio::task::yield_now().await;
        }
        let second_writer = writer.clone();
        let cancel = CancellationToken::new();
        let second_cancel = cancel.clone();
        let second = tokio::spawn(async move {
            second_writer
                .write(vec![b'b'], Duration::from_secs(5), second_cancel)
                .await
        });
        while writer.pending_bytes.load(Ordering::Acquire) != 32769 {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "second input did not queue"
            );
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        assert_eq!(second.await??.outcome, "canceled");
        let reader = tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0; 32768];
            read.read_exact(&mut bytes)?;
            anyhow::Ok(bytes)
        });
        let result = first.await??;
        assert_eq!(result.outcome, "written");
        assert_eq!(result.bytes_written, 32768);
        assert_eq!(reader.await??, vec![b'a'; 32768]);
        drop(writer);
        Ok(())
    }
}
