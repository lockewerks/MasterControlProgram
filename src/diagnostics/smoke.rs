use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::GetFileType;
use windows::Win32::System::Diagnostics::Debug::{CheckRemoteDebuggerPresent, OutputDebugStringW};
use windows::Win32::System::Threading::*;

use super::debugger::{Command as DebugCommand, SessionView, State};
use super::native::{open_thread, thread_ids, Deadline, Handle, Process};
use super::*;

const FIXTURE: &str = "diagnostics::smoke::child_fixture";

pub(super) fn fixture_arguments() -> Vec<String> {
    ["--exact", FIXTURE, "--ignored", "--nocapture"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[test]
#[ignore = "subprocess fixture, only waits when selected by exact name"]
fn child_fixture() {
    if !std::env::args().any(|arg| arg == "--exact") {
        return;
    }
    let event = Handle(unsafe { CreateEventW(None, false, false, None) }.unwrap());
    println!("MCP_DIAGNOSTICS_FIXTURE_READY");
    std::io::stdout().flush().unwrap();
    let stdout_type = unsafe { GetFileType(HANDLE(std::io::stdout().as_raw_handle())) };
    let message: Vec<u16> = format!(
        "MCP diagnostics disposable child stdout_type={}",
        stdout_type.0
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    unsafe {
        OutputDebugStringW(PCWSTR(message.as_ptr()));
        WaitForSingleObject(event.0, 60_000);
    }
}

pub(super) struct ChildFixture(Child);

impl ChildFixture {
    pub(super) fn spawn() -> Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command.args(fixture_arguments());
        Self::spawn_ready(command, "MCP_DIAGNOSTICS_FIXTURE_READY")
    }

    fn spawn_ready(mut command: Command, marker: &str) -> Result<Self> {
        command.env_clear().env(
            "SystemRoot",
            std::env::var_os("SystemRoot").context("SystemRoot unavailable")?,
        );
        let mut child = Self(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let output = child
            .0
            .stdout
            .take()
            .context("fixture stdout unavailable")?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let marker = marker.to_string();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            let mut ready = false;
            let result = (|| -> Result<()> {
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 {
                        if ready {
                            return Ok(());
                        }
                        bail!("fixture exited before ready");
                    }
                    if !ready && line.contains(&marker) {
                        send.send(Ok(()))
                            .context("fixture readiness receiver closed")?;
                        ready = true;
                    }
                }
            })();
            if !ready {
                let _ = send.send(result);
            }
        });
        receive
            .recv_timeout(Duration::from_secs(10))
            .context("fixture readiness timeout")??;
        Ok(child)
    }

    pub(super) fn target(&self) -> Result<TargetInput> {
        let process = Process::open(self.0.id(), None, PROCESS_ACCESS_RIGHTS(0))?;
        Ok(TargetInput {
            pid: process.identity.pid,
            creation_time: process.created,
        })
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        if self.0.try_wait()?.is_none() {
            self.0.kill()?;
        }
        self.0.wait()?;
        assert!(self.0.try_wait()?.is_some());
        Ok(())
    }
}

impl Drop for ChildFixture {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("disposable child cleanup failed: {error:#}");
        }
    }
}

struct Artifact(std::path::PathBuf);

impl Artifact {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("mcp-diagnostics-{}.dmp", uuid::Uuid::new_v4())))
    }

    fn path(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!("disposable dump cleanup failed: {error}"),
        }
    }
}

#[test]
#[ignore = "native diagnostics against an explicitly disposable child"]
fn native_smoke_snapshots_and_suspend_balance() -> Result<()> {
    let mut child = ChildFixture::spawn()?;
    let target = child.target()?;
    let process = Process::open(
        target.pid,
        Some(target.creation_time),
        PROCESS_ACCESS_RIGHTS(0),
    )?;
    assert!(native::context_compatible(
        std::env::consts::ARCH,
        &process.identity.architecture
    ));
    assert!(process.identity.target_privileges.elevated.is_some());
    assert!(Process::open(
        target.pid,
        Some(target.creation_time + 1),
        PROCESS_ACCESS_RIGHTS(0)
    )
    .is_err());

    let handles = handles::capture(
        HandlesInput {
            target: target.clone(),
            limit: Some(512),
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )?;
    assert!(handles.total_captured > 0, "{handles:?}");
    assert!(!handles.handles.is_empty(), "{handles:?}");

    let wait = waits::capture(
        WaitChainInput {
            target: target.clone(),
            thread_id: None,
            max_threads: Some(16),
            follow_owners: false,
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )?;
    assert!(
        wait.threads.iter().any(|thread| !thread.nodes.is_empty()),
        "{wait:?}"
    );

    let stack = stacks::capture(
        StacksInput {
            target: target.clone(),
            thread_id: None,
            max_threads: Some(16),
            max_frames: Some(32),
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )?;
    assert!(
        stack.threads.iter().any(|thread| !thread.frames.is_empty()),
        "{stack:?}"
    );
    assert!(
        stack.threads.iter().all(|thread| thread.error.is_none()),
        "{stack:?}"
    );

    let tids = thread_ids(&process, 16, &Deadline::new(1000)?)?.0;
    let tid = *tids.first().context("fixture has no threads")?;
    let (thread, _) = open_thread(&process, tid, THREAD_SUSPEND_RESUME)?;
    let prior = unsafe { SuspendThread(thread.0) };
    assert_ne!(prior, u32::MAX);
    struct Resume(HANDLE);
    impl Drop for Resume {
        fn drop(&mut self) {
            unsafe {
                ResumeThread(self.0);
            }
        }
    }
    let resume = Resume(thread.0);
    let stack = stacks::capture(
        StacksInput {
            target: target.clone(),
            thread_id: Some(tid),
            max_threads: None,
            max_frames: Some(16),
            timeout_ms: None,
        },
        Deadline::new(5000)?,
    )?;
    assert_eq!(stack.threads[0].prior_suspend_count, Some(prior + 1));
    let after = unsafe { SuspendThread(thread.0) };
    assert_ne!(after, u32::MAX);
    let extra_resume = Resume(thread.0);
    assert_eq!(after, prior + 1, "capture must restore the count it found");
    drop(extra_resume);
    drop(resume);

    let artifact = Artifact::new();
    let report = dump::capture(
        DumpInput {
            target: target.clone(),
            path: artifact.path(),
            kind: DumpKind::Mini,
            include_handles: true,
            max_bytes: Some(64 * 1024 * 1024),
            timeout_ms: None,
        },
        Deadline::new(30000)?,
    )?;
    assert!(report.complete);
    assert_eq!(std::fs::metadata(&artifact.0)?.len(), report.size_bytes);
    let mut header = [0u8; 32];
    std::fs::File::open(&artifact.0)?.read_exact(&mut header)?;
    assert_eq!(&header[..4], b"MDMP");
    assert_eq!(
        u64::from_le_bytes(header[24..32].try_into().unwrap()),
        report.captured_flags
    );
    assert_eq!(
        report.captured_flags & u64::from(report.requested_flags),
        u64::from(report.requested_flags)
    );
    let error = dump::capture(
        DumpInput {
            target: target.clone(),
            path: artifact.path(),
            kind: DumpKind::Mini,
            include_handles: false,
            max_bytes: None,
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("fresh exclusive"));
    assert_eq!(std::fs::metadata(&artifact.0)?.len(), report.size_bytes);

    let capped = Artifact::new();
    let error = dump::capture(
        DumpInput {
            target,
            path: capped.path(),
            kind: DumpKind::Full,
            include_handles: false,
            max_bytes: Some(1024 * 1024),
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("max_bytes"), "{error:#}");
    assert!(
        !capped.0.exists(),
        "incomplete dumps must be deleted through the open handle"
    );
    child.finish()?;
    Ok(())
}

async fn state(
    manager: &DiagnosticsManager,
    id: &str,
    owner: &str,
    expected: State,
) -> Result<SessionView> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let view = manager.inspect(id, owner)?;
        if view.state == expected {
            return Ok(view);
        }
        if view.state == State::Failed {
            bail!("debugger failed: {view:?}");
        }
        if Instant::now() >= deadline {
            bail!("expected {expected:?}, got {view:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(super) fn assert_not_debugged(target: &TargetInput) -> Result<()> {
    let process = Process::open(
        target.pid,
        Some(target.creation_time),
        PROCESS_QUERY_INFORMATION,
    )?;
    let mut present = windows::core::BOOL::default();
    unsafe { CheckRemoteDebuggerPresent(process.handle.0, &mut present) }?;
    assert!(
        !present.as_bool(),
        "disposable target must have no remaining debugger"
    );
    process.ensure_alive()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native debugger lifecycle against an explicitly disposable child"]
async fn native_smoke_attach_inspect_break_detach_and_persistence() -> Result<()> {
    let mut child = ChildFixture::spawn()?;
    let target = child.target()?;
    let manager = DiagnosticsManager::new(true);
    manager.register_connection("first")?;
    manager.register_connection("second")?;
    let view = manager
        .attach(
            DebugAttachInput {
                target: target.clone(),
                lifetime: Lifetime::Connection,
                event_capacity: Some(32),
                timeout_ms: None,
            },
            "first",
            Deadline::new(10000)?,
        )
        .await?;
    let id = view.id;
    let stopped = state(&manager, &id, "first", State::Stopped).await?;
    assert!(manager.inspect(&id, "different").is_err());
    let stop = stopped.stop.context("missing stop")?;
    let pc_register = match stopped
        .target
        .as_ref()
        .context("target missing")?
        .architecture
        .as_str()
    {
        "x64" => "rip",
        "x86" => "eip",
        "arm64" => "pc",
        _ => bail!("unsupported smoke architecture"),
    };
    let registers = manager
        .command(
            &id,
            "first",
            DebugCommand::Inspect {
                stop_id: stop.stop_id,
                inspection: InspectionCommand::Registers {
                    thread_id: stop.thread_id,
                },
            },
            Deadline::new(5000)?,
        )
        .await?;
    assert!(
        registers.data["registers"][pc_register].as_str().is_some(),
        "{registers:?}"
    );
    let evaluated = manager
        .command(
            &id,
            "first",
            DebugCommand::Evaluate {
                stop_id: stop.stop_id,
                thread_id: stop.thread_id,
                expression: format!("@{pc_register}+0"),
            },
            Deadline::new(5000)?,
        )
        .await?;
    let address: u64 = evaluated.data["value"]
        .as_str()
        .context("no evaluation value")?
        .parse()?;
    let memory = manager
        .command(
            &id,
            "first",
            DebugCommand::Inspect {
                stop_id: stop.stop_id,
                inspection: InspectionCommand::ReadMemory { address, length: 8 },
            },
            Deadline::new(5000)?,
        )
        .await?;
    assert_eq!(memory.data["read_bytes"], 8);
    assert!(manager
        .command(&id, "first", DebugCommand::Terminate, Deadline::new(5000)?)
        .await
        .is_err());
    assert!(manager
        .command(
            &id,
            "first",
            DebugCommand::Continue {
                stop_id: stop.stop_id + 1,
                disposition: ContinueDisposition::Default,
            },
            Deadline::new(5000)?
        )
        .await
        .is_err());
    assert_eq!(manager.inspect(&id, "first")?.state, State::Stopped);

    let canceled = Deadline::new(1000)?;
    canceled.cancel();
    assert!(manager
        .command(
            &id,
            "first",
            DebugCommand::Continue {
                stop_id: stop.stop_id,
                disposition: ContinueDisposition::Default,
            },
            canceled
        )
        .await
        .is_err());
    assert_eq!(manager.inspect(&id, "first")?.state, State::Stopped);
    manager
        .command(
            &id,
            "first",
            DebugCommand::Continue {
                stop_id: stop.stop_id,
                disposition: ContinueDisposition::Default,
            },
            Deadline::new(5000)?,
        )
        .await?;
    state(&manager, &id, "first", State::Running).await?;
    let breaking = manager
        .command(&id, "first", DebugCommand::Break, Deadline::new(5000)?)
        .await?;
    assert_eq!(breaking.data["stop_observed"], false);
    state(&manager, &id, "first", State::Stopped).await?;
    let detached = manager
        .command(&id, "first", DebugCommand::Detach, Deadline::new(5000)?)
        .await?;
    assert_eq!(detached.session.state, State::Detached);
    assert_not_debugged(&target)?;
    assert!(
        child.0.try_wait()?.is_none(),
        "detach must leave the attached child alive"
    );
    manager.disconnect("first").await?;

    manager.register_connection("persistent-owner")?;
    let persistent = manager
        .attach(
            DebugAttachInput {
                target: target.clone(),
                lifetime: Lifetime::Persistent,
                event_capacity: Some(16),
                timeout_ms: None,
            },
            "persistent-owner",
            Deadline::new(10000)?,
        )
        .await?;
    state(&manager, &persistent.id, "second", State::Stopped).await?;
    manager.disconnect("persistent-owner").await?;
    assert_eq!(
        manager.inspect(&persistent.id, "second")?.state,
        State::Stopped
    );
    manager
        .command(
            &persistent.id,
            "second",
            DebugCommand::Detach,
            Deadline::new(5000)?,
        )
        .await?;
    manager.shutdown().await?;
    assert_not_debugged(&target)?;
    assert!(child.0.try_wait()?.is_none());
    child.finish()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native debugger disconnect cleanup against an explicitly disposable child"]
async fn native_smoke_connection_cleanup_detaches_stopped_target() -> Result<()> {
    let mut child = ChildFixture::spawn()?;
    let target = child.target()?;
    let manager = DiagnosticsManager::new(true);
    manager.register_connection("connection")?;
    let view = manager
        .attach(
            DebugAttachInput {
                target: target.clone(),
                lifetime: Lifetime::Connection,
                event_capacity: None,
                timeout_ms: None,
            },
            "connection",
            Deadline::new(10000)?,
        )
        .await?;
    state(&manager, &view.id, "connection", State::Stopped).await?;
    manager.disconnect("connection").await?;
    assert_eq!(
        manager.inspect(&view.id, "connection")?.state,
        State::Detached
    );
    assert_not_debugged(&target)?;
    assert!(child.0.try_wait()?.is_none());
    child.finish()?;
    Ok(())
}

pub(super) struct OwnedTarget(pub(super) Process);

impl Drop for OwnedTarget {
    fn drop(&mut self) {
        unsafe {
            if WaitForSingleObject(self.0.handle.0, 0) == WAIT_TIMEOUT {
                if let Err(error) = TerminateProcess(self.0.handle.0, 1) {
                    eprintln!("disposable owned debugger target termination failed: {error}");
                }
                if WaitForSingleObject(self.0.handle.0, 5000) != WAIT_OBJECT_0 {
                    eprintln!("disposable owned debugger target exit was not observed");
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native debugger launch/terminate against an explicitly disposable child"]
async fn native_smoke_launch_owned_terminate_observes_exit() -> Result<()> {
    let mut cleanup = Vec::new();
    let manager = DiagnosticsManager::new(false);
    manager.register_connection("owner")?;
    let view = manager
        .launch(
            DebugLaunchInput {
                program: std::env::current_exe()?.to_string_lossy().into_owned(),
                args: fixture_arguments(),
                working_dir: None,
                lifetime: Lifetime::Connection,
                event_capacity: None,
                timeout_ms: None,
            },
            "owner",
            Deadline::new(10000)?,
        )
        .await?;
    let identity = view.target.as_ref().context("launch has no identity")?;
    cleanup.push(OwnedTarget(Process::open(
        identity.pid,
        Some(identity.creation_time.parse()?),
        PROCESS_TERMINATE,
    )?));
    let stopped = state(&manager, &view.id, "owner", State::Stopped).await?;
    assert!(stopped.owned);
    let stop = stopped.stop.context("launch has no stop")?;
    manager
        .command(
            &view.id,
            "owner",
            DebugCommand::Continue {
                stop_id: stop.stop_id,
                disposition: ContinueDisposition::Default,
            },
            Deadline::new(5000)?,
        )
        .await?;
    let output_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = manager.events(
            DebugEventsInput {
                id: view.id.clone(),
                after_cursor: Some(0),
                limit: Some(1024),
            },
            "owner",
        )?;
        if events.events.iter().any(|event| {
            event.kind == "output"
                && event.data["text"]
                    .as_str()
                    .is_some_and(|text| text.contains("stdout_type=2"))
        }) {
            break;
        }
        assert!(Instant::now() < output_deadline, "debug launch must write successfully to isolated NUL stdout and emit its native debug output: {events:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    manager
        .command(
            &view.id,
            "owner",
            DebugCommand::Terminate,
            Deadline::new(5000)?,
        )
        .await?;
    let exited = state(&manager, &view.id, "owner", State::Exited).await?;
    assert_eq!(exited.exit_code, Some(1));
    assert_eq!(
        unsafe { WaitForSingleObject(cleanup[0].0.handle.0, 0) },
        WAIT_OBJECT_0
    );
    manager.disconnect("owner").await?;
    Ok(())
}

fn current_handle_count() -> Result<u32> {
    let mut count = 0;
    unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) }?;
    Ok(count)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native debugger handle lifecycle against an explicitly disposable child"]
async fn native_smoke_repeated_attach_detach_closes_handles() -> Result<()> {
    let mut child = ChildFixture::spawn()?;
    let target = child.target()?;
    let manager = DiagnosticsManager::new(false);
    let mut baseline = 0;
    for iteration in 0..9 {
        let connection = format!("connection-{iteration}");
        manager.register_connection(&connection)?;
        let view = manager
            .attach(
                DebugAttachInput {
                    target: target.clone(),
                    lifetime: Lifetime::Connection,
                    event_capacity: None,
                    timeout_ms: None,
                },
                &connection,
                Deadline::new(10000)?,
            )
            .await?;
        let stopped = state(&manager, &view.id, &connection, State::Stopped).await?;
        if iteration % 2 != 0 {
            manager
                .command(
                    &view.id,
                    &connection,
                    DebugCommand::Continue {
                        stop_id: stopped.stop.context("fixture stop missing")?.stop_id,
                        disposition: ContinueDisposition::Default,
                    },
                    Deadline::new(5000)?,
                )
                .await?;
            manager
                .command(
                    &view.id,
                    &connection,
                    DebugCommand::Break,
                    Deadline::new(5000)?,
                )
                .await?;
            manager
                .command(
                    &view.id,
                    &connection,
                    DebugCommand::Detach,
                    Deadline::new(5000)?,
                )
                .await?;
        }
        manager.disconnect(&connection).await?;
        assert_not_debugged(&target)?;
        let process = Process::open(
            target.pid,
            Some(target.creation_time),
            PROCESS_ACCESS_RIGHTS(0),
        )?;
        assert_eq!(
            unsafe { WaitForSingleObject(process.handle.0, 100) },
            WAIT_TIMEOUT
        );
        drop(process);
        if iteration == 0 {
            baseline = current_handle_count()?;
        }
    }
    let after = current_handle_count()?;
    assert!(
        after <= baseline + 3,
        "handle count grew from {baseline} to {after} across eight completed detach cycles"
    );
    child.finish()?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WOW64 diagnostics against an owned loopback-only ping child"]
async fn native_smoke_wow64_stacks_dump_and_debug_registers() -> Result<()> {
    let program =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot unavailable")?)
            .join(r"SysWOW64\ping.exe");
    let mut command = Command::new(program);
    command.args(["-n", "60", "127.0.0.1"]);
    let mut child = ChildFixture::spawn_ready(command, "127.0.0.1")?;
    let target = child.target()?;
    let stack = stacks::capture(
        StacksInput {
            target: target.clone(),
            thread_id: None,
            max_threads: Some(16),
            max_frames: Some(32),
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )?;
    assert_eq!(stack.target.architecture, "x86");
    assert!(
        stack.threads.iter().any(|thread| thread.frames.len() > 1),
        "{stack:?}"
    );
    let artifact = Artifact::new();
    let dump = dump::capture(
        DumpInput {
            target: target.clone(),
            path: artifact.path(),
            kind: DumpKind::Mini,
            include_handles: false,
            max_bytes: Some(64 * 1024 * 1024),
            timeout_ms: None,
        },
        Deadline::new(10000)?,
    )?;
    assert_eq!(dump.target.architecture, "x86");
    assert!(dump.size_bytes > 32);
    let manager = DiagnosticsManager::new(false);
    manager.register_connection("wow64")?;
    let view = manager
        .attach(
            DebugAttachInput {
                target: target.clone(),
                lifetime: Lifetime::Connection,
                event_capacity: None,
                timeout_ms: None,
            },
            "wow64",
            Deadline::new(10000)?,
        )
        .await?;
    let stopped = state(&manager, &view.id, "wow64", State::Stopped).await?;
    let stop = stopped.stop.context("WOW64 stop missing")?;
    let registers = manager
        .command(
            &view.id,
            "wow64",
            DebugCommand::Inspect {
                stop_id: stop.stop_id,
                inspection: InspectionCommand::Registers {
                    thread_id: stop.thread_id,
                },
            },
            Deadline::new(5000)?,
        )
        .await?;
    assert!(
        registers.data["registers"]["eip"].as_str().is_some(),
        "{registers:?}"
    );
    manager.disconnect("wow64").await?;
    assert_not_debugged(&target)?;
    child.finish()?;
    Ok(())
}
