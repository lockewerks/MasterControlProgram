use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::GetFileType;
use windows::Win32::System::Diagnostics::Debug::{CheckRemoteDebuggerPresent, OutputDebugStringW};
use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory};
use windows::Win32::System::Memory::*;
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

#[test]
#[ignore = "editing subprocess fixture, requires MCP_DIAGNOSTICS_EDIT_CHILD"]
fn editing_child_fixture() {
    if std::env::var_os("MCP_DIAGNOSTICS_EDIT_CHILD").is_none()
        || !std::env::args().any(|arg| arg == "--exact")
    {
        return;
    }
    unsafe {
        let code = VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        let data = VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        assert!(!code.is_null() && !data.is_null());
        std::ptr::copy_nonoverlapping([0x90u8, 0xc3].as_ptr(), code.cast(), 2);
        std::ptr::write_bytes(data.cast::<u8>().add(8), 0x11, 8);
        let mut old = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &mut old).unwrap();
        FlushInstructionCache(GetCurrentProcess(), Some(code), 2).unwrap();
        println!("MCP_EDIT_READY {} {}", code as usize, data as usize);
        std::io::stdout().flush().unwrap();
        let code = code as usize;
        let data = data as usize;
        let workers: Vec<_> = (0..2)
            .map(|_| {
                std::thread::spawn(move || {
                    let function: unsafe extern "C" fn() = std::mem::transmute(code);
                    let counter = &*(data as *const std::sync::atomic::AtomicU64);
                    for _ in 0..12000 {
                        function();
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

pub(super) struct ChildFixture(Child, Option<String>);

impl ChildFixture {
    pub(super) fn spawn() -> Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command.args(fixture_arguments());
        Self::spawn_ready(command, "MCP_DIAGNOSTICS_FIXTURE_READY")
    }

    fn spawn_ready(mut command: Command, marker: &str) -> Result<Self> {
        command
            .env_clear()
            .env("MCP_DIAGNOSTICS_EDIT_CHILD", "1")
            .env(
                "SystemRoot",
                std::env::var_os("SystemRoot").context("SystemRoot unavailable")?,
            );
        let mut child = Self(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?,
            None,
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
                        send.send(Ok(line.clone()))
                            .context("fixture readiness receiver closed")?;
                        ready = true;
                    }
                }
            })();
            if !ready {
                if let Err(error) = result {
                    let _ = send.send(Err(error));
                }
            }
        });
        child.1 = Some(
            receive
                .recv_timeout(Duration::from_secs(10))
                .context("fixture readiness timeout")??,
        );
        Ok(child)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native editing against a guarded disposable x64 child"]
#[cfg(target_arch = "x86_64")]
async fn native_smoke_debugger_editing() -> Result<()> {
    use base64::Engine;
    let mut command = Command::new(std::env::current_exe()?);
    command.args([
        "--exact",
        "diagnostics::smoke::editing_child_fixture",
        "--ignored",
        "--nocapture",
    ]);
    let mut child = ChildFixture::spawn_ready(command, "MCP_EDIT_READY")?;
    let line = child.1.as_ref().context("editing rendezvous missing")?;
    let mut fields = line
        .split_whitespace()
        .skip_while(|part| *part != "MCP_EDIT_READY")
        .skip(1);
    let code: u64 = fields.next().context("missing code address")?.parse()?;
    let data: u64 = fields.next().context("missing data address")?.parse()?;
    let target = child.target()?;
    let process = Process::open(target.pid, Some(target.creation_time), PROCESS_VM_READ)?;
    let read = |address: u64, length: usize| -> Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        let mut count = 0;
        unsafe {
            ReadProcessMemory(
                process.handle.0,
                address as *const _,
                bytes.as_mut_ptr().cast(),
                length,
                Some(&mut count),
            )
        }?;
        assert_eq!(count, length);
        Ok(bytes)
    };
    let manager = DiagnosticsManager::new(false);
    manager.register_connection("edit")?;
    let view = manager
        .attach(
            DebugAttachInput {
                target: target.clone(),
                lifetime: Lifetime::Connection,
                event_capacity: Some(512),
                timeout_ms: None,
            },
            "edit",
            Deadline::new(10000)?,
        )
        .await?;
    let id = view.id;
    let stopped = state(&manager, &id, "edit", State::Stopped).await?;
    let stop = stopped.stop.context("missing initial stop")?;
    assert_eq!(stop.reason, "initial_breakpoint");
    let send = |command| manager.command(&id, "edit", command, Deadline::new(10000).unwrap());
    let encoded = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    assert!(send(DebugCommand::WriteMemory {
        stop_id: stop.stop_id + 1,
        address: data + 8,
        bytes_base64: encoded(&[0x22; 8]),
        expected_base64: encoded(&[0x11; 8]),
    })
    .await
    .is_err());
    assert!(send(DebugCommand::WriteMemory {
        stop_id: stop.stop_id,
        address: data + 8,
        bytes_base64: encoded(&[0x22; 8]),
        expected_base64: encoded(&[0x33; 8]),
    })
    .await
    .is_err());
    assert_eq!(read(data + 8, 8)?, [0x11; 8]);
    let written = send(DebugCommand::WriteMemory {
        stop_id: stop.stop_id,
        address: data + 8,
        bytes_base64: encoded(&[0x22; 8]),
        expected_base64: encoded(&[0x11; 8]),
    })
    .await?;
    assert_eq!(written.data["complete"], true);
    assert_eq!(written.data["written_bytes"], 8);
    assert_eq!(written.data["readback_base64"], encoded(&[0x22; 8]));
    assert_eq!(read(data + 8, 8)?, [0x22; 8]);
    assert!(!written.application_completion_observed);
    let denied = serde_json::to_value(debugger::guarded_write(
        &process,
        data + 8,
        &[0x33; 8],
        &[0x22; 8],
    )?)?;
    assert_eq!(denied["api_success"], false);
    assert_eq!(denied["partial"], true);
    assert_eq!(denied["written_bytes"], 0);
    assert_eq!(denied["readback_base64"], encoded(&[0x22; 8]));
    assert!(denied["errors"]
        .as_array()
        .is_some_and(|errors| !errors.is_empty()));
    assert!(send(DebugCommand::WriteMemory {
        stop_id: stop.stop_id,
        address: 0,
        bytes_base64: encoded(&[1]),
        expected_base64: encoded(&[0]),
    })
    .await
    .is_err());
    assert!(send(DebugCommand::WriteMemory {
        stop_id: stop.stop_id,
        address: data + 4095,
        bytes_base64: encoded(&[1, 2]),
        expected_base64: encoded(&[0, 0]),
    })
    .await
    .is_err());
    send(DebugCommand::Breakpoint {
        stop_id: stop.stop_id,
        action: BreakpointAction::Add {
            address: code,
            expected_byte: 0x90,
        },
    })
    .await?;
    assert_eq!(read(code, 2)?, [0xcc, 0xc3]);
    assert!(send(DebugCommand::WriteMemory {
        stop_id: stop.stop_id,
        address: code,
        bytes_base64: encoded(&[0x90]),
        expected_base64: encoded(&[0xcc]),
    })
    .await
    .is_err());
    for action in [
        BreakpointAction::Disable { address: code },
        BreakpointAction::Enable { address: code },
        BreakpointAction::List,
    ] {
        send(DebugCommand::Breakpoint {
            stop_id: stop.stop_id,
            action,
        })
        .await?;
    }
    let mut region = MEMORY_BASIC_INFORMATION::default();
    unsafe {
        VirtualQueryEx(
            process.handle.0,
            Some(code as *const _),
            &mut region,
            std::mem::size_of_val(&region),
        )
    };
    assert_eq!(region.Protect, PAGE_EXECUTE_READ);
    send(DebugCommand::Continue {
        stop_id: stop.stop_id,
        disposition: ContinueDisposition::Default,
    })
    .await?;
    let hit = state(&manager, &id, "edit", State::Stopped)
        .await?
        .stop
        .context("missing owned hit")?;
    assert_eq!(hit.reason, "software_breakpoint");
    assert_eq!(hit.breakpoint_address, Some(format!("0x{code:x}")));
    assert_eq!(read(code, 2)?, [0x90, 0xc3]);
    let registers = send(DebugCommand::Inspect {
        stop_id: hit.stop_id,
        inspection: InspectionCommand::Registers {
            thread_id: hit.thread_id,
        },
    })
    .await?;
    assert_eq!(registers.data["registers"]["rip"], format!("0x{code:x}"));
    let before = read(data, 8)?;
    send(DebugCommand::Step {
        stop_id: hit.stop_id,
    })
    .await?;
    let stepped = state(&manager, &id, "edit", State::Stopped)
        .await?
        .stop
        .context("missing single step")?;
    assert_eq!(stepped.reason, "single_step");
    assert_eq!(stepped.thread_id, hit.thread_id);
    assert_eq!(
        read(data, 8)?,
        before,
        "no thread may pass the unpatched instruction during step"
    );
    assert_eq!(read(code, 2)?, [0xcc, 0xc3]);
    send(DebugCommand::Continue {
        stop_id: stepped.stop_id,
        disposition: ContinueDisposition::Default,
    })
    .await?;
    let hit = state(&manager, &id, "edit", State::Stopped)
        .await?
        .stop
        .context("missing second owned hit")?;
    assert_eq!(hit.reason, "software_breakpoint");
    send(DebugCommand::Continue {
        stop_id: hit.stop_id,
        disposition: ContinueDisposition::Default,
    })
    .await?;
    let hit = state(&manager, &id, "edit", State::Stopped)
        .await?
        .stop
        .context("missing reinserted breakpoint hit")?;
    assert_eq!(hit.reason, "software_breakpoint");
    send(DebugCommand::Breakpoint {
        stop_id: hit.stop_id,
        action: BreakpointAction::Remove { address: code },
    })
    .await?;
    send(DebugCommand::Continue {
        stop_id: hit.stop_id,
        disposition: ContinueDisposition::Default,
    })
    .await?;
    state(&manager, &id, "edit", State::Running).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        manager.inspect(&id, "edit")?.state,
        State::Running,
        "{:?}",
        manager.inspect(&id, "edit")?
    );
    send(DebugCommand::Break).await?;
    let stop = state(&manager, &id, "edit", State::Stopped)
        .await?
        .stop
        .context("missing requested stop")?;
    assert_eq!(stop.reason, "requested_break");
    send(DebugCommand::Breakpoint {
        stop_id: stop.stop_id,
        action: BreakpointAction::Add {
            address: code,
            expected_byte: 0x90,
        },
    })
    .await?;
    // Disconnect with a patched byte and a stopped event must restore and release both.
    manager.disconnect("edit").await?;
    assert_not_debugged(&target)?;
    assert_eq!(read(code, 2)?, [0x90, 0xc3]);
    let before = read(data, 8)?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_ne!(
        read(data, 8)?,
        before,
        "disconnect must leave child threads running"
    );
    for phase in 0..3 {
        let manager = DiagnosticsManager::new(false);
        manager.register_connection("cleanup")?;
        let view = manager
            .attach(
                DebugAttachInput {
                    target: target.clone(),
                    lifetime: Lifetime::Connection,
                    event_capacity: None,
                    timeout_ms: None,
                },
                "cleanup",
                Deadline::new(10000)?,
            )
            .await?;
        let send =
            |command| manager.command(&view.id, "cleanup", command, Deadline::new(10000).unwrap());
        let stop = state(&manager, &view.id, "cleanup", State::Stopped)
            .await?
            .stop
            .context("missing cleanup stop")?;
        send(DebugCommand::Breakpoint {
            stop_id: stop.stop_id,
            action: BreakpointAction::Add {
                address: code,
                expected_byte: 0x90,
            },
        })
        .await?;
        send(DebugCommand::Continue {
            stop_id: stop.stop_id,
            disposition: ContinueDisposition::Default,
        })
        .await?;
        if phase != 2 {
            let hit = state(&manager, &view.id, "cleanup", State::Stopped)
                .await?
                .stop
                .context("missing cleanup hit")?;
            assert_eq!(hit.reason, "software_breakpoint");
            if phase == 1 {
                send(DebugCommand::Step {
                    stop_id: hit.stop_id,
                })
                .await?;
            }
        }
        manager.disconnect("cleanup").await?;
        assert_not_debugged(&target)?;
        assert_eq!(read(code, 2)?, [0x90, 0xc3]);
        let before = read(data, 8)?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_ne!(
            read(data, 8)?,
            before,
            "cleanup phase {phase} must leave threads running"
        );
    }
    let manager = DiagnosticsManager::new(false);
    manager.register_connection("changed")?;
    let view = manager
        .attach(
            DebugAttachInput {
                target: target.clone(),
                lifetime: Lifetime::Connection,
                event_capacity: None,
                timeout_ms: None,
            },
            "changed",
            Deadline::new(10000)?,
        )
        .await?;
    let stop = state(&manager, &view.id, "changed", State::Stopped)
        .await?
        .stop
        .context("missing ownership stop")?;
    manager
        .command(
            &view.id,
            "changed",
            DebugCommand::Breakpoint {
                stop_id: stop.stop_id,
                action: BreakpointAction::Add {
                    address: code,
                    expected_byte: 0x90,
                },
            },
            Deadline::new(5000)?,
        )
        .await?;
    let external = Process::open(
        target.pid,
        Some(target.creation_time),
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
    )?;
    let changed =
        serde_json::to_value(debugger::guarded_write(&external, code, &[0x91], &[0xcc])?)?;
    assert_eq!(changed["complete"], true);
    let failure = manager
        .disconnect("changed")
        .await
        .expect_err("ownership loss must be reported");
    assert!(
        format!("{failure:#}").contains("ownership lost"),
        "{failure:#}"
    );
    assert_not_debugged(&target)?;
    assert_eq!(
        read(code, 1)?,
        [0x91],
        "cleanup must not overwrite another writer's byte"
    );
    let before = read(data, 8)?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_ne!(read(data, 8)?, before);
    child.finish()?;
    Ok(())
}

impl ChildFixture {
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
    let editing = Process::open(
        target.pid,
        Some(target.creation_time),
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
    )?;
    // Only this disposable child receives the test rendezvous. Its x86 thread
    // increments a counter so detach proves execution resumes without INT3.
    let code = unsafe {
        VirtualAllocEx(
            editing.handle.0,
            None,
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    assert!(!code.is_null());
    let address = code as u64;
    let counter = u32::try_from(address + 128)?;
    let mut bytes = vec![0x90, 0xff, 0x05];
    bytes.extend(counter.to_le_bytes());
    bytes.extend([0xeb, 0xf7]);
    unsafe {
        windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
            editing.handle.0,
            code,
            bytes.as_ptr().cast(),
            bytes.len(),
            None,
        )?;
        FlushInstructionCache(editing.handle.0, Some(code), bytes.len())?;
    }
    let thread = Handle(unsafe {
        CreateRemoteThread(
            editing.handle.0,
            None,
            0,
            Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(code)),
            None,
            CREATE_SUSPENDED.0,
            None,
        )
    }?);
    manager
        .command(
            &view.id,
            "wow64",
            DebugCommand::Breakpoint {
                stop_id: stop.stop_id,
                action: BreakpointAction::Add {
                    address,
                    expected_byte: 0x90,
                },
            },
            Deadline::new(5000)?,
        )
        .await?;
    assert_ne!(unsafe { ResumeThread(thread.0) }, u32::MAX);
    let mut current = stop;
    for _ in 0..4 {
        manager
            .command(
                &view.id,
                "wow64",
                DebugCommand::Continue {
                    stop_id: current.stop_id,
                    disposition: ContinueDisposition::Default,
                },
                Deadline::new(5000)?,
            )
            .await?;
        current = state(&manager, &view.id, "wow64", State::Stopped)
            .await?
            .stop
            .context("WOW64 editing stop missing")?;
        if current.reason == "software_breakpoint" {
            break;
        }
        assert!(
            matches!(
                current.reason,
                "initial_breakpoint" | "wow64_initial_breakpoint"
            ),
            "{current:?}"
        );
    }
    assert_eq!(current.reason, "software_breakpoint");
    assert_eq!(current.breakpoint_address, Some(format!("0x{address:x}")));
    manager
        .command(
            &view.id,
            "wow64",
            DebugCommand::Step {
                stop_id: current.stop_id,
            },
            Deadline::new(5000)?,
        )
        .await?;
    let stepped = state(&manager, &view.id, "wow64", State::Stopped)
        .await?
        .stop
        .context("WOW64 step stop missing")?;
    assert_eq!(stepped.reason, "single_step");
    let registers = manager
        .command(
            &view.id,
            "wow64",
            DebugCommand::Inspect {
                stop_id: stepped.stop_id,
                inspection: InspectionCommand::Registers {
                    thread_id: stepped.thread_id,
                },
            },
            Deadline::new(5000)?,
        )
        .await?;
    assert_eq!(
        registers.data["registers"]["eip"],
        format!("0x{:x}", address + 1)
    );
    manager.disconnect("wow64").await?;
    assert_not_debugged(&target)?;
    let mut restored = 0u8;
    unsafe {
        ReadProcessMemory(
            editing.handle.0,
            code,
            (&mut restored as *mut u8).cast(),
            1,
            None,
        )
    }?;
    assert_eq!(restored, 0x90);
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut counted = 0u32;
    unsafe {
        ReadProcessMemory(
            editing.handle.0,
            counter as *const _,
            (&mut counted as *mut u32).cast(),
            4,
            None,
        )
    }?;
    assert_ne!(counted, 0);
    child.finish()?;
    Ok(())
}
