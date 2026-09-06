use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StartupPhase {
    AfterPreflight,
    NativeCreated,
    BeforeAdmission,
    BeforeResume,
}

pub(super) struct StartupGate {
    phase: StartupPhase,
    reached: Mutex<Option<tokio::sync::oneshot::Sender<Option<Arc<NativeProcess>>>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

struct StartupGateControl {
    reached: tokio::sync::oneshot::Receiver<Option<Arc<NativeProcess>>>,
    release: std::sync::mpsc::SyncSender<()>,
}

impl StartupGate {
    fn install(manager: &ExecutionManager, phase: StartupPhase) -> StartupGateControl {
        let (send, reached) = tokio::sync::oneshot::channel();
        let (release, receive) = std::sync::mpsc::sync_channel(1);
        *manager.startup_gate.lock().unwrap() = Some(Arc::new(Self {
            phase,
            reached: Mutex::new(Some(send)),
            release: Mutex::new(receive),
        }));
        StartupGateControl { reached, release }
    }

    pub(super) fn pause(
        &self,
        phase: StartupPhase,
        process: Option<&Arc<NativeProcess>>,
    ) -> anyhow::Result<()> {
        if self.phase == phase {
            if let Some(reached) = self.reached.lock().unwrap().take() {
                reached
                    .send(process.cloned())
                    .map_err(|_| anyhow::anyhow!("startup gate receiver closed"))?;
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))?;
            }
        }
        Ok(())
    }
}

fn manager() -> anyhow::Result<(ExecutionManager, String)> {
    let manager = ExecutionManager::new(PersistenceContext::connection_owned()?)?;
    let owner = uuid::Uuid::new_v4().to_string();
    manager.register_connection(&owner)?;
    Ok((manager, owner))
}

fn fixture_input(mode: &str) -> anyhow::Result<JobStartInput> {
    Ok(JobStartInput {
        program: std::env::current_exe()?.to_string_lossy().into_owned(),
        args: vec![
            "--exact".into(),
            "execution::tests::execution_fixture".into(),
            "--nocapture".into(),
        ],
        env: BTreeMap::from([("MCP_EXECUTION_TEST_MODE".into(), Some(mode.into()))]),
        ..Default::default()
    })
}

#[test]
fn execution_fixture() {
    let Ok(mode) = std::env::var("MCP_EXECUTION_TEST_MODE") else {
        return;
    };
    match mode.as_str() {
        "streams" => {
            std::io::stdout().write_all(b"mcp-stdout\n").unwrap();
            std::io::stderr().write_all(b"mcp-stderr\n").unwrap();
        }
        "huge" => {
            std::io::stdout().write_all(&vec![b'x'; 2_000_000]).unwrap();
            std::io::stderr().write_all(&[0xe2, 0x82]).unwrap();
        }
        "sleep" => {
            std::io::stdout().write_all(b"ready\n").unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
        "stdin" => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes).unwrap();
            std::io::stdout().write_all(&bytes).unwrap();
        }
        "mark" => {
            std::fs::write(std::env::var("MCP_TEST_MARKER").unwrap(), b"resumed").unwrap();
        }
        "descendant" => {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "execution::tests::execution_fixture",
                    "--nocapture",
                ])
                .env("MCP_EXECUTION_TEST_MODE", "sleep")
                .spawn()
                .unwrap();
            println!("descendant_pid={}", child.id());
            std::process::exit(0);
        }
        other => panic!("unknown execution fixture: {other}"),
    }
}

#[tokio::test]
async fn job_streams_identity_and_drain() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let record = manager.start_job(fixture_input("streams")?, &owner)?;
    assert!(record.pid > 0 && record.process_creation_time > 0);
    let entry = manager.entry(&record.id, &owner)?;
    assert_eq!(
        crate::context::process_creation_time(entry.native.as_ref().unwrap().process_handle())?,
        record.process_creation_time,
    );
    let wait = manager
        .wait(&record.id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(wait.outcome, "exited");
    assert_eq!(wait.process.root_exit_code, Some(0));
    assert!(wait.process.output_drained);
    let stdout = manager.read(
        OutputInput {
            id: record.id.clone(),
            stream: Some(Stream::Stdout),
            cursor: Some(0),
            max_bytes: None,
        },
        &owner,
    )?;
    let stderr = manager.read(
        OutputInput {
            id: record.id,
            stream: Some(Stream::Stderr),
            cursor: Some(0),
            max_bytes: None,
        },
        &owner,
    )?;
    assert!(stdout.output.text_utf8_lossy.contains("mcp-stdout"));
    assert!(!stdout.output.text_utf8_lossy.contains("mcp-stderr"));
    assert!(stderr.output.text_utf8_lossy.contains("mcp-stderr"));
    manager.shutdown()?;
    Ok(())
}

#[tokio::test]
async fn truncated_output_and_partial_bytes() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let mut input = fixture_input("huge")?;
    input.output_limit_bytes = Some(1024);
    let record = manager.start_job(input, &owner)?;
    let wait = manager
        .wait(&record.id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(wait.outcome, "exited");
    let stdout = manager.read(
        OutputInput {
            id: record.id.clone(),
            stream: Some(Stream::Stdout),
            cursor: Some(0),
            max_bytes: None,
        },
        &owner,
    )?;
    assert!(stdout.output.dropped_bytes > 1_900_000);
    assert_eq!(stdout.output.gap_bytes, stdout.output.dropped_bytes);
    assert_eq!(STANDARD.decode(stdout.output.bytes_base64)?.len(), 1024);
    let stderr = manager.read(
        OutputInput {
            id: record.id,
            stream: Some(Stream::Stderr),
            cursor: Some(0),
            max_bytes: None,
        },
        &owner,
    )?;
    assert!(!stderr.output.valid_utf8);
    assert_eq!(STANDARD.decode(stderr.output.bytes_base64)?, [0xe2, 0x82]);
    manager.shutdown()?;
    Ok(())
}

#[tokio::test]
async fn root_exit_does_not_finish_descendant_or_pipes() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let record = manager.start_job(fixture_input("descendant")?, &owner)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let current = manager.inspect(&record.id, &owner)?;
        if current.root_exit_code.is_some() {
            assert!(current.tree_active_processes > 0);
            assert_eq!(current.status, ExecutionStatus::RootExited);
            assert!(!current.output_drained);
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "fixture root did not exit"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        manager
            .wait(&record.id, &owner, 10, CancellationToken::new())
            .await?
            .outcome,
        "timed_out"
    );
    manager.cancel(&record.id, &owner)?;
    let finished = manager
        .wait(&record.id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(finished.outcome, "canceled");
    assert_eq!(finished.process.tree_active_processes, 0);
    assert!(finished.process.output_drained);
    manager.shutdown()?;
    Ok(())
}

#[test]
fn numeric_strings_and_invalid_arguments() -> anyhow::Result<()> {
    let input: JobStartInput = serde_json::from_str(
        r#"{"program":"cmd.exe","output_limit_bytes":"4096","timeout_ms":"50"}"#,
    )?;
    assert_eq!(validate_start(&input)?, 4096);
    assert_eq!(input.timeout_ms, Some(50));
    let terminal: TerminalCreateInput =
        serde_json::from_str(r#"{"program":"cmd.exe","cols":"80","rows":"24"}"#)?;
    assert_eq!(terminal.cols, Some(80));
    assert!(serde_json::from_str::<OutputInput>(r#"{"id":"x","cursor":"-1"}"#).is_err());
    assert!(serde_json::from_str::<JobStartInput>(r#"{"program":"cmd.exe","typo":true}"#).is_err());
    assert!(input_bytes(Some("a"), Some("YQ=="), true).is_err());
    assert!(input_bytes(None, Some("?!"), true).is_err());
    assert!(validate_size(0, 24).is_err());
    assert!(validate_size(80, 1001).is_err());
    assert!(validate_start(&JobStartInput {
        program: "cmd.exe".into(),
        args: vec!["x".repeat(32767 * 4)],
        ..Default::default()
    })
    .is_err());
    assert!(validate_start(&JobStartInput {
        program: "cmd.exe".into(),
        env: BTreeMap::from([("TEST".into(), Some("x".repeat(1_048_576 * 4)))]),
        ..Default::default()
    })
    .is_err());
    let (manager, owner) = manager()?;
    assert!(manager.inspect("123", &owner).is_err());
    let input = JobStartInput {
        program: "cmd.exe".into(),
        lifetime: Lifetime::Persistent,
        ..Default::default()
    };
    assert!(manager.start_job(input, &owner).is_err());
    Ok(())
}

#[tokio::test]
async fn process_deadline_and_wait_cancellation_are_distinct() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let record = manager.start_job(fixture_input("sleep")?, &owner)?;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let canceled_wait = manager.wait(&record.id, &owner, 10000, cancel).await?;
    assert_eq!(canceled_wait.outcome, "canceled");
    assert!(!canceled_wait.process.cancellation_requested);
    assert_eq!(canceled_wait.process.root_exit_code, None);
    manager.cancel(&record.id, &owner)?;
    manager
        .wait(&record.id, &owner, 10000, CancellationToken::new())
        .await?;
    let mut input = fixture_input("sleep")?;
    input.timeout_ms = Some(50);
    let timed = manager.start_job(input, &owner)?;
    let result = manager
        .wait(&timed.id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(result.outcome, "timed_out");
    assert_eq!(
        result.process.cancellation_reason.as_deref(),
        Some("deadline_exceeded")
    );
    assert_eq!(result.process.tree_active_processes, 0);
    manager.shutdown()?;
    Ok(())
}

#[tokio::test]
async fn job_stdin_is_bounded_and_closed() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let mut input = fixture_input("stdin")?;
    input.stdin_base64 = Some(STANDARD.encode(b"mcp-stdin-\0\xff-end"));
    let record = manager.start_job(input, &owner)?;
    let wait = manager
        .wait(&record.id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(wait.outcome, "exited");
    let output = manager.read(
        OutputInput {
            id: record.id,
            stream: None,
            cursor: Some(0),
            max_bytes: None,
        },
        &owner,
    )?;
    let bytes = STANDARD.decode(output.output.bytes_base64)?;
    assert!(bytes
        .windows(b"mcp-stdin-\0\xff-end".len())
        .any(|part| part == b"mcp-stdin-\0\xff-end"));
    assert!(!output.output.valid_utf8);
    manager.shutdown()?;
    Ok(())
}

fn conpty_unavailable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<windows::core::Error>()
        .is_some_and(|error| {
            matches!(
                error.code().0 as u32,
                0x80004001 | 0x80070032 | 0x80070078 | 0x8007047e
            )
        })
}

fn terminal_start(lifetime: Lifetime, cwd: Option<String>) -> anyhow::Result<TerminalCreateInput> {
    let program =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot is missing")?)
            .join("System32")
            .join("cmd.exe");
    Ok(TerminalCreateInput {
        process: JobStartInput {
            program: program.to_string_lossy().into_owned(),
            args: vec!["/d".into(), "/q".into()],
            lifetime,
            cwd,
            env: BTreeMap::from([("MCP_TEST_BOOT".into(), Some("boot-value-927".into()))]),
            ..Default::default()
        },
        cols: Some(80),
        rows: Some(24),
    })
}

async fn terminal_command(
    manager: &ExecutionManager,
    owner: &str,
    id: &str,
    text: &str,
) -> anyhow::Result<()> {
    let written = manager
        .terminal_input(
            TerminalInput {
                id: id.into(),
                text: Some(text.into()),
                base64: None,
                timeout_ms: Some(5000),
            },
            owner,
            CancellationToken::new(),
        )
        .await?;
    anyhow::ensure!(
        written.outcome == "written",
        "terminal write failed: {written:?}"
    );
    Ok(())
}

async fn terminal_contains(
    manager: &ExecutionManager,
    owner: &str,
    id: &str,
    expected: &str,
) -> anyhow::Result<OutputResult> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let output = manager.read(
            OutputInput {
                id: id.into(),
                stream: None,
                cursor: Some(0),
                max_bytes: Some(MAX_READ_BYTES),
            },
            owner,
        )?;
        if output.output.text_utf8_lossy.contains(expected) {
            return Ok(output);
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "terminal did not produce {expected:?}; output: {}",
            output.output.text_utf8_lossy
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn conpty_state_environment_resize_interrupt_and_close() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let directory = std::env::temp_dir().join(format!("mcp-terminal-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let record = match manager.create_terminal(
        terminal_start(
            Lifetime::Connection,
            Some(directory.to_string_lossy().into_owned()),
        )?,
        &owner,
    ) {
        Ok(record) => record,
        Err(error) if conpty_unavailable(&error) => {
            eprintln!("ConPTY capability unavailable in this Windows environment: {error:#}");
            std::fs::remove_dir(directory)?;
            return Ok(());
        }
        Err(error) => {
            std::fs::remove_dir(directory)?;
            return Err(error);
        }
    };
    let test = async {
        terminal_command(
            &manager,
            &owner,
            &record.id,
            "set /a MCP_TEST_STATE=100+23\r",
        )
        .await?;
        terminal_command(
            &manager,
            &owner,
            &record.id,
            "echo mcp_state:%MCP_TEST_STATE% & echo mcp_boot:%MCP_TEST_BOOT% & echo mcp_dir:%CD%\r",
        )
        .await?;
        let output = terminal_contains(&manager, &owner, &record.id, "mcp_state:123").await?;
        assert_eq!(output.stream, Stream::Combined);
        assert!(output.virtual_terminal_sequences);
        terminal_contains(&manager, &owner, &record.id, "mcp_boot:boot-value-927").await?;
        terminal_contains(
            &manager,
            &owner,
            &record.id,
            directory.file_name().unwrap().to_str().unwrap(),
        )
        .await?;
        manager.resize(
            ResizeInput {
                id: record.id.clone(),
                cols: 132,
                rows: 40,
            },
            &owner,
        )?;
        assert_eq!(manager.inspect(&record.id, &owner)?.cols, Some(132));
        terminal_command(&manager, &owner, &record.id, "set /a MCP_TEST_STATE+=1\r").await?;
        terminal_command(
            &manager,
            &owner,
            &record.id,
            "echo mcp_later:%MCP_TEST_STATE%\r",
        )
        .await?;
        terminal_contains(&manager, &owner, &record.id, "mcp_later:124").await?;
        assert!(manager
            .read(
                OutputInput {
                    id: record.id.clone(),
                    stream: Some(Stream::Stderr),
                    cursor: None,
                    max_bytes: None
                },
                &owner
            )
            .is_err());
        terminal_command(&manager, &owner, &record.id, "\u{3}").await?;
        manager.cancel(&record.id, &owner)?;
        let stopped = manager
            .wait(&record.id, &owner, 10000, CancellationToken::new())
            .await?;
        assert_eq!(stopped.outcome, "canceled");
        assert!(stopped.process.output_drained);
        anyhow::Ok(())
    }
    .await;
    manager.shutdown()?;
    std::fs::remove_dir(directory)?;
    test
}

#[tokio::test]
async fn conpty_captures_console_program_standard_handles() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let record = match manager.create_terminal(
        TerminalCreateInput {
            process: fixture_input("streams")?,
            cols: Some(80),
            rows: Some(24),
        },
        &owner,
    ) {
        Ok(record) => record,
        Err(error) if conpty_unavailable(&error) => {
            eprintln!("ConPTY capability unavailable in this Windows environment: {error:#}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let finished = manager
        .wait(&record.id, &owner, 10000, CancellationToken::new())
        .await?;
    let output = manager.read(
        OutputInput {
            id: record.id,
            stream: None,
            cursor: Some(0),
            max_bytes: None,
        },
        &owner,
    )?;
    manager.shutdown()?;
    assert_eq!(finished.process.root_exit_code, Some(0));
    assert!(
        output.output.text_utf8_lossy.contains("mcp-stdout"),
        "{output:?}"
    );
    assert!(
        output.output.text_utf8_lossy.contains("mcp-stderr"),
        "{output:?}"
    );
    Ok(())
}

#[tokio::test]
async fn host_lifetimes_and_restart_history_do_not_replay_processes() -> anyhow::Result<()> {
    let directory =
        std::env::temp_dir().join(format!("mcp-execution-state-{}", uuid::Uuid::new_v4()));
    let context = PersistenceContext::test_host(&directory)?;
    let initial_epoch = context.epoch.clone();
    let manager = ExecutionManager::new(context.clone())?;
    let first = uuid::Uuid::new_v4().to_string();
    let second = uuid::Uuid::new_v4().to_string();
    manager.register_connection(&first)?;
    manager.register_connection(&second)?;
    let ordinary = manager.start_job(fixture_input("sleep")?, &first)?;
    let ordinary_entry = manager.entry(&ordinary.id, &first)?;
    let mut input = fixture_input("sleep")?;
    input.lifetime = Lifetime::Persistent;
    let persistent = manager.start_job(input, &first)?;
    let persistent_entry = manager.entry(&persistent.id, &first)?;
    assert!(manager.inspect(&ordinary.id, &second).is_err());
    manager.shutdown_connection(&first)?;
    assert!(manager.start_job(fixture_input("sleep")?, &first).is_err());
    assert!(manager.inspect(&ordinary.id, &first).is_err());
    assert_eq!(
        manager.inspect(&persistent.id, &second)?.pid,
        persistent.pid
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ordinary_entry.record().status.finished() {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "disconnected job did not exit"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(ordinary_entry.record().tree_active_processes, 0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let output = manager.read(
            OutputInput {
                id: persistent.id.clone(),
                stream: None,
                cursor: Some(0),
                max_bytes: None,
            },
            &second,
        )?;
        if output.output.text_utf8_lossy.contains("ready") {
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "persistent fixture did not write"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    manager.checkpoint()?;
    drop(manager);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !persistent_entry.record().status.finished() {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "old host tree did not exit"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(context);
    let reopened_context = PersistenceContext::test_host(&directory)?;
    assert_ne!(initial_epoch, reopened_context.epoch);
    let reopened = ExecutionManager::new(reopened_context)?;
    let third = uuid::Uuid::new_v4().to_string();
    reopened.register_connection(&third)?;
    let saved = reopened.inspect(&persistent.id, &third)?;
    assert_eq!(saved.status, ExecutionStatus::InterruptedHostRestart);
    assert_eq!(saved.epoch, initial_epoch);
    assert_eq!(
        saved.process_creation_time,
        persistent.process_creation_time
    );
    assert!(!saved.process_state_current);
    assert!(!saved.output_drained);
    assert!(!saved.restart_gap.as_ref().unwrap().mutations_replayed);
    assert!(reopened.cancel(&saved.id, &third).is_err());
    assert!(reopened
        .read(
            OutputInput {
                id: saved.id,
                stream: None,
                cursor: Some(0),
                max_bytes: None
            },
            &third
        )?
        .output
        .text_utf8_lossy
        .contains("ready"));
    assert!(reopened.inspect(&ordinary.id, &third).is_err());
    reopened.shutdown()?;
    drop(reopened);
    drop(ordinary_entry);
    drop(persistent_entry);
    std::fs::remove_file(directory.join(CHECKPOINT_FILE))?;
    std::fs::remove_dir(directory)?;
    Ok(())
}

#[tokio::test]
async fn canceled_before_resume_never_returns_to_running() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join(format!("mcp-resume-race-{}", uuid::Uuid::new_v4()));
    let manager = Arc::new(ExecutionManager::new(PersistenceContext::test_host(
        &path,
    )?)?);
    let owner = uuid::Uuid::new_v4().to_string();
    manager.register_connection(&owner)?;
    let gate = StartupGate::install(&manager, StartupPhase::BeforeResume);
    let mut input = fixture_input("mark")?;
    input.lifetime = Lifetime::Persistent;
    input.timeout_ms = Some(1);
    input.env.insert(
        "MCP_TEST_MARKER".into(),
        Some(path.join("resumed").to_string_lossy().into_owned()),
    );
    let worker_manager = manager.clone();
    let worker_owner = owner.clone();
    let worker =
        tokio::task::spawn_blocking(move || worker_manager.start_job(input, &worker_owner));
    let _process = tokio::time::timeout(Duration::from_secs(10), gate.reached).await??;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let record = loop {
        let records = manager.list(&owner, None).records;
        if let Some(record) = records.into_iter().find(|record| record.status.finished()) {
            break record;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "suspended fixture did not reach its deadline"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    gate.release.send(())?;
    assert!(worker.await?.is_err());
    let current = manager.inspect(&record.id, &owner)?;
    assert!(current.status.finished());
    assert_eq!(
        current.cancellation_reason.as_deref(),
        Some("deadline_exceeded")
    );
    assert_eq!(current.tree_active_processes, 0);
    assert!(!path.join("resumed").exists());
    manager.shutdown()?;
    drop(manager);
    std::fs::remove_file(path.join(CHECKPOINT_FILE))?;
    std::fs::remove_dir(path)?;
    Ok(())
}

#[tokio::test]
async fn accepted_persistent_start_survives_its_client_disconnect() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join(format!("mcp-persistent-start-{}", uuid::Uuid::new_v4()));
    let manager = Arc::new(ExecutionManager::new(PersistenceContext::test_host(
        &path,
    )?)?);
    let first = uuid::Uuid::new_v4().to_string();
    let second = uuid::Uuid::new_v4().to_string();
    manager.register_connection(&first)?;
    manager.register_connection(&second)?;
    let gate = StartupGate::install(&manager, StartupPhase::BeforeResume);
    let request_cancel = CancellationToken::new();
    let startup_cancel = request_cancel.clone();
    let mut input = fixture_input("streams")?;
    input.lifetime = Lifetime::Persistent;
    let worker_manager = manager.clone();
    let worker_owner = first.clone();
    let worker = tokio::task::spawn_blocking(move || {
        worker_manager.start_job_cancellable(input, &worker_owner, startup_cancel)
    });
    let _process = tokio::time::timeout(Duration::from_secs(10), gate.reached).await??;
    manager.shutdown_connection(&first)?;
    request_cancel.cancel();
    gate.release.send(())?;
    let record = worker.await??;
    let finished = manager
        .wait(&record.id, &second, 10000, CancellationToken::new())
        .await?;
    assert_eq!(finished.outcome, "exited");
    assert!(!finished.process.cancellation_requested);
    manager.shutdown()?;
    drop(manager);
    std::fs::remove_file(path.join(CHECKPOINT_FILE))?;
    std::fs::remove_dir(path)?;
    Ok(())
}

#[tokio::test]
async fn request_cancellation_at_native_startup_boundaries_never_resumes() -> anyhow::Result<()> {
    for terminal in [false, true] {
        for phase in [
            StartupPhase::AfterPreflight,
            StartupPhase::NativeCreated,
            StartupPhase::BeforeAdmission,
            StartupPhase::BeforeResume,
        ] {
            let (manager, owner) = manager()?;
            let manager = Arc::new(manager);
            let mut gate = StartupGate::install(&manager, phase);
            let marker =
                std::env::temp_dir().join(format!("mcp-canceled-start-{}", uuid::Uuid::new_v4()));
            let mut input = fixture_input("mark")?;
            input.env.insert(
                "MCP_TEST_MARKER".into(),
                Some(marker.to_string_lossy().into_owned()),
            );
            let request = CancellationToken::new();
            let startup = request.clone();
            let worker_manager = manager.clone();
            let worker_owner = owner.clone();
            let mut worker = tokio::task::spawn_blocking(move || {
                if terminal {
                    worker_manager.create_terminal_cancellable(
                        TerminalCreateInput {
                            process: input,
                            cols: Some(80),
                            rows: Some(24),
                        },
                        &worker_owner,
                        startup,
                    )
                } else {
                    worker_manager.start_job_cancellable(input, &worker_owner, startup)
                }
            });
            let process = tokio::select! {
                reached = &mut gate.reached => reached?,
                result = &mut worker => {
                    let error = result?.err().context("fixture resumed without reaching the startup gate")?;
                    if terminal && conpty_unavailable(&error) {
                        eprintln!("ConPTY startup cancellation probe unavailable: {error:#}");
                        manager.shutdown()?;
                        continue;
                    }
                    return Err(error);
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => bail!("startup did not reach the cancellation gate"),
            };
            request.cancel();
            gate.release.send(())?;
            let error = worker
                .await?
                .err()
                .context("canceled startup was accepted")?;
            assert!(
                format!("{error:#}").contains("startup request canceled"),
                "{error:#}"
            );
            manager.shutdown()?;
            if let Some(process) = process {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let (exit, active) = process.sample()?;
                    if exit.is_some() && active == 0 {
                        break;
                    }
                    anyhow::ensure!(
                        tokio::time::Instant::now() < deadline,
                        "canceled suspended process survived"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            assert!(
                !marker.exists(),
                "canceled startup executed a mutating instruction"
            );
            assert_eq!(manager.registry.lock().unwrap().pending, 0);
            if phase != StartupPhase::BeforeResume {
                assert!(manager.list(&owner, None).records.is_empty());
                assert_eq!(manager.registry.lock().unwrap().budget, 0);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn dropping_start_handler_cancels_worker_without_canceling_parent_token() -> anyhow::Result<()>
{
    let (manager, owner) = manager()?;
    let manager = Arc::new(manager);
    let gate = StartupGate::install(&manager, StartupPhase::BeforeResume);
    let parent = CancellationToken::new();
    let parent_request = parent.clone();
    let worker_manager = manager.clone();
    let worker_owner = owner.clone();
    let input = fixture_input("sleep")?;
    let (finished, completed) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn(async move {
        tools::run_start(parent_request, move |startup| {
            let result =
                worker_manager.start_job_cancellable(input, &worker_owner, startup.clone());
            let _ = finished.send((startup.is_cancelled(), result.is_err()));
            result
        })
        .await
    });
    let _process = tokio::time::timeout(Duration::from_secs(10), gate.reached).await??;
    handler.abort();
    assert!(handler.await.unwrap_err().is_cancelled());
    assert!(!parent.is_cancelled());
    gate.release.send(())?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), completed).await??,
        (true, true)
    );
    manager.shutdown()?;
    for record in manager.list(&owner, None).records {
        assert!(record.status.finished());
        assert_eq!(record.tree_active_processes, 0);
    }
    let normal = tools::run_start(parent.clone(), |_| bail!("ordinary fixture failure")).await?;
    assert_eq!(normal.is_error, Some(true));
    assert!(!parent.is_cancelled());
    Ok(())
}

#[tokio::test]
async fn persistent_request_cancellation_before_resume_differs_from_lost_acknowledgement(
) -> anyhow::Result<()> {
    let path = std::env::temp_dir().join(format!("mcp-start-request-{}", uuid::Uuid::new_v4()));
    let manager = Arc::new(ExecutionManager::new(PersistenceContext::test_host(
        &path,
    )?)?);
    let owner = uuid::Uuid::new_v4().to_string();
    manager.register_connection(&owner)?;
    let gate = StartupGate::install(&manager, StartupPhase::BeforeResume);
    let request = CancellationToken::new();
    let startup = request.clone();
    let mut input = fixture_input("sleep")?;
    input.lifetime = Lifetime::Persistent;
    let worker_manager = manager.clone();
    let worker_owner = owner.clone();
    let worker = tokio::task::spawn_blocking(move || {
        worker_manager.start_job_cancellable(input, &worker_owner, startup)
    });
    let _process = tokio::time::timeout(Duration::from_secs(10), gate.reached).await??;
    request.cancel();
    gate.release.send(())?;
    assert!(worker.await?.is_err());

    let request = CancellationToken::new();
    let mut input = fixture_input("sleep")?;
    input.lifetime = Lifetime::Persistent;
    let accepted = manager.start_job_cancellable(input, &owner, request.clone())?;
    request.cancel();
    assert!(
        !manager
            .inspect(&accepted.id, &owner)?
            .cancellation_requested
    );
    assert_eq!(manager.inspect(&accepted.id, &owner)?.root_exit_code, None);
    manager.shutdown()?;
    drop(manager);
    std::fs::remove_file(path.join(CHECKPOINT_FILE))?;
    std::fs::remove_dir(path)?;
    Ok(())
}

#[test]
fn pending_starts_are_bounded_before_process_creation() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let mut reservations = Vec::new();
    for _ in 0..MAX_RECORDS {
        reservations.push(manager.reserve(&owner, Lifetime::Connection, 1)?);
    }
    assert!(manager.reserve(&owner, Lifetime::Connection, 1).is_err());
    drop(reservations);
    let mut reservations = Vec::new();
    for _ in 0..8 {
        reservations.push(manager.reserve(&owner, Lifetime::Connection, MAX_OUTPUT_BYTES * 2)?);
    }
    assert!(manager
        .reserve(&owner, Lifetime::Connection, MAX_OUTPUT_BYTES * 2)
        .is_err());
    drop(reservations);
    assert_eq!(manager.registry.lock().unwrap().budget, 0);
    Ok(())
}

#[tokio::test]
async fn checkpoint_failure_prevents_child_resume_and_reaps_the_owned_tree() -> anyhow::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let directory =
        std::env::temp_dir().join(format!("mcp-checkpoint-failure-{}", uuid::Uuid::new_v4()));
    let context = PersistenceContext::test_host(&directory)?;
    let manager = ExecutionManager::new(context.clone())?;
    let owner = uuid::Uuid::new_v4().to_string();
    manager.register_connection(&owner)?;
    context.write_checkpoint(CHECKPOINT_FILE, b"locked")?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(directory.join(CHECKPOINT_FILE))?;
    let marker = directory.join("must-not-exist");
    let mut input = fixture_input("mark")?;
    input.lifetime = Lifetime::Persistent;
    input.env.insert(
        "MCP_TEST_MARKER".into(),
        Some(marker.to_string_lossy().into_owned()),
    );
    let error = manager
        .start_job(input, &owner)
        .err()
        .context("uncheckpointed process was resumed")?;
    assert!(
        error.to_string().contains("did not complete startup"),
        "{error:#}"
    );
    let list = manager.list(&owner, None);
    assert_eq!(list.records.len(), 1);
    assert!(list.checkpoint_error.is_some());
    let stopped = manager
        .wait(&list.records[0].id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(stopped.outcome, "failed");
    assert_eq!(stopped.process.tree_active_processes, 0);
    assert!(stopped.process.root_exit_code.is_some());
    assert!(
        !marker.exists(),
        "a mutating child instruction ran before durable startup metadata"
    );
    drop(lock);
    manager.shutdown()?;
    drop(manager);
    drop(context);
    std::fs::remove_file(directory.join(CHECKPOINT_FILE))?;
    std::fs::remove_dir(directory)?;
    Ok(())
}

#[test]
fn failed_terminal_launch_and_invalid_cwd_release_resources() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let mut terminal = terminal_start(Lifetime::Connection, None)?;
    terminal.process.program = format!(
        "C:\\Windows\\System32\\mcp-missing-{}.exe",
        uuid::Uuid::new_v4()
    );
    let error = manager
        .create_terminal(terminal, &owner)
        .err()
        .context("nonexistent terminal program started")?;
    if conpty_unavailable(&error) {
        eprintln!("ConPTY capability unavailable in this Windows environment: {error:#}");
    } else {
        assert!(
            error
                .downcast_ref::<windows::core::Error>()
                .is_some_and(|error| {
                    error.code() == windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.to_hresult()
                }),
            "{error:#}"
        );
    }
    let mut job = fixture_input("streams")?;
    job.cwd = Some(
        std::env::temp_dir()
            .join(format!("mcp-missing-cwd-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned(),
    );
    assert!(manager.start_job(job, &owner).is_err());
    assert!(manager.list(&owner, None).records.is_empty());
    assert_eq!(manager.registry.lock().unwrap().budget, 0);
    assert!(!manager.is_persistent());
    assert!(manager.request_host_shutdown().is_err());
    manager.shutdown()?;
    Ok(())
}

#[tokio::test]
async fn system_program_name_and_actual_failure_exit_code() -> anyhow::Result<()> {
    let (manager, owner) = manager()?;
    let job = manager.start_job(
        JobStartInput {
            program: "cmd.exe".into(),
            args: vec![
                "/d".into(),
                "/q".into(),
                "/c".into(),
                "exit".into(),
                "7".into(),
            ],
            ..Default::default()
        },
        &owner,
    )?;
    let result = manager
        .wait(&job.id, &owner, 10000, CancellationToken::new())
        .await?;
    assert_eq!(result.outcome, "exited");
    assert_eq!(result.process.root_exit_code, Some(7));
    assert!(result.process.program.ends_with("\\cmd.exe"));
    manager.shutdown()?;
    Ok(())
}
