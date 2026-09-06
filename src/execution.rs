mod buffer;
mod input;
mod native;
mod tools;

use std::{
    collections::{BTreeMap, HashSet},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::context::{now_ms, PersistenceContext};
pub use buffer::OutputChunk;
use buffer::{ByteBuffer, SavedBuffer};
pub use input::InputResult;
use input::InputWriter;
use native::NativeProcess;

const DEFAULT_OUTPUT_BYTES: usize = 262_144;
const MAX_OUTPUT_BYTES: usize = 4_194_304;
const MAX_TOTAL_OUTPUT_BYTES: usize = 67_108_864;
const MAX_RECORDS: usize = 64;
const MAX_READ_BYTES: usize = 262_144;
const MAX_INPUT_BYTES: usize = 65_536;
const MAX_WAIT_MS: u64 = 300_000;
const CHECKPOINT_FILE: &str = "execution.json";
const MAX_CHECKPOINT_BYTES: usize = 96 * 1024 * 1024;

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    #[default]
    Connection,
    Persistent,
}

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobStartInput {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub lifetime: Lifetime,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub output_limit_bytes: Option<usize>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub stdin_text: Option<String>,
    pub stdin_base64: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct TerminalCreateInput {
    #[serde(flatten)]
    pub process: JobStartInput,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub cols: Option<u16>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub rows: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdInput {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResizeInput {
    pub id: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub cols: u16,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub rows: u16,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Combined,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputInput {
    pub id: String,
    pub stream: Option<Stream>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub cursor: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminalInput {
    pub id: String,
    pub text: Option<String>,
    pub base64: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitInput {
    pub id: String,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionKind {
    Job,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Starting,
    Running,
    RootExited,
    Exited,
    Canceled,
    TimedOut,
    Failed,
    InterruptedHostRestart,
}

impl ExecutionStatus {
    fn finished(self) -> bool {
        matches!(
            self,
            Self::Exited
                | Self::Canceled
                | Self::TimedOut
                | Self::Failed
                | Self::InterruptedHostRestart
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartGap {
    pub checkpoint_at_ms: u64,
    pub observed_restart_at_ms: u64,
    pub output_after_checkpoint_unknown: bool,
    pub mutations_replayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub id: String,
    pub epoch: String,
    pub kind: ExecutionKind,
    pub lifetime: Lifetime,
    pub owner_connection: Option<String>,
    pub pid: u32,
    pub process_creation_time: u64,
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub status: ExecutionStatus,
    pub root_exit_code: Option<u32>,
    pub tree_active_processes: u32,
    pub process_state_current: bool,
    pub output_drained: bool,
    pub cancellation_requested: bool,
    pub cancellation_reason: Option<String>,
    pub last_error: Option<String>,
    pub restart_gap: Option<RestartGap>,
    pub cols: Option<u16>,
    pub rows: Option<u16>,
    pub output_limit_bytes: usize,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct OutputResult {
    pub id: String,
    pub epoch: String,
    pub stream: Stream,
    pub encoding: String,
    pub virtual_terminal_sequences: bool,
    pub output: OutputChunk,
    pub process: ExecutionRecord,
}

#[derive(Debug, Serialize)]
pub struct WaitResult {
    pub outcome: String,
    pub process: ExecutionRecord,
}

#[derive(Debug, Serialize)]
pub struct ExecutionList {
    pub epoch: String,
    pub records: Vec<ExecutionRecord>,
    pub evicted_records: u64,
    pub record_limit: usize,
    pub output_budget_bytes: usize,
    pub last_checkpoint_at_ms: Option<u64>,
    pub checkpoint_error: Option<String>,
}

struct EntryData {
    record: ExecutionRecord,
    streams: BTreeMap<Stream, ByteBuffer>,
    stdin_pending: bool,
}

struct Entry {
    data: Mutex<EntryData>,
    native: Option<Arc<NativeProcess>>,
    input: Mutex<Option<Arc<InputWriter>>>,
    changed: Notify,
    budget: usize,
}

impl Entry {
    fn record(&self) -> ExecutionRecord {
        self.data
            .lock()
            .expect("execution record mutex poisoned")
            .record
            .clone()
    }

    fn authorized(&self, connection: &str) -> bool {
        let data = self.data.lock().expect("execution record mutex poisoned");
        data.record.lifetime == Lifetime::Persistent
            || data.record.owner_connection.as_deref() == Some(connection)
    }

    fn terminate(&self, reason: &str) -> anyhow::Result<ExecutionRecord> {
        let process = self
            .native
            .as_ref()
            .context("historical record has no live process handle; no PID is reopened")?;
        let mut data = self.data.lock().expect("execution record mutex poisoned");
        if data.record.status.finished()
            && data.record.root_exit_code.is_some()
            && data.record.tree_active_processes == 0
        {
            return Ok(data.record.clone());
        }
        process.terminate()?;
        if !data.record.cancellation_requested {
            data.record.cancellation_requested = true;
            data.record.cancellation_reason = Some(reason.into());
        }
        let record = data.record.clone();
        drop(data);
        self.changed.notify_waiters();
        Ok(record)
    }
}

struct Registry {
    entries: BTreeMap<String, Arc<Entry>>,
    connections: BTreeMap<String, CancellationToken>,
    closed: bool,
    pending: usize,
    budget: usize,
    evicted: u64,
}

impl Registry {
    fn connection_is_open(&self, id: &str) -> bool {
        !self.closed
            && self
                .connections
                .get(id)
                .is_some_and(|cancel| !cancel.is_cancelled())
    }
}

#[derive(Default)]
struct CheckpointStatus {
    at_ms: Option<u64>,
    error: Option<String>,
}

pub struct ExecutionManager {
    context: PersistenceContext,
    registry: Mutex<Registry>,
    checkpoint_status: Mutex<CheckpointStatus>,
    checkpoint_lock: Mutex<()>,
    host_shutdown: CancellationToken,
    #[cfg(test)]
    startup_gate: Mutex<Option<Arc<tests::StartupGate>>>,
}

#[derive(Default)]
struct StartupCancellation {
    request: CancellationToken,
    connection: CancellationToken,
    #[cfg(test)]
    gate: Option<Arc<tests::StartupGate>>,
}

impl StartupCancellation {
    fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.request.is_cancelled(),
            "execution startup request canceled"
        );
        anyhow::ensure!(
            !self.connection.is_cancelled(),
            "execution connection closed during startup"
        );
        Ok(())
    }

    fn before_resume(&self, lifetime: Lifetime) -> anyhow::Result<()> {
        if lifetime == Lifetime::Connection {
            self.check()?;
        } else if !self.connection.is_cancelled() {
            // An admitted persistent start no longer depends on its disconnected caller.
            anyhow::ensure!(
                !self.request.is_cancelled(),
                "execution startup request canceled"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn pause(
        &self,
        phase: tests::StartupPhase,
        process: Option<&Arc<NativeProcess>>,
    ) -> anyhow::Result<()> {
        if let Some(gate) = &self.gate {
            gate.pause(phase, process)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    version: u32,
    epoch: String,
    saved_at_ms: u64,
    evicted: u64,
    records: Vec<SavedEntry>,
}

#[derive(Serialize, Deserialize)]
struct SavedEntry {
    record: ExecutionRecord,
    streams: BTreeMap<Stream, SavedBuffer>,
}

struct Reservation<'a> {
    manager: &'a ExecutionManager,
    budget: usize,
    committed: bool,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let mut registry = self
                .manager
                .registry
                .lock()
                .expect("execution registry mutex poisoned");
            registry.pending -= 1;
            registry.budget -= self.budget;
        }
    }
}

impl ExecutionManager {
    pub fn new(context: PersistenceContext) -> anyhow::Result<Self> {
        let manager = Self {
            context,
            registry: Mutex::new(Registry {
                entries: BTreeMap::new(),
                connections: BTreeMap::new(),
                closed: false,
                pending: 0,
                budget: 0,
                evicted: 0,
            }),
            checkpoint_status: Mutex::new(CheckpointStatus::default()),
            checkpoint_lock: Mutex::new(()),
            host_shutdown: CancellationToken::new(),
            #[cfg(test)]
            startup_gate: Mutex::new(None),
        };
        manager.restore()?;
        Ok(manager)
    }

    pub fn context(&self) -> &PersistenceContext {
        &self.context
    }
    pub fn is_persistent(&self) -> bool {
        self.context.is_persistent()
    }
    pub fn state_directory(&self) -> Option<&Path> {
        self.context.state_directory()
    }
    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.host_shutdown.clone()
    }

    pub fn register_connection(&self, id: &str) -> anyhow::Result<()> {
        uuid::Uuid::parse_str(id).context("invalid connection UUID")?;
        let mut registry = self
            .registry
            .lock()
            .expect("execution registry mutex poisoned");
        anyhow::ensure!(!registry.closed, "execution manager is shutting down");
        anyhow::ensure!(
            registry.connections.len() < 64,
            "too many active execution connections"
        );
        anyhow::ensure!(
            !registry.connections.contains_key(id),
            "connection UUID is already registered"
        );
        registry
            .connections
            .insert(id.into(), CancellationToken::new());
        Ok(())
    }

    pub fn connection_cancellation(&self, id: &str) -> anyhow::Result<CancellationToken> {
        self.registry
            .lock()
            .expect("execution registry mutex poisoned")
            .connections
            .get(id)
            .cloned()
            .context("unknown execution connection")
    }

    fn reserve(
        &self,
        connection: &str,
        lifetime: Lifetime,
        budget: usize,
    ) -> anyhow::Result<Reservation<'_>> {
        anyhow::ensure!(
            lifetime != Lifetime::Persistent || self.is_persistent(),
            "persistent execution requires a manually started --local-host and explicit --connect-host bridge"
        );
        let mut registry = self
            .registry
            .lock()
            .expect("execution registry mutex poisoned");
        anyhow::ensure!(
            registry.connection_is_open(connection),
            "execution connection has closed"
        );
        while registry.entries.len() + registry.pending >= MAX_RECORDS
            || registry.budget + budget > MAX_TOTAL_OUTPUT_BYTES
        {
            let oldest = registry
                .entries
                .iter()
                .filter_map(|(id, entry)| {
                    let record = entry.record();
                    (record.status.finished()
                        && (entry.native.is_none()
                            || (record.root_exit_code.is_some()
                                && record.tree_active_processes == 0)))
                        .then_some((id.clone(), record.started_at_ms))
                })
                .min_by_key(|(_, time)| *time);
            let Some((id, _)) = oldest else {
                bail!("execution capacity reached: at most {MAX_RECORDS} records and {MAX_TOTAL_OUTPUT_BYTES} reserved output bytes");
            };
            if let Some(removed) = registry.entries.remove(&id) {
                registry.budget -= removed.budget;
                registry.evicted += 1;
            }
        }
        registry.pending += 1;
        registry.budget += budget;
        Ok(Reservation {
            manager: self,
            budget,
            committed: false,
        })
    }

    #[cfg(test)]
    pub fn start_job(
        &self,
        input: JobStartInput,
        connection: &str,
    ) -> anyhow::Result<ExecutionRecord> {
        self.start_job_cancellable(input, connection, CancellationToken::new())
    }

    pub fn start_job_cancellable(
        &self,
        input: JobStartInput,
        connection: &str,
        request_cancel: CancellationToken,
    ) -> anyhow::Result<ExecutionRecord> {
        self.start(input, None, connection, request_cancel)
    }

    #[cfg(test)]
    pub fn create_terminal(
        &self,
        input: TerminalCreateInput,
        connection: &str,
    ) -> anyhow::Result<ExecutionRecord> {
        self.create_terminal_cancellable(input, connection, CancellationToken::new())
    }

    pub fn create_terminal_cancellable(
        &self,
        input: TerminalCreateInput,
        connection: &str,
        request_cancel: CancellationToken,
    ) -> anyhow::Result<ExecutionRecord> {
        let size = (input.cols.unwrap_or(120), input.rows.unwrap_or(30));
        validate_size(size.0, size.1)?;
        anyhow::ensure!(
            input.process.stdin_text.is_none() && input.process.stdin_base64.is_none(),
            "use terminal_input after creating a terminal"
        );
        self.start(input.process, Some(size), connection, request_cancel)
    }

    fn start(
        &self,
        input: JobStartInput,
        size: Option<(u16, u16)>,
        connection: &str,
        request_cancel: CancellationToken,
    ) -> anyhow::Result<ExecutionRecord> {
        let cancel = StartupCancellation {
            request: request_cancel,
            connection: self.connection_cancellation(connection)?,
            #[cfg(test)]
            gate: self
                .startup_gate
                .lock()
                .expect("startup test gate mutex poisoned")
                .clone(),
        };
        cancel.check()?;
        let capacity = validate_start(&input)?;
        let stdin = input_bytes(
            input.stdin_text.as_deref(),
            input.stdin_base64.as_deref(),
            false,
        )?;
        let budget = capacity * if size.is_some() { 1 } else { 2 };
        let mut reservation = self.reserve(connection, input.lifetime, budget)?;
        let mut created = native::create(&input, size, &cancel)?;
        cancel.check()?;
        #[cfg(test)]
        cancel.pause(tests::StartupPhase::BeforeAdmission, Some(&created.process))?;
        let id = uuid::Uuid::new_v4().to_string();
        let entry = Arc::new(Entry {
            data: Mutex::new(EntryData {
                record: ExecutionRecord {
                    id: id.clone(),
                    epoch: self.context.epoch.clone(),
                    kind: if size.is_some() {
                        ExecutionKind::Terminal
                    } else {
                        ExecutionKind::Job
                    },
                    lifetime: input.lifetime,
                    owner_connection: (input.lifetime == Lifetime::Connection)
                        .then(|| connection.into()),
                    pid: created.process.pid,
                    process_creation_time: created.process.creation_time,
                    program: created.process.program.clone(),
                    args: input.args.clone(),
                    cwd: created.process.cwd.clone(),
                    started_at_ms: now_ms(),
                    finished_at_ms: None,
                    status: ExecutionStatus::Starting,
                    root_exit_code: None,
                    tree_active_processes: 1,
                    process_state_current: true,
                    output_drained: false,
                    cancellation_requested: false,
                    cancellation_reason: None,
                    last_error: None,
                    restart_gap: None,
                    cols: size.map(|s| s.0),
                    rows: size.map(|s| s.1),
                    output_limit_bytes: capacity,
                    timeout_ms: input.timeout_ms,
                },
                streams: created
                    .readers
                    .iter()
                    .map(|(stream, _)| (*stream, ByteBuffer::new(capacity)))
                    .collect(),
                stdin_pending: size.is_none() && !stdin.is_empty(),
            }),
            native: Some(created.process.clone()),
            input: Mutex::new(None),
            changed: Notify::new(),
            budget,
        });
        {
            let mut registry = self
                .registry
                .lock()
                .expect("execution registry mutex poisoned");
            cancel.check()?;
            anyhow::ensure!(
                registry.connection_is_open(connection),
                "connection closed before process resume; suspended child has been terminated"
            );
            registry.entries.insert(id.clone(), entry.clone());
            registry.pending -= 1;
            reservation.committed = true;
        }
        let mut supervisor_started = false;
        let mut readers_started = HashSet::new();
        let mut stdin_started = false;
        let prepare = (|| -> anyhow::Result<()> {
            let monitor_entry = entry.clone();
            std::thread::Builder::new()
                .name(format!("mcp-process-{id}"))
                .spawn(move || supervise(monitor_entry))?;
            supervisor_started = true;
            for (stream, mut file) in created.readers.drain(..) {
                let reader_entry = entry.clone();
                std::thread::Builder::new()
                    .name(format!("mcp-output-{id}"))
                    .spawn(move || {
                        let mut bytes = [0u8; 16384];
                        loop {
                            let read = file.read(&mut bytes);
                            let mut data = reader_entry
                                .data
                                .lock()
                                .expect("execution record mutex poisoned");
                            let buffer =
                                data.streams.get_mut(&stream).expect("output stream exists");
                            let done = match read {
                                Ok(0) => {
                                    buffer.eof = true;
                                    true
                                }
                                Ok(count) => {
                                    buffer.append(&bytes[..count]);
                                    false
                                }
                                Err(error) if error.raw_os_error() == Some(109) => {
                                    buffer.eof = true;
                                    true
                                }
                                Err(error) => {
                                    buffer.error = Some(error.to_string());
                                    data.record.last_error =
                                        Some(format!("{stream:?} read failed: {error}"));
                                    true
                                }
                            };
                            drop(data);
                            reader_entry.changed.notify_waiters();
                            if done {
                                break;
                            }
                        }
                    })?;
                readers_started.insert(stream);
            }
            let input_pipe = created
                .stdin
                .take()
                .context("process input pipe is missing")?;
            if size.is_some() {
                *entry.input.lock().expect("terminal input mutex poisoned") =
                    Some(Arc::new(InputWriter::new(input_pipe, &id)?));
            } else if !stdin.is_empty() {
                let writer_entry = entry.clone();
                std::thread::Builder::new()
                    .name(format!("mcp-stdin-{id}"))
                    .spawn(move || {
                        let mut file = input_pipe;
                        let result = file.write_all(&stdin);
                        drop(file);
                        let mut data = writer_entry
                            .data
                            .lock()
                            .expect("execution record mutex poisoned");
                        data.stdin_pending = false;
                        if let Err(error) = result {
                            data.record.last_error = Some(format!("stdin write failed: {error}"));
                        }
                        drop(data);
                        writer_entry.changed.notify_waiters();
                    })?;
                stdin_started = true;
            }
            // Record the identity before any child instruction can run. A restart never resumes it.
            if input.lifetime == Lifetime::Persistent {
                self.checkpoint()?;
            }
            #[cfg(test)]
            cancel.pause(tests::StartupPhase::BeforeResume, Some(&created.process))?;
            {
                let registry = self
                    .registry
                    .lock()
                    .expect("execution registry mutex poisoned");
                anyhow::ensure!(
                    !registry.closed
                        && !self.host_shutdown.is_cancelled()
                        && (input.lifetime == Lifetime::Persistent
                            || registry.connection_is_open(connection)),
                    "execution scope closed before process resume"
                );
                let mut data = entry.data.lock().expect("execution record mutex poisoned");
                anyhow::ensure!(
                    data.record.status == ExecutionStatus::Starting
                        && !data.record.cancellation_requested,
                    "owned process exited or was canceled before resume"
                );
                cancel.before_resume(input.lifetime)?;
                created.resume()?;
                data.record.status = ExecutionStatus::Running;
            }
            Ok(())
        })();
        if let Err(error) = prepare {
            {
                let mut data = entry.data.lock().expect("execution record mutex poisoned");
                data.record.last_error = Some(format!("process start failed: {error:#}"));
                if !stdin_started {
                    data.stdin_pending = false;
                }
                for (stream, buffer) in &mut data.streams {
                    if !readers_started.contains(stream) {
                        buffer.error = Some(
                            "output reader could not start; no child instruction was resumed"
                                .into(),
                        );
                    }
                }
            }
            let cleanup = entry.terminate("start_failed");
            created.readers.clear();
            created.stdin.take();
            entry
                .input
                .lock()
                .expect("terminal input mutex poisoned")
                .take();
            created.process.close_pty();
            cleanup.with_context(|| {
                format!("failed to clean up execution {id} after startup error: {error:#}")
            })?;
            if !supervisor_started {
                supervise(entry.clone());
            }
            return Err(error.context(format!(
                "execution {id} did not complete startup; owned tree terminated"
            )));
        }
        if input.lifetime == Lifetime::Persistent {
            self.checkpoint().with_context(|| format!(
                "execution {id} was resumed but its post-start checkpoint failed; inspect this ID and do not replay the command"
            ))?;
        } else if cancel.request.is_cancelled() {
            entry.terminate("startup_request_canceled")?;
            bail!(
                "execution startup request canceled after resume; owned tree termination requested for {id}"
            );
        }
        Ok(entry.record())
    }

    fn entry(&self, id: &str, connection: &str) -> anyhow::Result<Arc<Entry>> {
        uuid::Uuid::parse_str(id).context("invalid execution UUID")?;
        let registry = self
            .registry
            .lock()
            .expect("execution registry mutex poisoned");
        anyhow::ensure!(
            registry.connection_is_open(connection),
            "execution connection has closed"
        );
        let entry = registry
            .entries
            .get(id)
            .context("unknown or evicted execution ID")?;
        anyhow::ensure!(
            entry.authorized(connection),
            "execution belongs to another connection"
        );
        Ok(entry.clone())
    }

    pub fn inspect(&self, id: &str, connection: &str) -> anyhow::Result<ExecutionRecord> {
        Ok(self.entry(id, connection)?.record())
    }

    pub fn read(&self, input: OutputInput, connection: &str) -> anyhow::Result<OutputResult> {
        let maximum = input.max_bytes.unwrap_or(65536);
        anyhow::ensure!(
            (1..=MAX_READ_BYTES).contains(&maximum),
            "max_bytes must be 1-{MAX_READ_BYTES}"
        );
        let entry = self.entry(&input.id, connection)?;
        let data = entry.data.lock().expect("execution record mutex poisoned");
        let terminal = data.record.kind == ExecutionKind::Terminal;
        let stream = input.stream.unwrap_or(if terminal {
            Stream::Combined
        } else {
            Stream::Stdout
        });
        let buffer = data.streams.get(&stream).context(
            "stream unavailable: ConPTY has combined output; jobs have separate stdout and stderr",
        )?;
        Ok(OutputResult {
            id: input.id,
            epoch: data.record.epoch.clone(),
            stream,
            encoding: if terminal {
                "ConPTY UTF-8 bytes with VT sequences; reads may split code points"
            } else {
                "raw child-defined bytes; UTF-8 text is a lossy convenience preview"
            }
            .into(),
            virtual_terminal_sequences: terminal,
            output: buffer.read(input.cursor, maximum)?,
            process: data.record.clone(),
        })
    }

    pub async fn terminal_input(
        &self,
        input: TerminalInput,
        connection: &str,
        cancel: CancellationToken,
    ) -> anyhow::Result<InputResult> {
        let connection_cancel = self.connection_cancellation(connection)?;
        let entry = self.entry(&input.id, connection)?;
        let writer = entry
            .input
            .lock()
            .expect("terminal input mutex poisoned")
            .clone()
            .context("terminal input is unavailable or closed")?;
        let bytes = input_bytes(input.text.as_deref(), input.base64.as_deref(), true)?;
        let timeout = input.timeout_ms.unwrap_or(5000);
        anyhow::ensure!(
            (1..=MAX_WAIT_MS).contains(&timeout),
            "input timeout_ms must be 1-{MAX_WAIT_MS}"
        );
        tokio::select! {
            result = writer.write(bytes, Duration::from_millis(timeout), cancel) => result,
            _ = connection_cancel.cancelled() => {
                anyhow::bail!("terminal input canceled by connection closure; an in-flight write may have completed")
            }
        }
    }

    pub fn resize(&self, input: ResizeInput, connection: &str) -> anyhow::Result<ExecutionRecord> {
        validate_size(input.cols, input.rows)?;
        let entry = self.entry(&input.id, connection)?;
        entry
            .native
            .as_ref()
            .context("historical terminal has no live pseudoconsole")?
            .resize(input.cols, input.rows)?;
        let mut data = entry.data.lock().expect("execution record mutex poisoned");
        data.record.cols = Some(input.cols);
        data.record.rows = Some(input.rows);
        Ok(data.record.clone())
    }

    pub fn cancel(&self, id: &str, connection: &str) -> anyhow::Result<ExecutionRecord> {
        let entry = self.entry(id, connection)?;
        let record = entry.terminate("requested")?;
        if record.lifetime == Lifetime::Persistent {
            self.checkpoint()?;
        }
        Ok(record)
    }

    pub fn list(&self, connection: &str, kind: Option<ExecutionKind>) -> ExecutionList {
        let registry = self
            .registry
            .lock()
            .expect("execution registry mutex poisoned");
        let records = registry
            .entries
            .values()
            .filter(|entry| entry.authorized(connection))
            .map(|entry| entry.record())
            .filter(|record| kind.is_none_or(|kind| kind == record.kind))
            .collect();
        let checkpoint = self
            .checkpoint_status
            .lock()
            .expect("checkpoint status mutex poisoned");
        ExecutionList {
            epoch: self.context.epoch.clone(),
            records,
            evicted_records: registry.evicted,
            record_limit: MAX_RECORDS,
            output_budget_bytes: MAX_TOTAL_OUTPUT_BYTES,
            last_checkpoint_at_ms: checkpoint.at_ms,
            checkpoint_error: checkpoint.error.clone(),
        }
    }

    pub async fn wait(
        &self,
        id: &str,
        connection: &str,
        timeout_ms: u64,
        cancel: CancellationToken,
    ) -> anyhow::Result<WaitResult> {
        anyhow::ensure!(
            timeout_ms <= MAX_WAIT_MS,
            "wait timeout_ms must be 0-{MAX_WAIT_MS}"
        );
        let connection_cancel = self.connection_cancellation(connection)?;
        let entry = self.entry(id, connection)?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let changed = entry.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let record = entry.record();
            if record.status.finished() {
                let outcome = match record.status {
                    ExecutionStatus::Canceled => "canceled",
                    ExecutionStatus::TimedOut => "timed_out",
                    ExecutionStatus::Failed => "failed",
                    ExecutionStatus::InterruptedHostRestart => "interrupted_host_restart",
                    _ => "exited",
                };
                return Ok(WaitResult {
                    outcome: outcome.into(),
                    process: record,
                });
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(WaitResult { outcome: "canceled".into(), process: entry.record() }),
                _ = connection_cancel.cancelled() => return Ok(WaitResult { outcome: "canceled".into(), process: entry.record() }),
                _ = tokio::time::sleep_until(deadline) => return Ok(WaitResult { outcome: "timed_out".into(), process: entry.record() }),
                _ = changed => {}
            }
        }
    }

    pub fn shutdown_connection(&self, id: &str) -> anyhow::Result<()> {
        let entries: Vec<_> = {
            let mut registry = self
                .registry
                .lock()
                .expect("execution registry mutex poisoned");
            if let Some(cancel) = registry.connections.remove(id) {
                cancel.cancel();
            }
            registry
                .entries
                .values()
                .filter(|entry| entry.record().owner_connection.as_deref() == Some(id))
                .cloned()
                .collect()
        };
        let mut errors = Vec::new();
        for entry in entries {
            if let Err(error) = entry.terminate("connection_closed") {
                errors.push(error.to_string());
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "connection process cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }

    pub fn request_host_shutdown(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.is_persistent(),
            "this is a connection-owned stdio server, not a resident host"
        );
        self.host_shutdown.cancel();
        Ok(())
    }

    pub fn shutdown(&self) -> anyhow::Result<()> {
        let entries: Vec<_> = {
            let mut registry = self
                .registry
                .lock()
                .expect("execution registry mutex poisoned");
            registry.closed = true;
            for cancel in registry.connections.values() {
                cancel.cancel();
            }
            registry.connections.clear();
            registry
                .entries
                .values()
                .filter(|entry| entry.native.is_some())
                .cloned()
                .collect()
        };
        let mut errors = Vec::new();
        for entry in &entries {
            if let Err(error) = entry.terminate("host_shutdown") {
                errors.push(error.to_string());
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut pending = false;
            for entry in &entries {
                match entry.native.as_ref().expect("selected live entry").sample() {
                    Ok((exit, active)) => {
                        pending |=
                            exit.is_none() || active != 0 || !entry.record().status.finished();
                    }
                    Err(error) => {
                        let error = format!("cannot confirm owned tree exit: {error:#}");
                        if !errors.contains(&error) {
                            errors.push(error);
                        }
                    }
                }
            }
            if !pending {
                break;
            }
            if Instant::now() >= deadline {
                errors.push("owned process cleanup did not drain within ten seconds".into());
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.is_persistent() {
            if let Err(error) = self.checkpoint() {
                errors.push(error.to_string());
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "execution shutdown failed: {}",
            errors.join("; ")
        );
        Ok(())
    }

    pub fn checkpoint(&self) -> anyhow::Result<()> {
        if !self.is_persistent() {
            return Ok(());
        }
        let _serial = self
            .checkpoint_lock
            .lock()
            .expect("checkpoint mutex poisoned");
        let saved_at_ms = now_ms();
        let checkpoint = {
            let registry = self
                .registry
                .lock()
                .expect("execution registry mutex poisoned");
            Checkpoint {
                version: 1,
                epoch: self.context.epoch.clone(),
                saved_at_ms,
                evicted: registry.evicted,
                records: registry
                    .entries
                    .values()
                    .filter_map(|entry| {
                        let data = entry.data.lock().expect("execution record mutex poisoned");
                        (data.record.lifetime == Lifetime::Persistent).then(|| SavedEntry {
                            record: data.record.clone(),
                            streams: data
                                .streams
                                .iter()
                                .map(|(key, value)| (*key, value.save()))
                                .collect(),
                        })
                    })
                    .collect(),
            }
        };
        let result = serde_json::to_vec(&checkpoint)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| self.context.write_checkpoint(CHECKPOINT_FILE, &bytes));
        let mut status = self
            .checkpoint_status
            .lock()
            .expect("checkpoint status mutex poisoned");
        match &result {
            Ok(()) => {
                status.at_ms = Some(saved_at_ms);
                status.error = None;
            }
            Err(error) => {
                status.error = Some(format!("{error:#}"));
            }
        }
        result
    }

    fn restore(&self) -> anyhow::Result<()> {
        if !self.is_persistent() {
            return Ok(());
        }
        let Some(bytes) = self
            .context
            .read_checkpoint(CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES)?
        else {
            return Ok(());
        };
        let checkpoint: Checkpoint = serde_json::from_slice(&bytes)
            .context("invalid execution checkpoint; no mutations were replayed")?;
        anyhow::ensure!(
            checkpoint.version == 1,
            "unsupported execution checkpoint version"
        );
        anyhow::ensure!(
            checkpoint.records.len() <= MAX_RECORDS,
            "execution checkpoint record limit exceeded"
        );
        let mut registry = self
            .registry
            .lock()
            .expect("execution registry mutex poisoned");
        registry.evicted = checkpoint.evicted;
        for saved in checkpoint.records {
            let mut record = saved.record;
            uuid::Uuid::parse_str(&record.id).context("invalid saved execution UUID")?;
            anyhow::ensure!(
                record.lifetime == Lifetime::Persistent && record.owner_connection.is_none(),
                "invalid saved execution owner"
            );
            anyhow::ensure!(
                (1..=MAX_OUTPUT_BYTES).contains(&record.output_limit_bytes),
                "invalid saved output capacity"
            );
            let expected: &[Stream] = if record.kind == ExecutionKind::Terminal {
                &[Stream::Combined]
            } else {
                &[Stream::Stdout, Stream::Stderr]
            };
            anyhow::ensure!(
                saved.streams.len() == expected.len()
                    && expected.iter().all(|key| saved.streams.contains_key(key)),
                "invalid saved output streams"
            );
            let mut streams = BTreeMap::new();
            for (key, saved_buffer) in saved.streams {
                anyhow::ensure!(
                    saved_buffer.capacity == record.output_limit_bytes,
                    "saved output capacity mismatch"
                );
                streams.insert(key, ByteBuffer::restore(saved_buffer, MAX_OUTPUT_BYTES)?);
            }
            let was_live = !record.status.finished();
            if was_live {
                record.status = ExecutionStatus::InterruptedHostRestart;
                record.output_drained = false;
                record.finished_at_ms = Some(now_ms());
                record.restart_gap = Some(RestartGap {
                    checkpoint_at_ms: checkpoint.saved_at_ms,
                    observed_restart_at_ms: self.context.started_at_ms,
                    output_after_checkpoint_unknown: true,
                    mutations_replayed: false,
                });
            }
            record.process_state_current = false;
            let budget = record.output_limit_bytes * streams.len();
            registry.budget += budget;
            anyhow::ensure!(
                registry.budget <= MAX_TOTAL_OUTPUT_BYTES,
                "execution checkpoint output budget exceeded"
            );
            let id = record.id.clone();
            anyhow::ensure!(
                !registry.entries.contains_key(&id),
                "duplicate saved execution ID"
            );
            registry.entries.insert(
                id,
                Arc::new(Entry {
                    data: Mutex::new(EntryData {
                        record,
                        streams,
                        stdin_pending: false,
                    }),
                    native: None,
                    input: Mutex::new(None),
                    changed: Notify::new(),
                    budget,
                }),
            );
        }
        self.checkpoint_status
            .lock()
            .expect("checkpoint status mutex poisoned")
            .at_ms = Some(checkpoint.saved_at_ms);
        Ok(())
    }
}

impl Drop for ExecutionManager {
    fn drop(&mut self) {
        let registry = self
            .registry
            .get_mut()
            .expect("execution registry mutex poisoned");
        for entry in registry
            .entries
            .values()
            .filter(|entry| entry.native.is_some())
        {
            if let Err(error) = entry.terminate("manager_dropped") {
                tracing::error!(%error, "failed to stop owned process during manager drop");
            }
        }
    }
}

fn validate_size(cols: u16, rows: u16) -> anyhow::Result<()> {
    anyhow::ensure!(
        cols > 0 && rows > 0 && cols <= 1000 && rows <= 1000,
        "terminal columns and rows must each be 1-1000"
    );
    Ok(())
}

fn validate_start(input: &JobStartInput) -> anyhow::Result<usize> {
    anyhow::ensure!(
        !input.program.is_empty() && !input.program.contains('\0'),
        "program must be nonempty and contain no NUL"
    );
    anyhow::ensure!(
        input.args.len() <= 4096 && input.args.iter().all(|arg| !arg.contains('\0')),
        "invalid or excessive process arguments"
    );
    // Bound temporary quoting/UTF-16 allocations before checking exact native lengths.
    let mut command_bytes = 0;
    for argument in std::iter::once(&input.program).chain(&input.args) {
        anyhow::ensure!(
            argument.len() <= 32767 * 4 - command_bytes,
            "process arguments exceed the Windows command-line input limit"
        );
        command_bytes += argument.len();
    }
    if let Some(cwd) = &input.cwd {
        anyhow::ensure!(
            cwd.len() <= 32767 * 4,
            "working directory exceeds the Windows path input limit"
        );
    }
    anyhow::ensure!(input.env.len() <= 1024, "too many environment overrides");
    let mut environment_bytes = 0;
    for (name, value) in &input.env {
        for part in std::iter::once(name).chain(value.iter()) {
            anyhow::ensure!(
                part.len() <= 1_048_576 * 4 - environment_bytes,
                "environment overrides exceed the input limit"
            );
            environment_bytes += part.len();
        }
    }
    let capacity = input.output_limit_bytes.unwrap_or(DEFAULT_OUTPUT_BYTES);
    anyhow::ensure!(
        (1..=MAX_OUTPUT_BYTES).contains(&capacity),
        "output_limit_bytes must be 1-{MAX_OUTPUT_BYTES} per stream"
    );
    if let Some(timeout) = input.timeout_ms {
        anyhow::ensure!(
            (1..=604_800_000).contains(&timeout),
            "process timeout_ms must be 1-604800000, or omitted for no deadline"
        );
    }
    Ok(capacity)
}

fn input_bytes(
    text: Option<&str>,
    base64: Option<&str>,
    required: bool,
) -> anyhow::Result<Vec<u8>> {
    match (text, base64) {
        (Some(_), Some(_)) => bail!("provide text or base64, not both"),
        (None, None) if required => bail!("provide text or base64"),
        (None, None) => Ok(Vec::new()),
        (Some(text), None) => {
            anyhow::ensure!(
                text.len() <= MAX_INPUT_BYTES,
                "input exceeds {MAX_INPUT_BYTES} bytes"
            );
            Ok(text.as_bytes().to_vec())
        }
        (None, Some(encoded)) => {
            anyhow::ensure!(
                encoded.len() <= MAX_INPUT_BYTES.div_ceil(3) * 4,
                "base64 input exceeds its limit"
            );
            let bytes = STANDARD.decode(encoded).context("invalid input base64")?;
            anyhow::ensure!(
                bytes.len() <= MAX_INPUT_BYTES,
                "input exceeds {MAX_INPUT_BYTES} bytes"
            );
            Ok(bytes)
        }
    }
}

fn supervise(entry: Arc<Entry>) {
    let process = entry
        .native
        .as_ref()
        .expect("live entry has native process");
    let started = Instant::now();
    let mut pty_closed = false;
    loop {
        let sample = process.sample();
        let mut data = entry.data.lock().expect("execution record mutex poisoned");
        match sample {
            Ok((exit, active)) => {
                data.record.root_exit_code = exit;
                data.record.tree_active_processes = active;
                if active == 0 && !pty_closed {
                    drop(data);
                    entry
                        .input
                        .lock()
                        .expect("terminal input mutex poisoned")
                        .take();
                    process.close_pty();
                    pty_closed = true;
                    continue;
                }
                let closed = data
                    .streams
                    .values()
                    .all(|stream| stream.eof || stream.error.is_some());
                data.record.output_drained = data.streams.values().all(|stream| stream.eof);
                if exit.is_some() && active == 0 && closed && !data.stdin_pending {
                    data.record.status = if data.record.last_error.is_some() {
                        ExecutionStatus::Failed
                    } else if data.record.cancellation_reason.as_deref()
                        == Some("deadline_exceeded")
                    {
                        ExecutionStatus::TimedOut
                    } else if data.record.cancellation_requested {
                        ExecutionStatus::Canceled
                    } else {
                        ExecutionStatus::Exited
                    };
                    data.record.finished_at_ms = Some(now_ms());
                    drop(data);
                    entry.changed.notify_waiters();
                    break;
                }
                if exit.is_some() {
                    data.record.status = ExecutionStatus::RootExited;
                }
                let timeout = data.record.timeout_ms;
                let cancellation_requested = data.record.cancellation_requested;
                drop(data);
                if !cancellation_requested
                    && timeout.is_some_and(|ms| started.elapsed() >= Duration::from_millis(ms))
                {
                    if let Err(error) = entry.terminate("deadline_exceeded") {
                        entry
                            .data
                            .lock()
                            .expect("execution record mutex poisoned")
                            .record
                            .last_error = Some(format!("deadline cleanup failed: {error:#}"));
                    }
                }
            }
            Err(error) => {
                data.record.last_error =
                    Some(format!("owned process observation failed: {error:#}"));
                data.record.status = ExecutionStatus::Failed;
                data.record.process_state_current = false;
                drop(data);
                if let Err(cleanup) = process.terminate() {
                    tracing::error!(%cleanup, "failed to terminate process after observation failure");
                }
                process.close_pty();
                entry
                    .input
                    .lock()
                    .expect("terminal input mutex poisoned")
                    .take();
                entry.changed.notify_waiters();
                break;
            }
        }
        entry.changed.notify_waiters();
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests;
