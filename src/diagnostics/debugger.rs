use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::mem::size_of;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError},
    Arc, Mutex, MutexGuard,
};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use windows::core::{w, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;

use super::native::{
    native_error, open_thread, timestamp_ms, Deadline, Handle, Process, ProcessIdentity,
};
use super::stacks::ThreadContext;
use super::{
    ContinueDisposition, DebugAttachInput, DebugEventsInput, DebugLaunchInput, InspectionCommand,
    Lifetime,
};

const MAX_ACTIVE: usize = 8;
const MAX_RETAINED: usize = 32;
const MAX_CONNECTIONS: usize = 128;
const MAX_CONNECTION_ID_BYTES: usize = 128;
const MAX_EVENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_ONE_EVENT: usize = 64 * 1024;
const MAX_TRACKED_THREADS: usize = 1024;
const MAX_TRACKED_MODULES: usize = 1024;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Starting,
    Running,
    Stopped,
    Exited,
    Detached,
    Failed,
}

impl State {
    fn terminal(self) -> bool {
        matches!(self, Self::Exited | Self::Detached | Self::Failed)
    }

    fn allows(self, next: Self) -> bool {
        self == next
            || match self {
                Self::Starting => matches!(next, Self::Running | Self::Failed | Self::Detached),
                Self::Running => matches!(
                    next,
                    Self::Stopped | Self::Exited | Self::Failed | Self::Detached
                ),
                Self::Stopped => matches!(
                    next,
                    Self::Running | Self::Exited | Self::Failed | Self::Detached
                ),
                Self::Exited | Self::Detached | Self::Failed => false,
            }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StopInfo {
    pub stop_id: u64,
    pub thread_id: u32,
    pub exception_code: u32,
    pub exception_address: String,
    pub first_chance: bool,
    pub default_disposition: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    pub id: String,
    pub lifetime: Lifetime,
    pub state: State,
    pub owned: bool,
    pub target: Option<ProcessIdentity>,
    pub stop: Option<StopInfo>,
    pub break_requested: bool,
    pub termination_requested: bool,
    pub exit_code: Option<u32>,
    pub failure: Option<String>,
    pub created_at_ms: u64,
    pub last_event_cursor: u64,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub cursor: u64,
    pub timestamp_ms: u64,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub kind: String,
    pub data: Value,
}

#[derive(Debug, Serialize)]
pub struct EventsPage {
    pub session_id: String,
    pub events: Vec<Event>,
    pub oldest_available_cursor: u64,
    pub latest_cursor: u64,
    pub next_cursor: u64,
    pub gap: bool,
    pub lost_events: u64,
    pub state: State,
}

struct EventBuffer {
    rows: VecDeque<(Event, usize)>,
    capacity: usize,
    bytes: usize,
    latest: u64,
}

impl EventBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            rows: VecDeque::new(),
            capacity,
            bytes: 0,
            latest: 0,
        }
    }

    fn push(&mut self, mut event: Event) -> Result<u64> {
        self.latest = self
            .latest
            .checked_add(1)
            .context("debug event cursor exhausted")?;
        event.cursor = self.latest;
        let mut bytes = serde_json::to_vec(&event)?.len();
        if bytes > MAX_ONE_EVENT {
            event.data = json!({ "truncated": true, "original_event_bytes": bytes });
            bytes = serde_json::to_vec(&event)?.len();
        }
        self.bytes += bytes;
        self.rows.push_back((event, bytes));
        while self.rows.len() > self.capacity || self.bytes > MAX_EVENT_BYTES {
            if let Some((_, bytes)) = self.rows.pop_front() {
                self.bytes -= bytes;
            }
        }
        Ok(self.latest)
    }

    fn page(&self, session_id: &str, after: u64, limit: usize, state: State) -> Result<EventsPage> {
        if after > self.latest {
            bail!("event cursor is ahead of this debugger session");
        }
        let oldest = self
            .rows
            .front()
            .map(|row| row.0.cursor)
            .unwrap_or(self.latest + 1);
        let lost = oldest.saturating_sub(after.saturating_add(1));
        let events: Vec<_> = self
            .rows
            .iter()
            .filter(|row| row.0.cursor > after)
            .take(limit)
            .map(|row| row.0.clone())
            .collect();
        let next_cursor = events.last().map(|event| event.cursor).unwrap_or(after);
        Ok(EventsPage {
            session_id: session_id.into(),
            events,
            oldest_available_cursor: oldest,
            latest_cursor: self.latest,
            next_cursor,
            gap: lost != 0,
            lost_events: lost,
            state,
        })
    }
}

struct Record {
    view: SessionView,
    events: EventBuffer,
}

impl Record {
    fn state(&mut self, state: State) -> Result<()> {
        if !self.view.state.allows(state) {
            bail!(
                "invalid debugger transition {:?} -> {state:?}",
                self.view.state
            );
        }
        self.view.state = state;
        if state != State::Stopped {
            self.view.stop = None;
        }
        Ok(())
    }

    fn event(&mut self, kind: &str, thread_id: Option<u32>, data: Value) -> Result<u64> {
        let cursor = self.events.push(Event {
            cursor: 0,
            timestamp_ms: timestamp_ms(),
            process_id: self.view.target.as_ref().map(|target| target.pid),
            thread_id,
            kind: kind.into(),
            data,
        })?;
        self.view.last_event_cursor = cursor;
        Ok(cursor)
    }
}

struct Shared(Mutex<Record>);

impl Shared {
    fn lock(&self) -> Result<MutexGuard<'_, Record>> {
        self.0
            .lock()
            .map_err(|_| anyhow!("debugger state lock poisoned"))
    }

    fn view(&self) -> Result<SessionView> {
        Ok(self.lock()?.view.clone())
    }
}

pub(super) enum Command {
    Continue {
        stop_id: u64,
        disposition: ContinueDisposition,
    },
    Break,
    Detach,
    Terminate,
    Inspect {
        stop_id: u64,
        inspection: InspectionCommand,
    },
    Evaluate {
        stop_id: u64,
        thread_id: u32,
        expression: String,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Continue { .. } => "continue",
            Self::Break => "break",
            Self::Detach => "detach",
            Self::Terminate => "terminate",
            Self::Inspect { .. } => "inspect",
            Self::Evaluate { .. } => "evaluate",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CommandReply {
    pub request_id: String,
    pub native_accepted: bool,
    pub application_completion_observed: bool,
    pub session: SessionView,
    pub data: Value,
}

struct Envelope {
    request_id: String,
    command: Command,
    deadline: Deadline,
    reply: oneshot::Sender<Result<CommandReply>>,
}

struct Session {
    owner: String,
    lifetime: Lifetime,
    commands: SyncSender<Envelope>,
    shared: Arc<Shared>,
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Worker>,
}

#[derive(Default)]
struct Worker {
    thread: Option<JoinHandle<Result<(), String>>>,
    completion: Option<Result<(), String>>,
}

impl Worker {
    fn finish(&mut self) -> Result<(), String> {
        if self.completion.is_none() {
            self.completion = Some(match self.thread.take() {
                Some(thread) => match thread.join() {
                    Ok(result) => result,
                    Err(_) => Err("debugger thread panicked during cleanup".into()),
                },
                None => Err("debugger worker has no thread or cleanup result".into()),
            });
        }
        self.completion
            .as_ref()
            .expect("completion was set")
            .clone()
    }
}

struct StartingGuard {
    shutdown: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for StartingGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shutdown.store(true, Ordering::Release);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Explicit disconnect/shutdown joins off the async executor. This is
        // the fallback when the entire owner is dropped during cancellation.
        if let Ok(thread) = self.thread.get_mut() {
            if thread.thread.as_ref().is_some_and(JoinHandle::is_finished) {
                if let Err(error) = thread.finish() {
                    tracing::error!(%error, "diagnostics debugger cleanup failed");
                }
            }
        }
    }
}

enum Start {
    Attach(DebugAttachInput),
    Launch(DebugLaunchInput),
    #[cfg(test)]
    Paused {
        start: Box<Start>,
        entered: oneshot::Sender<ProcessIdentity>,
        release: Receiver<()>,
    },
}

impl Start {
    fn owned(&self) -> bool {
        match self {
            Self::Attach(_) => false,
            Self::Launch(_) => true,
            #[cfg(test)]
            Self::Paused { start, .. } => start.owned(),
        }
    }
}

#[derive(Default)]
struct Registry {
    sessions: HashMap<String, Arc<Session>>,
    connections: HashSet<String>,
    shutting_down: bool,
}

impl Registry {
    fn require_connection(&self, connection: &str) -> Result<()> {
        if self.shutting_down {
            bail!("diagnostics manager is shutting down");
        }
        if !self.connections.contains(connection) {
            bail!("debugger connection is not registered or has disconnected");
        }
        Ok(())
    }
}

pub(crate) struct DiagnosticsManager {
    persistent_host: bool,
    registry: Mutex<Registry>,
}

impl DiagnosticsManager {
    pub(crate) fn new(persistent_host: bool) -> Self {
        Self {
            persistent_host,
            registry: Mutex::new(Registry::default()),
        }
    }

    fn records(&self) -> Result<MutexGuard<'_, Registry>> {
        self.registry
            .lock()
            .map_err(|_| anyhow!("diagnostics manager lock poisoned"))
    }

    pub(crate) fn register_connection(&self, connection: &str) -> Result<()> {
        if connection.is_empty() || connection.len() > MAX_CONNECTION_ID_BYTES {
            bail!("debugger connection identity must contain 1-{MAX_CONNECTION_ID_BYTES} bytes");
        }
        let mut registry = self.records()?;
        if registry.shutting_down {
            bail!("diagnostics manager is shutting down");
        }
        if registry.connections.contains(connection) {
            bail!("debugger connection is already registered");
        }
        if registry.connections.len() >= MAX_CONNECTIONS {
            bail!("at most {MAX_CONNECTIONS} active debugger connection scopes are supported");
        }
        registry.connections.insert(connection.into());
        Ok(())
    }

    fn session(&self, id: &str, connection: &str) -> Result<Arc<Session>> {
        let records = self.records()?;
        let session = records
            .sessions
            .get(id)
            .context("unknown or expired debugger session")?;
        if session.lifetime == Lifetime::Connection && session.owner != connection {
            bail!("debugger session belongs to another connection");
        }
        Ok(Arc::clone(session))
    }

    pub(super) async fn attach(
        &self,
        input: DebugAttachInput,
        connection: &str,
        deadline: Deadline,
    ) -> Result<SessionView> {
        let lifetime = input.lifetime;
        let capacity = input.event_capacity;
        self.start(
            Start::Attach(input),
            connection,
            lifetime,
            capacity,
            deadline,
        )
        .await
    }

    pub(super) async fn launch(
        &self,
        input: DebugLaunchInput,
        connection: &str,
        deadline: Deadline,
    ) -> Result<SessionView> {
        validate_launch(&input)?;
        let lifetime = input.lifetime;
        let capacity = input.event_capacity;
        self.start(
            Start::Launch(input),
            connection,
            lifetime,
            capacity,
            deadline,
        )
        .await
    }

    async fn start(
        &self,
        start: Start,
        connection: &str,
        lifetime: Lifetime,
        capacity: Option<usize>,
        deadline: Deadline,
    ) -> Result<SessionView> {
        if lifetime == Lifetime::Persistent && !self.persistent_host {
            bail!("persistent debugger sessions require an explicitly running local resident host");
        }
        if connection.is_empty() {
            bail!("debugger connection identity is required");
        }
        let capacity = super::bounded(capacity, 512, 16, 4096, "event_capacity")?;
        deadline.check()?;
        let id = uuid::Uuid::new_v4().to_string();
        let shared = Arc::new(Shared(Mutex::new(Record {
            view: SessionView {
                id: id.clone(), lifetime, state: State::Starting,
                owned: start.owned(), target: None, stop: None,
                break_requested: false, termination_requested: false, exit_code: None, failure: None,
                created_at_ms: timestamp_ms(), last_event_cursor: 0,
                limitations: vec![
                    "User-mode native debugger, no kernel or secure-desktop access. Protected processes and insufficient token rights can prevent attach.".into(),
                    "Session records and live debug targets do not survive host exit or reboot. Detach never kills the target.".into(),
                    "Only DEBUG_ONLY_THIS_PROCESS targets are owned; child processes are not debugger-owned.".into(),
                    "debug_launch directs stdin/stdout/stderr to NUL. Debug events capture OutputDebugString, not console I/O; attaching to an existing terminal leaves its I/O unchanged.".into(),
                    "Windows synthesizes initial thread/module notifications when attaching. Event timestamps are observation times, not a reconstruction of earlier process history.".into(),
                    "Evaluation supports unsigned literals and native registers with checked constant offsets, not arbitrary debugger scripts or function calls.".into(),
                ],
            },
            events: EventBuffer::new(capacity),
        })));
        let (commands, receiver) = mpsc::sync_channel(16);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut starting = StartingGuard {
            shutdown: Arc::clone(&shutdown),
            armed: true,
        };
        let session = Arc::new(Session {
            owner: connection.into(),
            lifetime,
            commands,
            shared: Arc::clone(&shared),
            shutdown: Arc::clone(&shutdown),
            thread: Mutex::new(Worker::default()),
        });
        let (ready, initialized) = oneshot::channel();
        {
            let mut registry = self.records()?;
            // Admission and revocation share this lock. Every actor is
            // registered before disconnect can collect the work it must join.
            registry.require_connection(connection)?;
            let records = &mut registry.sessions;
            let mut active = 0;
            let mut terminal = Vec::new();
            for (key, session) in records.iter() {
                let view = session.shared.view()?;
                if view.state.terminal() {
                    terminal.push((view.created_at_ms, key.clone()));
                } else {
                    active += 1;
                }
            }
            if active >= MAX_ACTIVE {
                bail!("at most {MAX_ACTIVE} active debugger sessions are supported");
            }
            terminal.sort();
            while records.len() >= MAX_RETAINED {
                let Some((_, key)) = terminal.first() else {
                    bail!("debugger session retention capacity exhausted");
                };
                records.remove(key);
                terminal.remove(0);
            }
            let actor_shared = Arc::clone(&shared);
            let thread = std::thread::Builder::new()
                .name(format!("mcp-debug-{id}"))
                .spawn(move || actor(start, receiver, actor_shared, shutdown, deadline, ready))
                .context("start native debugger thread")?;
            session
                .thread
                .lock()
                .map_err(|_| anyhow!("debugger thread lock poisoned"))?
                .thread = Some(thread);
            records.insert(id.clone(), session);
        }
        let view = initialized
            .await
            .with_context(|| format!("debugger {id} initialization channel closed"))?
            .with_context(|| format!("debugger session {id} failed to initialize"))?;
        {
            let registry = self.records()?;
            if registry.shutting_down || starting.shutdown.load(Ordering::Acquire) {
                bail!("debugger initialization canceled by request or owner shutdown");
            }
            if lifetime == Lifetime::Connection {
                registry.require_connection(connection)?;
            }
        }
        starting.armed = false;
        Ok(view)
    }

    pub(super) fn list(&self, connection: &str) -> Result<Vec<SessionView>> {
        let records = self.records()?;
        let mut result = Vec::new();
        for session in records.sessions.values() {
            if session.lifetime == Lifetime::Persistent || session.owner == connection {
                result.push(session.shared.view()?);
            }
        }
        result.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms).then(a.id.cmp(&b.id)));
        Ok(result)
    }

    pub(super) fn inspect(&self, id: &str, connection: &str) -> Result<SessionView> {
        self.session(id, connection)?.shared.view()
    }

    pub(super) fn events(&self, input: DebugEventsInput, connection: &str) -> Result<EventsPage> {
        let limit = super::bounded(input.limit, 128, 1, 1024, "limit")?;
        let session = self.session(&input.id, connection)?;
        let record = session.shared.lock()?;
        record.events.page(
            &input.id,
            input.after_cursor.unwrap_or(0),
            limit,
            record.view.state,
        )
    }

    pub(super) async fn command(
        &self,
        id: &str,
        connection: &str,
        command: Command,
        deadline: Deadline,
    ) -> Result<CommandReply> {
        let session = self.session(id, connection)?;
        deadline.check()?;
        if session.shared.view()?.state.terminal() {
            bail!("debugger session is terminal; inspect its retained state/events");
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let (reply, result) = oneshot::channel();
        session
            .commands
            .try_send(Envelope {
                request_id: request_id.clone(),
                command,
                deadline: deadline.clone(),
                reply,
            })
            .map_err(|error| anyhow!("debugger command was not queued: {error}"))?;
        tokio::time::timeout(deadline.remaining(), result).await
            .with_context(|| format!("debugger command {request_id} timed out; consult its completion event before retrying"))?
            .with_context(|| format!("debugger command {request_id} result channel closed"))?
    }

    pub(crate) async fn disconnect(&self, connection: &str) -> Result<()> {
        let sessions = {
            let mut registry = self.records()?;
            registry.connections.remove(connection);
            registry
                .sessions
                .values()
                .filter(|session| {
                    session.lifetime == Lifetime::Connection && session.owner == connection
                })
                .map(|session| {
                    session.shutdown.store(true, Ordering::Release);
                    Arc::clone(session)
                })
                .collect()
        };
        Self::join_sessions(sessions).await
    }

    pub(crate) async fn shutdown(&self) -> Result<()> {
        let sessions = {
            let mut registry = self.records()?;
            registry.shutting_down = true;
            registry.connections.clear();
            registry
                .sessions
                .values()
                .map(|session| {
                    session.shutdown.store(true, Ordering::Release);
                    Arc::clone(session)
                })
                .collect()
        };
        Self::join_sessions(sessions).await
    }

    async fn join_sessions(sessions: Vec<Arc<Session>>) -> Result<()> {
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut errors = Vec::new();
            for session in sessions {
                // Hold the lock through joining and cache its result. A
                // concurrent or previously canceled cleanup must await the
                // same actor, not treat an extracted JoinHandle as completion.
                let mut worker = session
                    .thread
                    .lock()
                    .map_err(|_| anyhow!("debugger join lock poisoned"))?;
                if let Err(error) = worker.finish() {
                    errors.push(error);
                }
            }
            if !errors.is_empty() {
                bail!("debugger cleanup errors: {}", errors.join("; "));
            }
            Ok(())
        })
        .await
        .context("debugger cleanup task failed")?
    }
}

impl Drop for DiagnosticsManager {
    fn drop(&mut self) {
        if let Ok(registry) = self.registry.get_mut() {
            registry.shutting_down = true;
            registry.connections.clear();
            for session in registry.sessions.values() {
                session.shutdown.store(true, Ordering::Release);
            }
        }
    }
}

struct Pending {
    process_id: u32,
    thread_id: u32,
    default_disposition: NTSTATUS,
}

struct Target {
    process: Process,
    attached: bool,
    detach_attempted: bool,
    owned: bool,
    pending: Option<Pending>,
    threads: BTreeMap<u32, Option<String>>,
    modules: BTreeMap<u64, Value>,
    omitted_threads: u64,
    omitted_modules: u64,
}

impl Target {
    fn remember_thread(&mut self, tid: u32, address: Option<String>) {
        if self.threads.len() < MAX_TRACKED_THREADS || self.threads.contains_key(&tid) {
            self.threads.insert(tid, address);
        } else {
            self.omitted_threads = self.omitted_threads.saturating_add(1);
        }
    }

    fn remember_module(&mut self, base: u64, module: Value) {
        if self.modules.len() < MAX_TRACKED_MODULES || self.modules.contains_key(&base) {
            self.modules.insert(base, module);
        } else {
            self.omitted_modules = self.omitted_modules.saturating_add(1);
        }
    }

    fn continue_event(&mut self, disposition: Option<NTSTATUS>) -> Result<()> {
        if let Some(pending) = &self.pending {
            unsafe {
                ContinueDebugEvent(
                    pending.process_id,
                    pending.thread_id,
                    disposition.unwrap_or(pending.default_disposition),
                )
            }
            .map_err(|error| native_error("ContinueDebugEvent", error))?;
            self.pending = None;
        }
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        self.detach_attempted = true;
        let continued = self.continue_event(None);
        let stopped = unsafe { DebugActiveProcessStop(self.process.identity.pid) };
        match stopped {
            Ok(()) => {
                self.attached = false;
                self.pending = None;
                continued
                    .context("target detached, but continuing the outstanding debug event failed")
            }
            Err(_) if unsafe { WaitForSingleObject(self.process.handle.0, 0) } == WAIT_OBJECT_0 => {
                self.attached = false;
                self.pending = None;
                Ok(())
            }
            Err(error) => Err(native_error("DebugActiveProcessStop", error)),
        }
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        if self.attached && !self.detach_attempted {
            if let Err(error) = self.detach() {
                tracing::error!(%error, "diagnostics debugger cleanup failed");
            }
        }
    }
}

fn quote_arg(value: &str) -> String {
    let mut output = String::from("\"");
    let mut backslashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else {
            if ch == '"' {
                output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            } else {
                output.extend(std::iter::repeat_n('\\', backslashes));
            }
            backslashes = 0;
            output.push(ch);
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
    output
}

fn validate_launch(input: &DebugLaunchInput) -> Result<()> {
    if !Path::new(&input.program).is_absolute()
        || input.program.is_empty()
        || input.program.contains('\0')
    {
        bail!("debug launch program must be an absolute executable path without NUL");
    }
    if input.args.len() > 256 || input.args.iter().any(|arg| arg.contains('\0')) {
        bail!("debug launch accepts at most 256 arguments, without NUL");
    }
    let mut units = input.program.encode_utf16().take(32768).count();
    for arg in &input.args {
        units = units
            .checked_add(arg.encode_utf16().take(32768).count())
            .context("argument length overflow")?;
        if units > 32767 {
            bail!("debug launch arguments exceed Windows' command-line bound");
        }
    }
    if input
        .working_dir
        .as_ref()
        .is_some_and(|dir| !Path::new(dir).is_absolute() || dir.contains('\0'))
    {
        bail!("debug working_dir must be absolute and without NUL");
    }
    Ok(())
}

#[repr(C, align(16))]
#[derive(Clone)]
struct AttributeBlock([u8; 16]);

struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<AttributeBlock>,
}

impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

struct LaunchIo {
    startup: STARTUPINFOEXW,
    _attributes: Attributes,
    _inherited: Box<[HANDLE; 1]>,
    _null: Handle,
}

impl LaunchIo {
    fn new() -> Result<Self> {
        let security = windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: true.into(),
            ..Default::default()
        };
        let null = Handle(
            unsafe {
                CreateFileW(
                    w!("NUL"),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    Some(&security),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }
            .context("open debugger launch NUL streams")?,
        );
        let inherited = Box::new([null.0]);
        let mut bytes = 0;
        let probe = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut bytes) };
        if let Err(error) = probe {
            if error.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
                return Err(native_error("size debugger launch attributes", error));
            }
        }
        if bytes == 0 || bytes > 65536 {
            bail!("invalid debugger launch attribute size");
        }
        let mut storage = vec![AttributeBlock([0; 16]); bytes.div_ceil(16)];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut bytes) }
            .context("initialize debugger launch attributes")?;
        let attributes = Attributes {
            list,
            _storage: storage,
        };
        // Explicit inheritance is essential: a console child must never use
        // the MCP protocol pipes or inherit another connection's handles.
        unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(inherited.as_ptr().cast()),
                size_of::<HANDLE>(),
                None,
                None,
            )
        }
        .context("restrict debugger launch handle inheritance")?;
        Ok(Self {
            startup: STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: size_of::<STARTUPINFOEXW>() as u32,
                    dwFlags: STARTF_USESTDHANDLES,
                    hStdInput: null.0,
                    hStdOutput: null.0,
                    hStdError: null.0,
                    ..Default::default()
                },
                lpAttributeList: list,
            },
            _attributes: attributes,
            _inherited: inherited,
            _null: null,
        })
    }
}

#[derive(Debug)]
struct StartRevoked;

impl std::fmt::Display for StartRevoked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("debugger initialization canceled by request or owner shutdown")
    }
}

impl std::error::Error for StartRevoked {}

fn start_checkpoint(deadline: &Deadline, shutdown: &AtomicBool) -> Result<()> {
    if shutdown.load(Ordering::Acquire) {
        return Err(StartRevoked.into());
    }
    deadline.check()
}

fn start_target(start: Start, deadline: &Deadline, shutdown: &AtomicBool) -> Result<Target> {
    start_checkpoint(deadline, shutdown)?;
    let (process, owned) = match start {
        Start::Attach(input) => {
            let process = Process::open(
                input.target.pid,
                Some(input.target.creation_time),
                PROCESS_ALL_ACCESS,
            )?;
            process.ensure_external()?;
            process.ensure_context_supported()?;
            start_checkpoint(deadline, shutdown)?;
            unsafe { DebugActiveProcess(process.identity.pid) }
                .map_err(|error| native_error("DebugActiveProcess", error))?;
            (process, false)
        }
        Start::Launch(input) => {
            validate_launch(&input)?;
            let line = std::iter::once(input.program.as_str())
                .chain(input.args.iter().map(String::as_str))
                .map(quote_arg)
                .collect::<Vec<_>>()
                .join(" ");
            let mut line: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
            if line.len() > 32767 {
                bail!("debug launch command line exceeds Windows' 32767 UTF-16 code-unit limit");
            }
            let program: Vec<u16> = input.program.encode_utf16().chain(Some(0)).collect();
            let cwd: Option<Vec<u16>> = input
                .working_dir
                .as_ref()
                .map(|dir| dir.encode_utf16().chain(Some(0)).collect());
            let io = LaunchIo::new()?;
            let mut information = PROCESS_INFORMATION::default();
            start_checkpoint(deadline, shutdown)?;
            unsafe {
                CreateProcessW(
                    PCWSTR(program.as_ptr()),
                    Some(PWSTR(line.as_mut_ptr())),
                    None,
                    None,
                    true,
                    DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                    None,
                    cwd.as_ref()
                        .map(|dir| PCWSTR(dir.as_ptr()))
                        .unwrap_or(PCWSTR::null()),
                    &io.startup.StartupInfo,
                    &mut information,
                )
            }
            .map_err(|error| native_error("CreateProcessW under debugger", error))?;
            let _thread = Handle(information.hThread);
            let process = match Process::from_handle(Handle(information.hProcess), None) {
                Ok(process) => process,
                Err(error) => {
                    // Creation succeeded, so failing metadata must not leave an
                    // invisible stopped target behind.
                    unsafe {
                        let _ = DebugSetProcessKillOnExit(false);
                        DebugActiveProcessStop(information.dwProcessId).map_err(|error| {
                            native_error("detach after debug launch initialization failed", error)
                        })?;
                    }
                    bail!(
                        "PID {} was launched and detached after identity query failed: {error:#}",
                        information.dwProcessId
                    );
                }
            };
            (process, true)
        }
        #[cfg(test)]
        Start::Paused {
            start,
            entered,
            release,
        } => {
            let target = start_target(*start, deadline, shutdown)?;
            entered
                .send(target.process.identity.clone())
                .map_err(|_| anyhow!("native start gate observer closed"))?;
            release
                .recv_timeout(Duration::from_secs(10))
                .context("native start gate timed out")?;
            return Ok(target);
        }
    };
    let mut target = Target {
        process,
        attached: true,
        detach_attempted: false,
        owned,
        pending: None,
        threads: BTreeMap::new(),
        modules: BTreeMap::new(),
        omitted_threads: 0,
        omitted_modules: 0,
    };
    if let Err(error) = unsafe { DebugSetProcessKillOnExit(false) } {
        let detached = target.detach();
        bail!("DebugSetProcessKillOnExit(false) failed: {error}; detach result: {detached:?}");
    }
    target.process.ensure_context_supported()?;
    Ok(target)
}

fn actor(
    start: Start,
    commands: Receiver<Envelope>,
    shared: Arc<Shared>,
    shutdown: Arc<AtomicBool>,
    deadline: Deadline,
    ready: oneshot::Sender<Result<SessionView>>,
) -> Result<(), String> {
    if shutdown.load(Ordering::Acquire) || ready.is_closed() {
        fail_record(&shared, "debugger initialization canceled before attach");
        return Ok(());
    }
    let mut target = match start_target(start, &deadline, &shutdown) {
        Ok(target) => target,
        Err(error) => {
            let revoked = error.is::<StartRevoked>();
            let message = format!("{error:#}");
            fail_record(&shared, &message);
            let _ = ready.send(Err(error));
            return if revoked { Ok(()) } else { Err(message) };
        }
    };
    if let Err(error) = start_checkpoint(&deadline, &shutdown).and_then(|()| {
        if ready.is_closed() {
            bail!("debugger initialization request was dropped");
        }
        Ok(())
    }) {
        let detached = target.detach().and_then(|()| {
            let mut record = shared.lock()?;
            record.view.target = Some(target.process.identity.clone());
            record.state(State::Detached)?;
            record.event(
                "startup_canceled",
                None,
                json!({
                    "target_terminated": false, "error": format!("{error:#}"),
                }),
            )?;
            Ok(())
        });
        let message = match &detached {
            Ok(()) => format!("{error:#}; debugger detached"),
            Err(cleanup) => format!("{error:#}; startup cleanup failed: {cleanup:#}"),
        };
        if detached.is_err() {
            fail_record(&shared, &message);
        }
        let _ = ready.send(Err(anyhow!(message)));
        return detached.map_err(|error| format!("{error:#}"));
    }
    let initialized = (|| -> Result<SessionView> {
        let mut record = shared.lock()?;
        record.view.target = Some(target.process.identity.clone());
        record.state(State::Running)?;
        record.event(
            "attached",
            None,
            json!({ "owned": target.owned, "kill_on_debugger_exit": false }),
        )?;
        Ok(record.view.clone())
    })();
    if initialized.is_err() || deadline.check().is_err() {
        shutdown.store(true, Ordering::Release);
    }
    if ready.send(initialized).is_err() {
        shutdown.store(true, Ordering::Release);
    }
    let result = debug_loop(&mut target, &commands, &shared, &shutdown);
    if let Err(error) = result {
        let cleanup = target.detach();
        let message = match &cleanup {
            Ok(()) => format!("{error:#}; debugger detached"),
            Err(cleanup) => format!("{error:#}; detach also failed: {cleanup:#}"),
        };
        fail_record(&shared, &message);
        return cleanup.map_err(|error| format!("{error:#}"));
    }
    Ok(())
}

fn fail_record(shared: &Shared, message: &str) {
    match shared.lock() {
        Ok(mut record) => {
            record.view.failure = Some(message.into());
            if let Err(error) = record.state(State::Failed) {
                tracing::error!(%error, "diagnostics failed-state transition failed");
            }
            if let Err(error) = record.event("failed", None, json!({ "error": message })) {
                tracing::error!(%error, "diagnostics failed-state recording failed");
            }
        }
        Err(error) => tracing::error!(%error, "diagnostics debugger state unavailable"),
    }
}

fn debug_loop(
    target: &mut Target,
    commands: &Receiver<Envelope>,
    shared: &Shared,
    shutdown: &AtomicBool,
) -> Result<()> {
    while target.attached {
        if shutdown.load(Ordering::Acquire) {
            target.detach()?;
            let mut record = shared.lock()?;
            record.state(State::Detached)?;
            record.event(
                "detached",
                None,
                json!({ "reason": "owner_disconnect_or_shutdown", "target_terminated": false }),
            )?;
            break;
        }
        let command = if target.pending.is_some() {
            match commands.recv_timeout(Duration::from_millis(20)) {
                Ok(command) => Some(command),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    shutdown.store(true, Ordering::Release);
                    None
                }
            }
        } else {
            match commands.try_recv() {
                Ok(command) => Some(command),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => {
                    shutdown.store(true, Ordering::Release);
                    None
                }
            }
        };
        if let Some(command) = command {
            execute_envelope(target, shared, command)?;
        }
        if !target.attached || target.pending.is_some() {
            continue;
        }
        let mut event = DEBUG_EVENT::default();
        match unsafe { WaitForDebugEventEx(&mut event, 20) } {
            Ok(()) => handle_event(target, shared, event)?,
            Err(error)
                if error.code() == HRESULT::from_win32(ERROR_SEM_TIMEOUT.0)
                    || error.code() == HRESULT::from_win32(ERROR_TIMEOUT.0) => {}
            Err(error) => return Err(native_error("WaitForDebugEventEx", error)),
        }
    }
    Ok(())
}

fn default_exception_status(code: u32) -> NTSTATUS {
    // Breakpoint exceptions are debugger stops. Other first- and second-chance
    // exceptions are passed to the target unless the caller explicitly handles them.
    if code == 0x80000003 || code == 0x4000001f {
        DBG_CONTINUE
    } else {
        DBG_EXCEPTION_NOT_HANDLED
    }
}

fn module_info(file: HANDLE, base: u64) -> Value {
    let file = Handle(file);
    if file.0.is_invalid() {
        return json!({ "base": format!("0x{base:x}"), "path": null, "path_unavailable": "debug event supplied no file handle" });
    }
    let mut buffer = vec![0u16; 32768];
    let size = unsafe { GetFinalPathNameByHandleW(file.0, &mut buffer, FILE_NAME_NORMALIZED) };
    if size == 0 || size as usize >= buffer.len() {
        return json!({ "base": format!("0x{base:x}"), "path": null, "path_unavailable": "GetFinalPathNameByHandleW failed or path exceeded bounds" });
    }
    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    let truncated = path.chars().count() > 1024;
    json!({
        "base": format!("0x{base:x}"), "path": path.chars().take(1024).collect::<String>(),
        "path_truncated": truncated,
    })
}

fn handle_event(target: &mut Target, shared: &Shared, event: DEBUG_EVENT) -> Result<()> {
    let exception = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT;
    let disposition = if exception {
        default_exception_status(
            unsafe { event.u.Exception.ExceptionRecord.ExceptionCode }.0 as u32,
        )
    } else {
        DBG_CONTINUE
    };
    // Install the continuation guard before decoding any event fields or
    // acquiring shared state, so every failure path can release the target.
    target.pending = Some(Pending {
        process_id: event.dwProcessId,
        thread_id: event.dwThreadId,
        default_disposition: disposition,
    });
    let tid = event.dwThreadId;
    let (kind, data) = unsafe {
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let created = event.u.CreateProcessInfo;
                // Windows owns the debug-event process/thread handles and closes
                // them on continued exit events. hFile is debugger-owned.
                target.remember_thread(
                    tid,
                    created
                        .lpStartAddress
                        .map(|address| format!("0x{:x}", address as usize)),
                );
                let module = module_info(created.hFile, created.lpBaseOfImage as u64);
                target.remember_module(created.lpBaseOfImage as u64, module.clone());
                (
                    if target.owned {
                        "process_created"
                    } else {
                        "process_attached"
                    },
                    module,
                )
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let address = event
                    .u
                    .CreateThread
                    .lpStartAddress
                    .map(|address| format!("0x{:x}", address as usize));
                target.remember_thread(tid, address.clone());
                ("thread_created", json!({ "start_address": address }))
            }
            EXIT_THREAD_DEBUG_EVENT => {
                target.threads.remove(&tid);
                (
                    "thread_exited",
                    json!({ "exit_code": event.u.ExitThread.dwExitCode }),
                )
            }
            LOAD_DLL_DEBUG_EVENT => {
                let loaded = event.u.LoadDll;
                let module = module_info(loaded.hFile, loaded.lpBaseOfDll as u64);
                target.remember_module(loaded.lpBaseOfDll as u64, module.clone());
                ("module_loaded", module)
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let base = event.u.UnloadDll.lpBaseOfDll as u64;
                target.modules.remove(&base);
                ("module_unloaded", json!({ "base": format!("0x{base:x}") }))
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let string = event.u.DebugString;
                let requested = usize::from(string.nDebugStringLength)
                    * if string.fUnicode != 0 { 2 } else { 1 };
                let result = read_memory(
                    &target.process,
                    string.lpDebugStringData.0 as u64,
                    requested.min(16384),
                );
                let data = match result {
                    Ok(memory) => {
                        let text = if string.fUnicode != 0 {
                            let utf16: Vec<_> = memory
                                .bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                                .collect();
                            Some(
                                String::from_utf16_lossy(&utf16)
                                    .trim_end_matches('\0')
                                    .to_string(),
                            )
                        } else {
                            None
                        };
                        json!({
                            "encoding": if string.fUnicode != 0 { "utf16le" } else { "windows_ansi" },
                            "text": text, "base64": base64::engine::general_purpose::STANDARD.encode(&memory.bytes),
                            "truncated": requested > memory.bytes.len(), "read_error": memory.error,
                        })
                    }
                    Err(error) => {
                        json!({ "error": format!("{error:#}"), "requested_bytes": requested })
                    }
                };
                ("output", data)
            }
            EXCEPTION_DEBUG_EVENT => {
                let info = event.u.Exception;
                let record = info.ExceptionRecord;
                let count =
                    (record.NumberParameters as usize).min(record.ExceptionInformation.len());
                (
                    "exception",
                    json!({
                        "code": record.ExceptionCode.0 as u32,
                        "address": format!("0x{:x}", record.ExceptionAddress as usize),
                        "first_chance": info.dwFirstChance != 0,
                        "parameters": record.ExceptionInformation[..count].iter().map(|value| format!("0x{value:x}")).collect::<Vec<_>>(),
                    }),
                )
            }
            EXIT_PROCESS_DEBUG_EVENT => (
                "process_exited",
                json!({ "exit_code": event.u.ExitProcess.dwExitCode }),
            ),
            RIP_EVENT => (
                "rip",
                json!({ "error": event.u.RipInfo.dwError, "type": event.u.RipInfo.dwType.0 }),
            ),
            _ => ("native_event", json!({ "code": event.dwDebugEventCode.0 })),
        }
    };
    if exception {
        let info = unsafe { event.u.Exception };
        let mut record = shared.lock()?;
        let stop_id = record.event(kind, Some(tid), data)?;
        record.state(State::Stopped)?;
        record.view.break_requested = false;
        record.view.stop = Some(StopInfo {
            stop_id,
            thread_id: tid,
            exception_code: info.ExceptionRecord.ExceptionCode.0 as u32,
            exception_address: format!("0x{:x}", info.ExceptionRecord.ExceptionAddress as usize),
            first_chance: info.dwFirstChance != 0,
            default_disposition: if disposition == DBG_CONTINUE {
                "handled"
            } else {
                "not_handled"
            },
        });
    } else {
        shared.lock()?.event(kind, Some(tid), data)?;
        target.continue_event(None)?;
        if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            target.attached = false;
            let mut record = shared.lock()?;
            record.view.exit_code = Some(unsafe { event.u.ExitProcess.dwExitCode });
            record.state(State::Exited)?;
        }
    }
    Ok(())
}

fn require_stop(shared: &Shared, expected: u64) -> Result<StopInfo> {
    let record = shared.lock()?;
    if record.view.state != State::Stopped {
        bail!("debugger target is not stopped");
    }
    let stop = record
        .view
        .stop
        .as_ref()
        .context("debugger has no outstanding stop")?;
    if stop.stop_id != expected {
        bail!("stale stop_id; inspect the current stop before changing target state");
    }
    Ok(stop.clone())
}

fn execute_envelope(target: &mut Target, shared: &Shared, envelope: Envelope) -> Result<()> {
    let Envelope {
        request_id,
        command,
        deadline,
        reply,
    } = envelope;
    let name = command.name();
    let result = if reply.is_closed() {
        Err(anyhow!("debugger command canceled before execution"))
    } else {
        deadline
            .check()
            .and_then(|()| execute(target, shared, command, &deadline))
    };
    let event = match &result {
        Ok(_) => json!({ "request_id": request_id, "command": name, "native_accepted": true }),
        Err(error) => json!({
            "request_id": request_id, "command": name, "native_accepted": null,
            "outcome": "failed_or_partial", "automatic_retry_safe": false, "error": format!("{error:#}"),
        }),
    };
    {
        let mut record = shared.lock()?;
        if !target.attached && !record.view.state.terminal() {
            record.state(State::Detached)?;
        }
        record.event("command_completed", None, event)?;
    }
    let result = result.and_then(|data| {
        Ok(CommandReply {
            request_id,
            native_accepted: true,
            application_completion_observed: false,
            session: shared.view()?,
            data,
        })
    });
    let _ = reply.send(result);
    Ok(())
}

fn execute(
    target: &mut Target,
    shared: &Shared,
    command: Command,
    deadline: &Deadline,
) -> Result<Value> {
    match command {
        Command::Continue {
            stop_id,
            disposition,
        } => {
            require_stop(shared, stop_id)?;
            let disposition = match disposition {
                ContinueDisposition::Default => None,
                ContinueDisposition::Handled => Some(DBG_CONTINUE),
                ContinueDisposition::NotHandled => Some(DBG_EXCEPTION_NOT_HANDLED),
            };
            target.continue_event(disposition)?;
            shared.lock()?.state(State::Running)?;
            Ok(json!({ "debug_event_continued": true }))
        }
        Command::Break => {
            let view = shared.view()?;
            if view.state != State::Running {
                bail!("break requires a running debugger target");
            }
            if view.break_requested {
                bail!("a break is already pending; inspect state/events instead of replaying it");
            }
            unsafe { DebugBreakProcess(target.process.handle.0) }
                .map_err(|error| native_error("DebugBreakProcess", error))?;
            shared.lock()?.view.break_requested = true;
            Ok(json!({ "break_requested": true, "stop_observed": false }))
        }
        Command::Detach => {
            target.detach()?;
            let mut record = shared.lock()?;
            record.state(State::Detached)?;
            record.event("detached", None, json!({ "target_terminated": false }))?;
            Ok(json!({ "detached": true, "target_terminated": false }))
        }
        Command::Terminate => {
            if !target.owned {
                bail!("debugger terminate is limited to a target launched by this session; attached targets are not owned");
            }
            if shared.view()?.termination_requested {
                bail!("termination is already requested; inspect the exit event instead of replaying it");
            }
            unsafe { TerminateProcess(target.process.handle.0, 1) }.map_err(|error| {
                native_error("TerminateProcess for owned debugger target", error)
            })?;
            shared.lock()?.view.termination_requested = true;
            target.continue_event(Some(DBG_CONTINUE))?;
            let mut record = shared.lock()?;
            record.state(State::Running)?;
            Ok(
                json!({ "termination_requested": true, "exit_observed": false, "child_tree_terminated": false }),
            )
        }
        Command::Inspect {
            stop_id,
            inspection,
        } => {
            require_stop(shared, stop_id)?;
            match inspection {
                InspectionCommand::Threads => {
                    let mut threads = Vec::new();
                    for (tid, start) in target.threads.iter().take(256) {
                        deadline.check()?;
                        match open_thread(&target.process, *tid, THREAD_ACCESS_RIGHTS(0)) {
                            Ok((_handle, created)) => threads.push(json!({
                                "thread_id": tid, "creation_time": created.to_string(), "start_address": start,
                            })),
                            Err(error) => threads.push(json!({ "thread_id": tid, "error": format!("{error:#}") })),
                        }
                    }
                    Ok(json!({
                        "threads": threads, "truncated": target.threads.len() > 256 || target.omitted_threads != 0,
                        "omitted_thread_events": target.omitted_threads,
                    }))
                }
                InspectionCommand::Modules => Ok(json!({
                    "modules": target.modules.values().take(1024).collect::<Vec<_>>(),
                    "truncated": target.omitted_modules != 0, "omitted_module_events": target.omitted_modules,
                })),
                InspectionCommand::Registers { thread_id } => {
                    let (thread, created) =
                        open_thread(&target.process, thread_id, THREAD_GET_CONTEXT)?;
                    let registers = ThreadContext::read(&target.process, thread.0)?
                        .registers()
                        .into_iter()
                        .map(|(name, value)| (name, format!("0x{value:x}")))
                        .collect::<BTreeMap<_, _>>();
                    Ok(
                        json!({ "thread_id": thread_id, "creation_time": created.to_string(), "registers": registers }),
                    )
                }
                InspectionCommand::ReadMemory { address, length } => {
                    if !(1..=65536).contains(&length) {
                        bail!("debug memory length must be between 1 and 65536 bytes");
                    }
                    let memory = read_memory(&target.process, address, length)?;
                    Ok(json!({
                        "address": format!("0x{address:x}"), "requested_bytes": length,
                        "read_bytes": memory.bytes.len(), "partial": memory.bytes.len() != length,
                        "base64": base64::engine::general_purpose::STANDARD.encode(&memory.bytes), "error": memory.error,
                    }))
                }
            }
        }
        Command::Evaluate {
            stop_id,
            thread_id,
            expression,
        } => {
            require_stop(shared, stop_id)?;
            let (thread, created) = open_thread(&target.process, thread_id, THREAD_GET_CONTEXT)?;
            let registers = ThreadContext::read(&target.process, thread.0)?.registers();
            let value = evaluate(&expression, &registers)?;
            Ok(json!({
                "thread_id": thread_id, "creation_time": created.to_string(), "value": value.to_string(),
                "hex": format!("0x{value:x}"), "side_effects": false,
            }))
        }
    }
}

struct Memory {
    bytes: Vec<u8>,
    error: Option<String>,
}

fn read_memory(process: &Process, address: u64, length: usize) -> Result<Memory> {
    if length > 65536 {
        bail!("memory read exceeds 65536-byte bound");
    }
    let end = address
        .checked_add(length as u64)
        .context("memory address overflow")?;
    if process.identity.architecture == "x86" && end > (u64::from(u32::MAX) + 1) {
        bail!("memory range exceeds x86 address space");
    }
    let pointer = usize::try_from(address)
        .context("memory address does not fit the debugger architecture")?;
    let mut bytes = vec![0u8; length];
    if length == 0 {
        return Ok(Memory { bytes, error: None });
    }
    let mut read = 0;
    let result = unsafe {
        ReadProcessMemory(
            process.handle.0,
            pointer as *const _,
            bytes.as_mut_ptr().cast(),
            length,
            Some(&mut read),
        )
    };
    if read > length {
        bail!("ReadProcessMemory returned an invalid byte count");
    }
    bytes.truncate(read);
    match result {
        Ok(()) => Ok(Memory { bytes, error: None }),
        Err(error) if read != 0 => Ok(Memory {
            bytes,
            error: Some(format!("{error}")),
        }),
        Err(error) => Err(native_error("ReadProcessMemory", error)),
    }
}

fn integer(value: &str) -> Result<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("invalid hexadecimal literal");
        }
        u64::from_str_radix(hex, 16).context("hexadecimal literal overflow")
    } else {
        if value.is_empty() || !value.bytes().all(|ch| ch.is_ascii_digit()) {
            bail!("expected unsigned decimal or hexadecimal literal");
        }
        value.parse().context("integer literal overflow")
    }
}

fn evaluate(expression: &str, registers: &BTreeMap<String, u64>) -> Result<u64> {
    if expression.len() > 128 || !expression.is_ascii() {
        bail!("expression must contain at most 128 ASCII characters");
    }
    let expression = expression.trim();
    let operator = expression
        .char_indices()
        .find(|(_, ch)| *ch == '+' || *ch == '-');
    let (base, offset) = match operator {
        Some((index, ch)) => (&expression[..index], Some((ch, &expression[index + 1..]))),
        None => (expression, None),
    };
    let base = base.trim();
    let value = if let Some(register) = base.strip_prefix('@') {
        *registers
            .get(&register.to_ascii_lowercase())
            .context("register unavailable for this architecture")?
    } else {
        integer(base)?
    };
    match offset {
        Some(('+', offset)) => value
            .checked_add(integer(offset)?)
            .context("evaluation overflow"),
        Some(('-', offset)) => value
            .checked_sub(integer(offset)?)
            .context("evaluation underflow"),
        _ => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        smoke::{assert_not_debugged, fixture_arguments, ChildFixture, OwnedTarget},
        TargetInput,
    };
    use super::*;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    fn attach_input(target: TargetInput, lifetime: Lifetime) -> DebugAttachInput {
        DebugAttachInput {
            target,
            lifetime,
            event_capacity: None,
            timeout_ms: None,
        }
    }

    #[tokio::test]
    async fn registration_is_bounded_and_releases_closed_scopes() -> Result<()> {
        let manager = DiagnosticsManager::new(true);
        assert!(manager.register_connection("").is_err());
        assert!(manager
            .register_connection(&"x".repeat(MAX_CONNECTION_ID_BYTES + 1))
            .is_err());
        for cycle in 0..3 {
            for index in 0..MAX_CONNECTIONS {
                manager.register_connection(&format!("connection-{cycle}-{index}"))?;
            }
            assert!(manager
                .register_connection(&format!("connection-{cycle}-0"))
                .is_err());
            assert!(manager.register_connection("one-too-many").is_err());
            assert_eq!(manager.records()?.connections.len(), MAX_CONNECTIONS);
            for index in 0..MAX_CONNECTIONS {
                manager
                    .disconnect(&format!("connection-{cycle}-{index}"))
                    .await?;
            }
            assert!(manager.records()?.connections.is_empty());
            assert!(manager.records()?.sessions.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn late_attach_and_launch_after_disconnect_cannot_be_admitted() -> Result<()> {
        let manager = DiagnosticsManager::new(true);
        manager.register_connection("closing")?;
        let target = TargetInput {
            pid: 0,
            creation_time: 0,
        };
        let late_attach = manager.attach(
            attach_input(target.clone(), Lifetime::Connection),
            "closing",
            Deadline::new(10000)?,
        );
        let late_launch = manager.launch(
            DebugLaunchInput {
                program: std::env::current_exe()?.to_string_lossy().into_owned(),
                args: fixture_arguments(),
                working_dir: None,
                lifetime: Lifetime::Connection,
                event_capacity: None,
                timeout_ms: None,
            },
            "closing",
            Deadline::new(10000)?,
        );
        manager.disconnect("closing").await?;
        for result in [
            late_attach.await,
            late_launch.await,
            manager
                .attach(
                    attach_input(target, Lifetime::Persistent),
                    "closing",
                    Deadline::new(10000)?,
                )
                .await,
        ] {
            assert!(format!("{:#}", result.unwrap_err()).contains("not registered"));
        }
        assert!(manager.records()?.connections.is_empty());
        assert!(
            manager.records()?.sessions.is_empty(),
            "late starts must not create actors or records"
        );
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_permanently_closes_registration_and_admission() -> Result<()> {
        let manager = DiagnosticsManager::new(true);
        manager.register_connection("closing")?;
        manager.shutdown().await?;
        assert!(manager.records()?.connections.is_empty());
        assert!(manager
            .register_connection("new-client")
            .unwrap_err()
            .to_string()
            .contains("shutting down"));
        let result = manager
            .attach(
                attach_input(
                    TargetInput {
                        pid: 0,
                        creation_time: 0,
                    },
                    Lifetime::Persistent,
                ),
                "closing",
                Deadline::new(10000)?,
            )
            .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("shutting down"));
        assert!(manager.records()?.sessions.is_empty());
        manager.disconnect("closing").await?;
        manager.shutdown().await?;
        Ok(())
    }

    async fn in_flight_native_start_is_revoked(
        lifetime: Lifetime,
        drop_request: bool,
        launch: bool,
    ) -> Result<()> {
        let mut child = if launch {
            None
        } else {
            Some(ChildFixture::spawn()?)
        };
        let mut launched_cleanup = Vec::new();
        let manager = Arc::new(DiagnosticsManager::new(true));
        manager.register_connection("closing")?;
        let native = if launch {
            Start::Launch(DebugLaunchInput {
                program: std::env::current_exe()?.to_string_lossy().into_owned(),
                args: fixture_arguments(),
                working_dir: None,
                lifetime,
                event_capacity: None,
                timeout_ms: None,
            })
        } else {
            Start::Attach(attach_input(child.as_ref().unwrap().target()?, lifetime))
        };
        let (entered, waiting) = oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let request_manager = Arc::clone(&manager);
        let request = tokio::spawn(async move {
            request_manager
                .start(
                    Start::Paused {
                        start: Box::new(native),
                        entered,
                        release: blocked,
                    },
                    "closing",
                    lifetime,
                    None,
                    Deadline::new(30000)?,
                )
                .await
        });
        let identity = tokio::time::timeout(Duration::from_secs(10), waiting).await??;
        let target = TargetInput {
            pid: identity.pid,
            creation_time: identity.creation_time.parse()?,
        };
        if launch {
            launched_cleanup.push(OwnedTarget(Process::open(
                target.pid,
                Some(target.creation_time),
                PROCESS_TERMINATE,
            )?));
        }
        assert_eq!(manager.list("closing")?[0].state, State::Starting);
        let request = if drop_request {
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
            None
        } else {
            Some(request)
        };
        let mut cleanup = Box::pin(async {
            if lifetime == Lifetime::Persistent {
                manager.shutdown().await
            } else {
                manager.disconnect("closing").await
            }
        });
        poll_fn(|cx| {
            assert!(
                matches!(cleanup.as_mut().poll(cx), Poll::Pending),
                "cleanup must wait for the paused native start to detach"
            );
            Poll::Ready(())
        })
        .await;
        assert!(!manager.records()?.connections.contains("closing"));
        let late = manager
            .attach(
                attach_input(target.clone(), Lifetime::Connection),
                "closing",
                Deadline::new(1000)?,
            )
            .await;
        assert!(late.is_err());
        assert_eq!(manager.records()?.sessions.len(), 1);
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(10), cleanup).await??;
        if let Some(request) = request {
            let result = tokio::time::timeout(Duration::from_secs(10), request).await??;
            assert!(format!("{:#}", result.unwrap_err()).contains("canceled"));
        }
        let views = manager.list("closing")?;
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].state, State::Detached);
        assert_not_debugged(&target)?;
        if let Some(child) = &mut child {
            child.finish()?;
        }
        drop(launched_cleanup);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "deterministic late native attach cleanup on a disposable child"]
    async fn native_admission_race_disconnect_waits_for_native_attach() -> Result<()> {
        in_flight_native_start_is_revoked(Lifetime::Connection, false, false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "deterministic dropped request cleanup on a disposable child"]
    async fn native_admission_race_dropped_attach_still_detaches() -> Result<()> {
        in_flight_native_start_is_revoked(Lifetime::Connection, true, false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "deterministic late native launch cleanup on a disposable child"]
    async fn native_admission_race_disconnect_waits_for_native_launch() -> Result<()> {
        in_flight_native_start_is_revoked(Lifetime::Connection, false, true).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "deterministic host shutdown cleanup on a disposable child"]
    async fn native_admission_race_shutdown_waits_for_persistent_start() -> Result<()> {
        in_flight_native_start_is_revoked(Lifetime::Persistent, false, false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "deterministic explicitly persistent admission on a disposable child"]
    async fn native_admission_race_accepted_persistent_start_survives_disconnect() -> Result<()> {
        let mut child = ChildFixture::spawn()?;
        let target = child.target()?;
        let manager = Arc::new(DiagnosticsManager::new(true));
        manager.register_connection("closing")?;
        let (entered, waiting) = oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let request_manager = Arc::clone(&manager);
        let native = Start::Attach(attach_input(target.clone(), Lifetime::Persistent));
        let request = tokio::spawn(async move {
            request_manager
                .start(
                    Start::Paused {
                        start: Box::new(native),
                        entered,
                        release: blocked,
                    },
                    "closing",
                    Lifetime::Persistent,
                    None,
                    Deadline::new(30000)?,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), waiting).await??;
        tokio::time::timeout(Duration::from_secs(10), manager.disconnect("closing")).await??;
        {
            let registry = manager.records()?;
            assert!(registry.connections.is_empty());
            assert_eq!(registry.sessions.len(), 1);
            assert!(!registry
                .sessions
                .values()
                .next()
                .unwrap()
                .shutdown
                .load(Ordering::Acquire));
        }
        release.send(())?;
        let accepted = tokio::time::timeout(Duration::from_secs(10), request).await???;
        manager.register_connection("reconnected")?;
        assert_eq!(
            manager.inspect(&accepted.id, "reconnected")?.lifetime,
            Lifetime::Persistent
        );
        manager.shutdown().await?;
        assert_eq!(
            manager.inspect(&accepted.id, "reconnected")?.state,
            State::Detached
        );
        assert_not_debugged(&target)?;
        child.finish()?;
        Ok(())
    }

    #[test]
    fn event_retention_reports_exact_cursor_gaps() {
        let mut buffer = EventBuffer::new(2);
        for index in 0..4 {
            buffer
                .push(Event {
                    cursor: 0,
                    timestamp_ms: index,
                    process_id: Some(123),
                    thread_id: None,
                    kind: "test".into(),
                    data: json!({ "index": index }),
                })
                .unwrap();
        }
        let page = buffer.page("session", 0, 1, State::Running).unwrap();
        assert_eq!(page.lost_events, 2);
        assert_eq!(page.oldest_available_cursor, 3);
        assert_eq!(page.next_cursor, 3);
        assert!(page.gap);
        let page = buffer
            .page("session", page.next_cursor, 16, State::Running)
            .unwrap();
        assert!(!page.gap);
        assert_eq!(page.events[0].cursor, 4);
        assert!(buffer.page("session", 5, 16, State::Running).is_err());
    }

    #[test]
    fn event_retention_bounds_bytes_and_single_events() {
        let mut buffer = EventBuffer::new(4096);
        for _ in 0..80 {
            buffer
                .push(Event {
                    cursor: 0,
                    timestamp_ms: 1,
                    process_id: None,
                    thread_id: None,
                    kind: "output".into(),
                    data: json!({ "text": "a".repeat(60000) }),
                })
                .unwrap();
        }
        assert!(buffer.bytes <= MAX_EVENT_BYTES);
        assert!(buffer.page("session", 0, 1024, State::Running).unwrap().gap);
        buffer
            .push(Event {
                cursor: 0,
                timestamp_ms: 1,
                process_id: None,
                thread_id: None,
                kind: "output".into(),
                data: json!({ "text": "a".repeat(MAX_ONE_EVENT + 1) }),
            })
            .unwrap();
        assert_eq!(buffer.rows.back().unwrap().0.data["truncated"], true);
    }

    #[test]
    fn dropped_start_future_requests_actor_cleanup() {
        let shutdown = Arc::new(AtomicBool::new(false));
        {
            let _guard = StartingGuard {
                shutdown: Arc::clone(&shutdown),
                armed: true,
            };
        }
        assert!(shutdown.load(Ordering::Acquire));
        shutdown.store(false, Ordering::Release);
        {
            let _guard = StartingGuard {
                shutdown: Arc::clone(&shutdown),
                armed: false,
            };
        }
        assert!(!shutdown.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_cleanup_waits_for_and_shares_completion() {
        let (release, wait) = std::sync::mpsc::channel();
        let worker = Arc::new(Mutex::new(Worker {
            thread: Some(std::thread::spawn(move || {
                wait.recv().unwrap();
                Err("fixture cleanup failure".into())
            })),
            completion: None,
        }));
        let first_worker = Arc::clone(&worker);
        let first = tokio::task::spawn_blocking(move || first_worker.lock().unwrap().finish());
        let second_worker = Arc::clone(&worker);
        let second = tokio::task::spawn_blocking(move || second_worker.lock().unwrap().finish());
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap(), Err("fixture cleanup failure".into()));
        assert_eq!(second.await.unwrap(), Err("fixture cleanup failure".into()));
        assert_eq!(
            worker.lock().unwrap().finish(),
            Err("fixture cleanup failure".into())
        );
    }

    #[test]
    fn terminal_states_cannot_resume() {
        assert!(State::Starting.allows(State::Running));
        assert!(State::Running.allows(State::Stopped));
        assert!(State::Stopped.allows(State::Running));
        assert!(State::Stopped.allows(State::Detached));
        for state in [State::Exited, State::Detached, State::Failed] {
            assert!(!state.allows(State::Running));
            assert!(!state.allows(State::Stopped));
        }
    }

    #[test]
    fn read_only_evaluation_has_explicit_grammar_and_checked_arithmetic() {
        let registers = BTreeMap::from([("rip".into(), 4096)]);
        assert_eq!(evaluate("@rip + 0x10", &registers).unwrap(), 4112);
        assert_eq!(evaluate("123", &registers).unwrap(), 123);
        for expression in [
            "@unknown",
            "@rip+1+2",
            "0-1",
            "0xffffffffffffffff+1",
            "call(1)",
            "poi(@rip)",
            "",
        ] {
            assert!(evaluate(expression, &registers).is_err(), "{expression}");
        }
    }

    #[test]
    fn exceptions_are_not_silently_swallowed() {
        assert_eq!(
            default_exception_status(0xc0000005),
            DBG_EXCEPTION_NOT_HANDLED
        );
        assert_eq!(default_exception_status(0x80000003), DBG_CONTINUE);
    }

    #[test]
    fn launch_quotes_empty_arguments_quotes_and_trailing_slashes() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("two words"), "\"two words\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("a\\"), "\"a\\\\\"");
    }

    #[tokio::test]
    async fn persistent_sessions_require_explicit_host() {
        let manager = DiagnosticsManager::new(false);
        manager.register_connection("client").unwrap();
        let result = manager
            .attach(
                DebugAttachInput {
                    target: super::super::TargetInput {
                        pid: 99999,
                        creation_time: 1,
                    },
                    lifetime: Lifetime::Persistent,
                    event_capacity: None,
                    timeout_ms: None,
                },
                "client",
                Deadline::new(100).unwrap(),
            )
            .await;
        assert!(result.unwrap_err().to_string().contains("explicitly"));
    }
}
