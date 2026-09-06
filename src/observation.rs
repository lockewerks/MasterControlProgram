use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, ensure, Context};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars,
    service::RequestContext,
    tool, tool_router, ErrorData, RoleServer,
};
use serde::{de::IntoDeserializer, Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;

mod etw;
mod native;
#[cfg(test)]
pub(crate) mod test_support;
mod uia;

pub use etw::recovery::RecoveryReport;

pub const MAX_DURATION_MS: u64 = 86_400_000;
const MAX_RECORDS: usize = 128;
const MAX_ACTIVE_WATCHES: usize = 32;
const MAX_EVENTS: usize = 8192;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;

pub(crate) async fn request_canceled(
    context: &RequestContext<RoleServer>,
    connection: &tokio_util::sync::CancellationToken,
) {
    tokio::select! {
        _ = context.ct.cancelled() => {}
        _ = connection.cancelled() => {}
    }
}

pub trait CheckpointStore: Send + Sync {
    fn read_checkpoint(&self, name: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>>;
    fn write_checkpoint(&self, name: &str, data: &[u8]) -> anyhow::Result<()>;
}

impl CheckpointStore for crate::context::PersistenceContext {
    fn read_checkpoint(&self, name: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_checkpoint(name, max_bytes)
    }

    fn write_checkpoint(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        self.write_checkpoint(name, data)
    }
}

fn number_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr + serde::de::DeserializeOwned,
    T::Err: std::fmt::Display,
{
    Vec::<Value>::deserialize(deserializer)?
        .into_iter()
        .map(|value| {
            crate::coerce::num(value.into_deserializer()).map_err(serde::de::Error::custom)
        })
        .collect()
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Clone)]
pub struct Cancellation {
    signal: watch::Sender<bool>,
}

impl Default for Cancellation {
    fn default() -> Self {
        Self {
            signal: watch::channel(false).0,
        }
    }
}

impl Cancellation {
    pub fn cancel(&self) {
        self.signal.send_replace(true);
    }

    pub fn is_canceled(&self) -> bool {
        *self.signal.borrow()
    }

    pub async fn canceled(&self) {
        let mut rx = self.signal.subscribe();
        let _ = rx.wait_for(|value| *value).await;
    }
}

#[derive(Default)]
pub(crate) struct CheckpointWorker {
    cancel: Cancellation,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl CheckpointWorker {
    pub(crate) fn cancellation(&self) -> Cancellation {
        self.cancel.clone()
    }

    pub(crate) fn attach(&self, task: tokio::task::JoinHandle<()>) {
        *self.task.lock().expect("checkpoint task lock poisoned") = Some(task);
    }

    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.cancel.cancel();
        let task = self
            .task
            .lock()
            .expect("checkpoint task lock poisoned")
            .take();
        if let Some(task) = task {
            task.await
                .context("checkpoint worker did not finish cleanly")?;
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    #[default]
    Connection,
    Persistent,
}

pub fn visible(owner: &str, lifetime: Lifetime, connection: &str) -> bool {
    lifetime == Lifetime::Persistent || owner == connection
}

fn optional_100ns_as_string<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.map(|value| value.to_string()).serialize(serializer)
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct ProcessIdentity {
    #[serde(deserialize_with = "crate::coerce::num")]
    pub pid: u32,
    #[serde(
        default,
        deserialize_with = "crate::coerce::opt_num",
        serialize_with = "optional_100ns_as_string"
    )]
    #[schemars(
        with = "Option<String>",
        description = "Exact decimal FILETIME creation identity. Numeric input is also accepted."
    )]
    pub process_created_100ns: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TargetIdentity {
    pub process: Option<ProcessIdentity>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub hwnd: Option<u64>,
    pub path: Option<String>,
    pub registry_key: Option<String>,
    pub service: Option<String>,
    pub provider_guid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct EtwProvider {
    pub guid: String,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub level: Option<u8>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub match_any_keyword: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub match_all_keyword: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RecordingScope {
    /// Exact process lifetimes. Empty means all processes for the selected source.
    #[serde(default)]
    pub processes: Vec<ProcessIdentity>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
    #[serde(default, deserialize_with = "number_vec")]
    pub event_ids: Vec<u16>,
}

impl RecordingScope {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.processes.len() <= 64, "at most 64 process identities");
        ensure!(self.event_ids.len() <= 128, "at most 128 event IDs");
        for process in &self.processes {
            ensure!(
                process.process_created_100ns.is_some(),
                "process scopes require process_created_100ns to reject reused PIDs"
            );
        }
        Ok(())
    }

    fn matches(&self, process: Option<&ProcessIdentity>, event_id: Option<u16>) -> bool {
        if !self.event_ids.is_empty() && !event_id.is_some_and(|id| self.event_ids.contains(&id)) {
            return false;
        }
        if self.session_id.is_some()
            && self.session_id != process.and_then(|identity| identity.session_id)
        {
            return false;
        }
        self.processes.is_empty()
            || process.is_some_and(|actual| {
                self.processes.iter().any(|wanted| {
                    actual.pid == wanted.pid
                        && actual.process_created_100ns == wanted.process_created_100ns
                })
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Filesystem {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    Registry {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    Service {
        name: String,
    },
    Process {
        #[serde(default)]
        scope: RecordingScope,
    },
    Etw {
        providers: Vec<EtwProvider>,
        #[serde(default)]
        scope: RecordingScope,
    },
    UiAutomation {
        #[serde(default, deserialize_with = "crate::coerce::opt_num")]
        hwnd: Option<u64>,
        /// Supported events: window_opened, window_closed, invoked, selection, text_changed.
        #[serde(default)]
        events: Vec<String>,
        #[serde(default)]
        scope: RecordingScope,
    },
}

impl Source {
    fn name(&self) -> &'static str {
        match self {
            Self::Filesystem { .. } => "filesystem",
            Self::Registry { .. } => "registry",
            Self::Service { .. } => "service",
            Self::Process { .. } => "process",
            Self::Etw { .. } => "etw",
            Self::UiAutomation { .. } => "ui_automation",
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Filesystem { path, .. } | Self::Registry { path, .. } => {
                ensure!(
                    !path.is_empty() && path.len() <= 32_768 && !path.contains('\0'),
                    "invalid path"
                );
            }
            Self::Service { name } => {
                ensure!(
                    !name.is_empty() && name.len() <= 256 && !name.contains('\0'),
                    "invalid service name"
                );
            }
            Self::Process { scope } => scope.validate()?,
            Self::Etw { providers, scope } => {
                ensure!(
                    !providers.is_empty() && providers.len() <= 8,
                    "select 1 to 8 ETW provider GUIDs"
                );
                for provider in providers {
                    uuid::Uuid::parse_str(&provider.guid).context("invalid ETW provider GUID")?;
                    ensure!(provider.level.unwrap_or(5) <= 5, "ETW level must be 0 to 5");
                }
                scope.validate()?;
            }
            Self::UiAutomation { events, scope, .. } => {
                ensure!(events.len() <= 5, "at most five UI Automation event types");
                for event in events {
                    ensure!(
                        matches!(
                            event.as_str(),
                            "window_opened"
                                | "window_closed"
                                | "invoked"
                                | "selection"
                                | "text_changed"
                        ),
                        "unsupported UI Automation event: {event}"
                    );
                }
                scope.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WatchInput {
    pub source: Source,
    #[serde(default)]
    pub lifetime: Lifetime,
    /// Recording ends at this duration, measured from watch creation. Maximum 24 hours.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_duration_ms: Option<u64>,
    /// Maximum retained events for this watch. Older events become explicit history gaps.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_events: Option<u64>,
    /// Maximum retained serialized event bytes for this watch.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_bytes: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_recorded_events: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_recorded_bytes: Option<u64>,
}

impl WatchInput {
    fn validate(&self) -> anyhow::Result<u64> {
        self.source.validate()?;
        let duration = self.max_duration_ms.unwrap_or(300_000);
        ensure!(
            (1..=MAX_DURATION_MS).contains(&duration),
            "max_duration_ms must be 1 to {MAX_DURATION_MS}"
        );
        ensure!(
            (1..=MAX_EVENTS as u64).contains(&self.max_events.unwrap_or(1024)),
            "max_events must be 1 to {MAX_EVENTS}"
        );
        ensure!(
            (1024..=MAX_BYTES as u64).contains(&self.max_bytes.unwrap_or(1024 * 1024)),
            "max_bytes must be 1024 to {MAX_BYTES}"
        );
        ensure!(
            (1..=1_000_000).contains(&self.max_recorded_events.unwrap_or(100_000)),
            "max_recorded_events must be 1 to 1000000"
        );
        ensure!(
            (1024..=1024 * 1024 * 1024)
                .contains(&self.max_recorded_bytes.unwrap_or(64 * 1024 * 1024)),
            "max_recorded_bytes must be 1024 to 1073741824"
        );
        Ok(duration)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchStatus {
    Starting,
    Recording,
    Stopping,
    Stopped,
    Failed,
}

impl WatchStatus {
    fn active(self) -> bool {
        matches!(self, Self::Starting | Self::Recording | Self::Stopping)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct Cursor {
    pub epoch: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub id: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Event {
    pub cursor: Cursor,
    pub watch_id: String,
    pub observed_at_unix_ms: u64,
    #[serde(
        default,
        deserialize_with = "crate::coerce::opt_num",
        serialize_with = "optional_100ns_as_string"
    )]
    pub native_timestamp_100ns: Option<u64>,
    pub source: String,
    pub kind: String,
    pub target: TargetIdentity,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatchRecord {
    pub id: String,
    pub owner: String,
    pub input: WatchInput,
    pub status: WatchStatus,
    pub started_at_unix_ms: u64,
    pub recording_started_at_unix_ms: Option<u64>,
    pub deadline_unix_ms: u64,
    pub start_cursor: Cursor,
    pub finished_at_unix_ms: Option<u64>,
    pub recorded_events: u64,
    pub recorded_bytes: u64,
    pub retained_events: u64,
    pub retained_bytes: u64,
    pub retention_dropped_events: u64,
    pub retention_dropped_bytes: u64,
    pub last_dropped_id: u64,
    pub last_gap_id: u64,
    pub provider_lost_events: u64,
    pub provider_lost_buffers: u64,
    pub error: Option<String>,
    pub stop_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct EventFilter {
    pub watch_id: Option<String>,
    pub source: Option<String>,
    pub kind: Option<String>,
    /// Supplying a creation identity prevents matching a later process using the same PID.
    pub process: Option<ProcessIdentity>,
    pub path: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub since_unix_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub until_unix_ms: Option<u64>,
    /// Exact top-level payload properties, not expressions or executable predicates.
    #[serde(default)]
    pub payload_equals: BTreeMap<String, Value>,
}

impl EventFilter {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.process
                .as_ref()
                .is_none_or(|p| p.process_created_100ns.is_some()),
            "process history filters require process_created_100ns"
        );
        ensure!(
            self.since_unix_ms
                .zip(self.until_unix_ms)
                .is_none_or(|(a, b)| a <= b),
            "since_unix_ms exceeds until_unix_ms"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= 16 * 1024,
            "event filter is too large"
        );
        Ok(())
    }

    fn matches(&self, event: &Event) -> bool {
        self.watch_id
            .as_ref()
            .is_none_or(|id| id == &event.watch_id)
            && self
                .source
                .as_ref()
                .is_none_or(|source| source == &event.source)
            && self.kind.as_ref().is_none_or(|kind| kind == &event.kind)
            && self.process.as_ref().is_none_or(|wanted| {
                event.target.process.as_ref().is_some_and(|actual| {
                    wanted.pid == actual.pid
                        && wanted.process_created_100ns == actual.process_created_100ns
                        && wanted
                            .session_id
                            .is_none_or(|session| actual.session_id == Some(session))
                })
            })
            && self
                .path
                .as_ref()
                .is_none_or(|path| event.target.path.as_ref() == Some(path))
            && self
                .since_unix_ms
                .is_none_or(|time| event.observed_at_unix_ms >= time)
            && self
                .until_unix_ms
                .is_none_or(|time| event.observed_at_unix_ms <= time)
            && self
                .payload_equals
                .iter()
                .all(|(key, value)| event.payload.get(key) == Some(value))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct EventsInput {
    pub after: Option<Cursor>,
    #[serde(default)]
    pub filter: EventFilter,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventsPage {
    pub epoch: String,
    pub epoch_started_at_unix_ms: u64,
    pub next_cursor: Cursor,
    pub oldest_retained_id: Option<u64>,
    pub retention_gap: bool,
    pub recording_gap: bool,
    pub restarted: bool,
    pub dropped_events: u64,
    pub dropped_bytes: u64,
    pub persistence_error: Option<String>,
    pub native_recovery: RecoveryReport,
    pub events: Vec<Event>,
    pub watches: Vec<WatchRecord>,
    pub history_scope: &'static str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Running,
    Satisfied,
    TimedOut,
    Canceled,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WaitInput {
    #[serde(default)]
    pub lifetime: Lifetime,
    #[serde(default)]
    pub filter: EventFilter,
    pub after: Option<Cursor>,
    /// Absolute Unix-millisecond deadline. A relative timeout is not renewed on reconnect.
    #[serde(deserialize_with = "crate::coerce::num")]
    pub deadline_unix_ms: u64,
    /// Return a retained wait ID immediately. The wait continues without a client request.
    #[serde(default)]
    pub background: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WaitRecord {
    pub id: String,
    pub owner: String,
    pub input: WaitInput,
    pub started_at_unix_ms: u64,
    pub outcome: Outcome,
    pub event: Option<Event>,
    pub finished_at_unix_ms: Option<u64>,
    pub error: Option<String>,
    pub cursor: Cursor,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct IdInput {
    pub id: String,
}

#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct HistoryInput {
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct HistoryPage<T> {
    pub retained: usize,
    pub records: Vec<T>,
}

#[derive(Debug, Serialize)]
pub struct WaitSummary {
    pub id: String,
    pub owner: String,
    pub lifetime: Lifetime,
    pub watch_id: Option<String>,
    pub outcome: Outcome,
    pub started_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    pub matched_event: Option<Cursor>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ObservationSnapshot {
    version: u32,
    epoch: String,
    epoch_started_at_unix_ms: u64,
    next_id: u64,
    dropped_events: u64,
    dropped_bytes: u64,
    watches: Vec<WatchRecord>,
    waits: Vec<WaitRecord>,
    events: Vec<Event>,
}

struct Store {
    epoch: String,
    started: u64,
    next_id: u64,
    bytes: usize,
    dropped_events: u64,
    dropped_bytes: u64,
    events: VecDeque<(Event, usize)>,
    watches: BTreeMap<String, WatchRecord>,
    controls: BTreeMap<String, Arc<native::Control>>,
    waits: BTreeMap<String, WaitRecord>,
    wait_cancels: BTreeMap<String, Cancellation>,
    retired_watches: BTreeSet<String>,
}

pub struct ObservationState {
    persistent_enabled: bool,
    store: Mutex<Store>,
    changed: watch::Sender<u64>,
    checkpoint: Option<Arc<dyn CheckpointStore>>,
    checkpoint_serial: Mutex<()>,
    checkpoint_worker: CheckpointWorker,
    persistence_error: Mutex<Option<String>>,
    native_recovery: Mutex<RecoveryReport>,
}

impl ObservationState {
    pub fn new(persistent_enabled: bool) -> Self {
        Self {
            persistent_enabled,
            store: Mutex::new(Store {
                epoch: uuid::Uuid::new_v4().to_string(),
                started: now_ms(),
                next_id: 1,
                bytes: 0,
                dropped_events: 0,
                dropped_bytes: 0,
                events: VecDeque::new(),
                watches: BTreeMap::new(),
                controls: BTreeMap::new(),
                waits: BTreeMap::new(),
                wait_cancels: BTreeMap::new(),
                retired_watches: BTreeSet::new(),
            }),
            changed: watch::channel(0).0,
            checkpoint: None,
            checkpoint_serial: Mutex::new(()),
            checkpoint_worker: CheckpointWorker::default(),
            persistence_error: Mutex::new(None),
            native_recovery: Mutex::new(RecoveryReport::default()),
        }
    }

    pub async fn recover_native_traces(&self) {
        let result = tokio::task::spawn_blocking(etw::recover_native_traces)
            .await
            .context("ETW ownership recovery worker failed")
            .and_then(|result| result);
        let report = match result {
            Ok(report) => report,
            Err(error) => RecoveryReport {
                completed_at_unix_ms: Some(now_ms()),
                errors: vec![format!("ETW ownership recovery failed: {error:#}")],
                ..Default::default()
            },
        };
        for error in &report.errors {
            tracing::error!(%error, "recovering owned native traces");
        }
        *self
            .native_recovery
            .lock()
            .expect("native recovery report lock poisoned") = report;
        self.notify();
    }

    pub fn open(checkpoint: Arc<dyn CheckpointStore>) -> anyhow::Result<Arc<Self>> {
        let runtime = tokio::runtime::Handle::try_current()
            .context("observation persistence requires the host runtime")?;
        let mut state = match checkpoint.read_checkpoint("observation.json", 32 * 1024 * 1024)? {
            Some(bytes) => Self::restore(
                serde_json::from_slice(&bytes).context("invalid observation checkpoint")?,
            )?,
            None => Self::new(true),
        };
        state.checkpoint = Some(checkpoint);
        state.persist_now()?;
        let state = Arc::new(state);
        let weak = Arc::downgrade(&state);
        let mut changes = state.changes();
        let stop = state.checkpoint_worker.cancellation();
        let task = runtime.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = stop.canceled() => break,
                    result = changes.changed() => if result.is_err() { break },
                }
                let Some(state) = weak.upgrade() else { break };
                if let Err(error) = state.flush().await {
                    state.checkpoint_failed(format!("{error:#}"));
                    break;
                }
            }
        });
        state.checkpoint_worker.attach(task);
        Ok(state)
    }

    fn persist_now(&self) -> anyhow::Result<()> {
        let Some(checkpoint) = &self.checkpoint else {
            return Ok(());
        };
        let _serial = self
            .checkpoint_serial
            .lock()
            .expect("observation checkpoint lock poisoned");
        let snapshot = self.snapshot();
        checkpoint
            .write_checkpoint("observation.json", &serde_json::to_vec(&snapshot)?)
            .context("writing observation checkpoint")
    }

    async fn flush(self: &Arc<Self>) -> anyhow::Result<()> {
        if self.checkpoint.is_none() {
            return Ok(());
        }
        let state = self.clone();
        tokio::task::spawn_blocking(move || state.persist_now())
            .await
            .context("observation checkpoint worker failed")?
    }

    fn checkpoint_failed(&self, error: String) {
        tracing::error!(%error, "observation persistence failed");
        *self
            .persistence_error
            .lock()
            .expect("observation persistence error lock poisoned") = Some(error.clone());
        let mut store = self.lock();
        let ids: Vec<_> = store
            .watches
            .values()
            .filter(|record| {
                record.input.lifetime == Lifetime::Persistent && record.status.active()
            })
            .map(|record| record.id.clone())
            .collect();
        for id in ids {
            if let Some(record) = store.watches.get_mut(&id) {
                record.status = WatchStatus::Failed;
                record.error = Some(format!("persistence failed: {error}"));
                record.finished_at_unix_ms = Some(now_ms());
            }
            if let Some(control) = store.controls.get(&id) {
                control.cancel();
            }
        }
        let ids: Vec<_> = store
            .waits
            .values()
            .filter(|record| {
                record.input.lifetime == Lifetime::Persistent && record.outcome == Outcome::Running
            })
            .map(|record| record.id.clone())
            .collect();
        for id in ids {
            if let Some(record) = store.waits.get_mut(&id) {
                record.outcome = Outcome::Failed;
                record.error = Some(format!("persistence failed: {error}"));
                record.finished_at_unix_ms = Some(now_ms());
            }
            if let Some(cancellation) = store.wait_cancels.remove(&id) {
                cancellation.cancel();
            }
        }
        drop(store);
        self.notify();
    }

    fn lock(&self) -> MutexGuard<'_, Store> {
        self.store.lock().expect("observation store poisoned")
    }

    fn notify(&self) {
        self.changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    /// The resident host can checkpoint when this version changes. Subscribing before
    /// snapshotting avoids losing a change between reading state and waiting.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn cursor(&self) -> Cursor {
        let store = self.lock();
        Cursor {
            epoch: store.epoch.clone(),
            id: store.next_id - 1,
        }
    }

    pub fn allows_persistence(&self, lifetime: Lifetime) -> anyhow::Result<()> {
        ensure!(
            lifetime != Lifetime::Persistent || self.persistent_enabled,
            "persistent observation requires an explicitly started local resident host"
        );
        if lifetime == Lifetime::Persistent {
            if let Some(error) = &*self
                .persistence_error
                .lock()
                .expect("observation persistence error lock poisoned")
            {
                return Err(anyhow!(
                    "persistent observation unavailable after checkpoint failure: {error}"
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub async fn create(
        self: &Arc<Self>,
        input: WatchInput,
        owner: &str,
    ) -> anyhow::Result<WatchRecord> {
        self.create_scoped(input, owner, None).await
    }

    async fn create_scoped(
        self: &Arc<Self>,
        input: WatchInput,
        owner: &str,
        connection: Option<tokio_util::sync::CancellationToken>,
    ) -> anyhow::Result<WatchRecord> {
        self.allows_persistence(input.lifetime)?;
        let duration = input.validate()?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(duration);
        let id = uuid::Uuid::new_v4().to_string();
        let control = Arc::new(native::Control::new()?);
        {
            let mut store = self.lock();
            ensure!(
                input.lifetime == Lifetime::Persistent
                    || connection
                        .as_ref()
                        .is_none_or(|cancel| !cancel.is_cancelled()),
                "observation connection is closed"
            );
            ensure!(
                store
                    .controls
                    .values()
                    .filter(|control| !control.is_finished())
                    .count()
                    < MAX_ACTIVE_WATCHES,
                "active watch limit reached"
            );
            ensure!(store.watches.len() < MAX_RECORDS, "retained watch limit reached; remove terminal watches with watch_remove forget=true");
            let started = now_ms();
            let record = WatchRecord {
                id: id.clone(),
                owner: owner.into(),
                input: input.clone(),
                status: WatchStatus::Starting,
                started_at_unix_ms: started,
                recording_started_at_unix_ms: None,
                deadline_unix_ms: started + duration,
                start_cursor: Cursor {
                    epoch: store.epoch.clone(),
                    id: store.next_id - 1,
                },
                finished_at_unix_ms: None,
                recorded_events: 0,
                recorded_bytes: 0,
                retained_events: 0,
                retained_bytes: 0,
                retention_dropped_events: 0,
                retention_dropped_bytes: 0,
                last_dropped_id: 0,
                last_gap_id: 0,
                provider_lost_events: 0,
                provider_lost_buffers: 0,
                error: None,
                stop_reason: None,
            };
            store.watches.insert(id.clone(), record);
            store.controls.insert(id.clone(), control.clone());
        }
        self.notify();
        let mut request = WatchStartup {
            state: Arc::downgrade(self),
            id: id.clone(),
            connection_owned: input.lifetime == Lifetime::Connection,
            returned: false,
        };
        let sink = Sink {
            state: Arc::downgrade(self),
            watch_id: id.clone(),
            control: control.clone(),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let thread_sink = sink.clone();
        let worker = std::thread::Builder::new()
            .name(format!("observe-{}", input.source.name()))
            .spawn(move || {
                let result = native::run(input.source, thread_sink.clone(), ready_tx);
                thread_sink.finish(result);
            });
        if let Err(error) = worker {
            sink.finish(Err(error.into()));
            return self.watch(&id, owner);
        }
        let weak = Arc::downgrade(self);
        let deadline_id = id.clone();
        let deadline_control = control.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    if let Some(state) = weak.upgrade() {
                        state.request_stop(&deadline_id, "recording_deadline");
                    }
                }
                _ = deadline_control.finished() => {}
            }
        });
        // Startup has its own bound; a provider stuck in COM setup never looks ready.
        match tokio::time::timeout(Duration::from_secs(10), ready_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => sink.fail(error),
            Ok(Err(_)) => sink.fail("provider exited before reporting readiness".into()),
            Err(_) => sink.fail("provider setup exceeded 10000 ms; cancellation requested".into()),
        }
        if self.watch(&id, owner)?.input.lifetime == Lifetime::Persistent {
            if let Err(error) = self.flush().await {
                self.checkpoint_failed(format!("{error:#}"));
            }
        }
        let result = self.watch(&id, owner);
        request.returned = true;
        result
    }

    pub fn watch(&self, id: &str, owner: &str) -> anyhow::Result<WatchRecord> {
        self.lock()
            .watches
            .get(id)
            .filter(|record| visible(&record.owner, record.input.lifetime, owner))
            .cloned()
            .ok_or_else(|| anyhow!("watch not found in this connection"))
    }

    fn request_stop(&self, id: &str, reason: &str) {
        let control = {
            let mut store = self.lock();
            if let Some(record) = store.watches.get_mut(id) {
                if record.status.active() {
                    record.status = WatchStatus::Stopping;
                    record.stop_reason.get_or_insert_with(|| reason.into());
                }
            }
            store.controls.get(id).cloned()
        };
        if let Some(control) = control {
            control.cancel();
        }
        self.notify();
    }

    pub async fn remove(&self, id: &str, owner: &str, forget: bool) -> anyhow::Result<WatchRecord> {
        self.watch(id, owner)?;
        self.request_stop(id, "removed");
        let control = self.lock().controls.get(id).cloned();
        if let Some(control) = control {
            // COM/provider cancellation can be delayed. A retained stopping/failed
            // record is honest; freeing callback context on a timeout is not safe.
            let _ = tokio::time::timeout(Duration::from_secs(5), control.finished()).await;
        }
        let record = self.watch(id, owner)?;
        if forget {
            ensure!(
                !record.status.active(),
                "watch is still stopping; cannot forget callback state"
            );
            let mut store = self.lock();
            ensure!(
                store
                    .controls
                    .get(id)
                    .is_none_or(|control| control.is_finished()),
                "provider has not quiesced; cannot forget callback state"
            );
            store.forget(id);
        }
        self.notify();
        Ok(record)
    }

    pub fn read(&self, input: &EventsInput, owner: &str) -> anyhow::Result<EventsPage> {
        input.filter.validate()?;
        let limit = input.limit.unwrap_or(100);
        ensure!((1..=1000).contains(&limit), "limit must be 1 to 1000");
        let persistence_error = self
            .persistence_error
            .lock()
            .expect("observation persistence error lock poisoned")
            .clone();
        let native_recovery = self
            .native_recovery
            .lock()
            .expect("native recovery report lock poisoned")
            .clone();
        let store = self.lock();
        if let Some(id) = &input.filter.watch_id {
            ensure!(
                store.watches.get(id).is_some_and(|record| visible(
                    &record.owner,
                    record.input.lifetime,
                    owner
                )),
                "watch not found in this connection"
            );
        }
        let restarted = input
            .after
            .as_ref()
            .is_some_and(|cursor| cursor.epoch != store.epoch);
        let after = input.after.as_ref().map_or(0, |cursor| cursor.id);
        ensure!(
            after < store.next_id || restarted,
            "cursor is ahead of the recording"
        );
        let after = if after >= store.next_id { 0 } else { after };
        let oldest = store.events.front().map(|(event, _)| event.cursor.id);
        let watches: Vec<_> = store
            .watches
            .values()
            .filter(|record| visible(&record.owner, record.input.lifetime, owner))
            .filter(|record| {
                input
                    .filter
                    .watch_id
                    .as_ref()
                    .is_none_or(|id| id == &record.id)
            })
            .filter(|record| {
                input
                    .filter
                    .source
                    .as_ref()
                    .is_none_or(|source| source == record.input.source.name())
            })
            .cloned()
            .collect();
        let mut events = Vec::new();
        let mut page_bytes = 0;
        let mut next = after;
        let mut exhausted = true;
        for (event, bytes) in &store.events {
            if event.cursor.id <= after {
                continue;
            }
            let visible_event = store
                .watches
                .get(&event.watch_id)
                .is_some_and(|record| visible(&record.owner, record.input.lifetime, owner));
            if visible_event && input.filter.matches(event) {
                if events.len() == limit || page_bytes + bytes > 4 * 1024 * 1024 {
                    exhausted = false;
                    break;
                }
                page_bytes += bytes;
                events.push(event.clone());
            }
            next = event.cursor.id;
        }
        if exhausted {
            next = store.next_id - 1;
        }
        Ok(EventsPage {
            epoch: store.epoch.clone(), epoch_started_at_unix_ms: store.started,
            next_cursor: Cursor { epoch: store.epoch.clone(), id: next },
            oldest_retained_id: oldest,
            retention_gap: watches.iter().any(|record| record.last_dropped_id > after),
            recording_gap: watches.iter().any(|record| record.last_gap_id > after),
            restarted,
            dropped_events: watches.iter().map(|record| record.retention_dropped_events).sum(),
            dropped_bytes: watches.iter().map(|record| record.retention_dropped_bytes).sum(),
            persistence_error,
            native_recovery,
            events, watches,
            history_scope: "Only retained events observed after each watch started. Events are facts, not causal explanations.",
        })
    }

    #[cfg(test)]
    pub async fn start_wait(
        self: &Arc<Self>,
        input: WaitInput,
        owner: &str,
    ) -> anyhow::Result<WaitRecord> {
        self.start_wait_scoped(input, owner, None).await
    }

    pub(crate) async fn start_wait_scoped(
        self: &Arc<Self>,
        mut input: WaitInput,
        owner: &str,
        connection: Option<tokio_util::sync::CancellationToken>,
    ) -> anyhow::Result<WaitRecord> {
        self.allows_persistence(input.lifetime)?;
        input.filter.validate()?;
        let now = now_ms();
        ensure!(
            input.deadline_unix_ms.saturating_sub(now) <= MAX_DURATION_MS,
            "wait deadline exceeds 24 hours"
        );
        if input.after.is_none() {
            input.after = Some(self.cursor());
        }
        self.read(
            &EventsInput {
                after: input.after.clone(),
                filter: input.filter.clone(),
                limit: Some(1),
            },
            owner,
        )?;
        let id = uuid::Uuid::new_v4().to_string();
        let cancellation = Cancellation::default();
        let record = WaitRecord {
            id: id.clone(),
            owner: owner.into(),
            input: input.clone(),
            started_at_unix_ms: now,
            outcome: Outcome::Running,
            event: None,
            finished_at_unix_ms: None,
            error: None,
            cursor: input.after.clone().expect("cursor assigned"),
        };
        {
            let mut store = self.lock();
            ensure!(
                input.lifetime == Lifetime::Persistent
                    || connection
                        .as_ref()
                        .is_none_or(|cancel| !cancel.is_cancelled()),
                "observation connection is closed"
            );
            ensure!(
                store.waits.len() < MAX_RECORDS,
                "retained wait limit reached; forget terminal waits with wait_cancel forget=true"
            );
            store.waits.insert(id.clone(), record.clone());
            store.wait_cancels.insert(id.clone(), cancellation.clone());
        }
        self.notify();
        let weak = Arc::downgrade(self);
        let owner = owner.to_owned();
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(input.deadline_unix_ms.saturating_sub(now_ms()));
            let mut cursor = input.after.clone();
            let mut filter = input.filter.clone();
            filter.until_unix_ms = Some(
                filter
                    .until_unix_ms
                    .unwrap_or(input.deadline_unix_ms)
                    .min(input.deadline_unix_ms),
            );
            loop {
                let Some(state) = weak.upgrade() else { break };
                let mut changes = state.changes();
                if cancellation.is_canceled() {
                    state.finish_wait(&id, Outcome::Canceled, None, None, cursor.clone());
                    break;
                }
                let page = state.read(
                    &EventsInput {
                        after: cursor.clone(),
                        filter: filter.clone(),
                        limit: Some(1),
                    },
                    &owner,
                );
                match page {
                    Err(error) => {
                        state.finish_wait(
                            &id,
                            Outcome::Failed,
                            None,
                            Some(error.to_string()),
                            cursor.clone(),
                        );
                        break;
                    }
                    Ok(page) => {
                        if page.restarted {
                            state.finish_wait(&id, Outcome::Failed, None,
                                Some("recording epoch changed; establish a new cursor before waiting".into()),
                                Some(page.next_cursor));
                            break;
                        }
                        if let Some(event) = page.events.into_iter().next() {
                            let cursor = event.cursor.clone();
                            state.finish_wait(
                                &id,
                                Outcome::Satisfied,
                                Some(event),
                                None,
                                Some(cursor),
                            );
                            break;
                        }
                        if page.retention_gap || page.recording_gap {
                            state.finish_wait(&id, Outcome::Failed, None, Some("recording gap: cannot establish whether the condition occurred".into()), Some(page.next_cursor));
                            break;
                        }
                        if input.filter.watch_id.is_some()
                            && page.watches.iter().all(|record| !record.status.active())
                        {
                            let error = page
                                .watches
                                .iter()
                                .find_map(|record| record.error.clone())
                                .unwrap_or_else(|| {
                                    "recording stopped before the condition was observed".into()
                                });
                            state.finish_wait(
                                &id,
                                Outcome::Failed,
                                None,
                                Some(error),
                                Some(page.next_cursor),
                            );
                            break;
                        }
                        cursor = Some(page.next_cursor);
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    state.finish_wait(&id, Outcome::TimedOut, None, None, cursor.clone());
                    break;
                }
                drop(state);
                tokio::select! {
                    _ = cancellation.canceled() => {}
                    _ = tokio::time::sleep_until(deadline) => {}
                    _ = changes.changed() => {}
                }
            }
        });
        if record.input.lifetime == Lifetime::Persistent {
            if let Err(error) = self.flush().await {
                self.checkpoint_failed(format!("{error:#}"));
            }
        }
        self.wait_status(&record.id, &record.owner)
    }

    fn finish_wait(
        &self,
        id: &str,
        outcome: Outcome,
        event: Option<Event>,
        error: Option<String>,
        cursor: Option<Cursor>,
    ) {
        let mut store = self.lock();
        if let Some(record) = store.waits.get_mut(id) {
            if record.outcome == Outcome::Running {
                record.outcome = outcome;
                record.event = event;
                record.error = error;
                record.finished_at_unix_ms = Some(now_ms());
                if let Some(cursor) = cursor {
                    record.cursor = cursor;
                }
                store.wait_cancels.remove(id);
            }
        }
        drop(store);
        self.notify();
    }

    pub fn wait_status(&self, id: &str, owner: &str) -> anyhow::Result<WaitRecord> {
        self.lock()
            .waits
            .get(id)
            .filter(|record| visible(&record.owner, record.input.lifetime, owner))
            .cloned()
            .ok_or_else(|| anyhow!("wait not found in this connection"))
    }

    pub fn wait_history(
        &self,
        input: &HistoryInput,
        owner: &str,
    ) -> anyhow::Result<HistoryPage<WaitSummary>> {
        let limit = input.limit.unwrap_or(20);
        ensure!(
            (1..=MAX_RECORDS).contains(&limit),
            "wait history limit must be 1 to {MAX_RECORDS}"
        );
        let store = self.lock();
        let mut records: Vec<_> = store
            .waits
            .values()
            .filter(|record| visible(&record.owner, record.input.lifetime, owner))
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse((record.started_at_unix_ms, &record.id)));
        Ok(HistoryPage {
            retained: records.len(),
            records: records
                .into_iter()
                .take(limit)
                .map(|record| WaitSummary {
                    id: record.id.clone(),
                    owner: record.owner.clone(),
                    lifetime: record.input.lifetime,
                    watch_id: record.input.filter.watch_id.clone(),
                    outcome: record.outcome,
                    started_at_unix_ms: record.started_at_unix_ms,
                    deadline_unix_ms: record.input.deadline_unix_ms,
                    finished_at_unix_ms: record.finished_at_unix_ms,
                    matched_event: record.event.as_ref().map(|event| event.cursor.clone()),
                })
                .collect(),
        })
    }

    pub fn cancel_wait(&self, id: &str, owner: &str, forget: bool) -> anyhow::Result<WaitRecord> {
        self.wait_status(id, owner)?;
        if let Some(cancellation) = self.lock().wait_cancels.get(id).cloned() {
            cancellation.cancel();
        }
        self.finish_wait(id, Outcome::Canceled, None, None, None);
        let record = self.wait_status(id, owner)?;
        if forget {
            self.lock().waits.remove(id);
            self.notify();
        }
        Ok(record)
    }

    pub async fn await_wait(
        &self,
        id: &str,
        owner: &str,
        cancel: &Cancellation,
    ) -> anyhow::Result<WaitRecord> {
        loop {
            let mut changes = self.changes();
            let record = self.wait_status(id, owner)?;
            if record.outcome != Outcome::Running {
                return Ok(record);
            }
            tokio::select! {
                _ = cancel.canceled() => { return self.cancel_wait(id, owner, false); }
                _ = changes.changed() => {}
            }
        }
    }

    pub fn shutdown_connection(&self, owner: &str) {
        let watches = {
            let mut store = self.lock();
            let watches = store
                .watches
                .values()
                .filter(|r| r.owner == owner && r.input.lifetime == Lifetime::Connection)
                .map(|r| r.id.clone())
                .collect::<Vec<_>>();
            for id in &watches {
                store.retired_watches.insert(id.clone());
            }
            let waits = store
                .waits
                .values()
                .filter(|r| r.owner == owner && r.input.lifetime == Lifetime::Connection)
                .map(|r| r.id.clone())
                .collect::<Vec<_>>();
            for id in waits {
                if let Some(cancellation) = store.wait_cancels.remove(&id) {
                    cancellation.cancel();
                }
                store.waits.remove(&id);
            }
            watches
        };
        for id in watches {
            self.request_stop(&id, "connection_disconnected");
            let mut store = self.lock();
            if store
                .controls
                .get(&id)
                .is_none_or(|control| control.is_finished())
            {
                store.forget(&id);
            }
        }
        self.notify();
    }

    pub async fn shutdown(self: &Arc<Self>) {
        let (ids, controls) = {
            let store = self.lock();
            for cancellation in store.wait_cancels.values() {
                cancellation.cancel();
            }
            (
                store.watches.keys().cloned().collect::<Vec<_>>(),
                store.controls.values().cloned().collect::<Vec<_>>(),
            )
        };
        for id in ids {
            self.request_stop(&id, "host_shutdown");
        }
        for control in &controls {
            control.cancel();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for control in controls {
            if tokio::time::timeout_at(deadline, control.finished())
                .await
                .is_err()
            {
                tracing::error!(
                    "observation provider did not finish cancellation within 5 seconds"
                );
            }
        }
        if let Err(error) = self.checkpoint_worker.shutdown().await {
            self.checkpoint_failed(format!("{error:#}"));
        }
        if let Err(error) = self.flush().await {
            self.checkpoint_failed(format!("{error:#}"));
        }
    }

    pub fn snapshot(&self) -> ObservationSnapshot {
        let store = self.lock();
        let watches: Vec<_> = store
            .watches
            .values()
            .filter(|r| r.input.lifetime == Lifetime::Persistent)
            .cloned()
            .collect();
        ObservationSnapshot {
            version: 1,
            epoch: store.epoch.clone(),
            epoch_started_at_unix_ms: store.started,
            next_id: store.next_id,
            dropped_events: store.dropped_events,
            dropped_bytes: store.dropped_bytes,
            waits: store
                .waits
                .values()
                .filter(|r| r.input.lifetime == Lifetime::Persistent)
                .cloned()
                .collect(),
            events: store
                .events
                .iter()
                .filter(|(event, _)| watches.iter().any(|r| r.id == event.watch_id))
                .map(|(event, _)| event.clone())
                .collect(),
            watches,
        }
    }

    pub fn restore(snapshot: ObservationSnapshot) -> anyhow::Result<Self> {
        ensure!(
            snapshot.version == 1,
            "unsupported observation checkpoint version"
        );
        ensure!(
            snapshot.watches.len() <= MAX_RECORDS
                && snapshot.waits.len() <= MAX_RECORDS
                && snapshot.events.len() <= MAX_EVENTS,
            "observation checkpoint exceeds retention limits"
        );
        ensure!(snapshot.next_id > 0, "invalid checkpoint cursor");
        ensure!(
            snapshot.next_id < u64::MAX - snapshot.watches.len() as u64,
            "checkpoint cursor has no room for restart markers"
        );
        let state = Self::new(true);
        {
            let mut store = state.lock();
            store.next_id = snapshot.next_id;
            store.dropped_events = snapshot.dropped_events;
            store.dropped_bytes = snapshot.dropped_bytes;
            for mut record in snapshot.watches {
                ensure!(
                    record.input.lifetime == Lifetime::Persistent,
                    "checkpoint contains a connection-owned watch"
                );
                record.input.validate()?;
                if record.status.active() {
                    record.status = WatchStatus::Failed;
                    record.finished_at_unix_ms = Some(now_ms());
                    record.error = Some(
                        "host restarted: recording interrupted; watcher was not replayed".into(),
                    );
                    record.stop_reason = Some("host_restarted".into());
                }
                record.retained_events = 0;
                record.retained_bytes = 0;
                ensure!(
                    store.watches.insert(record.id.clone(), record).is_none(),
                    "duplicate watch ID in checkpoint"
                );
            }
            for mut record in snapshot.waits {
                ensure!(
                    record.input.lifetime == Lifetime::Persistent,
                    "checkpoint contains a connection-owned wait"
                );
                if record.outcome == Outcome::Running {
                    record.outcome = Outcome::Failed;
                    record.finished_at_unix_ms = Some(now_ms());
                    record.error =
                        Some("host restarted: wait interrupted by an observation gap".into());
                }
                record.input.filter.validate()?;
                ensure!(
                    store.waits.insert(record.id.clone(), record).is_none(),
                    "duplicate wait ID in checkpoint"
                );
            }
            let mut previous = 0;
            for event in snapshot.events {
                ensure!(
                    event.cursor.id > previous && event.cursor.id < store.next_id,
                    "invalid retained event ordering"
                );
                ensure!(
                    store.watches.contains_key(&event.watch_id),
                    "checkpoint event has no watch"
                );
                previous = event.cursor.id;
                let bytes = serde_json::to_vec(&event)?.len();
                ensure!(
                    bytes <= MAX_EVENT_BYTES && store.bytes + bytes <= MAX_BYTES,
                    "checkpoint events exceed byte limit"
                );
                store.bytes += bytes;
                let record = store
                    .watches
                    .get_mut(&event.watch_id)
                    .expect("validated watch");
                record.retained_events += 1;
                record.retained_bytes += bytes as u64;
                store.events.push_back((event, bytes));
            }
            let ids: Vec<_> = store.watches.keys().cloned().collect();
            for id in ids {
                store.append(
                    &id,
                    "gap",
                    TargetIdentity::default(),
                    json!({
                        "reason": "host_restarted", "previous_epoch": snapshot.epoch,
                        "previous_epoch_started_at_unix_ms": snapshot.epoch_started_at_unix_ms,
                        "lost_count": null, "replayed": false
                    }),
                    None,
                );
            }
        }
        Ok(state)
    }
}

impl Drop for ObservationState {
    fn drop(&mut self) {
        let store = self.store.get_mut().expect("observation store poisoned");
        for control in store.controls.values() {
            control.cancel();
        }
        for cancellation in store.wait_cancels.values() {
            cancellation.cancel();
        }
    }
}

impl Store {
    fn forget(&mut self, id: &str) {
        while let Some(index) = self
            .events
            .iter()
            .position(|(event, _)| event.watch_id == id)
        {
            self.discard(index);
        }
        self.watches.remove(id);
        self.controls.remove(id);
        self.retired_watches.remove(id);
    }

    fn discard(&mut self, index: usize) {
        if let Some((event, bytes)) = self.events.remove(index) {
            self.bytes -= bytes;
            self.dropped_events += 1;
            self.dropped_bytes += bytes as u64;
            if let Some(record) = self.watches.get_mut(&event.watch_id) {
                record.retained_events -= 1;
                record.retained_bytes -= bytes as u64;
                record.retention_dropped_events += 1;
                record.retention_dropped_bytes += bytes as u64;
                record.last_dropped_id = record.last_dropped_id.max(event.cursor.id);
            }
        }
    }

    fn append(
        &mut self,
        watch_id: &str,
        kind: &str,
        target: TargetIdentity,
        payload: Value,
        native_timestamp: Option<u64>,
    ) {
        let Some(record) = self.watches.get(watch_id) else {
            return;
        };
        let max_events = record.input.max_events.unwrap_or(1024);
        let max_bytes = record.input.max_bytes.unwrap_or(1024 * 1024);
        let mut event = Event {
            cursor: Cursor {
                epoch: self.epoch.clone(),
                id: self.next_id,
            },
            watch_id: watch_id.into(),
            observed_at_unix_ms: now_ms(),
            native_timestamp_100ns: native_timestamp,
            source: record.input.source.name().into(),
            kind: kind.into(),
            target,
            payload,
        };
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("observation cursor exhausted");
        let mut bytes = serde_json::to_vec(&event)
            .expect("event serialization")
            .len();
        if bytes > MAX_EVENT_BYTES || bytes as u64 > max_bytes {
            event.kind = "gap".into();
            event.payload = json!({"reason":"event_exceeds_byte_limit", "lost_count":1, "original_bytes":bytes});
            event.target = TargetIdentity::default();
            bytes = serde_json::to_vec(&event).expect("gap serialization").len();
        }
        loop {
            let record = self
                .watches
                .get(watch_id)
                .expect("watch retained during append");
            if record.retained_events < max_events
                && record.retained_bytes + bytes as u64 <= max_bytes
            {
                break;
            }
            if let Some(index) = self
                .events
                .iter()
                .position(|(event, _)| event.watch_id == watch_id)
            {
                self.discard(index);
            } else {
                break;
            }
        }
        while self.events.len() >= MAX_EVENTS || self.bytes + bytes > MAX_BYTES {
            self.discard(0);
        }
        let gap_id = (event.kind == "gap").then_some(event.cursor.id);
        self.bytes += bytes;
        self.events.push_back((event, bytes));
        if let Some(record) = self.watches.get_mut(watch_id) {
            record.recorded_events += 1;
            record.recorded_bytes += bytes as u64;
            record.retained_events += 1;
            record.retained_bytes += bytes as u64;
            if let Some(id) = gap_id {
                record.last_gap_id = id;
            }
            if record.status.active()
                && (record.recorded_events >= record.input.max_recorded_events.unwrap_or(100_000)
                    || record.recorded_bytes
                        >= record.input.max_recorded_bytes.unwrap_or(64 * 1024 * 1024))
            {
                record.status = WatchStatus::Stopping;
                record.stop_reason = Some("recording_limit".into());
                if let Some(control) = self.controls.get(watch_id) {
                    control.cancel();
                }
            }
        }
    }
}

#[derive(Clone)]
struct Sink {
    state: Weak<ObservationState>,
    watch_id: String,
    control: Arc<native::Control>,
}

impl Sink {
    fn ready(&self) {
        if let Some(state) = self.state.upgrade() {
            let mut store = state.lock();
            if let Some(record) = store.watches.get_mut(&self.watch_id) {
                if record.status == WatchStatus::Starting {
                    record.status = WatchStatus::Recording;
                    record.recording_started_at_unix_ms = Some(now_ms());
                }
            }
            drop(store);
            state.notify();
        }
    }

    fn emit(&self, kind: &str, target: TargetIdentity, payload: Value, timestamp: Option<u64>) {
        if self.control.is_canceled() {
            return;
        }
        if let Some(state) = self.state.upgrade() {
            let mut store = state.lock();
            if store.watches.get(&self.watch_id).is_some_and(|record| {
                matches!(
                    record.status,
                    WatchStatus::Starting | WatchStatus::Recording
                )
            }) {
                store.append(&self.watch_id, kind, target, payload, timestamp);
            }
            drop(store);
            state.notify();
        }
    }

    fn lost(&self, events: Option<u64>, buffers: Option<u64>, reason: &str) {
        if let Some(state) = self.state.upgrade() {
            let mut store = state.lock();
            if let Some(record) = store.watches.get_mut(&self.watch_id) {
                if let Some(events) = events {
                    record.provider_lost_events += events;
                }
                if let Some(buffers) = buffers {
                    record.provider_lost_buffers += buffers;
                }
            }
            store.append(
                &self.watch_id,
                "gap",
                TargetIdentity::default(),
                json!({
                    "reason": reason, "lost_events": events, "lost_buffers": buffers,
                    "counts_known": events.is_some() && buffers.is_some()
                }),
                None,
            );
            drop(store);
            state.notify();
        }
    }

    fn fail(&self, error: String) {
        if let Some(state) = self.state.upgrade() {
            let mut store = state.lock();
            if let Some(record) = store.watches.get_mut(&self.watch_id) {
                record.status = WatchStatus::Failed;
                record.error = Some(error.clone());
                record.finished_at_unix_ms = Some(now_ms());
            }
            store.append(
                &self.watch_id,
                "watch.failed",
                TargetIdentity::default(),
                json!({"error":error}),
                None,
            );
            drop(store);
            state.notify();
        }
        self.control.cancel();
    }

    fn finish(&self, result: anyhow::Result<()>) {
        if let Err(error) = result {
            self.fail(format!("{error:#}"));
        }
        if let Some(state) = self.state.upgrade() {
            let mut store = state.lock();
            if let Some(record) = store.watches.get_mut(&self.watch_id) {
                if record.status != WatchStatus::Failed {
                    record.status = WatchStatus::Stopped;
                    record.finished_at_unix_ms = Some(now_ms());
                    record
                        .stop_reason
                        .get_or_insert_with(|| "provider_stopped".into());
                }
            }
            if store.retired_watches.contains(&self.watch_id) {
                store.forget(&self.watch_id);
            }
            drop(store);
            state.notify();
        }
        self.control.mark_finished();
    }
}

pub fn tool_result<T: Serialize>(result: anyhow::Result<T>) -> Result<CallToolResult, ErrorData> {
    match result {
        Ok(value) => {
            let json = serde_json::to_value(value)
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
            let text = serde_json::to_string(&json)
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
            let mut result = CallToolResult::success(vec![Content::text(text)]);
            result.structured_content = Some(json);
            Ok(result)
        }
        Err(error) => Ok(CallToolResult::error(vec![Content::text(format!(
            "{error:#}"
        ))])),
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoveInput {
    pub id: String,
    #[serde(default)]
    pub forget: bool,
}

struct WatchStartup {
    state: Weak<ObservationState>,
    id: String,
    connection_owned: bool,
    returned: bool,
}

impl Drop for WatchStartup {
    fn drop(&mut self) {
        if self.connection_owned && !self.returned {
            if let Some(state) = self.state.upgrade() {
                state.request_stop(&self.id, "watch_create_request_canceled");
            }
        }
    }
}

struct ForegroundWait {
    state: Arc<ObservationState>,
    id: String,
    owner: String,
    persistent: bool,
}

impl Drop for ForegroundWait {
    fn drop(&mut self) {
        if !self.persistent {
            if let Err(error) = self.state.cancel_wait(&self.id, &self.owner, false) {
                tracing::error!(%error, "canceling dropped foreground event wait");
            }
        }
    }
}

mod tools;

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::{FixtureDirectory, MemoryCheckpoint};

    pub(super) fn synthetic(
        state: &Arc<ObservationState>,
        lifetime: Lifetime,
        max_events: u64,
        max_bytes: u64,
    ) -> Sink {
        let id = uuid::Uuid::new_v4().to_string();
        let input: WatchInput = serde_json::from_value(json!({
            "source":{"kind":"filesystem","path":"C:\\fixture"}, "lifetime":lifetime,
            "max_events":max_events, "max_bytes":max_bytes
        }))
        .unwrap();
        let record = WatchRecord {
            id: id.clone(),
            owner: "first".into(),
            input,
            status: WatchStatus::Recording,
            started_at_unix_ms: now_ms(),
            recording_started_at_unix_ms: Some(now_ms()),
            deadline_unix_ms: now_ms() + 10_000,
            start_cursor: state.cursor(),
            finished_at_unix_ms: None,
            recorded_events: 0,
            recorded_bytes: 0,
            retained_events: 0,
            retained_bytes: 0,
            retention_dropped_events: 0,
            retention_dropped_bytes: 0,
            last_dropped_id: 0,
            last_gap_id: 0,
            provider_lost_events: 0,
            provider_lost_buffers: 0,
            error: None,
            stop_reason: None,
        };
        let control = Arc::new(native::Control::new().unwrap());
        let mut store = state.lock();
        store.watches.insert(id.clone(), record);
        store.controls.insert(id.clone(), control.clone());
        Sink {
            state: Arc::downgrade(state),
            watch_id: id,
            control,
        }
    }

    fn wait_input(
        state: &ObservationState,
        sink: &Sink,
        lifetime: Lifetime,
        kind: &str,
    ) -> WaitInput {
        WaitInput {
            lifetime,
            filter: EventFilter {
                watch_id: Some(sink.watch_id.clone()),
                kind: Some(kind.into()),
                ..Default::default()
            },
            after: Some(state.cursor()),
            deadline_unix_ms: now_ms() + 2000,
            background: true,
        }
    }

    #[test]
    fn numeric_strings_cover_deadlines_identities_and_etw_scopes() {
        let input: WatchInput = serde_json::from_value(json!({
                "source":{"kind":"etw","providers":[{"guid":"22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716","level":"5","match_any_keyword":"16"}],
                    "scope":{"processes":[{"pid":"123","process_created_100ns":"999","session_id":"1"}],"event_ids":["1",2],"session_id":"1"}},
                "max_events":"2","max_bytes":"4096","max_duration_ms":"1000","max_recorded_events":"100"
            })).unwrap();
        input.source.validate().unwrap();
        assert_eq!(input.max_events, Some(2));
        let input: WaitInput = serde_json::from_value(json!({"deadline_unix_ms":"12345"})).unwrap();
        assert_eq!(input.deadline_unix_ms, 12345);
        assert!(serde_json::from_value::<WatchInput>(
            json!({"source":{"kind":"filesystem","path":"x"},"max_events":"-1"})
        )
        .is_err());
    }

    #[test]
    fn dropped_watch_setup_cancels_only_connection_owned_providers() {
        let state = Arc::new(ObservationState::new(true));
        let connection = synthetic(&state, Lifetime::Connection, 10, 4096);
        let persistent = synthetic(&state, Lifetime::Persistent, 10, 4096);
        drop(WatchStartup {
            state: Arc::downgrade(&state),
            id: connection.watch_id.clone(),
            connection_owned: true,
            returned: false,
        });
        assert!(connection.control.is_canceled());
        assert_eq!(
            state
                .watch(&connection.watch_id, "first")
                .unwrap()
                .stop_reason
                .as_deref(),
            Some("watch_create_request_canceled")
        );
        drop(WatchStartup {
            state: Arc::downgrade(&state),
            id: persistent.watch_id.clone(),
            connection_owned: false,
            returned: false,
        });
        assert!(!persistent.control.is_canceled());
    }

    #[test]
    fn corrupt_checkpoints_fail_without_replaying_or_overflowing_cursors() {
        let state = Arc::new(ObservationState::new(true));
        synthetic(&state, Lifetime::Persistent, 10, 4096);
        let mut snapshot = state.snapshot();
        snapshot.next_id = u64::MAX;
        assert!(ObservationState::restore(snapshot).is_err());
        let mut snapshot = state.snapshot();
        snapshot.watches.push(snapshot.watches[0].clone());
        assert!(ObservationState::restore(snapshot).is_err());
        let mut snapshot = state.snapshot();
        snapshot.watches[0].input.max_bytes = Some(0);
        assert!(ObservationState::restore(snapshot).is_err());
    }

    #[test]
    fn cursors_retention_and_history_filters_are_exact() {
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 2, 4096);
        let start = state.cursor();
        for value in 0..5 {
            sink.emit(
                "filesystem.modified",
                TargetIdentity {
                    path: Some("C:\\fixture\\a".into()),
                    ..Default::default()
                },
                json!({"value":value}),
                None,
            );
        }
        let page = state
            .read(
                &EventsInput {
                    after: Some(start),
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        assert!(page.retention_gap);
        assert_eq!(page.dropped_events, 3);
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events[0].cursor.id, 4);
        assert_eq!(page.next_cursor.id, 5);
        assert_eq!(page.watches[0].status, WatchStatus::Recording);
        let filter = EventFilter {
            path: Some("C:\\fixture\\a".into()),
            payload_equals: BTreeMap::from([("value".into(), json!(4))]),
            ..Default::default()
        };
        let filtered = state
            .read(
                &EventsInput {
                    filter,
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        assert_eq!(filtered.events.len(), 1);
        assert_eq!(filtered.events[0].payload["value"], 4);
        assert!(state
            .read(&EventsInput::default(), "second")
            .unwrap()
            .events
            .is_empty());
    }

    #[test]
    fn byte_limited_pages_do_not_skip_unreturned_events() {
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 1000, MAX_BYTES as u64);
        for _ in 0..100 {
            sink.emit(
                "fixture",
                TargetIdentity::default(),
                json!({"text":"x".repeat(50_000)}),
                None,
            );
        }
        let first = state
            .read(
                &EventsInput {
                    limit: Some(1000),
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        assert!(first.events.len() < 100);
        let second = state
            .read(
                &EventsInput {
                    after: Some(first.next_cursor),
                    limit: Some(1000),
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        assert_eq!(first.events.len() + second.events.len(), 100);
        assert_eq!(second.events.last().unwrap().cursor.id, 100);
    }

    #[test]
    fn byte_overflow_and_unknown_loss_are_visible_even_when_filtered_out() {
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 100, 1024);
        sink.emit(
            "too_large",
            TargetIdentity::default(),
            json!({"bytes":"x".repeat(2000)}),
            None,
        );
        let page = state.read(&EventsInput::default(), "first").unwrap();
        assert!(page.recording_gap);
        assert_eq!(page.events[0].kind, "gap");
        sink.lost(Some(8), Some(1), "provider_overflow");
        let page = state
            .read(
                &EventsInput {
                    filter: EventFilter {
                        kind: Some("not-a-gap".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        assert!(page.recording_gap);
        assert!(page.events.is_empty());
        assert_eq!(page.watches[0].provider_lost_events, 8);
        assert_eq!(page.watches[0].provider_lost_buffers, 1);
        assert!(state.lock().bytes <= 1024);
    }

    #[test]
    fn process_filters_reject_reused_pids_and_require_creation_identity() {
        let wanted = ProcessIdentity {
            pid: 50,
            process_created_100ns: Some(100),
            session_id: Some(1),
            identity_error: None,
        };
        let filter = EventFilter {
            process: Some(wanted.clone()),
            ..Default::default()
        };
        filter.validate().unwrap();
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 10, 4096);
        sink.emit(
            "fixture",
            TargetIdentity {
                process: Some(ProcessIdentity {
                    process_created_100ns: Some(200),
                    ..wanted.clone()
                }),
                ..Default::default()
            },
            json!({}),
            None,
        );
        assert!(state
            .read(
                &EventsInput {
                    filter,
                    ..Default::default()
                },
                "first"
            )
            .unwrap()
            .events
            .is_empty());
        assert!(EventFilter {
            process: Some(ProcessIdentity {
                process_created_100ns: None,
                ..wanted
            }),
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[tokio::test]
    async fn waits_report_satisfied_canceled_timed_out_failed_and_provider_gaps() {
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 32, 16_384);
        let wait = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Connection, "match"),
                "first",
            )
            .await
            .unwrap();
        sink.emit(
            "match",
            TargetIdentity::default(),
            json!({"observed":true}),
            None,
        );
        let result = state
            .await_wait(&wait.id, "first", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(result.outcome, Outcome::Satisfied);
        let wait = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Connection, "absent"),
                "first",
            )
            .await
            .unwrap();
        assert_eq!(
            state.cancel_wait(&wait.id, "first", false).unwrap().outcome,
            Outcome::Canceled
        );
        let mut input = wait_input(&state, &sink, Lifetime::Connection, "absent");
        input.deadline_unix_ms = now_ms() + 25;
        let wait = state.start_wait(input, "first").await.unwrap();
        assert_eq!(
            state
                .await_wait(&wait.id, "first", &Cancellation::default())
                .await
                .unwrap()
                .outcome,
            Outcome::TimedOut
        );
        let wait = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Connection, "absent"),
                "first",
            )
            .await
            .unwrap();
        sink.lost(Some(2), Some(0), "provider_loss");
        assert_eq!(
            state
                .await_wait(&wait.id, "first", &Cancellation::default())
                .await
                .unwrap()
                .outcome,
            Outcome::Failed
        );
        let wait = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Connection, "absent"),
                "first",
            )
            .await
            .unwrap();
        sink.finish(Err(anyhow!("provider fixture failure")));
        let failed = state
            .await_wait(&wait.id, "first", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(failed.outcome, Outcome::Failed);
        assert!(failed.error.unwrap().contains("provider fixture failure"));
    }

    #[tokio::test]
    async fn positive_observations_satisfy_even_if_other_events_were_dropped() {
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 1, 4096);
        let input = wait_input(&state, &sink, Lifetime::Connection, "match");
        sink.emit("other", TargetIdentity::default(), json!({}), None);
        sink.emit("match", TargetIdentity::default(), json!({}), None);
        let wait = state.start_wait(input, "first").await.unwrap();
        assert_eq!(
            state
                .await_wait(&wait.id, "first", &Cancellation::default())
                .await
                .unwrap()
                .outcome,
            Outcome::Satisfied
        );
    }

    #[tokio::test]
    async fn persistent_waits_survive_disconnect_and_recovery_never_replays() {
        let checkpoint = Arc::new(MemoryCheckpoint::default());
        let state = ObservationState::open(checkpoint.clone()).unwrap();
        let sink = synthetic(&state, Lifetime::Persistent, 32, 16_384);
        let connection_sink = synthetic(&state, Lifetime::Connection, 32, 16_384);
        let pending = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Persistent, "later"),
                "first",
            )
            .await
            .unwrap();
        let interrupted = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Persistent, "never"),
                "first",
            )
            .await
            .unwrap();
        let connection_wait = state
            .start_wait(
                wait_input(&state, &connection_sink, Lifetime::Connection, "never"),
                "first",
            )
            .await
            .unwrap();
        state.shutdown_connection("first");
        assert!(state.wait_status(&connection_wait.id, "first").is_err());
        assert!(connection_sink.control.is_canceled());
        assert!(!sink.control.is_canceled());
        sink.emit(
            "later",
            TargetIdentity::default(),
            json!({"fact":true}),
            None,
        );
        assert_eq!(
            state
                .await_wait(&pending.id, "reconnected", &Cancellation::default())
                .await
                .unwrap()
                .outcome,
            Outcome::Satisfied
        );
        state.flush().await.unwrap();
        let bytes = checkpoint
            .read_checkpoint("observation.json", 32 * 1024 * 1024)
            .unwrap()
            .unwrap();
        let restored = ObservationState::restore(serde_json::from_slice(&bytes).unwrap()).unwrap();
        assert_eq!(
            restored
                .wait_status(&pending.id, "new-peer")
                .unwrap()
                .outcome,
            Outcome::Satisfied
        );
        assert_eq!(
            restored
                .wait_status(&interrupted.id, "new-peer")
                .unwrap()
                .outcome,
            Outcome::Failed
        );
        assert_eq!(
            restored.watch(&sink.watch_id, "new-peer").unwrap().status,
            WatchStatus::Failed
        );
        assert!(restored.lock().controls.is_empty());
        let page = restored
            .read(
                &EventsInput {
                    after: Some(state.cursor()),
                    ..Default::default()
                },
                "new-peer",
            )
            .unwrap();
        assert!(page.restarted && page.recording_gap);
        sink.finish(Ok(()));
        connection_sink.finish(Ok(()));
        state.shutdown().await;
    }

    #[tokio::test]
    async fn foreground_drop_cancels_only_connection_waits() {
        let state = Arc::new(ObservationState::new(true));
        let sink = synthetic(&state, Lifetime::Persistent, 10, 4096);
        let record = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Connection, "unused"),
                "first",
            )
            .await
            .unwrap();
        drop(ForegroundWait {
            state: state.clone(),
            id: record.id.clone(),
            owner: "first".into(),
            persistent: false,
        });
        assert_eq!(
            state.wait_status(&record.id, "first").unwrap().outcome,
            Outcome::Canceled
        );
        let record = state
            .start_wait(
                wait_input(&state, &sink, Lifetime::Persistent, "unused"),
                "first",
            )
            .await
            .unwrap();
        drop(ForegroundWait {
            state: state.clone(),
            id: record.id.clone(),
            owner: "first".into(),
            persistent: true,
        });
        assert_eq!(
            state.wait_status(&record.id, "another").unwrap().outcome,
            Outcome::Running
        );
    }

    #[tokio::test]
    async fn native_filesystem_events_overflow_and_shutdown_use_disposable_files() {
        let directory = FixtureDirectory::new();
        let state = Arc::new(ObservationState::new(false));
        let input: WatchInput = serde_json::from_value(json!({
            "source":{"kind":"filesystem","path":directory.path},
            "max_duration_ms":10000, "max_events":"2"
        }))
        .unwrap();
        let record = state.create(input, "first").await.unwrap();
        assert_eq!(record.status, WatchStatus::Recording, "{:?}", record.error);
        let wait = state
            .start_wait(
                WaitInput {
                    lifetime: Lifetime::Connection,
                    filter: EventFilter {
                        watch_id: Some(record.id.clone()),
                        kind: Some("filesystem.added".into()),
                        ..Default::default()
                    },
                    after: Some(record.start_cursor.clone()),
                    deadline_unix_ms: now_ms() + 5000,
                    background: true,
                },
                "first",
            )
            .await
            .unwrap();
        std::fs::write(directory.path.join("fixture.txt"), b"first").unwrap();
        let observed = state
            .await_wait(&wait.id, "first", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(observed.outcome, Outcome::Satisfied, "{:?}", observed.error);
        let after = state.cursor();
        let wait = state
            .start_wait(
                WaitInput {
                    lifetime: Lifetime::Connection,
                    filter: EventFilter {
                        watch_id: Some(record.id.clone()),
                        payload_equals: BTreeMap::from([(
                            "relative_path".into(),
                            json!("sentinel.txt"),
                        )]),
                        ..Default::default()
                    },
                    after: Some(after),
                    deadline_unix_ms: now_ms() + 5000,
                    background: true,
                },
                "first",
            )
            .await
            .unwrap();
        for index in 0..16 {
            std::fs::write(
                directory.path.join(format!("fixture-{index}.txt")),
                b"owned",
            )
            .unwrap();
        }
        std::fs::write(directory.path.join("sentinel.txt"), b"last").unwrap();
        let result = state
            .await_wait(&wait.id, "first", &Cancellation::default())
            .await
            .unwrap();
        // If the consumer fell behind the two-event ring, an explicit gap is
        // correct. It must never silently time out or stop the native source.
        assert!(matches!(
            result.outcome,
            Outcome::Satisfied | Outcome::Failed
        ));
        let page = state
            .read(
                &EventsInput {
                    after: Some(record.start_cursor),
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        assert!(page.retention_gap);
        assert!(page.events.len() <= 2);
        let stopped = state.remove(&record.id, "first", false).await.unwrap();
        assert_eq!(stopped.status, WatchStatus::Stopped, "{:?}", stopped.error);
        assert!(state.lock().controls[&record.id].is_finished());
        state.remove(&record.id, "first", true).await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_native_sources_remain_failed_records() {
        let state = Arc::new(ObservationState::new(false));
        let sources = [
            json!({"kind":"service","name":format!("MCP-absent-{}",uuid::Uuid::new_v4())}),
            json!({"kind":"filesystem","path":format!("C:\\MCP-absent-{}",uuid::Uuid::new_v4())}),
            json!({"kind":"etw","providers":[{"guid":"00000000-0000-0000-0000-000000000000"}]}),
            json!({"kind":"ui_automation","hwnd":0}),
        ];
        for source in sources {
            let input: WatchInput =
                serde_json::from_value(json!({"source":source,"max_duration_ms":1000})).unwrap();
            let record = state.create(input, "first").await.unwrap();
            assert_eq!(record.status, WatchStatus::Failed);
            assert!(record.error.is_some());
            assert_eq!(
                state.watch(&record.id, "first").unwrap().status,
                WatchStatus::Failed
            );
        }
        state.shutdown().await;
    }

    #[test]
    fn old_epoch_cursor_reports_restart_in_a_fresh_history() {
        let state = ObservationState::new(false);
        let page = state
            .read(
                &EventsInput {
                    after: Some(Cursor {
                        epoch: "previous-host".into(),
                        id: 10000,
                    }),
                    ..Default::default()
                },
                "reconnected",
            )
            .unwrap();
        assert!(page.restarted);
        assert_eq!(page.next_cursor.id, 0);
        assert!(page.events.is_empty());
        assert!(state
            .read(
                &EventsInput {
                    after: Some(Cursor {
                        epoch: page.epoch,
                        id: 10000
                    }),
                    ..Default::default()
                },
                "reconnected"
            )
            .is_err());
    }

    #[test]
    fn native_timestamps_round_trip_as_exact_decimal_strings() {
        let timestamp = 133000000000000001;
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 10, 4096);
        let identity = ProcessIdentity {
            pid: 42,
            process_created_100ns: Some(timestamp),
            session_id: Some(1),
            identity_error: None,
        };
        sink.emit(
            "fixture",
            TargetIdentity {
                process: Some(identity.clone()),
                ..Default::default()
            },
            json!({}),
            Some(timestamp),
        );
        let event = state
            .read(&EventsInput::default(), "first")
            .unwrap()
            .events
            .remove(0);
        let mut json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["native_timestamp_100ns"], timestamp.to_string());
        assert_eq!(
            json["target"]["process"]["process_created_100ns"],
            timestamp.to_string()
        );
        let restored: Event = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(restored.native_timestamp_100ns, Some(timestamp));
        assert_eq!(restored.target.process, Some(identity.clone()));
        json["native_timestamp_100ns"] = json!(timestamp);
        json["target"]["process"]["process_created_100ns"] = json!(timestamp);
        let legacy: Event = serde_json::from_value(json).unwrap();
        assert_eq!(legacy.native_timestamp_100ns, Some(timestamp));
        assert_eq!(legacy.target.process, Some(identity));
        sink.finish(Ok(()));
    }

    #[tokio::test]
    async fn closed_connections_cannot_admit_new_default_watches_or_waits() {
        let state = Arc::new(ObservationState::new(false));
        let closed = tokio_util::sync::CancellationToken::new();
        closed.cancel();
        let watch = serde_json::from_value(json!({
            "source":{"kind":"filesystem","path":"C:\\closed-connection-fixture"},
            "max_duration_ms":1000
        }))
        .unwrap();
        let error = state
            .create_scoped(watch, "closed", Some(closed.clone()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("connection is closed"));
        let wait = serde_json::from_value(json!({
            "deadline_unix_ms":now_ms() + 1000,"background":true
        }))
        .unwrap();
        let error = state
            .start_wait_scoped(wait, "closed", Some(closed))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("connection is closed"));
        assert!(state.lock().watches.is_empty());
        assert_eq!(
            state
                .wait_history(&HistoryInput::default(), "closed")
                .unwrap()
                .retained,
            0
        );
    }

    #[tokio::test]
    async fn an_old_epoch_cannot_satisfy_a_wait_with_an_incomparable_event_id() {
        let state = Arc::new(ObservationState::new(false));
        let sink = synthetic(&state, Lifetime::Connection, 10, 4096);
        sink.emit("fixture.match", TargetIdentity::default(), json!({}), None);
        let mut input = wait_input(&state, &sink, Lifetime::Connection, "fixture.match");
        input.after = Some(Cursor {
            epoch: "another-host".into(),
            id: 10000,
        });
        let wait = state.start_wait(input, "first").await.unwrap();
        let wait = state
            .await_wait(&wait.id, "first", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(wait.outcome, Outcome::Failed);
        assert!(wait.error.unwrap().contains("epoch changed"));
        sink.finish(Ok(()));
        state.shutdown().await;
    }
}
