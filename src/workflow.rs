use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, ensure, Context};
use rmcp::{
    handler::server::{tool::ToolCallContext, wrapper::Parameters},
    model::{CallToolRequestParams, CallToolResult},
    schemars,
    service::RequestContext,
    tool, tool_router, ErrorData, RoleServer,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::watch;

use crate::observation::{
    now_ms, request_canceled, tool_result, visible, Cancellation, CheckpointStore,
    CheckpointWorker, Cursor, EventFilter, HistoryInput, HistoryPage, IdInput, Lifetime,
    ObservationState, Outcome, WaitInput, MAX_DURATION_MS,
};

const MAX_STEPS: usize = 32;
const MAX_WORKFLOWS: usize = 64;
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    Action {
        tool: String,
        /// JSON object. A value {"$step":"name","pointer":"/data/field"} binds a
        /// result from an earlier step. This is data substitution, not code.
        #[serde(default)]
        arguments: Map<String, Value>,
    },
    Wait {
        /// EventFilter object, with the same explicit result bindings as action arguments.
        #[serde(default)]
        filter: Map<String, Value>,
        /// Defaults to the workflow's starting observation cursor.
        after: Option<Cursor>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Step {
    pub name: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub timeout_ms: u64,
    /// Continue with the next declared step after a failed/timed-out step, for
    /// example to capture a dialog and collect evidence. No retry occurs.
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(flatten)]
    pub operation: Operation,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct StartInput {
    pub name: String,
    #[serde(default)]
    pub lifetime: Lifetime,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub timeout_ms: u64,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StepResult {
    pub name: String,
    pub outcome: Outcome,
    pub started_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub action_may_have_completed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkflowRecord {
    pub id: String,
    pub epoch: String,
    pub owner: String,
    pub input: StartInput,
    pub outcome: Outcome,
    pub started_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    pub start_cursor: Cursor,
    pub steps: Vec<StepResult>,
    pub error: Option<String>,
    pub cancellation_requested: bool,
    pub replayed: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct WorkflowSnapshot {
    version: u32,
    epoch: String,
    records: Vec<WorkflowRecord>,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitWorkflowInput {
    pub id: String,
    /// Deadline for this retrieval call only; the workflow's deadline is unchanged.
    #[serde(deserialize_with = "crate::coerce::num")]
    pub deadline_unix_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct WaitWorkflowResult {
    pub outcome: Outcome,
    pub workflow: WorkflowRecord,
}

#[derive(Debug, Serialize)]
pub struct WorkflowSummary {
    pub id: String,
    pub name: String,
    pub lifetime: Lifetime,
    pub outcome: Outcome,
    pub started_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    pub declared_steps: usize,
    pub recorded_steps: usize,
}

type ActionFuture = Pin<Box<dyn Future<Output = anyhow::Result<CallToolResult>> + Send>>;
type CleanupFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

pub trait ActionDispatcher: Send + Sync {
    fn has_tool(&self, name: &str) -> bool;
    fn dispatch(&self, name: String, arguments: Map<String, Value>) -> ActionFuture;
    fn connection_id(&self) -> Option<&str> {
        None
    }
    fn connection_cancellation(&self) -> Option<tokio_util::sync::CancellationToken> {
        None
    }
    fn finish(&self) -> CleanupFuture {
        Box::pin(async { Ok(()) })
    }
}

struct RouterDispatcher {
    server: crate::server::MasterControlProgram,
    context: RequestContext<RoleServer>,
    owns_connection: bool,
    closed: Arc<AtomicBool>,
}

struct CancelRequestOnDrop(RequestContext<RoleServer>);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.ct.cancel();
    }
}

impl ActionDispatcher for RouterDispatcher {
    fn has_tool(&self, name: &str) -> bool {
        self.server.tool_router.has_route(name)
    }

    fn connection_id(&self) -> Option<&str> {
        Some(&self.server.execution_connection)
    }

    fn connection_cancellation(&self) -> Option<tokio_util::sync::CancellationToken> {
        Some(self.server.execution_connection_cancel.clone())
    }

    fn finish(&self) -> CleanupFuture {
        let server = self.server.clone();
        let closed = self.closed.clone();
        let owns_connection = self.owns_connection;
        Box::pin(async move {
            if owns_connection && !closed.swap(true, Ordering::AcqRel) {
                server.shutdown_connection().await?;
            }
            Ok(())
        })
    }

    fn dispatch(&self, name: String, arguments: Map<String, Value>) -> ActionFuture {
        let server = self.server.clone();
        let mut context = self.context.clone();
        // An explicit persistent workflow belongs to the host, not to the
        // workflow_start request's cancellation token or former peer.
        context.ct = server.execution_connection_cancel.child_token();
        Box::pin(async move {
            ensure!(
                !context.ct.is_cancelled(),
                "workflow action connection is closed"
            );
            let _cancel = CancelRequestOnDrop(context.clone());
            let mut request = CallToolRequestParams::new(name);
            request.arguments = Some(arguments);
            server
                .tool_router
                .call(ToolCallContext::new(&server, request, context))
                .await
                .map_err(|error| anyhow!("{error}"))
        })
    }
}

impl Drop for RouterDispatcher {
    fn drop(&mut self) {
        if self.owns_connection && !self.closed.load(Ordering::Acquire) {
            let cleanup = self.finish();
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    runtime.spawn(async move {
                        if let Err(error) = cleanup.await {
                            tracing::error!(%error, "cleaning up interrupted workflow scope");
                        }
                    });
                }
                Err(error) => {
                    tracing::error!(%error, "workflow scope dropped after host runtime shutdown")
                }
            }
        }
    }
}

struct StepContext<'a> {
    record: &'a WorkflowRecord,
    previous: &'a BTreeMap<String, Value>,
    observations: &'a Arc<ObservationState>,
    dispatcher: &'a dyn ActionDispatcher,
    deadline: u64,
    cancellation: &'a Cancellation,
}

struct Store {
    records: BTreeMap<String, WorkflowRecord>,
    cancellations: BTreeMap<String, Cancellation>,
    retired: BTreeSet<String>,
}

pub struct WorkflowState {
    epoch: String,
    persistent_enabled: bool,
    store: Mutex<Store>,
    changed: watch::Sender<u64>,
    checkpoint: Option<Arc<dyn CheckpointStore>>,
    checkpoint_serial: Mutex<()>,
    checkpoint_worker: CheckpointWorker,
    persistence_error: Mutex<Option<String>>,
}

impl WorkflowState {
    pub fn new(persistent_enabled: bool) -> Self {
        Self {
            epoch: uuid::Uuid::new_v4().to_string(),
            persistent_enabled,
            store: Mutex::new(Store {
                records: BTreeMap::new(),
                cancellations: BTreeMap::new(),
                retired: BTreeSet::new(),
            }),
            changed: watch::channel(0).0,
            checkpoint: None,
            checkpoint_serial: Mutex::new(()),
            checkpoint_worker: CheckpointWorker::default(),
            persistence_error: Mutex::new(None),
        }
    }

    pub fn open(checkpoint: Arc<dyn CheckpointStore>) -> anyhow::Result<Arc<Self>> {
        let runtime = tokio::runtime::Handle::try_current()
            .context("workflow persistence requires the host runtime")?;
        let mut state =
            match checkpoint.read_checkpoint("workflows.json", MAX_STATE_BYTES + 1024 * 1024)? {
                Some(bytes) => Self::restore(
                    serde_json::from_slice(&bytes).context("invalid workflow checkpoint")?,
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
            .expect("workflow checkpoint lock poisoned");
        checkpoint
            .write_checkpoint("workflows.json", &serde_json::to_vec(&self.snapshot())?)
            .context("writing workflow checkpoint")
    }

    async fn flush(self: &Arc<Self>) -> anyhow::Result<()> {
        if self.checkpoint.is_none() {
            return Ok(());
        }
        let state = self.clone();
        tokio::task::spawn_blocking(move || state.persist_now())
            .await
            .context("workflow checkpoint worker failed")?
    }

    fn checkpoint_failed(&self, error: String) {
        tracing::error!(%error, "workflow persistence failed");
        *self
            .persistence_error
            .lock()
            .expect("workflow persistence error lock poisoned") = Some(error.clone());
        let mut store = self.store.lock().expect("workflow store poisoned");
        let ids: Vec<_> = store
            .records
            .values()
            .filter(|record| {
                record.input.lifetime == Lifetime::Persistent && record.outcome == Outcome::Running
            })
            .map(|record| record.id.clone())
            .collect();
        for id in ids {
            if let Some(record) = store.records.get_mut(&id) {
                record.error = Some(format!("persistence failed: {error}"));
            }
            if let Some(cancellation) = store.cancellations.get(&id) {
                cancellation.cancel();
            }
        }
        drop(store);
        self.notify();
    }

    fn notify(&self) {
        self.changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn start(
        self: &Arc<Self>,
        input: StartInput,
        owner: &str,
        observations: Arc<ObservationState>,
        dispatcher: Arc<dyn ActionDispatcher>,
    ) -> anyhow::Result<WorkflowRecord> {
        ensure!(
            input.lifetime != Lifetime::Persistent || self.persistent_enabled,
            "persistent workflows require an explicitly started local resident host"
        );
        validate(&input, dispatcher.as_ref())?;
        if input.lifetime == Lifetime::Persistent {
            if let Some(error) = &*self
                .persistence_error
                .lock()
                .expect("workflow persistence error lock poisoned")
            {
                return Err(anyhow!(
                    "persistent workflows unavailable after checkpoint failure: {error}"
                ));
            }
        }
        let now = now_ms();
        let record = WorkflowRecord {
            id: uuid::Uuid::new_v4().to_string(),
            epoch: self.epoch.clone(),
            owner: owner.into(),
            input: input.clone(),
            outcome: Outcome::Running,
            started_at_unix_ms: now,
            deadline_unix_ms: now + input.timeout_ms,
            finished_at_unix_ms: None,
            start_cursor: observations.cursor(),
            steps: Vec::new(),
            error: None,
            cancellation_requested: false,
            replayed: false,
        };
        let cancellation = Cancellation::default();
        {
            let mut store = self.store.lock().expect("workflow store poisoned");
            ensure!(
                dispatcher
                    .connection_cancellation()
                    .is_none_or(|cancel| !cancel.is_cancelled()),
                "workflow connection is closed"
            );
            ensure!(store.records.len() < MAX_WORKFLOWS, "retained workflow limit reached; forget terminal workflows using workflow_cancel forget=true");
            ensure!(
                store.cancellations.len() < 16,
                "active workflow limit reached"
            );
            let bytes =
                serde_json::to_vec(&store.records)?.len() + serde_json::to_vec(&record)?.len();
            ensure!(
                bytes <= MAX_STATE_BYTES,
                "workflow state byte limit reached"
            );
            store.records.insert(record.id.clone(), record.clone());
            store
                .cancellations
                .insert(record.id.clone(), cancellation.clone());
        }
        self.notify();
        let state = self.clone();
        let running = record.clone();
        tokio::spawn(async move {
            let (outcome, error) = state
                .execute(
                    running.clone(),
                    observations,
                    dispatcher.clone(),
                    cancellation,
                )
                .await;
            match dispatcher.finish().await {
                Ok(()) => state.finish(&running.id, outcome, error),
                Err(cleanup) => state.finish(
                    &running.id, Outcome::Failed,
                    Some(format!("workflow scope cleanup failed: {cleanup:#}; prior outcome: {outcome:?}; prior error: {error:?}")),
                ),
            }
        });
        Ok(record)
    }

    async fn execute(
        self: &Arc<Self>,
        record: WorkflowRecord,
        observations: Arc<ObservationState>,
        dispatcher: Arc<dyn ActionDispatcher>,
        cancellation: Cancellation,
    ) -> (Outcome, Option<String>) {
        let overall_deadline = tokio::time::Instant::now()
            + Duration::from_millis(record.deadline_unix_ms.saturating_sub(now_ms()));
        let connection_cancel = dispatcher.connection_cancellation().unwrap_or_default();
        let mut previous = BTreeMap::new();
        let mut had_failure = false;
        for step in &record.input.steps {
            if cancellation.is_canceled() || connection_cancel.is_cancelled() {
                return (Outcome::Canceled, None);
            }
            if tokio::time::Instant::now() >= overall_deadline {
                return (
                    Outcome::TimedOut,
                    Some("workflow deadline elapsed before next action".into()),
                );
            }
            let started = now_ms();
            let deadline_unix_ms = started
                .saturating_add(step.timeout_ms)
                .min(record.deadline_unix_ms);
            let deadline = (tokio::time::Instant::now() + Duration::from_millis(step.timeout_ms))
                .min(overall_deadline);
            let action = matches!(step.operation, Operation::Action { .. });
            let mut result = StepResult {
                name: step.name.clone(),
                outcome: Outcome::Running,
                started_at_unix_ms: started,
                deadline_unix_ms,
                finished_at_unix_ms: None,
                result: None,
                error: None,
                action_may_have_completed: false,
            };
            self.put_step(&record.id, result.clone());
            let operation = self.execute_step(
                step,
                StepContext {
                    record: &record,
                    previous: &previous,
                    observations: &observations,
                    dispatcher: dispatcher.as_ref(),
                    deadline: deadline_unix_ms,
                    cancellation: &cancellation,
                },
            );
            let output = tokio::select! {
                biased;
                _ = cancellation.canceled() => {
                    result.outcome = Outcome::Canceled;
                    result.action_may_have_completed = action;
                    None
                }
                _ = connection_cancel.cancelled() => {
                    result.outcome = Outcome::Canceled;
                    result.action_may_have_completed = action;
                    None
                }
                _ = tokio::time::sleep_until(deadline) => {
                    result.outcome = Outcome::TimedOut;
                    result.error = Some("step deadline elapsed; action is not retried and may still finish in a native provider".into());
                    result.action_may_have_completed = action;
                    None
                }
                output = operation => Some(output)
            };
            if let Some(output) = output {
                match output {
                    Ok((outcome, value)) => {
                        result.outcome = outcome;
                        let bytes = serde_json::to_vec(&value).map(|bytes| bytes.len());
                        let size_error = match bytes {
                            Ok(size) if size <= MAX_RESULT_BYTES => None,
                            Ok(_) => Some("step output exceeds 8 MiB result limit".to_string()),
                            Err(error) => Some(format!("serializing step output: {error}")),
                        };
                        if let Some(error) = size_error {
                            result.outcome = Outcome::Failed;
                            result.error = Some(error);
                            result.action_may_have_completed = action;
                        } else {
                            result.result = Some(value);
                        }
                    }
                    Err(error) => {
                        result.outcome = Outcome::Failed;
                        result.error = Some(format!("{error:#}"));
                        result.action_may_have_completed = action;
                    }
                }
            }
            result.finished_at_unix_ms = Some(now_ms());
            if let Err(error) = self.put_result(&record.id, result.clone()) {
                result.outcome = Outcome::Failed;
                result.result = None;
                result.error = Some(format!("{error:#}"));
                result.action_may_have_completed = action;
                self.put_step(&record.id, result.clone());
            }
            if let Some(value) = &result.result {
                previous.insert(step.name.clone(), value.clone());
            }
            if result.outcome == Outcome::Canceled {
                return (Outcome::Canceled, result.error);
            }
            if result.outcome != Outcome::Satisfied {
                had_failure = true;
                if !step.continue_on_error {
                    return (
                        result.outcome,
                        result.error.or_else(|| {
                            Some(format!("step {} did not satisfy its outcome", step.name))
                        }),
                    );
                }
            }
        }
        (if had_failure { Outcome::Failed } else { Outcome::Satisfied },
            had_failure.then(|| "one or more steps failed; declared evidence-collection steps continued without retries".into()))
    }

    async fn execute_step(
        self: &Arc<Self>,
        step: &Step,
        context: StepContext<'_>,
    ) -> anyhow::Result<(Outcome, Value)> {
        let StepContext {
            record,
            previous,
            observations,
            dispatcher,
            deadline,
            cancellation,
        } = context;
        match &step.operation {
            Operation::Action { tool, arguments } => {
                let resolved = resolve(&Value::Object(arguments.clone()), previous, 0)?;
                let arguments = resolved
                    .as_object()
                    .context("action arguments must resolve to an object")?
                    .clone();
                if record.input.lifetime == Lifetime::Persistent {
                    // A crash after this marker makes the step incomplete on
                    // recovery. No state loader dispatches an action.
                    self.flush().await?;
                }
                ensure!(
                    !cancellation.is_canceled(),
                    "workflow canceled before action dispatch"
                );
                let result = dispatcher.dispatch(tool.clone(), arguments).await?;
                let value = normalize(&result);
                let outcome = if result.is_error == Some(true) {
                    Outcome::Failed
                } else {
                    match value
                        .get("data")
                        .and_then(|value| value.get("outcome"))
                        .and_then(Value::as_str)
                    {
                        Some("failed") => Outcome::Failed,
                        Some("timed_out") => Outcome::TimedOut,
                        Some("canceled") => Outcome::Canceled,
                        _ => Outcome::Satisfied,
                    }
                };
                Ok((outcome, value))
            }
            Operation::Wait { filter, after } => {
                let (owner, lifetime) = match dispatcher.connection_id() {
                    // Persistent router workflows already own a separate connection.
                    Some(owner) => (owner, Lifetime::Connection),
                    None => (record.owner.as_str(), record.input.lifetime),
                };
                let filter: EventFilter =
                    serde_json::from_value(resolve(&Value::Object(filter.clone()), previous, 0)?)
                        .context("invalid workflow event filter")?;
                let wait = observations
                    .start_wait_scoped(
                        WaitInput {
                            lifetime,
                            filter,
                            after: after.clone().or_else(|| Some(record.start_cursor.clone())),
                            deadline_unix_ms: deadline,
                            background: true,
                        },
                        owner,
                        dispatcher.connection_cancellation(),
                    )
                    .await?;
                let mut guard = WaitGuard {
                    observations: observations.clone(),
                    id: wait.id.clone(),
                    owner: owner.to_owned(),
                    finished: false,
                };
                let result = observations
                    .await_wait(&wait.id, owner, cancellation)
                    .await?;
                guard.finished = true;
                observations.cancel_wait(&wait.id, owner, true)?;
                Ok((result.outcome, json!({"data":result})))
            }
        }
    }

    fn put_step(&self, id: &str, result: StepResult) {
        let mut store = self.store.lock().expect("workflow store poisoned");
        if let Some(record) = store.records.get_mut(id) {
            if let Some(previous) = record
                .steps
                .iter_mut()
                .find(|previous| previous.name == result.name)
            {
                *previous = result;
            } else {
                record.steps.push(result);
            }
        }
        drop(store);
        self.notify();
    }

    fn put_result(&self, id: &str, result: StepResult) -> anyhow::Result<()> {
        let mut store = self.store.lock().expect("workflow store poisoned");
        let current_size = serde_json::to_vec(&store.records)?.len();
        let additional = serde_json::to_vec(&result)?.len();
        ensure!(
            current_size + additional <= MAX_STATE_BYTES,
            "retained workflow state exceeds 32 MiB; action is not replayed"
        );
        let record = store
            .records
            .get_mut(id)
            .context("workflow disappeared while running")?;
        let previous = record
            .steps
            .iter_mut()
            .find(|previous| previous.name == result.name)
            .context("workflow step disappeared while running")?;
        *previous = result;
        drop(store);
        self.notify();
        Ok(())
    }

    fn finish(&self, id: &str, outcome: Outcome, error: Option<String>) {
        let persistence_error = self
            .persistence_error
            .lock()
            .expect("workflow persistence error lock poisoned")
            .clone();
        let mut store = self.store.lock().expect("workflow store poisoned");
        if let Some(record) = store.records.get_mut(id) {
            if record.outcome == Outcome::Running {
                record.outcome = if record.input.lifetime == Lifetime::Persistent
                    && persistence_error.is_some()
                {
                    Outcome::Failed
                } else {
                    outcome
                };
                record.finished_at_unix_ms = Some(now_ms());
                if let Some(error) = error {
                    record.error = Some(error);
                }
                if record.input.lifetime == Lifetime::Persistent {
                    if let Some(error) = persistence_error {
                        record.error = Some(format!("persistence failed: {error}"));
                    }
                }
            }
        }
        store.cancellations.remove(id);
        if store.retired.remove(id) {
            store.records.remove(id);
        }
        drop(store);
        self.notify();
    }

    pub fn status(&self, id: &str, owner: &str) -> anyhow::Result<WorkflowRecord> {
        self.store
            .lock()
            .expect("workflow store poisoned")
            .records
            .get(id)
            .filter(|record| visible(&record.owner, record.input.lifetime, owner))
            .cloned()
            .ok_or_else(|| anyhow!("workflow not found in this connection"))
    }

    pub fn cancel(&self, id: &str, owner: &str, forget: bool) -> anyhow::Result<WorkflowRecord> {
        self.status(id, owner)?;
        let mut store = self.store.lock().expect("workflow store poisoned");
        if let Some(cancellation) = store.cancellations.get(id) {
            cancellation.cancel();
        }
        let record = store.records.get_mut(id).context("workflow not found")?;
        if record.outcome == Outcome::Running {
            record.cancellation_requested = true;
        }
        let record = record.clone();
        if forget {
            ensure!(
                record.outcome != Outcome::Running,
                "cancel requested; await terminal workflow before forgetting"
            );
            store.records.remove(id);
        }
        drop(store);
        self.notify();
        Ok(record)
    }

    pub async fn wait(
        &self,
        id: &str,
        owner: &str,
        deadline_unix_ms: u64,
        cancel: &Cancellation,
    ) -> anyhow::Result<WaitWorkflowResult> {
        ensure!(
            deadline_unix_ms.saturating_sub(now_ms()) <= MAX_DURATION_MS,
            "wait deadline exceeds 24 hours"
        );
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(deadline_unix_ms.saturating_sub(now_ms()));
        loop {
            let mut changes = self.changes();
            let record = self.status(id, owner)?;
            if record.outcome != Outcome::Running {
                return Ok(WaitWorkflowResult {
                    outcome: Outcome::Satisfied,
                    workflow: record,
                });
            }
            tokio::select! {
                _ = cancel.canceled() => return Ok(WaitWorkflowResult { outcome: Outcome::Canceled, workflow: self.status(id, owner)? }),
                _ = tokio::time::sleep_until(deadline) => return Ok(WaitWorkflowResult { outcome: Outcome::TimedOut, workflow: self.status(id, owner)? }),
                _ = changes.changed() => {}
            }
        }
    }

    pub fn history(
        &self,
        input: &HistoryInput,
        owner: &str,
    ) -> anyhow::Result<HistoryPage<WorkflowSummary>> {
        let limit = input.limit.unwrap_or(20);
        ensure!(
            (1..=MAX_WORKFLOWS).contains(&limit),
            "workflow history limit must be 1 to {MAX_WORKFLOWS}"
        );
        let store = self.store.lock().expect("workflow store poisoned");
        let mut records: Vec<_> = store
            .records
            .values()
            .filter(|record| visible(&record.owner, record.input.lifetime, owner))
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse((record.started_at_unix_ms, &record.id)));
        Ok(HistoryPage {
            retained: records.len(),
            records: records
                .into_iter()
                .take(limit)
                .map(|record| WorkflowSummary {
                    id: record.id.clone(),
                    name: record.input.name.clone(),
                    lifetime: record.input.lifetime,
                    outcome: record.outcome,
                    started_at_unix_ms: record.started_at_unix_ms,
                    deadline_unix_ms: record.deadline_unix_ms,
                    finished_at_unix_ms: record.finished_at_unix_ms,
                    declared_steps: record.input.steps.len(),
                    recorded_steps: record.steps.len(),
                })
                .collect(),
        })
    }

    pub fn shutdown_connection(&self, owner: &str) {
        let mut store = self.store.lock().expect("workflow store poisoned");
        let ids: Vec<_> = store
            .records
            .values()
            .filter(|record| record.owner == owner && record.input.lifetime == Lifetime::Connection)
            .map(|record| record.id.clone())
            .collect();
        for id in ids {
            if let Some(cancellation) = store.cancellations.get(&id) {
                cancellation.cancel();
                store.retired.insert(id);
            } else {
                store.records.remove(&id);
            }
        }
        drop(store);
        self.notify();
    }

    pub async fn shutdown(self: &Arc<Self>) {
        {
            let store = self.store.lock().expect("workflow store poisoned");
            for cancellation in store.cancellations.values() {
                cancellation.cancel();
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let mut changes = self.changes();
            if self
                .store
                .lock()
                .expect("workflow store poisoned")
                .cancellations
                .is_empty()
            {
                break;
            }
            if tokio::time::timeout_at(deadline, changes.changed())
                .await
                .is_err()
            {
                tracing::error!("workflow cancellation did not finish within 5 seconds");
                break;
            }
        }
        if let Err(error) = self.checkpoint_worker.shutdown().await {
            self.checkpoint_failed(format!("{error:#}"));
        }
        if let Err(error) = self.flush().await {
            self.checkpoint_failed(format!("{error:#}"));
        }
    }

    pub fn snapshot(&self) -> WorkflowSnapshot {
        WorkflowSnapshot {
            version: 1,
            epoch: self.epoch.clone(),
            records: self
                .store
                .lock()
                .expect("workflow store poisoned")
                .records
                .values()
                .filter(|record| record.input.lifetime == Lifetime::Persistent)
                .cloned()
                .collect(),
        }
    }

    pub fn restore(snapshot: WorkflowSnapshot) -> anyhow::Result<Self> {
        ensure!(
            snapshot.version == 1,
            "unsupported workflow checkpoint version"
        );
        ensure!(
            snapshot.records.len() <= MAX_WORKFLOWS
                && serde_json::to_vec(&snapshot)?.len() <= MAX_STATE_BYTES,
            "workflow checkpoint exceeds retention limits"
        );
        let state = Self::new(true);
        let mut store = state.store.lock().expect("workflow store poisoned");
        for mut record in snapshot.records {
            ensure!(
                record.input.lifetime == Lifetime::Persistent,
                "checkpoint contains a connection-owned workflow"
            );
            if record.outcome == Outcome::Running {
                record.outcome = Outcome::Failed;
                record.finished_at_unix_ms = Some(now_ms());
                record.error = Some(format!(
                    "host restarted after epoch {}; workflow interrupted and no action replayed",
                    snapshot.epoch
                ));
                for step in &mut record.steps {
                    if step.outcome == Outcome::Running {
                        step.outcome = Outcome::Failed;
                        step.finished_at_unix_ms = Some(now_ms());
                        step.action_may_have_completed = true;
                        step.error = Some(
                            "host restarted during step; application side effects are unknown"
                                .into(),
                        );
                    }
                }
            }
            store.records.insert(record.id.clone(), record);
        }
        drop(store);
        Ok(state)
    }
}

impl Drop for WorkflowState {
    fn drop(&mut self) {
        let store = self.store.get_mut().expect("workflow store poisoned");
        for cancellation in store.cancellations.values() {
            cancellation.cancel();
        }
    }
}

struct WaitGuard {
    observations: Arc<ObservationState>,
    id: String,
    owner: String,
    finished: bool,
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        if !self.finished {
            if let Err(error) = self.observations.cancel_wait(&self.id, &self.owner, false) {
                tracing::error!(%error, "canceling interrupted workflow wait");
            }
        }
    }
}

fn validate(input: &StartInput, dispatcher: &dyn ActionDispatcher) -> anyhow::Result<()> {
    ensure!(
        !input.name.is_empty() && input.name.len() <= 128,
        "workflow name must be 1 to 128 bytes"
    );
    ensure!(
        (1..=MAX_DURATION_MS).contains(&input.timeout_ms),
        "workflow timeout_ms must be 1 to {MAX_DURATION_MS}"
    );
    ensure!(
        !input.steps.is_empty() && input.steps.len() <= MAX_STEPS,
        "workflow must have 1 to {MAX_STEPS} steps"
    );
    ensure!(
        serde_json::to_vec(input)?.len() <= 256 * 1024,
        "workflow definition exceeds 256 KiB"
    );
    let mut names = BTreeSet::new();
    for step in &input.steps {
        ensure!(
            !step.name.is_empty() && step.name.len() <= 64,
            "step name must be 1 to 64 bytes"
        );
        ensure!(
            (1..=MAX_DURATION_MS).contains(&step.timeout_ms),
            "invalid step timeout_ms"
        );
        let arguments = match &step.operation {
            Operation::Action { tool, arguments } => {
                ensure!(
                    !tool.starts_with("workflow_"),
                    "recursive workflow actions are not supported"
                );
                ensure!(
                    dispatcher.has_tool(tool),
                    "unknown action tool {tool}; no step was executed"
                );
                arguments
            }
            Operation::Wait { filter, .. } => filter,
        };
        validate_bindings(&Value::Object(arguments.clone()), &names, 0)?;
        ensure!(
            names.insert(step.name.clone()),
            "duplicate step name {}",
            step.name
        );
    }
    Ok(())
}

fn validate_bindings(
    value: &Value,
    previous: &BTreeSet<String>,
    depth: usize,
) -> anyhow::Result<()> {
    ensure!(depth <= 32, "workflow argument nesting exceeds 32 levels");
    match value {
        Value::Object(object) if object.contains_key("$step") => {
            ensure!(
                object.len() == 2,
                "step binding must contain exactly $step and pointer"
            );
            let step = object
                .get("$step")
                .and_then(Value::as_str)
                .context("$step must be a name")?;
            ensure!(
                previous.contains(step),
                "binding references unknown, future or current step {step}"
            );
            let pointer = object
                .get("pointer")
                .and_then(Value::as_str)
                .context("binding pointer must be a JSON pointer string")?;
            ensure!(
                pointer.is_empty() || pointer.starts_with('/'),
                "binding pointer must be a JSON pointer"
            );
        }
        Value::Object(object) => {
            for value in object.values() {
                validate_bindings(value, previous, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                validate_bindings(value, previous, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve(
    value: &Value,
    previous: &BTreeMap<String, Value>,
    depth: usize,
) -> anyhow::Result<Value> {
    ensure!(depth <= 32, "workflow argument nesting exceeds 32 levels");
    match value {
        Value::Object(object) if object.contains_key("$step") => {
            let name = object
                .get("$step")
                .and_then(Value::as_str)
                .context("$step must be a name")?;
            let pointer = object
                .get("pointer")
                .and_then(Value::as_str)
                .context("binding pointer must be a string")?;
            previous
                .get(name)
                .and_then(|value| value.pointer(pointer))
                .cloned()
                .ok_or_else(|| {
                    anyhow!("step result {name}{pointer} is unavailable; action was not executed")
                })
        }
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| {
                resolve(value, previous, depth + 1).map(|value| (key.clone(), value))
            })
            .collect::<anyhow::Result<Map<_, _>>>()
            .map(Value::Object),
        Value::Array(array) => array
            .iter()
            .map(|value| resolve(value, previous, depth + 1))
            .collect::<anyhow::Result<Vec<_>>>()
            .map(Value::Array),
        value => Ok(value.clone()),
    }
}

fn normalize(result: &CallToolResult) -> Value {
    let data = result.structured_content.clone().unwrap_or_else(|| {
        let texts: Vec<_> = result
            .content
            .iter()
            .filter_map(|content| content.as_text().map(|text| text.text.as_str()))
            .collect();
        if texts.len() == 1 {
            serde_json::from_str(texts[0]).unwrap_or_else(|_| Value::String(texts[0].into()))
        } else {
            json!(texts)
        }
    });
    json!({"data":data, "tool_result":result})
}

mod tools;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use rmcp::model::Content;

    use super::*;
    use crate::observation::test_support::MemoryCheckpoint;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
    use tokio::net::windows::named_pipe::NamedPipeClient;

    struct McpPeer {
        reader: BufReader<ReadHalf<NamedPipeClient>>,
        writer: WriteHalf<NamedPipeClient>,
        next_id: u64,
    }

    impl McpPeer {
        async fn connect(name: &str) -> Self {
            let pipe = crate::host::connect(name.into()).await.unwrap();
            let (reader, writer) = tokio::io::split(pipe);
            let mut peer = Self {
                reader: BufReader::new(reader),
                writer,
                next_id: 1,
            };
            peer.request(
                "initialize",
                json!({
                    "protocolVersion":"2025-03-26","capabilities":{},
                    "clientInfo":{"name":"workflow-fixture","version":"1"}
                }),
            )
            .await;
            peer.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .await;
            peer
        }

        async fn send(&mut self, value: Value) {
            let mut bytes = serde_json::to_vec(&value).unwrap();
            bytes.push(b'\n');
            self.writer.write_all(&bytes).await.unwrap();
            self.writer.flush().await.unwrap();
        }

        async fn start_request(&mut self, method: &str, params: Value) -> u64 {
            let id = self.next_id;
            self.next_id += 1;
            self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
                .await;
            id
        }

        async fn request(&mut self, method: &str, params: Value) -> Value {
            let id = self.start_request(method, params).await;
            loop {
                let mut line = String::new();
                let bytes =
                    tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
                        .await
                        .unwrap()
                        .unwrap();
                assert!(bytes > 0, "MCP fixture disconnected");
                let value: Value = serde_json::from_str(&line).unwrap();
                if value["id"] == id {
                    assert!(value.get("error").is_none(), "{value}");
                    return value["result"].clone();
                }
            }
        }

        async fn tool(&mut self, name: &str, arguments: Value) -> Value {
            let result = self
                .request("tools/call", json!({"name":name,"arguments":arguments}))
                .await;
            assert!(result["isError"] != true, "{name}: {result}");
            if let Some(structured) = result.get("structuredContent") {
                structured.clone()
            } else {
                serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
            }
        }
    }

    type FixtureCalls = Arc<Mutex<Vec<(String, Map<String, Value>)>>>;

    struct FixtureDispatcher {
        calls: FixtureCalls,
        started: watch::Sender<u64>,
        release: watch::Sender<bool>,
        checkpoint: Option<Arc<MemoryCheckpoint>>,
        connection_cancel: Option<tokio_util::sync::CancellationToken>,
        saw_durable_running_marker: Arc<AtomicBool>,
    }

    impl Default for FixtureDispatcher {
        fn default() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                started: watch::channel(0).0,
                release: watch::channel(false).0,
                checkpoint: None,
                connection_cancel: None,
                saw_durable_running_marker: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl ActionDispatcher for FixtureDispatcher {
        fn has_tool(&self, name: &str) -> bool {
            name != "unknown"
        }

        fn connection_cancellation(&self) -> Option<tokio_util::sync::CancellationToken> {
            self.connection_cancel.clone()
        }

        fn dispatch(&self, name: String, arguments: Map<String, Value>) -> ActionFuture {
            let calls = self.calls.clone();
            let started = self.started.clone();
            let mut release = self.release.subscribe();
            let checkpoint = self.checkpoint.clone();
            let marker = self.saw_durable_running_marker.clone();
            Box::pin(async move {
                calls
                    .lock()
                    .unwrap()
                    .push((name.clone(), arguments.clone()));
                started.send_modify(|count| *count += 1);
                if let Some(checkpoint) = checkpoint {
                    let bytes = checkpoint
                        .read_checkpoint("workflows.json", MAX_STATE_BYTES)?
                        .unwrap();
                    let snapshot: WorkflowSnapshot = serde_json::from_slice(&bytes)?;
                    marker.store(
                        snapshot.records.iter().any(|record| {
                            record.steps.iter().any(|step| {
                                step.name == "first" && step.outcome == Outcome::Running
                            })
                        }),
                        Ordering::Release,
                    );
                }
                let data = match name.as_str() {
                    "job_start" => json!({"pid":42,"process_creation_time":"133000000000000001"}),
                    "ui_wait" => {
                        ensure!(arguments["target"]["query"]["pid"] == 42, "wrong bound PID");
                        ensure!(
                            arguments["target"]["query"]["process_created_100ns"]
                                == "133000000000000001",
                            "missing exact process creation identity"
                        );
                        json!({"outcome":"satisfied","window":{"window_ref":"fixture-window"}})
                    }
                    "desktop_snapshot" => {
                        ensure!(
                            arguments["target"]["window_ref"] == "fixture-window",
                            "capture did not bind the owned window"
                        );
                        json!({"snapshot_id":"fixture-capture","failure_dialog_observed":true})
                    }
                    "block" => {
                        release
                            .wait_for(|released| *released)
                            .await
                            .map_err(|_| anyhow!("fixture release closed"))?;
                        json!({"released":true})
                    }
                    "fail" => {
                        return Ok(CallToolResult::error(vec![Content::text(
                            "fixture action failed",
                        )]))
                    }
                    "timeout_result" => json!({"outcome":"timed_out"}),
                    _ => json!({"accepted":true,"arguments":arguments}),
                };
                let mut result =
                    CallToolResult::success(vec![Content::text(serde_json::to_string(&data)?)]);
                result.structured_content = Some(data);
                Ok(result)
            })
        }
    }

    fn input(tool: &str, lifetime: Lifetime) -> StartInput {
        StartInput {
            name: "fixture".into(),
            lifetime,
            timeout_ms: 2000,
            steps: vec![Step {
                name: "first".into(),
                timeout_ms: 1000,
                continue_on_error: false,
                operation: Operation::Action {
                    tool: tool.into(),
                    arguments: Map::new(),
                },
            }],
        }
    }

    async fn finished(state: &WorkflowState, id: &str, owner: &str) -> WorkflowRecord {
        let result = state
            .wait(id, owner, now_ms() + 3000, &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(result.outcome, Outcome::Satisfied);
        result.workflow
    }

    #[tokio::test]
    async fn owned_window_workflow_preserves_exact_bindings_and_action_order() {
        let state = Arc::new(WorkflowState::new(false));
        let observations = Arc::new(ObservationState::new(false));
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let input: StartInput = serde_json::from_value(json!({
                "name":"launch failure evidence","timeout_ms":"2000",
                "steps":[
                    {"name":"launch","kind":"action","tool":"job_start",
                     "arguments":{"program":std::env::current_exe().unwrap(),"args":["--help"],"timeout_ms":2000},"timeout_ms":"1000"},
                    {"name":"window","kind":"action","tool":"ui_wait","timeout_ms":1000,
                     "arguments":{"target":{"kind":"window","query":{
                        "pid":{"$step":"launch","pointer":"/data/pid"},
                        "process_created_100ns":{"$step":"launch","pointer":"/data/process_creation_time"}
                     }},"condition":"appear","timeout_ms":"800"}},
                    {"name":"capture","kind":"action","tool":"desktop_snapshot","timeout_ms":1000,
                     "arguments":{"target":{"kind":"window","window_ref":{"$step":"window","pointer":"/data/window/window_ref"}}}},
                    {"name":"process","kind":"action","tool":"process_detail","timeout_ms":1000,
                     "arguments":{"pid":{"$step":"launch","pointer":"/data/pid"}}},
                    {"name":"network","kind":"action","tool":"network_connections","timeout_ms":1000,"arguments":{}}
                ]
            })).unwrap();
        let record = state
            .start(input, "first", observations, dispatcher.clone())
            .unwrap();
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::Satisfied);
        assert_eq!(
            result
                .steps
                .iter()
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>(),
            ["launch", "window", "capture", "process", "network"]
        );
        assert_eq!(
            dispatcher
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>(),
            [
                "job_start",
                "ui_wait",
                "desktop_snapshot",
                "process_detail",
                "network_connections"
            ]
        );
        assert!(result
            .steps
            .iter()
            .all(|step| step.outcome == Outcome::Satisfied));
    }

    #[tokio::test]
    async fn timed_out_actions_are_not_retried_and_later_steps_do_not_run() {
        let state = Arc::new(WorkflowState::new(false));
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let mut input = input("block", Lifetime::Connection);
        input.steps[0].timeout_ms = 20;
        let mut later = input.steps[0].clone();
        later.name = "must_not_run".into();
        later.operation = Operation::Action {
            tool: "mutate".into(),
            arguments: Map::new(),
        };
        input.steps.push(later);
        let record = state
            .start(
                input,
                "first",
                Arc::new(ObservationState::new(false)),
                dispatcher.clone(),
            )
            .unwrap();
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::TimedOut);
        assert_eq!(result.steps.len(), 1);
        assert!(result.steps[0].action_may_have_completed);
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn explicit_cancel_drops_pending_action_and_preserves_ordered_result() {
        let state = Arc::new(WorkflowState::new(false));
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let mut started = dispatcher.started.subscribe();
        let record = state
            .start(
                input("block", Lifetime::Connection),
                "first",
                Arc::new(ObservationState::new(false)),
                dispatcher.clone(),
            )
            .unwrap();
        started.wait_for(|count| *count == 1).await.unwrap();
        assert!(
            state
                .cancel(&record.id, "first", false)
                .unwrap()
                .cancellation_requested
        );
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::Canceled);
        assert_eq!(result.steps[0].outcome, Outcome::Canceled);
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failure_continuation_is_explicit_and_does_not_claim_overall_success() {
        let state = Arc::new(WorkflowState::new(false));
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let mut input = input("fail", Lifetime::Connection);
        input.steps[0].continue_on_error = true;
        let mut evidence = input.steps[0].clone();
        evidence.name = "collect_evidence".into();
        evidence.continue_on_error = false;
        evidence.operation = Operation::Action {
            tool: "network_connections".into(),
            arguments: Map::new(),
        };
        input.steps.push(evidence);
        let record = state
            .start(
                input,
                "first",
                Arc::new(ObservationState::new(false)),
                dispatcher.clone(),
            )
            .unwrap();
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::Failed);
        assert_eq!(result.steps[1].outcome, Outcome::Satisfied);
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn invalid_definitions_fail_before_any_action() {
        let dispatcher = FixtureDispatcher::default();
        assert!(validate(&input("workflow_start", Lifetime::Connection), &dispatcher).is_err());
        assert!(validate(&input("unknown", Lifetime::Connection), &dispatcher).is_err());
        let mut oversized = input("mutate", Lifetime::Connection);
        oversized.steps = vec![oversized.steps[0].clone(); MAX_STEPS + 1];
        assert!(validate(&oversized, &dispatcher).is_err());
        let mut future = input("mutate", Lifetime::Connection);
        future.steps[0].operation = Operation::Action {
            tool: "mutate".into(),
            arguments: Map::from_iter([(
                "pid".into(),
                json!({"$step":"future","pointer":"/data/pid"}),
            )]),
        };
        assert!(validate(&future, &dispatcher).is_err());
        assert!(dispatcher.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_binding_never_dispatches_action() {
        let state = Arc::new(WorkflowState::new(false));
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let mut input = input("job_start", Lifetime::Connection);
        input.steps.push(Step {
            name: "bad-reference".into(),
            timeout_ms: 1000,
            continue_on_error: false,
            operation: Operation::Action {
                tool: "mutate".into(),
                arguments: Map::from_iter([(
                    "target".into(),
                    json!({"$step":"first","pointer":"/data/missing"}),
                )]),
            },
        });
        let record = state
            .start(
                input,
                "first",
                Arc::new(ObservationState::new(false)),
                dispatcher.clone(),
            )
            .unwrap();
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::Failed);
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn persistent_workflow_records_before_mutation_survives_disconnect_and_never_replays() {
        let checkpoint = Arc::new(MemoryCheckpoint::default());
        let state = WorkflowState::open(checkpoint.clone()).unwrap();
        let dispatcher = Arc::new(FixtureDispatcher {
            checkpoint: Some(checkpoint.clone()),
            ..Default::default()
        });
        let mut started = dispatcher.started.subscribe();
        let record = state
            .start(
                input("block", Lifetime::Persistent),
                "first",
                Arc::new(ObservationState::new(true)),
                dispatcher.clone(),
            )
            .unwrap();
        started.wait_for(|count| *count == 1).await.unwrap();
        assert!(dispatcher
            .saw_durable_running_marker
            .load(Ordering::Acquire));
        state.shutdown_connection("first");
        assert_eq!(
            state.status(&record.id, "reconnected").unwrap().outcome,
            Outcome::Running
        );
        state.flush().await.unwrap();
        let interrupted = state.snapshot();
        let recovered = WorkflowState::restore(interrupted).unwrap();
        let record_after_restart = recovered.status(&record.id, "new-host-peer").unwrap();
        assert_eq!(record_after_restart.outcome, Outcome::Failed);
        assert!(record_after_restart.steps[0].action_may_have_completed);
        assert!(!record_after_restart.replayed);
        assert!(recovered.store.lock().unwrap().cancellations.is_empty());
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 1);
        dispatcher.release.send_replace(true);
        assert_eq!(
            finished(&state, &record.id, "reconnected").await.outcome,
            Outcome::Satisfied
        );
        state.shutdown().await;
        let finished_snapshot = checkpoint
            .read_checkpoint("workflows.json", MAX_STATE_BYTES)
            .unwrap()
            .unwrap();
        let restored =
            WorkflowState::restore(serde_json::from_slice(&finished_snapshot).unwrap()).unwrap();
        assert_eq!(
            restored.status(&record.id, "new-peer").unwrap().outcome,
            Outcome::Satisfied
        );
    }

    #[tokio::test]
    async fn failed_checkpoint_prevents_persistent_action_dispatch() {
        let checkpoint = Arc::new(MemoryCheckpoint::default());
        let state = WorkflowState::open(checkpoint.clone()).unwrap();
        checkpoint.fail_writes.store(true, Ordering::Release);
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let record = state
            .start(
                input("mutate", Lifetime::Persistent),
                "first",
                Arc::new(ObservationState::new(true)),
                dispatcher.clone(),
            )
            .unwrap();
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::Failed);
        assert!(dispatcher.calls.lock().unwrap().is_empty());
        assert!(result.error.is_some() || result.steps.iter().any(|step| step.error.is_some()));
    }

    #[tokio::test]
    async fn connection_cleanup_does_not_accumulate_inaccessible_workflow_records() {
        let state = Arc::new(WorkflowState::new(true));
        let dispatcher = Arc::new(FixtureDispatcher::default());
        let record = state
            .start(
                input("job_start", Lifetime::Connection),
                "first",
                Arc::new(ObservationState::new(true)),
                dispatcher,
            )
            .unwrap();
        finished(&state, &record.id, "first").await;
        state.shutdown_connection("first");
        assert!(state.status(&record.id, "first").is_err());
        assert!(state.store.lock().unwrap().records.is_empty());
    }

    #[tokio::test]
    async fn closed_connections_reject_new_workflows_and_cancel_running_steps() {
        let state = Arc::new(WorkflowState::new(false));
        let observations = Arc::new(ObservationState::new(false));
        let canceled = tokio_util::sync::CancellationToken::new();
        canceled.cancel();
        let dispatcher = Arc::new(FixtureDispatcher {
            connection_cancel: Some(canceled),
            ..Default::default()
        });
        assert!(state
            .start(
                input("job_start", Lifetime::Connection),
                "first",
                observations.clone(),
                dispatcher.clone()
            )
            .is_err());
        assert!(dispatcher.calls.lock().unwrap().is_empty());
        assert_eq!(
            state
                .history(&HistoryInput::default(), "first")
                .unwrap()
                .retained,
            0
        );

        let cancel = tokio_util::sync::CancellationToken::new();
        let dispatcher = Arc::new(FixtureDispatcher {
            connection_cancel: Some(cancel.clone()),
            ..Default::default()
        });
        let mut started = dispatcher.started.subscribe();
        let record = state
            .start(
                input("block", Lifetime::Connection),
                "first",
                observations,
                dispatcher.clone(),
            )
            .unwrap();
        started.wait_for(|count| *count == 1).await.unwrap();
        cancel.cancel();
        let result = finished(&state, &record.id, "first").await;
        assert_eq!(result.outcome, Outcome::Canceled);
        assert!(result.steps[0].action_may_have_completed);
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn persistent_named_pipe_workflow_and_pending_waits_survive_disconnect() {
        use crate::observation::test_support::FixtureDirectory;

        let directory = FixtureDirectory::new();
        let watched = directory.path.join("watched");
        std::fs::create_dir(&watched).unwrap();
        let host_name = format!("observation-fixture-{}", uuid::Uuid::new_v4());
        let host =
            crate::host::LocalHost::bind(host_name.clone(), Some(directory.path.join("state")))
                .await
                .unwrap();
        let context = host.context();
        let execution = Arc::new(crate::execution::ExecutionManager::new(context.clone()).unwrap());
        let pool = crate::ps::Pool::new(1).await.unwrap();
        let root = crate::server::MasterControlProgram::new_with_execution(pool, execution.clone())
            .unwrap();
        let host_server = root.clone();
        let host_task = tokio::spawn(async move { host.run(host_server).await });
        let mut first = McpPeer::connect(&host_name).await;
        let failed_trace = first.request("tools/call", json!({
            "name":"trace_start", "arguments":{
                "source":{"kind":"etw","providers":[{"guid":"00000000-0000-0000-0000-000000000000"}]}
            }
        })).await;
        assert_eq!(failed_trace["isError"], true);
        assert_eq!(failed_trace["structuredContent"]["status"], "failed");
        assert!(failed_trace["structuredContent"]["id"].is_string());
        let watch = first
            .tool(
                "watch_create",
                json!({
                    "source":{"kind":"filesystem","path":watched},
                    "lifetime":"persistent","max_duration_ms":15000
                }),
            )
            .await;
        assert_eq!(watch["status"], "recording");
        let mut observation_changes = root.observation.changes();
        for (lifetime, filename) in [("persistent", "release.txt"), ("connection", "never.txt")] {
            first.start_request("tools/call", json!({
                "name":"wait_for", "arguments":{
                    "lifetime":lifetime,"background":false,"deadline_unix_ms":now_ms() + 12000,
                    "filter":{"watch_id":watch["id"],"kind":"filesystem.added","payload_equals":{"relative_path":filename}}
                }
            })).await;
        }
        let waits = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waits = first.tool("wait_list", json!({"limit":"128"})).await;
                if waits["records"].as_array().unwrap().len() == 2 {
                    break waits;
                }
                observation_changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let persistent_wait = waits["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|wait| wait["lifetime"] == "persistent")
            .unwrap()
            .clone();
        let connection_wait = waits["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|wait| wait["lifetime"] == "connection")
            .unwrap()
            .clone();
        let mut workflow_changes = root.workflows.changes();
        first.start_request("tools/call", json!({"name":"workflow_start","arguments":{
            "name":"disconnect-native-job-fixture","lifetime":"persistent","timeout_ms":"10000",
            "steps":[
                {"name":"release","kind":"wait","timeout_ms":8000,
                 "filter":{"watch_id":watch["id"],"kind":"filesystem.added","payload_equals":{"relative_path":"release.txt"}}},
                {"name":"launch","kind":"action","tool":"job_start","timeout_ms":2000,
                 "arguments":{"program":std::env::var("ComSpec").unwrap(),"args":["/d","/c","exit 0"],"timeout_ms":2000}},
                {"name":"exited","kind":"action","tool":"job_wait","timeout_ms":3000,
                 "arguments":{"id":{"$step":"launch","pointer":"/data/id"},"timeout_ms":2500}}
            ]
        }})).await;
        let workflow = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let history = first.tool("workflow_list", json!({})).await;
                if let Some(workflow) = history["records"].as_array().unwrap().first() {
                    break workflow.clone();
                }
                workflow_changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(workflow["id"].is_string());
        first.start_request("tools/call", json!({
            "name":"workflow_wait","arguments":{"id":workflow["id"],"deadline_unix_ms":now_ms() + 12000}
        })).await;
        let memory = first.tool("memory_info", json!({})).await;
        assert!(memory.is_object());
        drop(first);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut changes = root.observation.changes();
                if root
                    .observation
                    .wait_status(
                        connection_wait["id"].as_str().unwrap(),
                        connection_wait["owner"].as_str().unwrap(),
                    )
                    .is_err()
                {
                    break;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            root.workflows
                .status(workflow["id"].as_str().unwrap(), "reconnected")
                .unwrap()
                .outcome,
            Outcome::Running
        );
        let mut second = McpPeer::connect(&host_name).await;
        let retained_waits = second.tool("wait_list", json!({})).await;
        assert_eq!(retained_waits["records"].as_array().unwrap().len(), 1);
        assert_eq!(retained_waits["records"][0]["id"], persistent_wait["id"]);
        assert_eq!(retained_waits["records"][0]["outcome"], "running");
        let retained_workflows = second.tool("workflow_list", json!({"limit":"64"})).await;
        assert_eq!(retained_workflows["records"][0]["id"], workflow["id"]);
        std::fs::write(watched.join("release.txt"), b"owned-fixture").unwrap();
        let result = second
            .tool(
                "workflow_wait",
                json!({
                    "id":workflow["id"],"deadline_unix_ms":now_ms() + 8000
                }),
            )
            .await;
        assert_eq!(result["outcome"], "satisfied", "{result}");
        assert_eq!(result["workflow"]["outcome"], "satisfied", "{result}");
        assert_eq!(
            result["workflow"]["steps"][1]["result"]["data"]["lifetime"],
            "connection"
        );
        assert_eq!(
            result["workflow"]["steps"][2]["result"]["data"]["outcome"], "exited",
            "{result}"
        );
        let wait_result = second
            .tool("wait_status", json!({"id":persistent_wait["id"]}))
            .await;
        assert_eq!(wait_result["outcome"], "satisfied", "{wait_result}");
        second.tool("watch_remove", json!({"id":watch["id"]})).await;
        drop(second);
        execution.shutdown_token().cancel();
        tokio::time::timeout(Duration::from_secs(10), host_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        root.shutdown_connection().await.unwrap();
        root.workflows.shutdown().await;
        root.observation.shutdown().await;
        let recovered = WorkflowState::restore(
            serde_json::from_slice(
                &context
                    .read_checkpoint("workflows.json", MAX_STATE_BYTES)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            recovered
                .status(workflow["id"].as_str().unwrap(), "new-host")
                .unwrap()
                .outcome,
            Outcome::Satisfied
        );
        drop(root);
        drop(execution);
        drop(context);
    }
}
