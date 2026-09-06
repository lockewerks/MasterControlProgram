use ::windows::Win32::Foundation::HANDLE;
use ::windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use ::windows::Win32::System::StationsAndDesktops::*;
use ::windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::time::{Duration, Instant};

mod observation;
pub(crate) mod ocr;
mod router;
pub(crate) mod uia;
pub(crate) mod windows;

use self::windows::{
    WindowActionResult, WindowCatalog, WindowListInput, WindowListResult, WindowManageInput,
    WindowQuery, WindowRecord,
};
use crate::win32::{display, screen};
use observation::{Changes, FrameStore, Retention};
use uia::{
    UiActionResult, UiAutomation, UiElement, UiFindInput, UiFindResult, UiInvokeInput, UiQuery,
    UiSetValueInput, UiTextInput, UiTextResult,
};

const MAX_OPERATION_MS: u64 = 120_000;
const MAX_OPERATIONS: usize = 16;

struct Cancellation {
    canceled: AtomicBool,
    lock: Mutex<()>,
    wake: Condvar,
}

impl Cancellation {
    fn new() -> Self {
        Self {
            canceled: AtomicBool::new(false),
            lock: Mutex::new(()),
            wake: Condvar::new(),
        }
    }

    fn cancel(&self) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Cancellation lock poisoned"))?;
        self.canceled.store(true, Ordering::Release);
        self.wake.notify_all();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WaitOutcome {
    Satisfied,
    TimedOut,
    Canceled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationStopped {
    TimedOut,
    Canceled,
}

impl std::fmt::Display for OperationStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TimedOut => "Desktop operation deadline exceeded",
            Self::Canceled => "Desktop operation canceled",
        })
    }
}

impl std::error::Error for OperationStopped {}

#[derive(Clone)]
pub(crate) struct Operation {
    pub id: String,
    started: Instant,
    deadline: Instant,
    cancellation: Arc<Cancellation>,
    runtime: Option<crate::runtime::OperationContext>,
}

impl Operation {
    pub fn new(timeout_ms: u64) -> Result<Self> {
        Self::with_id(uuid::Uuid::new_v4().to_string(), timeout_ms)
    }

    fn with_id(id: String, timeout_ms: u64) -> Result<Self> {
        if !(1..=MAX_OPERATION_MS).contains(&timeout_ms) {
            bail!("timeout_ms must be in 1..={MAX_OPERATION_MS}");
        }
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        {
            bail!("operation_id must contain 1..=128 ASCII letters, digits, dots, underscores or hyphens");
        }
        let started = Instant::now();
        Ok(Self {
            id,
            started,
            deadline: started + Duration::from_millis(timeout_ms),
            cancellation: Arc::new(Cancellation::new()),
            runtime: crate::runtime::current_context(),
        })
    }

    pub fn check(&self) -> Result<()> {
        if self.is_canceled() {
            return Err(OperationStopped::Canceled.into());
        }
        if Instant::now() >= self.deadline {
            return Err(OperationStopped::TimedOut.into());
        }
        if let Some(runtime) = &self.runtime {
            runtime.checkpoint()?;
        }
        Ok(())
    }

    pub fn remaining(&self) -> Duration {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        match &self.runtime {
            Some(runtime) => remaining.min(runtime.remaining().unwrap_or(Duration::ZERO)),
            None => remaining,
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn is_canceled(&self) -> bool {
        self.cancellation.canceled.load(Ordering::Acquire)
    }

    pub fn wait(&self, duration: Duration) -> Result<()> {
        let end = Instant::now()
            .checked_add(duration)
            .context("Condition wait duration overflow")?;
        let mut guard = self
            .cancellation
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Cancellation lock poisoned"))?;
        loop {
            self.check()?;
            let delay = end.saturating_duration_since(Instant::now());
            if delay.is_zero() {
                return Ok(());
            }
            // Also observe caller cancellation from the shared native runtime.
            let delay = delay.min(self.remaining()).min(Duration::from_millis(25));
            guard = self
                .cancellation
                .wake
                .wait_timeout(guard, delay)
                .map_err(|_| anyhow::anyhow!("Cancellation lock poisoned"))?
                .0;
        }
    }

    pub fn stopped_outcome(&self) -> WaitOutcome {
        if self.is_canceled() {
            WaitOutcome::Canceled
        } else if Instant::now() >= self.deadline {
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Failed
        }
    }
}

#[derive(Default)]
struct Operations(Mutex<HashMap<String, Weak<Cancellation>>>);

impl Operations {
    fn start(&self, id: Option<String>, timeout_ms: u64) -> Result<Operation> {
        let operation = Operation::with_id(
            id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            timeout_ms,
        )?;
        let mut active = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation registry poisoned"))?;
        active.retain(|_, cancellation| cancellation.strong_count() > 0);
        if active.len() >= MAX_OPERATIONS {
            bail!("Desktop operation capacity is full ({MAX_OPERATIONS} active operations)");
        }
        if active.contains_key(&operation.id) {
            bail!("operation_id is already active");
        }
        active.insert(
            operation.id.clone(),
            Arc::downgrade(&operation.cancellation),
        );
        Ok(operation)
    }

    fn cancel(&self, id: &str) -> Result<CancelResult> {
        let active = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation registry poisoned"))?;
        let cancellation = active.get(id).and_then(Weak::upgrade);
        if let Some(cancellation) = &cancellation {
            cancellation.cancel()?;
        }
        Ok(CancelResult {
            operation_id: id.into(),
            cancellation_requested: cancellation.is_some(),
            completed: false,
            note: if cancellation.is_some() {
                "Cancellation was signaled; an action already accepted by Windows may have taken effect."
            } else {
                "No active operation has this ID. Completion is not inferred from absence."
            }.into(),
        })
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CancelInput {
    pub operation_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CancelResult {
    operation_id: String,
    cancellation_requested: bool,
    completed: bool,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionIdentity {
    pub session_id: u32,
    pub desktop: String,
    pub coordinate_space: &'static str,
}

struct InputDesktop(HDESK);

impl Drop for InputDesktop {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseDesktop(self.0) } {
            tracing::warn!(%error, "CloseDesktop failed");
        }
    }
}

fn desktop_name(desktop: HDESK) -> Result<String> {
    let mut name = [0u16; 512];
    let mut required = 0;
    unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            std::mem::size_of_val(&name) as u32,
            Some(&mut required),
        )
        .context("Cannot identify the interactive desktop")?;
    }
    if required == 0 || required as usize > std::mem::size_of_val(&name) {
        bail!("Invalid desktop name length");
    }
    Ok(crate::win32::wchar_to_string(&name))
}

pub(crate) fn require_session(selected: Option<u32>) -> Result<SessionIdentity> {
    let mut session_id = 0;
    unsafe {
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)
            .context("Cannot identify this process session")?;
    }
    if let Some(selected) = selected {
        if selected != session_id {
            bail!("Session {selected} is unsupported by this process in session {session_id}; no desktop action was taken");
        }
    }
    if session_id == 0 {
        bail!("Session 0 cannot control an interactive user desktop");
    }
    let thread_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
        .context("Cannot identify this thread's desktop")?;
    let input = InputDesktop(
        unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }.context(
            "Input desktop is unavailable or restricted; secure desktops are not accessible",
        )?,
    );
    let desktop = desktop_name(thread_desktop)?;
    if desktop != desktop_name(input.0)? {
        bail!("The active input desktop differs from this process desktop; no desktop action was taken");
    }
    Ok(SessionIdentity {
        session_id,
        desktop,
        coordinate_space: "physical_virtual_screen_pixels",
    })
}

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum SnapshotTarget {
    #[default]
    Desktop,
    Monitor {
        #[serde(deserialize_with = "crate::coerce::num")]
        index: u32,
    },
    Window {
        window_ref: String,
    },
    Region {
        #[serde(deserialize_with = "crate::coerce::num")]
        x: i32,
        #[serde(deserialize_with = "crate::coerce::num")]
        y: i32,
        #[serde(deserialize_with = "crate::coerce::num")]
        width: u32,
        #[serde(deserialize_with = "crate::coerce::num")]
        height: u32,
    },
}

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct SnapshotInput {
    pub target: Option<SnapshotTarget>,
    pub image: Option<bool>,
    pub accessibility: Option<bool>,
    pub ocr: Option<bool>,
    pub ocr_language: Option<String>,
    pub baseline_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_depth: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_nodes: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct OcrInput {
    pub target: Option<SnapshotTarget>,
    pub language: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessibilityObservation {
    pub status: &'static str,
    pub result: Option<UiFindResult>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OcrObservation {
    pub status: &'static str,
    pub result: Option<ocr::OcrResult>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct SnapshotResult {
    pub operation_id: String,
    pub snapshot_id: Option<String>,
    pub session: SessionIdentity,
    pub geometry: display::Geometry,
    pub capture: Option<screen::CaptureMetadata>,
    pub accessibility: AccessibilityObservation,
    pub ocr: OcrObservation,
    pub changes: Option<Changes>,
    pub retention: Option<Retention>,
    pub elapsed_ms: u64,
    pub limitations: Vec<String>,
    #[serde(skip)]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WaitTarget {
    Window { query: WindowQuery },
    Control { query: UiQuery },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WaitCondition {
    Appear,
    Disappear,
    Enabled,
    ValueChange,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiWaitInput {
    pub target: WaitTarget,
    pub condition: WaitCondition,
    #[schemars(
        description = "Previous control value or window title. If omitted for value_change, the first observation is the baseline."
    )]
    pub previous_value: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub poll_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UiWaitResult {
    pub operation_id: String,
    pub outcome: WaitOutcome,
    pub window: Option<WindowRecord>,
    pub element: Option<UiElement>,
    pub elapsed_ms: u64,
    pub observations: Option<u32>,
    pub error: Option<String>,
}

pub(crate) struct Desktop {
    windows: Arc<WindowCatalog>,
    automation: UiAutomation,
    operations: Operations,
    frames: Mutex<FrameStore>,
}

impl Desktop {
    pub fn new() -> Self {
        Self {
            windows: Arc::new(WindowCatalog::new()),
            automation: UiAutomation::default(),
            operations: Operations::default(),
            frames: Mutex::new(FrameStore::default()),
        }
    }

    pub fn cancel(&self, input: CancelInput) -> Result<CancelResult> {
        self.operations.cancel(&input.operation_id)
    }

    pub fn window_list(&self, input: WindowListInput) -> Result<WindowListResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(None, input.timeout_ms.unwrap_or(5000))?;
        self.windows.list(&input, &operation)
    }

    pub fn window_manage(&self, input: WindowManageInput) -> Result<WindowActionResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(None, input.timeout_ms.unwrap_or(5000))?;
        self.windows.manage(input, &operation)
    }

    pub fn find(&self, input: UiFindInput) -> Result<UiFindResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(input.operation_id.clone(), input.timeout_ms.unwrap_or(5000))?;
        self.automation
            .find(self.windows.clone(), input, &operation)
    }

    pub fn invoke(&self, input: UiInvokeInput) -> Result<UiActionResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(input.operation_id.clone(), input.timeout_ms.unwrap_or(5000))?;
        self.automation
            .invoke(self.windows.clone(), input, &operation)
    }

    pub fn set_value(&self, input: UiSetValueInput) -> Result<UiActionResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(input.operation_id.clone(), input.timeout_ms.unwrap_or(5000))?;
        self.automation
            .set_value(self.windows.clone(), input, &operation)
    }

    pub fn text(&self, input: UiTextInput) -> Result<UiTextResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(input.operation_id.clone(), input.timeout_ms.unwrap_or(5000))?;
        self.automation
            .text(self.windows.clone(), input, &operation)
    }

    pub fn ocr(&self, input: OcrInput) -> Result<SnapshotResult> {
        self.snapshot(SnapshotInput {
            target: input.target,
            image: Some(false),
            accessibility: Some(false),
            ocr: Some(true),
            ocr_language: input.language,
            timeout_ms: input.timeout_ms,
            operation_id: input.operation_id,
            session_id: input.session_id,
            ..Default::default()
        })
    }

    pub fn snapshot(&self, input: SnapshotInput) -> Result<SnapshotResult> {
        if input
            .baseline_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
        {
            bail!("baseline_id must contain 1..=128 bytes");
        }
        if input.max_depth.is_some_and(|depth| depth > uia::MAX_DEPTH)
            || input
                .max_nodes
                .is_some_and(|nodes| !(1..=uia::MAX_NODES).contains(&nodes))
        {
            bail!("Snapshot accessibility limits: depth 0..=32 and nodes 1..=2048");
        }
        let session = require_session(input.session_id)?;
        let operation = self
            .operations
            .start(input.operation_id, input.timeout_ms.unwrap_or(10_000))?;
        let target = input.target.unwrap_or_default();
        let geometry = display::geometry()?;
        let mut window = None;
        let source = match &target {
            SnapshotTarget::Desktop => screen::CaptureSource::Desktop,
            SnapshotTarget::Monitor { index } => screen::CaptureSource::Monitor(*index),
            SnapshotTarget::Region {
                x,
                y,
                width,
                height,
            } => screen::CaptureSource::Region(display::Rect {
                x: *x,
                y: *y,
                width: *width,
                height: *height,
            }),
            SnapshotTarget::Window { window_ref } => {
                if window_ref.is_empty() || window_ref.len() > 128 {
                    bail!("Invalid window_ref");
                }
                let resolved = self.windows.resolve(window_ref)?;
                window = Some(resolved.clone());
                screen::CaptureSource::Window(resolved)
            }
        };
        let query_bounds = match &source {
            screen::CaptureSource::Desktop => Some(geometry.virtual_screen),
            screen::CaptureSource::Monitor(index) => Some(
                geometry
                    .monitors
                    .iter()
                    .find(|m| m.index == *index)
                    .context("Requested monitor is unavailable")?
                    .bounds,
            ),
            screen::CaptureSource::Region(bounds) => {
                bounds.validate()?;
                Some(*bounds)
            }
            screen::CaptureSource::Window(_) => None,
        };
        let mut result = SnapshotResult {
            operation_id: operation.id.clone(), snapshot_id: None, session, geometry,
            capture: None, accessibility: AccessibilityObservation { status: "not_requested", result: None, error: None },
            ocr: OcrObservation { status: "not_requested", result: None, error: None },
            changes: None, retention: None, elapsed_ms: 0, image: None,
            limitations: vec!["Pixels, accessibility and OCR are observed sequentially, not as an atomic desktop state. UI references belong to this connection and expire; OCR boxes are not native references.".into()],
        };
        if input.image.unwrap_or(true) || input.ocr.unwrap_or(false) || input.baseline_id.is_some()
        {
            let frame = screen::capture_target(source, &operation)?;
            if let Some(window) = &window {
                let current = self.windows.resolve(&window.window_ref)?;
                if current.identity != window.identity
                    || current.bounds != window.bounds
                    || current.minimized
                    || !current.visible
                    || current.cloaked
                {
                    bail!("The window changed identity, position or visibility during capture; no image is being attributed to the old target");
                }
            }
            result.geometry = frame.metadata.geometry.clone();
            result.capture = Some(frame.metadata.clone());
            if input.ocr.unwrap_or(false) {
                result.ocr = match ocr::recognize(&frame, input.ocr_language.as_deref(), &operation)
                {
                    Ok(ocr) => OcrObservation {
                        status: "observed",
                        result: Some(ocr),
                        error: None,
                    },
                    Err(error) => OcrObservation {
                        status: "unavailable",
                        result: None,
                        error: Some(format!("{error:#}")),
                    },
                };
            }
            let (id, changes, retention) = self
                .frames
                .lock()
                .map_err(|_| anyhow::anyhow!("Capture baseline cache poisoned"))?
                .observe(&frame, input.baseline_id.as_deref(), &operation)?;
            result.snapshot_id = Some(id);
            result.changes = Some(changes);
            result.retention = Some(retention);
            if input.image.unwrap_or(true) {
                result.image = Some(frame.encode(&operation)?.base64_jpeg);
            }
        }
        if input.accessibility.unwrap_or(true) {
            let query_bounds = if window.is_none() {
                result
                    .capture
                    .as_ref()
                    .map(|capture| capture.physical_bounds)
                    .or(query_bounds)
            } else {
                None
            };
            let query = UiQuery {
                window_ref: window.as_ref().map(|window| window.window_ref.clone()),
                bounds: query_bounds,
                ..Default::default()
            };
            let max_nodes = input.max_nodes.unwrap_or(256);
            result.accessibility = match self.automation.find(
                self.windows.clone(),
                UiFindInput {
                    query: Some(query),
                    max_depth: input.max_depth,
                    max_nodes: Some(max_nodes),
                    max_results: Some(max_nodes),
                    ..Default::default()
                },
                &operation,
            ) {
                Ok(tree) => AccessibilityObservation {
                    status: if tree.complete { "complete" } else { "partial" },
                    result: Some(tree),
                    error: None,
                },
                Err(error) => AccessibilityObservation {
                    status: "unavailable",
                    result: None,
                    error: Some(format!("{error:#}")),
                },
            };
        }
        result.elapsed_ms = operation.elapsed_ms();
        Ok(result)
    }

    pub fn wait(&self, input: UiWaitInput) -> Result<UiWaitResult> {
        require_session(input.session_id)?;
        let operation = self
            .operations
            .start(input.operation_id, input.timeout_ms.unwrap_or(10_000))?;
        let poll_ms = input.poll_ms.unwrap_or(100);
        if !(25..=1000).contains(&poll_ms) {
            bail!("poll_ms must be in 25..=1000");
        }
        let mut result = UiWaitResult {
            operation_id: operation.id.clone(),
            outcome: WaitOutcome::Failed,
            window: None,
            element: None,
            elapsed_ms: 0,
            observations: Some(0),
            error: None,
        };
        let mut previous = input.previous_value;
        loop {
            let observation = (|| -> Result<(bool, Option<bool>, Option<String>)> {
                operation.check()?;
                require_session(input.session_id)?;
                if let Some(count) = &mut result.observations {
                    *count += 1;
                }
                result.window = None;
                result.element = None;
                match &input.target {
                    WaitTarget::Window { query } => {
                        let mut found = self.windows.list(
                            &WindowListInput {
                                query: Some(query.clone()),
                                limit: Some(2),
                                timeout_ms: Some(operation.remaining().as_millis() as u64),
                                session_id: input.session_id,
                            },
                            &operation,
                        )?;
                        if found.windows.len() > 1 {
                            bail!("Ambiguous window wait: multiple windows match the query");
                        }
                        if found.truncated || !found.issues.is_empty() {
                            bail!(
                                "Window wait observation is incomplete: {}",
                                found.issues.join("; ")
                            );
                        }
                        result.window = found.windows.pop();
                        Ok((
                            result.window.is_some(),
                            result.window.as_ref().map(|window| window.enabled),
                            result.window.as_ref().map(|window| window.title.clone()),
                        ))
                    }
                    WaitTarget::Control { query } => {
                        let mut found = self.automation.find(
                            self.windows.clone(),
                            UiFindInput {
                                query: Some(query.clone()),
                                max_depth: Some(uia::MAX_DEPTH),
                                max_nodes: Some(uia::MAX_NODES),
                                max_results: Some(2),
                                ..Default::default()
                            },
                            &operation,
                        )?;
                        if found.elements.len() > 1 {
                            bail!("Ambiguous control wait: multiple controls match the query");
                        }
                        if !found.complete {
                            operation.check()?;
                            bail!(
                                "Control wait observation is incomplete: {}",
                                found.issues.join("; ")
                            );
                        }
                        result.element = found.elements.pop();
                        Ok((
                            result.element.is_some(),
                            result.element.as_ref().and_then(|element| element.enabled),
                            result
                                .element
                                .as_ref()
                                .and_then(|element| element.value.clone()),
                        ))
                    }
                }
            })();
            let (present, enabled, value) = match observation {
                Ok(observation) => observation,
                Err(error) => {
                    result.outcome = operation.stopped_outcome();
                    result.error = Some(format!("{error:#}"));
                    break;
                }
            };
            let satisfied = match input.condition {
                WaitCondition::Appear => present,
                WaitCondition::Disappear => !present,
                WaitCondition::Enabled => {
                    if present && enabled.is_none() {
                        result.error = Some("The target's enabled state is unavailable.".into());
                        break;
                    }
                    enabled == Some(true)
                }
                WaitCondition::ValueChange => {
                    if present && value.is_none() {
                        result.error = Some("The target has no readable value; a value-change postcondition cannot be observed.".into());
                        break;
                    }
                    if previous.is_none() {
                        previous = value.clone();
                        false
                    } else {
                        value.is_some() && value != previous
                    }
                }
            };
            if satisfied {
                result.outcome = WaitOutcome::Satisfied;
                break;
            }
            if let Err(error) = operation.wait(Duration::from_millis(poll_ms)) {
                result.outcome = operation.stopped_outcome();
                result.error = Some(format!("{error:#}"));
                break;
            }
        }
        result.elapsed_ms = operation.elapsed_ms();
        Ok(result)
    }
}

#[cfg(test)]
mod operation_tests {
    use super::*;

    #[test]
    fn deadlines_and_cancellation_interrupt_condition_waits() {
        let operation = Operation::new(10).unwrap();
        let error = operation.wait(Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<OperationStopped>(),
            Some(&OperationStopped::TimedOut)
        );
        let operation = Operation::new(1000).unwrap();
        operation.cancellation.cancel().unwrap();
        let error = operation.wait(Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<OperationStopped>(),
            Some(&OperationStopped::Canceled)
        );
    }

    #[test]
    fn operation_registry_rejects_reused_active_ids_and_expires_completed_ids() {
        let operations = Operations::default();
        let operation = operations.start(Some("request-1".into()), 1000).unwrap();
        assert!(operations.start(Some("request-1".into()), 1000).is_err());
        assert!(
            operations
                .cancel("request-1")
                .unwrap()
                .cancellation_requested
        );
        assert!(operation.is_canceled());
        drop(operation);
        assert!(
            !operations
                .cancel("request-1")
                .unwrap()
                .cancellation_requested
        );
        assert!(operations.start(Some("request-1".into()), 1000).is_ok());
        assert!(Operation::new(0).is_err());
        assert!(Operation::new(MAX_OPERATION_MS + 1).is_err());
    }
}
