use super::{
    windows::{
        process_identity, read_identity, ProcessIdentity, WindowCatalog, WindowIdentity,
        WindowRecord,
    },
    Operation,
};
use crate::win32::display::{DpiScope, Rect};
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, OnceLock,
};
use std::time::{Duration, Instant};
use windows::core::{Interface, BSTR, HRESULT};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    SAFEARRAY,
};
use windows::Win32::System::Ole::{
    SafeArrayDestroy, SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
    SafeArrayGetVartype,
};
use windows::Win32::System::Variant::{
    VARIANT, VT_BOOL, VT_BSTR, VT_EMPTY, VT_I4, VT_R8, VT_UNKNOWN,
};
use windows::Win32::UI::Accessibility::*;

pub(crate) const MAX_NODES: u32 = 2048;
pub(crate) const MAX_DEPTH: u32 = 32;
const MAX_REFS: usize = 4096;
const REF_TTL: Duration = Duration::from_secs(300);
const MAX_STRING: usize = 4096;
const PROVIDER_TIMEOUT_MS: u32 = 500;

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiQuery {
    pub window_ref: Option<String>,
    #[schemars(description = "Exact control name, case sensitive")]
    pub name: Option<String>,
    #[schemars(description = "Case-insensitive control name substring")]
    pub name_contains: Option<String>,
    pub automation_id: Option<String>,
    #[schemars(
        description = "Control type name such as Button or Edit, or its numeric UIA ID as a string"
    )]
    pub control_type: Option<String>,
    pub class_name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub pid: Option<u32>,
    #[schemars(description = "Only controls intersecting these physical desktop bounds")]
    pub bounds: Option<Rect>,
}

impl UiQuery {
    fn validate(&self) -> Result<()> {
        for text in [
            &self.window_ref,
            &self.name,
            &self.name_contains,
            &self.automation_id,
            &self.control_type,
            &self.class_name,
        ]
        .into_iter()
        .flatten()
        {
            if text.len() > MAX_STRING {
                bail!("UI query strings must not exceed {MAX_STRING} bytes");
            }
        }
        if let Some(bounds) = self.bounds {
            bounds.validate()?;
        }
        if let Some(control_type) = &self.control_type {
            if !CONTROL_TYPES.iter().any(|(id, name)| {
                name.eq_ignore_ascii_case(control_type) || id.to_string() == *control_type
            }) {
                bail!("Unknown UI Automation control type {control_type}");
            }
        }
        Ok(())
    }

    fn classify(&self, node: &UiElement) -> QueryMatch {
        let known_match = self.name.as_ref().is_none_or(|name| node.name == *name)
            && self
                .name_contains
                .as_ref()
                .is_none_or(|name| node.name.to_lowercase().contains(&name.to_lowercase()))
            && self
                .automation_id
                .as_ref()
                .is_none_or(|id| node.automation_id == *id)
            && self
                .class_name
                .as_ref()
                .is_none_or(|class| node.class_name == *class)
            && self.control_type.as_ref().is_none_or(|kind| {
                node.control_type_name.eq_ignore_ascii_case(kind)
                    || node.control_type.to_string() == *kind
            })
            && self.bounds.is_none_or(|bounds| {
                node.bounds
                    .is_some_and(|node| node.intersect(&bounds).is_some())
            });
        if !known_match {
            return QueryMatch::NoMatch;
        }
        match_optional(self.enabled, node.enabled).combine(match_optional(
            self.pid,
            node.process.as_ref().map(|process| process.pid),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryMatch {
    Match,
    NoMatch,
    Unknown,
}

impl QueryMatch {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::NoMatch, _) | (_, Self::NoMatch) => Self::NoMatch,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Match,
        }
    }
}

fn match_optional<T: PartialEq>(expected: Option<T>, observed: Option<T>) -> QueryMatch {
    match (expected, observed) {
        (None, _) => QueryMatch::Match,
        (Some(_), None) => QueryMatch::Unknown,
        (Some(expected), Some(observed)) if expected == observed => QueryMatch::Match,
        _ => QueryMatch::NoMatch,
    }
}

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiFindInput {
    pub query: Option<UiQuery>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_depth: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_nodes: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_results: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiSelector {
    pub element_ref: Option<String>,
    pub query: Option<UiQuery>,
}

impl UiSelector {
    fn validate(&self) -> Result<()> {
        if self.element_ref.is_some() == self.query.is_some() {
            bail!("Specify exactly one of element_ref or query");
        }
        if self
            .element_ref
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
        {
            bail!("Invalid element_ref");
        }
        if let Some(query) = &self.query {
            query.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UiPattern {
    Invoke,
    Value,
    RangeValue,
    Selection,
    SelectionItem,
    Toggle,
    ExpandCollapse,
    Scroll,
    ScrollItem,
    Text,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UiElement {
    pub node_id: u32,
    pub parent_node_id: Option<u32>,
    pub element_ref: Option<String>,
    pub name: String,
    pub control_type: i32,
    pub control_type_name: String,
    pub automation_id: String,
    pub class_name: String,
    pub framework_id: String,
    pub patterns: Vec<UiPattern>,
    pub value: Option<String>,
    pub value_read_only: Option<bool>,
    pub range_value: Option<f64>,
    pub enabled: Option<bool>,
    pub selected: Option<bool>,
    pub toggle_state: Option<i32>,
    pub expand_collapse_state: Option<i32>,
    pub horizontal_scroll_percent: Option<f64>,
    pub vertical_scroll_percent: Option<f64>,
    pub bounds: Option<Rect>,
    pub offscreen: Option<bool>,
    pub keyboard_focused: Option<bool>,
    pub password: Option<bool>,
    pub owner: Option<WindowIdentity>,
    pub native_window: Option<WindowIdentity>,
    pub window_ref: Option<String>,
    pub process: Option<ProcessIdentity>,
    pub runtime_id: Vec<i32>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UiFindResult {
    pub operation_id: String,
    pub elements: Vec<UiElement>,
    pub visited: u32,
    pub complete: bool,
    pub truncated: bool,
    pub elapsed_ms: u64,
    pub provider_timeout_ms: u32,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UiAction {
    Invoke,
    Select,
    AddToSelection,
    RemoveFromSelection,
    Toggle,
    Expand,
    Collapse,
    Scroll,
    ScrollIntoView,
    Focus,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScrollStep {
    LargeDecrement,
    SmallDecrement,
    #[default]
    None,
    LargeIncrement,
    SmallIncrement,
}

impl ScrollStep {
    fn native(self) -> ScrollAmount {
        match self {
            Self::LargeDecrement => ScrollAmount_LargeDecrement,
            Self::SmallDecrement => ScrollAmount_SmallDecrement,
            Self::None => ScrollAmount_NoAmount,
            Self::LargeIncrement => ScrollAmount_LargeIncrement,
            Self::SmallIncrement => ScrollAmount_SmallIncrement,
        }
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiInvokeInput {
    #[serde(flatten)]
    pub target: UiSelector,
    pub action: Option<UiAction>,
    pub horizontal: Option<ScrollStep>,
    pub vertical: Option<ScrollStep>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub observe_timeout_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiSetValueInput {
    #[serde(flatten)]
    pub target: UiSelector,
    #[schemars(
        description = "Text for ValuePattern, or a finite numeric string for RangeValuePattern"
    )]
    pub value: String,
    #[schemars(description = "Use RangeValuePattern rather than ValuePattern")]
    pub range: Option<bool>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub observe_timeout_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct UiTextInput {
    #[serde(flatten)]
    pub target: UiSelector,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_chars: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UiTextResult {
    pub operation_id: String,
    pub element_ref: String,
    pub text: String,
    pub truncated: bool,
    pub source: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct UiActionResult {
    pub operation_id: String,
    pub accepted: Option<bool>,
    pub observed: bool,
    pub postcondition: String,
    pub before: UiElement,
    pub after: Option<UiElement>,
    pub error: Option<String>,
    pub observation_error: Option<String>,
}

type Work = Box<dyn FnOnce(&mut std::result::Result<Worker, String>) + Send>;

#[derive(Default)]
pub(crate) struct UiAutomation {
    sender: OnceLock<std::result::Result<mpsc::SyncSender<Work>, String>>,
    active: Arc<AtomicBool>,
}

struct Active(Arc<AtomicBool>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl UiAutomation {
    fn run<T: Send + 'static>(
        &self,
        operation: &Operation,
        work: impl FnOnce(&mut Worker, &Operation) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        operation.check()?;
        self.active.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("UI Automation provider work is busy; no additional provider thread was started"))?;
        let active = Active(self.active.clone());
        let sender = self
            .sender
            .get_or_init(|| {
                let (sender, receiver) = mpsc::sync_channel::<Work>(1);
                std::thread::Builder::new()
                    .name("desktop-uia".into())
                    .spawn(move || {
                        let mut worker = Worker::new().map_err(|error| format!("{error:#}"));
                        for work in receiver {
                            work(&mut worker);
                        }
                    })
                    .map_err(|error| error.to_string())?;
                Ok(sender)
            })
            .as_ref()
            .map_err(|error| anyhow::anyhow!("UI Automation worker unavailable: {error}"))?;
        let (reply, receiver) = mpsc::sync_channel(1);
        let operation = operation.clone();
        sender
            .try_send(Box::new(move |worker| {
                let result = match worker {
                    Ok(worker) => operation.check().and_then(|_| work(worker, &operation)),
                    Err(error) => Err(anyhow::anyhow!("UI Automation unavailable: {error}")),
                };
                drop(active);
                if reply.send(result).is_err() {
                    tracing::debug!("UI Automation caller disconnected");
                }
            }))
            .map_err(|_| anyhow::anyhow!("UI Automation worker is not accepting work"))?;
        // Keep the shared runtime input permit until the provider actually
        // returns, even if the outer MCP future has already been canceled.
        receiver
            .recv()
            .context("UI Automation worker stopped before replying")?
    }

    pub fn find(
        &self,
        windows: Arc<WindowCatalog>,
        input: UiFindInput,
        operation: &Operation,
    ) -> Result<UiFindResult> {
        self.run(operation, move |worker, operation| {
            worker.find(&windows, input, operation)
        })
    }

    pub fn invoke(
        &self,
        windows: Arc<WindowCatalog>,
        input: UiInvokeInput,
        operation: &Operation,
    ) -> Result<UiActionResult> {
        self.run(operation, move |worker, operation| {
            worker.invoke(&windows, input, operation)
        })
    }

    pub fn set_value(
        &self,
        windows: Arc<WindowCatalog>,
        input: UiSetValueInput,
        operation: &Operation,
    ) -> Result<UiActionResult> {
        self.run(operation, move |worker, operation| {
            worker.set_value(&windows, input, operation)
        })
    }

    pub fn text(
        &self,
        windows: Arc<WindowCatalog>,
        input: UiTextInput,
        operation: &Operation,
    ) -> Result<UiTextResult> {
        self.run(operation, move |worker, operation| {
            worker.text(&windows, input, operation)
        })
    }
}

struct Apartment;

impl Apartment {
    fn enter() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .context("UI Automation requires an owned multithreaded COM apartment")?;
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[derive(Clone)]
struct RetainedRef {
    id: String,
    element: IUIAutomationElement,
    runtime_id: Vec<i32>,
    window_ref: String,
    owner: WindowIdentity,
    native_window: Option<WindowIdentity>,
    process: ProcessIdentity,
    last_used: Instant,
}

struct Worker {
    automation: IUIAutomation,
    timed: IUIAutomation2,
    walker: IUIAutomationTreeWalker,
    cache: IUIAutomationCacheRequest,
    refs: VecDeque<RetainedRef>,
    _apartment: Apartment,
}

enum WalkStep {
    FirstChild,
    NextSibling,
}

impl Worker {
    fn new() -> Result<Self> {
        let apartment = Apartment::enter()?;
        let automation: IUIAutomation =
            unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
                .context("The native Windows UI Automation client is unavailable")?;
        let timed: IUIAutomation2 = automation.cast().context(
            "This UI Automation client has no provider timeout support (IUIAutomation2)",
        )?;
        unsafe {
            timed.SetConnectionTimeout(PROVIDER_TIMEOUT_MS)?;
            timed.SetTransactionTimeout(PROVIDER_TIMEOUT_MS)?;
        }
        let walker = unsafe { automation.RawViewWalker() }?;
        let cache = unsafe { automation.CreateCacheRequest() }?;
        unsafe {
            cache.SetTreeScope(TreeScope_Element)?;
            for property in PROPERTIES {
                cache.AddProperty(*property)?;
            }
            for (_, property) in PATTERNS {
                cache.AddProperty(*property)?;
            }
        }
        Ok(Self {
            automation,
            timed,
            walker,
            cache,
            refs: VecDeque::new(),
            _apartment: apartment,
        })
    }

    fn prepare(&self, operation: &Operation) -> Result<()> {
        operation.check()?;
        let timeout = operation
            .remaining()
            .as_millis()
            .clamp(1, u128::from(PROVIDER_TIMEOUT_MS)) as u32;
        unsafe {
            self.timed.SetConnectionTimeout(timeout)?;
            self.timed.SetTransactionTimeout(timeout)?;
        }
        Ok(())
    }

    fn step(
        &self,
        element: &IUIAutomationElement,
        step: WalkStep,
    ) -> Result<Option<IUIAutomationElement>> {
        let table = self.walker.vtable();
        let call = match step {
            WalkStep::FirstChild => table.GetFirstChildElementBuildCache,
            WalkStep::NextSibling => table.GetNextSiblingElementBuildCache,
        };
        optional_element(|output| unsafe {
            call(
                self.walker.as_raw(),
                element.as_raw(),
                self.cache.as_raw(),
                output,
            )
        })
    }

    fn root(
        &self,
        windows: &WindowCatalog,
        query: &UiQuery,
        operation: &Operation,
    ) -> Result<(IUIAutomationElement, Option<WindowRecord>)> {
        self.prepare(operation)?;
        match &query.window_ref {
            Some(reference) => {
                let window = windows.resolve(reference)?;
                let root = unsafe {
                    self.automation.ElementFromHandleBuildCache(
                        HWND(window.identity.hwnd as *mut _),
                        &self.cache,
                    )
                }
                .context("UI Automation cannot access this window")?;
                Ok((root, Some(window)))
            }
            None => Ok((
                unsafe { self.automation.GetRootElementBuildCache(&self.cache) }?,
                None,
            )),
        }
    }

    fn find(
        &mut self,
        windows: &WindowCatalog,
        input: UiFindInput,
        operation: &Operation,
    ) -> Result<UiFindResult> {
        let _dpi = DpiScope::enter()?;
        let query = input.query.unwrap_or_default();
        query.validate()?;
        let max_depth = input.max_depth.unwrap_or(8);
        let max_nodes = input.max_nodes.unwrap_or(256);
        let max_results = input.max_results.unwrap_or(50);
        if max_depth > MAX_DEPTH
            || !(1..=MAX_NODES).contains(&max_nodes)
            || !(1..=MAX_NODES).contains(&max_results)
        {
            bail!("UI traversal limits: depth 0..=32, nodes and results 1..={MAX_NODES}");
        }
        self.refs
            .retain(|reference| reference.last_used.elapsed() < REF_TTL);
        let (root, owner) = self.root(windows, &query, operation)?;
        let mut traversal = Traversal {
            query,
            max_depth,
            max_nodes,
            max_results,
            process_cache: HashMap::new(),
            result: UiFindResult {
                operation_id: operation.id.clone(),
                elements: Vec::new(),
                visited: 0,
                complete: true,
                truncated: false,
                elapsed_ms: 0,
                provider_timeout_ms: PROVIDER_TIMEOUT_MS,
                issues: Vec::new(),
            },
        };
        if let Err(error) = self.visit(
            windows,
            &root,
            owner.as_ref(),
            NodePosition {
                parent: None,
                depth: 0,
            },
            &mut traversal,
            operation,
        ) {
            traversal.result.complete = false;
            traversal.result.issues.push(format!("{error:#}"));
        }
        traversal.result.elapsed_ms = operation.elapsed_ms();
        Ok(traversal.result)
    }

    fn visit(
        &mut self,
        windows: &WindowCatalog,
        element: &IUIAutomationElement,
        inherited: Option<&WindowRecord>,
        position: NodePosition,
        traversal: &mut Traversal,
        operation: &Operation,
    ) -> Result<()> {
        let NodePosition { parent, depth } = position;
        operation.check()?;
        if traversal.result.visited >= traversal.max_nodes
            || traversal.result.elements.len() >= traversal.max_results as usize
        {
            traversal.result.complete = false;
            traversal.result.truncated = true;
            return Ok(());
        }
        let id = traversal.result.visited;
        traversal.result.visited += 1;
        let owner = match inherited {
            Some(owner) => Some(owner.clone()),
            None => match unsafe { element.CachedNativeWindowHandle() } {
                Ok(hwnd) if !hwnd.is_invalid() => match windows.record_for_hwnd(hwnd.0 as u64) {
                    Ok(owner) => Some(owner),
                    Err(error) => {
                        if traversal.result.issues.len() < 32 {
                            traversal.result.issues.push(format!(
                                "Window identity unavailable for HWND {}: {error:#}",
                                hwnd.0 as u64
                            ));
                        }
                        None
                    }
                },
                _ => None,
            },
        };
        match self.describe(
            element,
            owner.as_ref(),
            id,
            parent,
            &mut traversal.process_cache,
            operation,
        ) {
            Ok(node) => {
                if !node.issues.is_empty() {
                    traversal.result.complete = false;
                    if traversal.result.issues.len() < 32 {
                        traversal
                            .result
                            .issues
                            .push(format!("Node {id}: {}", node.issues.join("; ")));
                    }
                }
                match traversal.query.classify(&node) {
                    QueryMatch::Match => traversal.result.elements.push(node),
                    QueryMatch::NoMatch => {}
                    QueryMatch::Unknown => {
                        traversal.result.complete = false;
                        if traversal.result.issues.len() < 32 {
                            traversal.result.issues.push(format!("Node {id}: a requested filter property is unavailable; this control cannot be excluded as a competing match"));
                        }
                    }
                }
            }
            Err(error) => {
                traversal.result.complete = false;
                if traversal.result.issues.len() < 32 {
                    traversal
                        .result
                        .issues
                        .push(format!("Node {id}: {error:#}"));
                }
            }
        }
        self.prepare(operation)?;
        let mut child = self.step(element, WalkStep::FirstChild)?;
        if depth >= traversal.max_depth {
            if child.is_some() {
                traversal.result.complete = false;
                traversal.result.truncated = true;
            }
            return Ok(());
        }
        while let Some(element) = child {
            if traversal.result.visited >= traversal.max_nodes
                || traversal.result.elements.len() >= traversal.max_results as usize
            {
                traversal.result.complete = false;
                traversal.result.truncated = true;
                break;
            }
            self.visit(
                windows,
                &element,
                owner.as_ref(),
                NodePosition {
                    parent: Some(id),
                    depth: depth + 1,
                },
                traversal,
                operation,
            )?;
            self.prepare(operation)?;
            child = self.step(&element, WalkStep::NextSibling)?;
        }
        Ok(())
    }

    fn describe(
        &mut self,
        element: &IUIAutomationElement,
        owner: Option<&WindowRecord>,
        node_id: u32,
        parent_node_id: Option<u32>,
        process_cache: &mut HashMap<u32, ProcessIdentity>,
        operation: &Operation,
    ) -> Result<UiElement> {
        operation.check()?;
        let mut issues = Vec::new();
        let name = limited_bstr(unsafe { element.CachedName() }?, MAX_STRING, &mut issues);
        let automation_id = limited_bstr(
            unsafe { element.CachedAutomationId() }?,
            MAX_STRING,
            &mut issues,
        );
        let class_name = limited_bstr(
            unsafe { element.CachedClassName() }?,
            MAX_STRING,
            &mut issues,
        );
        let framework_id = limited_bstr(unsafe { element.CachedFrameworkId() }?, 256, &mut issues);
        let control_type = unsafe { element.CachedControlType() }?.0;
        let mut patterns = Vec::new();
        for (pattern, property) in PATTERNS {
            if cached_bool(element, *property, &mut issues) == Some(true) {
                patterns.push(*pattern);
            }
        }
        let password = cached_bool(element, UIA_IsPasswordPropertyId, &mut issues);
        let value = if patterns.contains(&UiPattern::Value) && password != Some(true) {
            cached_string(element, UIA_ValueValuePropertyId, &mut issues)
        } else {
            None
        };
        let value_read_only = if patterns.contains(&UiPattern::Value) {
            cached_bool(element, UIA_ValueIsReadOnlyPropertyId, &mut issues)
        } else {
            None
        };
        let range_value = patterns
            .contains(&UiPattern::RangeValue)
            .then(|| cached_number(element, UIA_RangeValueValuePropertyId, &mut issues))
            .flatten();
        let selected = patterns
            .contains(&UiPattern::SelectionItem)
            .then(|| cached_bool(element, UIA_SelectionItemIsSelectedPropertyId, &mut issues))
            .flatten();
        let toggle_state = patterns
            .contains(&UiPattern::Toggle)
            .then(|| cached_integer(element, UIA_ToggleToggleStatePropertyId, &mut issues))
            .flatten();
        let expand_collapse_state = patterns
            .contains(&UiPattern::ExpandCollapse)
            .then(|| {
                cached_integer(
                    element,
                    UIA_ExpandCollapseExpandCollapseStatePropertyId,
                    &mut issues,
                )
            })
            .flatten();
        let horizontal_scroll_percent = patterns
            .contains(&UiPattern::Scroll)
            .then(|| {
                cached_number(
                    element,
                    UIA_ScrollHorizontalScrollPercentPropertyId,
                    &mut issues,
                )
            })
            .flatten();
        let vertical_scroll_percent = patterns
            .contains(&UiPattern::Scroll)
            .then(|| {
                cached_number(
                    element,
                    UIA_ScrollVerticalScrollPercentPropertyId,
                    &mut issues,
                )
            })
            .flatten();
        let pid = unsafe { element.CachedProcessId() }?;
        let process = if pid > 0 {
            if let Some(process) = process_cache.get(&(pid as u32)) {
                Some(process.clone())
            } else {
                match process_identity(pid as u32) {
                    Ok(process) => {
                        process_cache.insert(pid as u32, process.clone());
                        Some(process)
                    }
                    Err(error) => {
                        issues.push(format!("Provider process identity unavailable: {error:#}"));
                        None
                    }
                }
            }
        } else {
            None
        };
        let bounds = unsafe { element.CachedBoundingRectangle() }
            .context("UI Automation bounds are unavailable")?;
        let bounds = if bounds.left == bounds.right || bounds.top == bounds.bottom {
            None
        } else {
            Some(Rect::from_native(bounds)?)
        };
        let native_hwnd = unsafe { element.CachedNativeWindowHandle() }?;
        let native_window = if native_hwnd.is_invalid() {
            None
        } else if let Some(owner) =
            owner.filter(|owner| owner.identity.hwnd == native_hwnd.0 as u64)
        {
            Some(owner.identity.clone())
        } else {
            Some(read_identity(native_hwnd, Some(operation))?)
        };
        self.prepare(operation)?;
        let runtime_id = runtime_id(element)?;
        let reference = if let (Some(owner), Some(process)) = (owner, &process) {
            if runtime_id.is_empty() {
                None
            } else {
                Some(self.retain(element, &runtime_id, owner, process, &native_window))
            }
        } else {
            None
        };
        Ok(UiElement {
            node_id,
            parent_node_id,
            element_ref: reference,
            name,
            control_type,
            control_type_name: CONTROL_TYPES
                .iter()
                .find(|(id, _)| *id == control_type)
                .map(|(_, name)| *name)
                .unwrap_or("Unknown")
                .into(),
            automation_id,
            class_name,
            framework_id,
            patterns,
            value,
            value_read_only,
            range_value,
            enabled: cached_bool(element, UIA_IsEnabledPropertyId, &mut issues),
            selected,
            toggle_state,
            expand_collapse_state,
            horizontal_scroll_percent,
            vertical_scroll_percent,
            bounds,
            offscreen: cached_bool(element, UIA_IsOffscreenPropertyId, &mut issues),
            keyboard_focused: cached_bool(element, UIA_HasKeyboardFocusPropertyId, &mut issues),
            password,
            owner: owner.map(|window| window.identity.clone()),
            native_window,
            window_ref: owner.map(|window| window.window_ref.clone()),
            process,
            runtime_id,
            issues,
        })
    }

    fn retain(
        &mut self,
        element: &IUIAutomationElement,
        runtime_id: &[i32],
        window: &WindowRecord,
        process: &ProcessIdentity,
        native_window: &Option<WindowIdentity>,
    ) -> String {
        if let Some(index) = self.refs.iter().position(|reference| {
            reference.owner == window.identity
                && reference.process == *process
                && reference.runtime_id == runtime_id
                && reference.native_window == *native_window
        }) {
            let reference = move_to_back(&mut self.refs, index).expect("matched reference index");
            reference.last_used = Instant::now();
            return reference.id.clone();
        }
        if self.refs.len() >= MAX_REFS {
            self.refs.pop_front();
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.refs.push_back(RetainedRef {
            id: id.clone(),
            element: element.clone(),
            runtime_id: runtime_id.to_vec(),
            window_ref: window.window_ref.clone(),
            owner: window.identity.clone(),
            native_window: native_window.clone(),
            process: process.clone(),
            last_used: Instant::now(),
        });
        id
    }

    fn resolve(
        &mut self,
        windows: &WindowCatalog,
        selector: &UiSelector,
        operation: &Operation,
    ) -> Result<(RetainedRef, WindowRecord, UiElement)> {
        selector.validate()?;
        self.refs
            .retain(|reference| reference.last_used.elapsed() < REF_TTL);
        let id = match &selector.element_ref {
            Some(id) => id.clone(),
            None => {
                let result = self.find(
                    windows,
                    UiFindInput {
                        query: selector.query.clone(),
                        max_depth: Some(32),
                        max_nodes: Some(MAX_NODES),
                        max_results: Some(2),
                        ..Default::default()
                    },
                    operation,
                )?;
                require_unique(result.elements.len(), result.complete)?;
                if !result.elements[0].issues.is_empty() {
                    bail!(
                        "The matching control has incomplete provider data: {}",
                        result.elements[0].issues.join("; ")
                    );
                }
                result.elements[0]
                    .element_ref
                    .clone()
                    .context("The matching control has no verifiable native reference")?
            }
        };
        let reference = self.refs.iter_mut().find(|reference| reference.id == id)
            .context("Stale or unknown element_ref; references expire after five minutes and do not survive reconnects")?;
        reference.last_used = Instant::now();
        let reference = reference.clone();
        let window = windows
            .resolve(&reference.window_ref)
            .context("Stale UI reference: the owning window is no longer the same window")?;
        let process = process_identity(reference.process.pid)
            .context("Stale UI reference: the provider process is no longer available")?;
        validate_identity(
            &reference.owner,
            &reference.process,
            &window.identity,
            &process,
        )?;
        if let Some(expected) = &reference.native_window {
            let current = read_identity(HWND(expected.hwnd as *mut _), Some(operation))
                .context("Stale UI reference: the native control window is unavailable")?;
            require_native_window(expected, &current)?;
        }
        self.prepare(operation)?;
        let current_runtime = runtime_id(&reference.element)
            .context("Stale UI reference: the original provider element is unavailable")?;
        if reference.runtime_id != current_runtime {
            bail!("Stale UI reference: UI Automation runtime ID changed");
        }
        self.prepare(operation)?;
        let current = unsafe { reference.element.BuildUpdatedCache(&self.cache) }
            .context("Stale UI reference: cannot refresh the original provider element")?;
        let node = self.describe(
            &current,
            Some(&window),
            0,
            None,
            &mut HashMap::new(),
            operation,
        )?;
        if node.runtime_id != reference.runtime_id
            || node.process.as_ref() != Some(&reference.process)
            || node.native_window != reference.native_window
        {
            bail!("Stale UI reference: refreshed provider identity changed");
        }
        Ok((reference, window, node))
    }

    fn invoke(
        &mut self,
        windows: &WindowCatalog,
        input: UiInvokeInput,
        operation: &Operation,
    ) -> Result<UiActionResult> {
        let action = input.action.unwrap_or(UiAction::Invoke);
        let horizontal = input.horizontal.unwrap_or_default();
        let vertical = input.vertical.unwrap_or_default();
        if action == UiAction::Scroll
            && horizontal == ScrollStep::None
            && vertical == ScrollStep::None
        {
            bail!("Scroll requires a non-none horizontal or vertical amount");
        }
        if action != UiAction::Scroll && (input.horizontal.is_some() || input.vertical.is_some()) {
            bail!("Scroll amounts are only valid for the scroll action");
        }
        let observe_ms = observation_timeout(input.observe_timeout_ms)?;
        let (reference, window, before) = self.resolve(windows, &input.target, operation)?;
        if before.enabled != Some(true) {
            bail!("The target control is disabled or its enabled state is unavailable");
        }
        super::require_session(Some(window.identity.session_id))?;
        macro_rules! pattern_action {
            ($interface:ty, $pattern:expr, $method:ident $(, $arg:expr)*) => {{
                self.prepare(operation)?;
                let pattern = unsafe { reference.element.GetCurrentPatternAs::<$interface>($pattern) }
                    .context("The target does not support the requested UI Automation pattern")?;
                self.prepare(operation)?;
                unsafe { pattern.$method($($arg),*) }
            }};
        }
        self.prepare(operation)?;
        let accepted = match action {
            UiAction::Invoke => {
                pattern_action!(IUIAutomationInvokePattern, UIA_InvokePatternId, Invoke)
            }
            UiAction::Select => pattern_action!(
                IUIAutomationSelectionItemPattern,
                UIA_SelectionItemPatternId,
                Select
            ),
            UiAction::AddToSelection => pattern_action!(
                IUIAutomationSelectionItemPattern,
                UIA_SelectionItemPatternId,
                AddToSelection
            ),
            UiAction::RemoveFromSelection => pattern_action!(
                IUIAutomationSelectionItemPattern,
                UIA_SelectionItemPatternId,
                RemoveFromSelection
            ),
            UiAction::Toggle => {
                pattern_action!(IUIAutomationTogglePattern, UIA_TogglePatternId, Toggle)
            }
            UiAction::Expand => pattern_action!(
                IUIAutomationExpandCollapsePattern,
                UIA_ExpandCollapsePatternId,
                Expand
            ),
            UiAction::Collapse => pattern_action!(
                IUIAutomationExpandCollapsePattern,
                UIA_ExpandCollapsePatternId,
                Collapse
            ),
            UiAction::Scroll => pattern_action!(
                IUIAutomationScrollPattern,
                UIA_ScrollPatternId,
                Scroll,
                horizontal.native(),
                vertical.native()
            ),
            UiAction::ScrollIntoView => pattern_action!(
                IUIAutomationScrollItemPattern,
                UIA_ScrollItemPatternId,
                ScrollIntoView
            ),
            UiAction::Focus => unsafe { reference.element.SetFocus() },
        };
        let postcondition = match action {
            UiAction::Invoke => "Application completion requires a separate condition wait",
            UiAction::Select | UiAction::AddToSelection => "Control is selected",
            UiAction::RemoveFromSelection => "Control is not selected",
            UiAction::Toggle => "Toggle state changed",
            UiAction::Expand => "Control is expanded",
            UiAction::Collapse => "Control is collapsed",
            UiAction::Scroll => "Requested scroll axis changed position",
            UiAction::ScrollIntoView => "Control is no longer offscreen",
            UiAction::Focus => "Control has keyboard focus",
        }
        .to_string();
        self.after_action(
            windows,
            reference,
            window,
            before,
            accepted,
            postcondition,
            observe_ms,
            operation,
            move |before, after| match action {
                UiAction::Invoke => false,
                UiAction::Select | UiAction::AddToSelection => after.selected == Some(true),
                UiAction::RemoveFromSelection => after.selected == Some(false),
                UiAction::Toggle => {
                    after.toggle_state.is_some()
                        && before.toggle_state.is_some()
                        && after.toggle_state != before.toggle_state
                }
                UiAction::Expand => {
                    after.expand_collapse_state == Some(ExpandCollapseState_Expanded.0)
                }
                UiAction::Collapse => {
                    after.expand_collapse_state == Some(ExpandCollapseState_Collapsed.0)
                }
                UiAction::Scroll => {
                    (horizontal == ScrollStep::None
                        || scroll_changed(
                            before.horizontal_scroll_percent,
                            after.horizontal_scroll_percent,
                        ))
                        && (vertical == ScrollStep::None
                            || scroll_changed(
                                before.vertical_scroll_percent,
                                after.vertical_scroll_percent,
                            ))
                }
                UiAction::ScrollIntoView => after.offscreen == Some(false),
                UiAction::Focus => after.keyboard_focused == Some(true),
            },
            action != UiAction::Invoke,
        )
    }

    fn set_value(
        &mut self,
        windows: &WindowCatalog,
        input: UiSetValueInput,
        operation: &Operation,
    ) -> Result<UiActionResult> {
        if input.value.encode_utf16().count() > 32768 || input.value.contains('\0') {
            bail!("Value must not contain NUL and must fit in 32768 UTF-16 code units");
        }
        let observe_ms = observation_timeout(input.observe_timeout_ms)?;
        let (reference, window, before) = self.resolve(windows, &input.target, operation)?;
        if before.enabled != Some(true) {
            bail!("The target control is disabled or its enabled state is unavailable");
        }
        super::require_session(Some(window.identity.session_id))?;
        self.prepare(operation)?;
        let use_range = input
            .range
            .unwrap_or(!before.patterns.contains(&UiPattern::Value));
        let number = if use_range {
            let value = input
                .value
                .parse::<f64>()
                .context("Range value must be numeric")?;
            if !value.is_finite() {
                bail!("Range value must be finite");
            }
            Some(value)
        } else {
            None
        };
        let accepted = if let Some(value) = number {
            let pattern = unsafe {
                reference
                    .element
                    .GetCurrentPatternAs::<IUIAutomationRangeValuePattern>(UIA_RangeValuePatternId)
            }
            .context("The target does not support RangeValuePattern")?;
            self.prepare(operation)?;
            if unsafe { pattern.CurrentIsReadOnly() }?.as_bool() {
                bail!("The target range value is read-only");
            }
            self.prepare(operation)?;
            unsafe { pattern.SetValue(value) }
        } else {
            let pattern = unsafe {
                reference
                    .element
                    .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
            }
            .context("The target does not support ValuePattern")?;
            self.prepare(operation)?;
            if unsafe { pattern.CurrentIsReadOnly() }?.as_bool() {
                bail!("The target value is read-only");
            }
            self.prepare(operation)?;
            unsafe { pattern.SetValue(&BSTR::from(&input.value)) }
        };
        self.after_action(
            windows,
            reference,
            window,
            before,
            accepted,
            "Control value equals the requested value".into(),
            observe_ms,
            operation,
            move |_, after| match number {
                Some(number) => after.range_value == Some(number),
                None => after.issues.is_empty() && after.value.as_ref() == Some(&input.value),
            },
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn after_action(
        &mut self,
        windows: &WindowCatalog,
        reference: RetainedRef,
        window: WindowRecord,
        before: UiElement,
        accepted: windows::core::Result<()>,
        postcondition: String,
        observe_ms: u64,
        operation: &Operation,
        condition: impl Fn(&UiElement, &UiElement) -> bool,
        poll: bool,
    ) -> Result<UiActionResult> {
        let mut result = UiActionResult {
            operation_id: operation.id.clone(),
            accepted: Some(true),
            observed: false,
            postcondition,
            before,
            after: None,
            error: None,
            observation_error: None,
        };
        if let Err(error) = accepted {
            result.accepted = None;
            result.error = Some(format!("UI Automation did not confirm acceptance: {error}. A provider timeout does not prove that an action had no effect."));
            return Ok(result);
        }
        let deadline = Instant::now() + Duration::from_millis(observe_ms);
        loop {
            let observed = (|| -> Result<UiElement> {
                self.prepare(operation)?;
                let current_window = windows.resolve(&reference.window_ref)?;
                if current_window.identity != reference.owner {
                    bail!("Window identity changed while observing the action");
                }
                let current = unsafe { reference.element.BuildUpdatedCache(&self.cache) }?;
                let after = self.describe(
                    &current,
                    Some(&window),
                    0,
                    None,
                    &mut HashMap::new(),
                    operation,
                )?;
                if after.runtime_id != reference.runtime_id
                    || after.process.as_ref() != Some(&reference.process)
                    || after.native_window != reference.native_window
                {
                    bail!("Element identity changed while observing the action");
                }
                Ok(after)
            })();
            match observed {
                Ok(after) => {
                    result.observed = condition(&result.before, &after);
                    result.after = Some(after);
                }
                Err(error) => {
                    result.observation_error = Some(format!("{error:#}"));
                    break;
                }
            }
            if result.observed || !poll || Instant::now() >= deadline {
                break;
            }
            if let Err(error) = operation.wait(
                Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
            ) {
                result.observation_error = Some(format!("{error:#}"));
                break;
            }
        }
        Ok(result)
    }

    fn text(
        &mut self,
        windows: &WindowCatalog,
        input: UiTextInput,
        operation: &Operation,
    ) -> Result<UiTextResult> {
        let max_chars = input.max_chars.unwrap_or(4096);
        if !(1..=32768).contains(&max_chars) {
            bail!("max_chars must be in 1..=32768");
        }
        let (reference, _, _) = self.resolve(windows, &input.target, operation)?;
        self.prepare(operation)?;
        let pattern = unsafe {
            reference
                .element
                .GetCurrentPatternAs::<IUIAutomationTextPattern>(UIA_TextPatternId)
        }
        .context("The target does not support TextPattern")?;
        self.prepare(operation)?;
        let range = unsafe { pattern.DocumentRange() }?;
        self.prepare(operation)?;
        let text = unsafe { range.GetText(max_chars as i32 + 1) }?;
        operation.check()?;
        let truncated = text.len() > max_chars as usize;
        let text = String::from_utf16_lossy(&text[..text.len().min(max_chars as usize)]);
        Ok(UiTextResult {
            operation_id: operation.id.clone(),
            element_ref: reference.id,
            text,
            truncated,
            source: "uia_text_pattern",
        })
    }
}

struct NodePosition {
    parent: Option<u32>,
    depth: u32,
}

struct Traversal {
    query: UiQuery,
    max_depth: u32,
    max_nodes: u32,
    max_results: u32,
    process_cache: HashMap<u32, ProcessIdentity>,
    result: UiFindResult,
}

fn move_to_back<T>(entries: &mut VecDeque<T>, index: usize) -> Option<&mut T> {
    let entry = entries.remove(index)?;
    entries.push_back(entry);
    entries.back_mut()
}

fn require_unique(matches: usize, complete: bool) -> Result<()> {
    if matches > 1 {
        bail!("Ambiguous UI query: more than one control matched; use a stable element_ref or a narrower query");
    }
    if !complete {
        bail!("UI query was incomplete; uniqueness or absence could not be established within provider/traversal limits");
    }
    if matches == 0 {
        bail!("No control matches the query");
    }
    Ok(())
}

fn validate_identity(
    expected_window: &WindowIdentity,
    expected_process: &ProcessIdentity,
    window: &WindowIdentity,
    process: &ProcessIdentity,
) -> Result<()> {
    if expected_window != window || expected_process != process {
        bail!("Stale UI reference: window handle or provider process identity was reused");
    }
    Ok(())
}

fn require_native_window(expected: &WindowIdentity, current: &WindowIdentity) -> Result<()> {
    if expected != current {
        bail!(
            "Stale UI reference: the native control HWND was reused or lifetime tracking changed"
        );
    }
    Ok(())
}

fn observation_timeout(timeout: Option<u64>) -> Result<u64> {
    let timeout = timeout.unwrap_or(500);
    if timeout > 10_000 {
        bail!("observe_timeout_ms must be in 0..=10000");
    }
    Ok(timeout)
}

fn scroll_changed(before: Option<f64>, after: Option<f64>) -> bool {
    before.zip(after).is_some_and(|(before, after)| {
        (0.0..=100.0).contains(&before) && (0.0..=100.0).contains(&after) && before != after
    })
}

fn optional_element(
    call: impl FnOnce(&mut *mut std::ffi::c_void) -> HRESULT,
) -> Result<Option<IUIAutomationElement>> {
    // The projected API converts a successful null result into Error::empty.
    // Read the HRESULT and pointer separately so real provider errors are not
    // mistaken for the end of a child/sibling chain.
    let mut output = std::ptr::null_mut();
    let status = call(&mut output);
    let element = (!output.is_null()).then(|| unsafe { IUIAutomationElement::from_raw(output) });
    status.ok().context("UI Automation tree traversal failed")?;
    Ok(element)
}

struct RuntimeArray(*mut SAFEARRAY);

impl Drop for RuntimeArray {
    fn drop(&mut self) {
        if !self.0.is_null() {
            if let Err(error) = unsafe { SafeArrayDestroy(self.0) } {
                tracing::warn!(%error, "Could not release the UI Automation runtime ID");
            }
        }
    }
}

fn runtime_id(element: &IUIAutomationElement) -> Result<Vec<i32>> {
    let array = RuntimeArray(unsafe { element.GetRuntimeId() }?);
    if array.0.is_null() {
        return Ok(Vec::new());
    }
    unsafe {
        if SafeArrayGetDim(array.0) != 1 || SafeArrayGetVartype(array.0)? != VT_I4 {
            bail!("UI Automation returned an invalid runtime ID array");
        }
        let lower = SafeArrayGetLBound(array.0, 1)?;
        let upper = SafeArrayGetUBound(array.0, 1)?;
        let count = i64::from(upper) - i64::from(lower) + 1;
        if !(1..=128).contains(&count) {
            bail!("UI Automation runtime ID exceeds its 128-integer bound");
        }
        let mut values = Vec::with_capacity(count as usize);
        for offset in 0..count {
            let index = i32::try_from(i64::from(lower) + offset)?;
            let mut value = 0i32;
            SafeArrayGetElement(array.0, &index, (&mut value as *mut i32).cast())?;
            values.push(value);
        }
        Ok(values)
    }
}

fn limited_bstr(text: BSTR, limit: usize, issues: &mut Vec<String>) -> String {
    if text.len() > limit && issues.len() < 16 {
        issues.push(format!(
            "Provider text was truncated at {limit} UTF-16 code units"
        ));
    }
    String::from_utf16_lossy(&text[..text.len().min(limit)])
}

fn cached_property(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    issues: &mut Vec<String>,
) -> Option<VARIANT> {
    match unsafe { element.GetCachedPropertyValueEx(property, true) } {
        Ok(value) if value.vt() == VT_EMPTY || value.vt() == VT_UNKNOWN => None,
        Ok(value) => Some(value),
        Err(error) => {
            if issues.len() < 16 {
                issues.push(format!("Property {} unavailable: {error}", property.0));
            }
            None
        }
    }
}

fn property_value<T>(
    value: VARIANT,
    property: UIA_PROPERTY_ID,
    expected: windows::Win32::System::Variant::VARENUM,
    issues: &mut Vec<String>,
    convert: impl FnOnce(&VARIANT) -> windows::core::Result<T>,
) -> Option<T> {
    if value.vt() != expected {
        if issues.len() < 16 {
            issues.push(format!(
                "Property {} has an unexpected provider type",
                property.0
            ));
        }
        return None;
    }
    match convert(&value) {
        Ok(value) => Some(value),
        Err(error) => {
            if issues.len() < 16 {
                issues.push(format!("Property {} cannot be read: {error}", property.0));
            }
            None
        }
    }
}

fn cached_bool(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    issues: &mut Vec<String>,
) -> Option<bool> {
    let value = cached_property(element, property, issues)?;
    property_value(value, property, VT_BOOL, issues, |value| {
        bool::try_from(value)
    })
}

fn cached_integer(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    issues: &mut Vec<String>,
) -> Option<i32> {
    let value = cached_property(element, property, issues)?;
    property_value(value, property, VT_I4, issues, |value| i32::try_from(value))
}

fn cached_number(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    issues: &mut Vec<String>,
) -> Option<f64> {
    let value = cached_property(element, property, issues)?;
    let number = property_value(value, property, VT_R8, issues, |value| f64::try_from(value))?;
    if number.is_finite() {
        Some(number)
    } else {
        issues.push(format!("Property {} is not finite", property.0));
        None
    }
}

fn cached_string(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    issues: &mut Vec<String>,
) -> Option<String> {
    let value = cached_property(element, property, issues)?;
    if value.vt() != VT_BSTR {
        if issues.len() < 16 {
            issues.push(format!(
                "Property {} has an unexpected provider type",
                property.0
            ));
        }
        return None;
    }
    // Borrow the bounded prefix instead of cloning an arbitrarily large BSTR.
    let text: &BSTR = unsafe { &value.Anonymous.Anonymous.Anonymous.bstrVal };
    if text.len() > MAX_STRING && issues.len() < 16 {
        issues.push(format!(
            "Provider text was truncated at {MAX_STRING} UTF-16 code units"
        ));
    }
    Some(String::from_utf16_lossy(
        &text[..text.len().min(MAX_STRING)],
    ))
}

const PATTERNS: &[(UiPattern, UIA_PROPERTY_ID)] = &[
    (UiPattern::Invoke, UIA_IsInvokePatternAvailablePropertyId),
    (UiPattern::Value, UIA_IsValuePatternAvailablePropertyId),
    (
        UiPattern::RangeValue,
        UIA_IsRangeValuePatternAvailablePropertyId,
    ),
    (
        UiPattern::Selection,
        UIA_IsSelectionPatternAvailablePropertyId,
    ),
    (
        UiPattern::SelectionItem,
        UIA_IsSelectionItemPatternAvailablePropertyId,
    ),
    (UiPattern::Toggle, UIA_IsTogglePatternAvailablePropertyId),
    (
        UiPattern::ExpandCollapse,
        UIA_IsExpandCollapsePatternAvailablePropertyId,
    ),
    (UiPattern::Scroll, UIA_IsScrollPatternAvailablePropertyId),
    (
        UiPattern::ScrollItem,
        UIA_IsScrollItemPatternAvailablePropertyId,
    ),
    (UiPattern::Text, UIA_IsTextPatternAvailablePropertyId),
];

const PROPERTIES: &[UIA_PROPERTY_ID] = &[
    UIA_NamePropertyId,
    UIA_AutomationIdPropertyId,
    UIA_ControlTypePropertyId,
    UIA_ClassNamePropertyId,
    UIA_FrameworkIdPropertyId,
    UIA_ProcessIdPropertyId,
    UIA_NativeWindowHandlePropertyId,
    UIA_BoundingRectanglePropertyId,
    UIA_IsEnabledPropertyId,
    UIA_IsOffscreenPropertyId,
    UIA_HasKeyboardFocusPropertyId,
    UIA_IsPasswordPropertyId,
    UIA_ValueValuePropertyId,
    UIA_ValueIsReadOnlyPropertyId,
    UIA_RangeValueValuePropertyId,
    UIA_SelectionItemIsSelectedPropertyId,
    UIA_ToggleToggleStatePropertyId,
    UIA_ExpandCollapseExpandCollapseStatePropertyId,
    UIA_ScrollHorizontalScrollPercentPropertyId,
    UIA_ScrollVerticalScrollPercentPropertyId,
];

const CONTROL_TYPES: &[(i32, &str)] = &[
    (50000, "Button"),
    (50001, "Calendar"),
    (50002, "CheckBox"),
    (50003, "ComboBox"),
    (50004, "Edit"),
    (50005, "Hyperlink"),
    (50006, "Image"),
    (50007, "ListItem"),
    (50008, "List"),
    (50009, "Menu"),
    (50010, "MenuBar"),
    (50011, "MenuItem"),
    (50012, "ProgressBar"),
    (50013, "RadioButton"),
    (50014, "ScrollBar"),
    (50015, "Slider"),
    (50016, "Spinner"),
    (50017, "StatusBar"),
    (50018, "Tab"),
    (50019, "TabItem"),
    (50020, "Text"),
    (50021, "ToolBar"),
    (50022, "ToolTip"),
    (50023, "Tree"),
    (50024, "TreeItem"),
    (50025, "Custom"),
    (50026, "Group"),
    (50027, "Thumb"),
    (50028, "DataGrid"),
    (50029, "DataItem"),
    (50030, "Document"),
    (50031, "SplitButton"),
    (50032, "Window"),
    (50033, "Pane"),
    (50034, "Header"),
    (50035, "HeaderItem"),
    (50036, "Table"),
    (50037, "TitleBar"),
    (50038, "Separator"),
    (50039, "SemanticZoom"),
    (50040, "AppBar"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_or_incomplete_queries_cannot_select_mutation_targets() {
        assert!(require_unique(1, true).is_ok());
        for (count, complete) in [(0, true), (0, false), (1, false), (2, true), (2, false)] {
            assert!(require_unique(count, complete).is_err());
        }
    }

    #[test]
    fn unavailable_query_properties_do_not_prove_uniqueness_or_absence() {
        assert_eq!(match_optional(Some(true), None), QueryMatch::Unknown);
        assert_eq!(match_optional(Some(false), None), QueryMatch::Unknown);
        assert_eq!(match_optional(Some(10u32), None), QueryMatch::Unknown);
        assert_eq!(match_optional(None::<bool>, None), QueryMatch::Match);
        assert_eq!(
            QueryMatch::Match.combine(QueryMatch::Unknown),
            QueryMatch::Unknown
        );
        assert_eq!(
            QueryMatch::NoMatch.combine(QueryMatch::Unknown),
            QueryMatch::NoMatch
        );
        assert_eq!(
            QueryMatch::Unknown.combine(QueryMatch::NoMatch),
            QueryMatch::NoMatch
        );
        assert!(require_unique(1, false).is_err());
    }

    #[test]
    fn a_refreshed_reference_survives_new_entries_in_a_full_cache() {
        let mut cache: VecDeque<usize> = (0..MAX_REFS).collect();
        assert_eq!(*move_to_back(&mut cache, 0).unwrap(), 0);
        cache.pop_front();
        cache.push_back(MAX_REFS);
        assert!(cache.contains(&0));
        assert!(!cache.contains(&1));
        assert_eq!(cache.len(), MAX_REFS);
    }

    #[test]
    fn successful_null_tree_links_are_distinct_from_provider_failures() {
        use windows::Win32::Foundation::{E_POINTER, S_OK};
        assert!(optional_element(|_| S_OK).unwrap().is_none());
        assert!(optional_element(|_| E_POINTER).is_err());
        assert!(optional_element(|_| HRESULT(UIA_E_ELEMENTNOTAVAILABLE as i32)).is_err());
    }

    #[test]
    fn numeric_strings_and_scroll_inputs_are_typed() {
        let input: UiFindInput = serde_json::from_str(r#"{"max_depth":"5","max_nodes":"100","max_results":"10","timeout_ms":"2000","query":{"pid":"123","bounds":{"x":"-100","y":"20","width":"40","height":"50"}}}"#).unwrap();
        assert_eq!(input.max_nodes, Some(100));
        assert_eq!(input.query.unwrap().bounds.unwrap().x, -100);
        assert!(observation_timeout(Some(10_001)).is_err());
        let query = UiQuery {
            control_type: Some("not-a-control".into()),
            ..Default::default()
        };
        assert!(query.validate().is_err());
    }

    #[test]
    fn provider_strings_are_bounded() {
        let mut issues = Vec::new();
        let value = limited_bstr(BSTR::from("abcdefgh"), 4, &mut issues);
        assert_eq!(value, "abcd");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn unsupported_scroll_positions_are_not_observed_movement() {
        assert!(scroll_changed(Some(0.0), Some(20.0)));
        for (before, after) in [
            (None, Some(20.0)),
            (Some(-1.0), Some(0.0)),
            (Some(0.0), Some(-1.0)),
            (Some(10.0), Some(10.0)),
            (Some(f64::NAN), Some(0.0)),
        ] {
            assert!(!scroll_changed(before, after));
        }
    }

    #[test]
    fn a_busy_provider_does_not_start_another_worker() {
        let automation = UiAutomation::default();
        automation.active.store(true, Ordering::Release);
        let result = automation.run(&Operation::new(1000).unwrap(), |_, _| Ok(()));
        assert!(result.is_err());
        assert!(automation.sender.get().is_none());
    }

    #[test]
    fn cancellation_does_not_release_the_worker_until_its_call_returns() {
        let automation = Arc::new(UiAutomation::default());
        let operation = Operation::new(5000).unwrap();
        let (started, started_rx) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::sync_channel(1);
        let worker = automation.clone();
        let running_operation = operation.clone();
        let thread = std::thread::spawn(move || {
            worker.run(&running_operation, move |_, operation| {
                started.send(()).unwrap();
                release_rx.recv().unwrap();
                operation.check()
            })
        });
        started_rx.recv_timeout(Duration::from_secs(4)).unwrap();
        operation.cancellation.cancel().unwrap();
        let busy = automation.run(&Operation::new(1000).unwrap(), |_, _| Ok(()));
        assert!(busy.is_err());
        release.send(()).unwrap();
        assert!(thread.join().unwrap().is_err());
        assert_eq!(
            automation
                .run(&Operation::new(1000).unwrap(), |_, _| Ok(7))
                .unwrap(),
            7
        );
    }

    #[test]
    fn an_unknown_element_reference_fails_without_issuing_input() {
        let automation = UiAutomation::default();
        let windows = Arc::new(WindowCatalog::new());
        let input: UiInvokeInput =
            serde_json::from_str(r#"{"element_ref":"stale-reference"}"#).unwrap();
        let result = automation.invoke(windows, input, &Operation::new(5000).unwrap());
        assert!(format!("{:#}", result.unwrap_err()).contains("Stale or unknown element_ref"));
    }

    #[test]
    fn owned_transparent_controls_support_complete_traversal_value_and_stale_rejection() {
        let windows = Arc::new(WindowCatalog::new());
        let fixture = super::super::windows::Fixture::accessible();
        let window = windows.record_for_hwnd(fixture.hwnd).unwrap();
        let automation = UiAutomation::default();
        let tree = automation
            .find(
                windows.clone(),
                UiFindInput {
                    query: Some(UiQuery {
                        window_ref: Some(window.window_ref.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                &Operation::new(5000).unwrap(),
            )
            .unwrap();
        assert!(tree.complete && !tree.truncated, "{tree:#?}");
        let edit = tree
            .elements
            .iter()
            .find(|node| node.control_type_name == "Edit")
            .expect("The owned EDIT must be reached through its parent");
        let button = tree
            .elements
            .iter()
            .find(|node| node.control_type_name == "Button")
            .expect("The owned BUTTON must be reached through its parent");
        assert!(edit.patterns.contains(&UiPattern::Value), "{edit:#?}");
        assert!(button.patterns.contains(&UiPattern::Invoke), "{button:#?}");
        assert_eq!(edit.value.as_deref(), Some("MCP fixture value"));
        assert_eq!(edit.owner.as_ref(), Some(&window.identity));
        let native_edit = edit.native_window.as_ref().unwrap();
        assert_eq!(native_edit.hwnd, fixture.edit_hwnd);
        let mut reused = native_edit.clone();
        reused.window_generation += 1;
        assert!(require_native_window(native_edit, &reused).is_err());
        reused = native_edit.clone();
        reused.process_created_100ns += 1;
        assert!(require_native_window(native_edit, &reused).is_err());
        let reference = edit.element_ref.clone().unwrap();

        let ambiguous: UiSetValueInput = serde_json::from_value(serde_json::json!({
            "query": {"window_ref": window.window_ref},
            "value": "must not be sent",
        }))
        .unwrap();
        assert!(automation
            .set_value(windows.clone(), ambiguous, &Operation::new(5000).unwrap())
            .is_err());
        let update: UiSetValueInput = serde_json::from_value(serde_json::json!({
            "query": {"window_ref": window.window_ref, "control_type": "Edit"},
            "value": "Updated owned fixture",
            "observe_timeout_ms": "500",
        }))
        .unwrap();
        let changed = automation
            .set_value(windows.clone(), update, &Operation::new(5000).unwrap())
            .unwrap();
        assert_eq!(changed.accepted, Some(true), "{changed:#?}");
        assert!(changed.observed, "{changed:#?}");
        assert_eq!(changed.before.value.as_deref(), Some("MCP fixture value"));
        assert_eq!(
            changed
                .after
                .as_ref()
                .and_then(|node| node.value.as_deref()),
            Some("Updated owned fixture")
        );
        assert_eq!(
            changed.before.element_ref.as_deref(),
            Some(reference.as_str())
        );
        assert_eq!(
            windows.resolve(&window.window_ref).unwrap().identity,
            window.identity
        );

        use windows::Win32::Foundation::{LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{IsWindow, PostMessageW, WM_CLOSE};
        let native_edit = HWND(fixture.edit_hwnd as *mut _);
        unsafe { PostMessageW(Some(native_edit), WM_CLOSE, WPARAM(0), LPARAM(0)) }.unwrap();
        let closing = Operation::new(1000).unwrap();
        while unsafe { IsWindow(Some(native_edit)) }.as_bool() {
            closing.wait(Duration::from_millis(10)).unwrap();
        }
        assert!(windows.resolve(&window.window_ref).is_ok());
        let stale: UiSetValueInput = serde_json::from_value(serde_json::json!({
            "element_ref": reference,
            "value": "must not be sent",
        }))
        .unwrap();
        let error = automation
            .set_value(windows.clone(), stale, &Operation::new(5000).unwrap())
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("Stale UI reference"),
            "{error:#}"
        );
        drop(fixture);
        assert!(windows.resolve(&window.window_ref).is_err());
    }
}
