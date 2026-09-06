use super::Operation;
use crate::win32::display::{DpiScope, Rect};
use ::windows::core::{w, BOOL};
use ::windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, FILETIME, HANDLE, HWND, LPARAM, RECT, WAIT_FAILED,
    WIN32_ERROR, WPARAM,
};
use ::windows::Win32::Graphics::Dwm::{
    DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS,
};
use ::windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use ::windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, GetProcessTimes, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use ::windows::Win32::UI::Accessibility::{
    NotifyWinEvent, SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK,
};
use ::windows::Win32::UI::HiDpi::GetDpiForWindow;
use ::windows::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled;
use ::windows::Win32::UI::WindowsAndMessaging::*;
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError},
    Arc, Mutex, OnceLock,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(test)]
pub(crate) use tests::Fixture;

const MAX_REFS: usize = 2048;
const REF_TTL: Duration = Duration::from_secs(600);
const MAX_TRACKED_WINDOWS: usize = 8192;
const MAX_ENUM_WINDOWS: usize = 8192;
const MAX_ISSUES: usize = 64;
const MAX_TITLE: usize = 4096;
const MAX_CLASS: usize = 256;
const TRACKER_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_PUMP_GAP: Duration = Duration::from_secs(2);
const TRACKER_WAKE: u32 = WM_APP + 71;

pub(crate) fn serialize_u64<S: serde::Serializer>(
    value: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
pub(crate) struct ProcessIdentity {
    #[serde(deserialize_with = "crate::coerce::num")]
    pub pid: u32,
    #[serde(
        serialize_with = "serialize_u64",
        deserialize_with = "crate::coerce::num"
    )]
    #[schemars(with = "String")]
    pub process_created_100ns: u64,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub session_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
pub(crate) struct WindowIdentity {
    #[serde(deserialize_with = "crate::coerce::num")]
    pub hwnd: u64,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub pid: u32,
    #[serde(
        serialize_with = "serialize_u64",
        deserialize_with = "crate::coerce::num"
    )]
    #[schemars(with = "String")]
    pub process_created_100ns: u64,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub session_id: u32,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub thread_id: u32,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub tracker_epoch: u64,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub window_generation: u64,
}

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct WindowQuery {
    #[schemars(description = "Case-insensitive title substring, up to 4096 UTF-16 code units.")]
    pub title: Option<String>,
    #[schemars(description = "Exact, case-sensitive native class name.")]
    pub class_name: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub pid: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub process_created_100ns: Option<u64>,
    #[schemars(
        description = "Visibility equality filter. Omitted means true; false selects only hidden windows."
    )]
    pub visible: Option<bool>,
}

impl WindowQuery {
    fn validate(&self) -> Result<()> {
        if self
            .title
            .as_ref()
            .is_some_and(|title| title.encode_utf16().count() > MAX_TITLE || title.contains('\0'))
        {
            bail!("title must contain at most {MAX_TITLE} UTF-16 code units and no NUL");
        }
        if self.class_name.as_ref().is_some_and(|name| {
            name.is_empty() || name.encode_utf16().count() > MAX_CLASS || name.contains('\0')
        }) {
            bail!("class_name must contain 1..={MAX_CLASS} UTF-16 code units and no NUL");
        }
        if self.pid == Some(0) || self.process_created_100ns == Some(0) {
            bail!("pid and process_created_100ns must be nonzero when specified");
        }
        Ok(())
    }

    fn matches(&self, record: &WindowRecord) -> Result<bool> {
        let known_fields = self.visible.unwrap_or(true) == record.visible
            && self.pid.is_none_or(|pid| pid == record.identity.pid)
            && self
                .process_created_100ns
                .is_none_or(|created| created == record.identity.process_created_100ns)
            && self
                .class_name
                .as_ref()
                .is_none_or(|class| class == &record.class_name);
        if !known_fields {
            return Ok(false);
        }
        if let Some(title) = &self.title {
            if !record.title.to_lowercase().contains(&title.to_lowercase()) {
                if record.title_truncated {
                    bail!("Title is truncated; this query cannot establish a non-match");
                }
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Default, Clone, Deserialize, schemars::JsonSchema)]
pub(crate) struct WindowListInput {
    pub query: Option<WindowQuery>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    #[schemars(range(min = 1, max = 512))]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WindowRecord {
    pub window_ref: String,
    pub identity: WindowIdentity,
    pub title: String,
    pub title_truncated: bool,
    pub class_name: String,
    pub bounds: Rect,
    pub visible: bool,
    pub minimized: bool,
    pub maximized: bool,
    pub enabled: bool,
    pub cloaked: bool,
    pub dpi: u32,
    pub bounds_source: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WindowListResult {
    pub windows: Vec<WindowRecord>,
    pub truncated: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WindowAction {
    Focus,
    Move,
    Resize,
    Minimize,
    Maximize,
    Restore,
    Close,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct WindowManageInput {
    #[schemars(
        description = "Preferred selector: a live opaque window_ref issued by this connection."
    )]
    pub window_ref: Option<String>,
    #[schemars(
        description = "Alternative selector. An incomplete query or more than one match is rejected."
    )]
    pub query: Option<WindowQuery>,
    pub action: WindowAction,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    #[schemars(
        description = "Move only: physical screen X of the visible frame, including negative monitor coordinates."
    )]
    pub x: Option<i32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    #[schemars(description = "Move only: physical screen Y of the visible frame.")]
    pub y: Option<i32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    #[schemars(
        description = "Resize only: physical visible-frame width in pixels, not client-area width."
    )]
    pub width: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    #[schemars(
        description = "Resize only: physical visible-frame height in pixels, not client-area height."
    )]
    pub height: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub session_id: Option<u32>,
}

impl WindowManageInput {
    fn validate(&self) -> Result<()> {
        if self.window_ref.is_some() == self.query.is_some() {
            bail!("Specify exactly one of window_ref or query; prefer an explicit window_ref");
        }
        if let Some(reference) = &self.window_ref {
            validate_reference(reference)?;
        }
        if let Some(query) = &self.query {
            query.validate()?;
        }
        validate_timeout(self.timeout_ms)?;
        match self.action {
            WindowAction::Move => {
                if self.x.is_none()
                    || self.y.is_none()
                    || self.width.is_some()
                    || self.height.is_some()
                {
                    bail!("move requires x and y, and does not accept width or height");
                }
            }
            WindowAction::Resize => {
                if self.x.is_some()
                    || self.y.is_some()
                    || self.width.is_none()
                    || self.height.is_none()
                {
                    bail!("resize requires width and height, and does not accept x or y");
                }
                if [self.width.unwrap_or(0), self.height.unwrap_or(0)]
                    .iter()
                    .any(|size| *size == 0 || *size > i32::MAX as u32)
                {
                    bail!("width and height must be in 1..=2147483647");
                }
            }
            _ => {
                if self.x.is_some()
                    || self.y.is_some()
                    || self.width.is_some()
                    || self.height.is_some()
                {
                    bail!("Coordinates and sizes are accepted only by move and resize");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct WindowActionResult {
    pub accepted: bool,
    pub observed: bool,
    pub action: WindowAction,
    pub window: Option<WindowRecord>,
    pub postcondition: String,
    pub limitations: Vec<String>,
    pub error: Option<String>,
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub(crate) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    if pid == 0 {
        bail!("Unsupported process identity: PID 0");
    }
    let handle = ProcessHandle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .with_context(|| format!("Unsupported process identity: OpenProcess for PID {pid}"))?,
    );
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(handle.0, &mut created, &mut exit, &mut kernel, &mut user) }
        .with_context(|| format!("Unsupported process identity: GetProcessTimes for PID {pid}"))?;
    let process_created_100ns =
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if process_created_100ns == 0 {
        bail!("Unsupported process identity: PID {pid} has no creation timestamp");
    }
    if exit.dwHighDateTime != 0 || exit.dwLowDateTime != 0 {
        bail!("Process identity is stale: PID {pid} has exited");
    }
    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(pid, &mut session_id) }
        .with_context(|| format!("Unsupported process identity: session for PID {pid}"))?;
    Ok(ProcessIdentity {
        pid,
        process_created_100ns,
        session_id,
    })
}

fn current_session(requested: Option<u32>) -> Result<u32> {
    let mut session = 0;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }
        .context("Cannot determine this process's Windows session")?;
    if requested.is_some_and(|requested| requested != session) {
        bail!("Unsupported Windows session; this catalog can access only session {session}");
    }
    Ok(session)
}

fn validate_timeout(timeout: Option<u64>) -> Result<()> {
    if timeout.is_some_and(|timeout| !(1..=120_000).contains(&timeout)) {
        bail!("timeout_ms must be in 1..=120000");
    }
    Ok(())
}

fn native_handle(value: u64) -> Result<HWND> {
    let value = usize::try_from(value).context("HWND exceeds this process's pointer width")?;
    if value == 0 || value > isize::MAX as usize {
        bail!("Invalid native window handle");
    }
    Ok(HWND(value as *mut _))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Lifetime {
    epoch: u64,
    generation: u64,
    alive: bool,
}

struct LifetimeState {
    epoch: u64,
    next_generation: u64,
    windows: HashMap<u64, Lifetime>,
    last_pump: Instant,
    sentinel: u64,
    fence_seen: bool,
    failed: bool,
}

impl LifetimeState {
    fn new(sentinel: u64) -> Self {
        Self {
            epoch: 1,
            next_generation: 0,
            windows: HashMap::new(),
            last_pump: Instant::now(),
            sentinel,
            fence_seen: false,
            failed: false,
        }
    }

    fn invalidate(&mut self) {
        match self.epoch.checked_add(1) {
            Some(epoch) => self.epoch = epoch,
            None => self.failed = true,
        }
        self.windows.clear();
    }

    fn note_pump(&mut self) {
        if self.last_pump.elapsed() > MAX_PUMP_GAP {
            self.invalidate();
        }
        self.last_pump = Instant::now();
    }

    fn generation(&mut self) -> u64 {
        match self.next_generation.checked_add(1) {
            Some(generation) => self.next_generation = generation,
            None => self.failed = true,
        }
        self.next_generation
    }

    fn event(&mut self, hwnd: u64, event: u32) {
        if self.windows.contains_key(&hwnd) {
            let generation = self.generation();
            self.windows.insert(
                hwnd,
                Lifetime {
                    epoch: self.epoch,
                    generation,
                    alive: event == EVENT_OBJECT_CREATE,
                },
            );
        }
    }

    fn snapshot(&mut self, hwnd: u64, alive: bool) -> Result<Lifetime> {
        if self.failed {
            bail!("Unsupported window identity: lifetime tracker failed");
        }
        if let Some(lifetime) = self.windows.get(&hwnd) {
            if lifetime.alive == alive {
                return Ok(*lifetime);
            }
        }
        if !self.windows.contains_key(&hwnd) && self.windows.len() >= MAX_TRACKED_WINDOWS {
            self.invalidate();
        }
        let lifetime = Lifetime {
            epoch: self.epoch,
            generation: self.generation(),
            alive,
        };
        if self.failed {
            bail!("Unsupported window identity: lifetime generation exhausted");
        }
        self.windows.insert(hwnd, lifetime);
        Ok(lifetime)
    }
}

thread_local! {
    static LIFETIMES: RefCell<Option<LifetimeState>> = const { RefCell::new(None) };
    static TRACKER_GAP: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "system" fn lifetime_event(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    object: i32,
    child: i32,
    _thread: u32,
    _event_time: u32,
) {
    if object != OBJID_WINDOW.0 || child != CHILDID_SELF as i32 || hwnd.is_invalid() {
        return;
    }
    LIFETIMES.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            TRACKER_GAP.with(|gap| gap.set(true));
            return;
        };
        let Some(state) = slot.as_mut() else {
            return;
        };
        let value = hwnd.0 as u64;
        if value == state.sentinel {
            if event == EVENT_OBJECT_NAMECHANGE {
                state.fence_seen = true;
            }
        } else if event == EVENT_OBJECT_CREATE || event == EVENT_OBJECT_DESTROY {
            state.event(value, event);
        }
    });
}

fn with_lifetimes<T>(work: impl FnOnce(&mut LifetimeState) -> Result<T>) -> Result<T> {
    LIFETIMES.with(|slot| {
        let mut slot = slot.borrow_mut();
        let state = slot
            .as_mut()
            .context("Unsupported window identity: no lifetime tracker")?;
        if TRACKER_GAP.with(|gap| gap.replace(false)) {
            state.invalidate();
        }
        state.note_pump();
        if state.failed {
            bail!("Unsupported window identity: lifetime tracker failed");
        }
        work(state)
    })
}

struct TrackerResources {
    hook: HWINEVENTHOOK,
    sentinel: HWND,
}

impl Drop for TrackerResources {
    fn drop(&mut self) {
        unsafe {
            let _ = UnhookWinEvent(self.hook);
            let _ = DestroyWindow(self.sentinel);
        }
        LIFETIMES.with(|slot| *slot.borrow_mut() = None);
    }
}

struct LifetimeRequest {
    hwnd: u64,
    deadline: Instant,
    reply: SyncSender<std::result::Result<Lifetime, String>>,
}

struct Tracker {
    sender: SyncSender<LifetimeRequest>,
    thread_id: u32,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Tracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        unsafe {
            let _ = PostThreadMessageW(self.thread_id, TRACKER_WAKE, WPARAM(0), LPARAM(0));
        }
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _ = worker.join();
            }
        }
    }
}

impl Tracker {
    fn global() -> Result<&'static Self> {
        // All catalogs share one hook owner. Repeated clients cannot create
        // additional tracking threads, including after an initialization failure.
        static TRACKER: OnceLock<std::result::Result<Tracker, String>> = OnceLock::new();
        TRACKER
            .get_or_init(|| Self::start().map_err(|error| format!("{error:#}")))
            .as_ref()
            .map_err(|error| anyhow::anyhow!("Unsupported window identity: {error}"))
    }

    fn start() -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(64);
        let (ready, startup) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::Builder::new()
            .name("desktop-window-lifetimes".into())
            .spawn(move || {
                let result = tracker_worker(receiver, &ready, &worker_stop);
                if let Err(error) = result {
                    let _ = ready.try_send(Err(format!("{error:#}")));
                    tracing::warn!("Window lifetime tracker stopped: {error:#}");
                }
                worker_stop.store(true, Ordering::Release);
            })
            .context("Cannot start the window lifetime tracker")?;
        match startup.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(thread_id)) => Ok(Self {
                sender,
                thread_id,
                stop,
                worker: Mutex::new(Some(worker)),
            }),
            failure => {
                stop.store(true, Ordering::Release);
                let _ = worker.join();
                match failure {
                    Ok(Err(error)) => bail!("{error}"),
                    _ => bail!("Window lifetime tracker initialization timed out or disconnected"),
                }
            }
        }
    }

    fn snapshot(&self, hwnd: u64, operation: Option<&Operation>) -> Result<Lifetime> {
        check(operation)?;
        if self.stop.load(Ordering::Acquire) {
            bail!("Unsupported window identity: lifetime tracker is unavailable");
        }
        let timeout = operation
            .map(|operation| operation.remaining().min(TRACKER_TIMEOUT))
            .unwrap_or(TRACKER_TIMEOUT);
        let deadline = Instant::now() + timeout;
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .try_send(LifetimeRequest {
                hwnd,
                deadline,
                reply,
            })
            .map_err(|_| {
                anyhow::anyhow!("Unsupported window identity: lifetime tracker busy or stopped")
            })?;
        unsafe { PostThreadMessageW(self.thread_id, TRACKER_WAKE, WPARAM(0), LPARAM(0)) }
            .context("Cannot wake the window lifetime tracker")?;
        loop {
            check(operation)?;
            match response.try_recv() {
                Ok(result) => return result.map_err(anyhow::Error::msg),
                Err(TryRecvError::Disconnected) => {
                    bail!("Unsupported window identity: lifetime tracker disconnected")
                }
                Err(TryRecvError::Empty) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("Unsupported window identity: lifetime tracking could not be synchronized");
            }
            if let Some(operation) = operation {
                operation.wait(remaining.min(Duration::from_millis(2)))?;
            } else {
                return response
                    .recv_timeout(remaining)
                    .context("Unsupported window identity: lifetime tracker response timed out")?
                    .map_err(anyhow::Error::msg);
            }
        }
    }
}

fn pump_tracker_messages() -> Result<()> {
    let mut message = MSG::default();
    for _ in 0..4096 {
        if !unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            return Ok(());
        }
        if message.message == WM_QUIT {
            bail!("Window lifetime tracker received WM_QUIT");
        }
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    bail!("Window lifetime tracker message queue exceeded its bounded drain")
}

fn tracker_fence(resources: &TrackerResources, stop: &AtomicBool) -> Result<()> {
    with_lifetimes(|state| {
        state.fence_seen = false;
        Ok(())
    })?;
    // An out-of-context WinEvent hook queues events in order. A notification
    // on our message-only window fences queued create/destroy events without
    // sending messages or adding properties to another application's HWND.
    unsafe {
        NotifyWinEvent(
            EVENT_OBJECT_NAMECHANGE,
            resources.sentinel,
            OBJID_WINDOW.0,
            CHILDID_SELF as i32,
        );
    }
    let deadline = Instant::now() + TRACKER_TIMEOUT;
    loop {
        pump_tracker_messages()?;
        if with_lifetimes(|state| Ok(state.fence_seen))? {
            return Ok(());
        }
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            bail!("Window lifetime event fence failed; retained identities are no longer usable");
        }
        let wait =
            unsafe { MsgWaitForMultipleObjectsEx(None, 10, QS_ALLINPUT, MWMO_INPUTAVAILABLE) };
        if wait == WAIT_FAILED {
            bail!("Window lifetime tracker message wait failed");
        }
    }
}

fn tracker_worker(
    receiver: Receiver<LifetimeRequest>,
    ready: &SyncSender<std::result::Result<u32, String>>,
    stop: &AtomicBool,
) -> Result<()> {
    let sentinel = unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            w!("STATIC"),
            w!("MCP window identity fence"),
            WINDOW_STYLE(0),
            0,
            0,
            1,
            1,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
    }
    .context("Cannot create the window lifetime tracker's message-only window")?;
    LIFETIMES.with(|slot| *slot.borrow_mut() = Some(LifetimeState::new(sentinel.0 as u64)));
    let hook = unsafe {
        SetWinEventHook(
            EVENT_OBJECT_CREATE,
            EVENT_OBJECT_NAMECHANGE,
            None,
            Some(lifetime_event),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    let resources = TrackerResources { hook, sentinel };
    if hook.is_invalid() {
        bail!(
            "SetWinEventHook failed: {}",
            ::windows::core::Error::from_thread()
        );
    }
    tracker_fence(&resources, stop)?;
    ready
        .send(Ok(unsafe { GetCurrentThreadId() }))
        .context("Window lifetime tracker startup was abandoned")?;
    while !stop.load(Ordering::Acquire) {
        pump_tracker_messages()?;
        with_lifetimes(|_| Ok(()))?;
        match receiver.try_recv() {
            Ok(request) => {
                if Instant::now() >= request.deadline {
                    let _ = request
                        .reply
                        .try_send(Err("Window identity request expired".into()));
                    continue;
                }
                tracker_fence(&resources, stop)?;
                let alive = unsafe { IsWindow(Some(native_handle(request.hwnd)?)) }.as_bool();
                let result = with_lifetimes(|state| state.snapshot(request.hwnd, alive));
                let _ = request
                    .reply
                    .try_send(result.map_err(|error| format!("{error:#}")));
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {
                let wait = unsafe {
                    MsgWaitForMultipleObjectsEx(None, 25, QS_ALLINPUT, MWMO_INPUTAVAILABLE)
                };
                if wait == WAIT_FAILED {
                    bail!("Window lifetime tracker message wait failed");
                }
            }
        }
    }
    Ok(())
}

struct RetainedWindow {
    reference: String,
    identity: WindowIdentity,
    touched: Instant,
}

#[derive(Default)]
struct References(VecDeque<RetainedWindow>);

impl References {
    fn prune(&mut self) {
        self.0.retain(|entry| entry.touched.elapsed() < REF_TTL);
    }

    fn get(&mut self, reference: &str) -> Result<WindowIdentity> {
        self.prune();
        self.0
            .iter()
            .find(|entry| entry.reference == reference)
            .map(|entry| entry.identity.clone())
            .context("Stale or unknown window_ref; list or find the window again")
    }

    fn retain(&mut self, identity: &WindowIdentity) -> String {
        self.prune();
        let reference = self
            .0
            .iter()
            .find(|entry| &entry.identity == identity)
            .map(|entry| entry.reference.clone())
            .unwrap_or_else(|| format!("window_{}", uuid::Uuid::new_v4()));
        self.0.retain(|entry| entry.identity.hwnd != identity.hwnd);
        while self.0.len() >= MAX_REFS {
            self.0.pop_front();
        }
        self.0.push_back(RetainedWindow {
            reference: reference.clone(),
            identity: identity.clone(),
            touched: Instant::now(),
        });
        reference
    }
}

pub(crate) struct WindowCatalog {
    references: Mutex<References>,
}

impl WindowCatalog {
    pub(crate) fn new() -> Self {
        let _ = Tracker::global();
        Self {
            references: Mutex::new(References::default()),
        }
    }

    pub(crate) fn record_for_hwnd(&self, hwnd: u64) -> Result<WindowRecord> {
        let hwnd = native_handle(hwnd)?;
        let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
        if root.is_invalid() {
            bail!(
                "Unsupported window identity: HWND {:#x} has no live top-level ancestor",
                hwnd.0 as u64
            );
        }
        let record = self.record(root.0 as u64, None, None)?;
        if unsafe { GetAncestor(hwnd, GA_ROOT) } != root {
            bail!("Window ancestry changed during observation; find the control again");
        }
        Ok(record)
    }

    pub(crate) fn resolve(&self, window_ref: &str) -> Result<WindowRecord> {
        self.resolve_with_operation(window_ref, None)
    }

    fn resolve_with_operation(
        &self,
        reference: &str,
        operation: Option<&Operation>,
    ) -> Result<WindowRecord> {
        validate_reference(reference)?;
        let identity = self
            .references
            .lock()
            .map_err(|_| anyhow::anyhow!("Window reference store poisoned"))?
            .get(reference)?;
        let record = self.record(identity.hwnd, Some(&identity), operation)?;
        if record.window_ref != reference {
            bail!("Stale window_ref: the reference expired or was evicted during resolution");
        }
        Ok(record)
    }

    fn record(
        &self,
        value: u64,
        expected: Option<&WindowIdentity>,
        operation: Option<&Operation>,
    ) -> Result<WindowRecord> {
        check(operation)?;
        let hwnd = native_handle(value)?;
        let _dpi = DpiScope::enter()?;
        let identity = read_identity(hwnd, operation)?;
        if let Some(expected) = expected {
            require_same_identity(expected, &identity)?;
        }
        let title = window_title(hwnd)?;
        let class_name = window_class(hwnd)?;
        let mut limitations = Vec::new();
        if title.truncated {
            limitations.push(format!(
                "Window title was truncated at {MAX_TITLE} UTF-16 code units"
            ));
        }
        limitations.push(
            "Title is cached caption text; application WM_GETTEXT handlers are never called".into(),
        );
        let (bounds, bounds_source) = frame_bounds(hwnd, &mut limitations)?;
        let mut cloaked_value: u32 = 0;
        let cloaked = match unsafe {
            DwmGetWindowAttribute(
                hwnd,
                DWMWA_CLOAKED,
                &mut cloaked_value as *mut _ as *mut _,
                std::mem::size_of_val(&cloaked_value) as u32,
            )
        } {
            Ok(()) => cloaked_value != 0,
            Err(error) => {
                limitations.push(format!(
                    "DWM cloaking state unavailable ({error}); treated as cloaked to prevent unsafe capture"
                ));
                true
            }
        };
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        if dpi == 0 {
            bail!("DPI is unavailable for HWND {value:#x}");
        }
        let visible = unsafe { IsWindowVisible(hwnd) }.as_bool();
        let minimized = unsafe { IsIconic(hwnd) }.as_bool();
        let maximized = unsafe { IsZoomed(hwnd) }.as_bool();
        let enabled = unsafe { IsWindowEnabled(hwnd) }.as_bool();
        if unsafe { GetAncestor(hwnd, GA_ROOT) } != hwnd {
            limitations
                .push("Child window: native window management requires a top-level HWND".into());
        }
        let after = read_identity(hwnd, operation)?;
        require_same_identity(&identity, &after)?;
        check(operation)?;
        let window_ref = self
            .references
            .lock()
            .map_err(|_| anyhow::anyhow!("Window reference store poisoned"))?
            .retain(&identity);
        Ok(WindowRecord {
            window_ref,
            identity,
            title: title.text,
            title_truncated: title.truncated,
            class_name,
            bounds,
            visible,
            minimized,
            maximized,
            enabled,
            cloaked,
            dpi,
            bounds_source,
            limitations,
        })
    }

    pub(crate) fn list(
        &self,
        input: &WindowListInput,
        operation: &Operation,
    ) -> Result<WindowListResult> {
        operation.check()?;
        validate_timeout(input.timeout_ms)?;
        current_session(input.session_id)?;
        let query = input.query.clone().unwrap_or_default();
        query.validate()?;
        let limit = input.limit.unwrap_or(50);
        if !(1..=512).contains(&limit) {
            bail!("limit must be in 1..=512");
        }
        let _dpi = DpiScope::enter()?;
        let mut enumeration = Enumeration {
            handles: Vec::new(),
            operation,
            truncated: false,
            error: None,
        };
        let enumerated = unsafe {
            EnumWindows(
                Some(enumerate_window),
                LPARAM(&mut enumeration as *mut _ as isize),
            )
        };
        if let Some(error) = enumeration.error {
            return Err(error);
        }
        if !enumeration.truncated {
            enumerated.context("Native top-level window enumeration failed")?;
        }
        let mut result = WindowListResult {
            windows: Vec::new(),
            truncated: enumeration.truncated,
            issues: Vec::new(),
        };
        if enumeration.truncated {
            add_issue(
                &mut result,
                format!("Window enumeration exceeded the {MAX_ENUM_WINDOWS}-HWND bound"),
            );
        }
        let needle = query.title.as_ref().map(|title| title.to_lowercase());
        for hwnd in enumeration.handles {
            operation.check()?;
            let mut pid = 0;
            let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
            if thread == 0 {
                add_issue(
                    &mut result,
                    format!(
                        "HWND {:#x}: window disappeared during enumeration",
                        hwnd.0 as u64
                    ),
                );
                continue;
            }
            if query.pid.is_some_and(|filter| filter != pid)
                || query.visible.unwrap_or(true) != unsafe { IsWindowVisible(hwnd) }.as_bool()
            {
                continue;
            }
            let candidate = (|| -> Result<bool> {
                if let Some(class) = &query.class_name {
                    if &window_class(hwnd)? != class {
                        return Ok(false);
                    }
                }
                if let Some(needle) = &needle {
                    let title = window_title(hwnd)?;
                    if !title.text.to_lowercase().contains(needle) {
                        if title.truncated {
                            bail!("Title is truncated; this query cannot establish a non-match");
                        }
                        return Ok(false);
                    }
                }
                Ok(true)
            })();
            match candidate {
                Ok(false) => continue,
                Err(error) => {
                    add_issue(
                        &mut result,
                        format!("HWND {:#x}, PID {pid}: {error:#}", hwnd.0 as u64),
                    );
                    continue;
                }
                Ok(true) => {}
            }
            let candidate = self
                .record(hwnd.0 as u64, None, Some(operation))
                .and_then(|record| query.matches(&record).map(|matched| (record, matched)));
            match candidate {
                Ok((record, true)) => {
                    if result.windows.len() >= limit as usize {
                        result.truncated = true;
                        break;
                    }
                    result.windows.push(record);
                }
                Ok((_, false)) => {}
                Err(error) => {
                    operation.check()?;
                    add_issue(
                        &mut result,
                        format!("HWND {:#x}, PID {pid}: {error:#}", hwnd.0 as u64),
                    );
                }
            }
        }
        operation.check()?;
        Ok(result)
    }

    pub(crate) fn manage(
        &self,
        input: WindowManageInput,
        operation: &Operation,
    ) -> Result<WindowActionResult> {
        input.validate()?;
        operation.check()?;
        current_session(input.session_id)?;
        let selected = match &input.window_ref {
            Some(reference) => self.resolve_with_operation(reference, Some(operation))?,
            None => {
                let found = self.list(
                    &WindowListInput {
                        query: input.query.clone(),
                        limit: Some(2),
                        timeout_ms: input.timeout_ms,
                        session_id: input.session_id,
                    },
                    operation,
                )?;
                require_unique(&found)?;
                found
                    .windows
                    .into_iter()
                    .next()
                    .context("No window matches the query")?
            }
        };
        let _dpi = DpiScope::enter()?;
        let before = self.resolve_with_operation(&selected.window_ref, Some(operation))?;
        if let Some(query) = &input.query {
            if !query.matches(&before)? {
                bail!("Window changed after selection and no longer matches the query");
            }
        }
        let hwnd = native_handle(before.identity.hwnd)?;
        if unsafe { GetAncestor(hwnd, GA_ROOT) } != hwnd {
            bail!("Unsupported window action: select a top-level window, not a child HWND");
        }
        if matches!(input.action, WindowAction::Move | WindowAction::Resize)
            && (before.minimized || before.maximized)
        {
            bail!("Restore the window before moving or resizing its physical frame");
        }
        if input.action == WindowAction::Focus
            && (!before.visible || before.minimized || before.cloaked || !before.enabled)
        {
            bail!("Focus requires a visible, restored, enabled, uncloaked window");
        }
        let target = target_bounds(&input, before.bounds)?;
        let mut geometry = if matches!(input.action, WindowAction::Move | WindowAction::Resize) {
            Some(native_geometry(hwnd, &before.bounds, &target)?)
        } else {
            None
        };
        let postcondition = postcondition(&input, &target);
        let mut result = WindowActionResult {
            accepted: false,
            observed: false,
            action: input.action,
            window: Some(before.clone()),
            postcondition,
            limitations: vec![
                "Acceptance is the native API result, not proof of application completion".into(),
                "Win32 cannot atomically pin an external HWND between identity validation and use"
                    .into(),
            ],
            error: None,
        };
        let identity = read_identity(hwnd, Some(operation))?;
        require_same_identity(&before.identity, &identity)?;
        operation.check()?;
        let accepted = unsafe {
            match input.action {
                WindowAction::Focus => {
                    if GetForegroundWindow() == hwnd || SetForegroundWindow(hwnd).as_bool() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!(
                            "SetForegroundWindow was denied; Windows foreground activation policy was not bypassed"
                        ))
                    }
                }
                WindowAction::Move | WindowAction::Resize => {
                    let geometry = geometry.context("Missing native geometry")?;
                    set_native_geometry(hwnd, input.action, geometry)
                }
                WindowAction::Minimize | WindowAction::Maximize | WindowAction::Restore => {
                    let command = match input.action {
                        WindowAction::Minimize => SW_MINIMIZE,
                        WindowAction::Maximize => SW_MAXIMIZE,
                        _ => SW_RESTORE,
                    };
                    if ShowWindowAsync(hwnd, command).as_bool() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!(
                            "ShowWindowAsync did not accept the window state request"
                        ))
                    }
                }
                WindowAction::Close => PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0))
                    .context("WM_CLOSE could not be posted; the process was not terminated"),
            }
        };
        if let Err(error) = accepted {
            result.error = Some(format!("{error:#}"));
            return Ok(result);
        }
        result.accepted = true;
        if input.action == WindowAction::Close {
            return Ok(poll_close(result, operation, || {
                if original_is_gone(&before.identity, Some(operation))? {
                    Ok(None)
                } else {
                    self.resolve_with_operation(&before.window_ref, Some(operation))
                        .map(Some)
                }
            }));
        }
        let mut corrections = 0;
        loop {
            if let Err(error) = operation.check() {
                result.error = Some(format!(
                    "{error:#}; the accepted action may have taken effect"
                ));
                return Ok(result);
            }
            match self.resolve_with_operation(&before.window_ref, Some(operation)) {
                Ok(current) => {
                    result.observed = action_observed(input.action, &current, &target);
                    if !result.observed && corrections < 2 {
                        if let Some(previous) = geometry {
                            // Moving between DPI domains can change invisible
                            // frame insets. Correct only a changed inset, not
                            // an application's minimum-size or position policy.
                            let correction = (|| -> Result<Option<Rect>> {
                                if current.minimized || current.maximized {
                                    bail!("The window is no longer restored");
                                }
                                let target = target_bounds(&input, current.bounds)?;
                                let adjusted = native_geometry(hwnd, &current.bounds, &target)?;
                                if !geometry_changed(input.action, previous, adjusted) {
                                    return Ok(None);
                                }
                                let identity = read_identity(hwnd, Some(operation))?;
                                require_same_identity(&before.identity, &identity)?;
                                operation.check()?;
                                set_native_geometry(hwnd, input.action, adjusted)?;
                                Ok(Some(adjusted))
                            })();
                            match correction {
                                Ok(Some(adjusted)) => {
                                    geometry = Some(adjusted);
                                    corrections += 1;
                                    result.limitations.push(format!(
                                        "Frame insets changed; issued physical geometry correction {corrections}/2"
                                    ));
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    result.window = Some(current);
                                    result.error = Some(format!(
                                        "The accepted geometry request could not be corrected: {error:#}"
                                    ));
                                    return Ok(result);
                                }
                            }
                        }
                    }
                    result.window = Some(current);
                    if result.observed {
                        return Ok(result);
                    }
                }
                Err(error) => {
                    result.window = None;
                    result.error = Some(format!("Postcondition could not be verified: {error:#}"));
                    return Ok(result);
                }
            }
            if let Err(error) = operation.wait(Duration::from_millis(25)) {
                result.error = Some(format!(
                    "{error:#}; the requested postcondition was not observed, and the accepted action may still take effect"
                ));
                return Ok(result);
            }
        }
    }
}

fn check(operation: Option<&Operation>) -> Result<()> {
    if let Some(operation) = operation {
        operation.check()?;
    }
    Ok(())
}

fn validate_reference(reference: &str) -> Result<()> {
    if reference.len() != 43
        || !reference.starts_with("window_")
        || uuid::Uuid::parse_str(&reference[7..]).is_err()
    {
        bail!("Stale or unknown window_ref; use an opaque reference returned by this connection");
    }
    Ok(())
}

fn require_same_identity(expected: &WindowIdentity, actual: &WindowIdentity) -> Result<()> {
    if expected.tracker_epoch != actual.tracker_epoch {
        bail!("Stale window_ref: lifetime tracking was interrupted or its bounded cache was reset");
    }
    if expected != actual {
        bail!("Stale window_ref: the window was destroyed, its HWND was reused, or its process restarted");
    }
    Ok(())
}

pub(crate) fn read_identity(hwnd: HWND, operation: Option<&Operation>) -> Result<WindowIdentity> {
    let value = hwnd.0 as u64;
    let lifetime = Tracker::global()?.snapshot(value, operation)?;
    if !lifetime.alive {
        bail!("Stale window identity: HWND {value:#x} no longer exists");
    }
    let mut pid = 0;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if thread_id == 0 || pid == 0 {
        bail!("Stale window identity: HWND {value:#x} has no owning thread or process");
    }
    let process = process_identity(pid)
        .with_context(|| format!("Cannot identify HWND {value:#x}, PID {pid}"))?;
    if process.session_id != current_session(None)? {
        bail!("Unsupported window identity: HWND {value:#x}, PID {pid} is in another session");
    }
    let mut final_pid = 0;
    let final_thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut final_pid)) };
    if final_pid != pid || final_thread != thread_id {
        bail!("Stale window identity: HWND {value:#x} changed owners during observation");
    }
    if Tracker::global()?.snapshot(value, operation)? != lifetime {
        bail!("Stale window identity: HWND {value:#x} changed lifetime during observation");
    }
    Ok(WindowIdentity {
        hwnd: value,
        pid,
        process_created_100ns: process.process_created_100ns,
        session_id: process.session_id,
        thread_id,
        tracker_epoch: lifetime.epoch,
        window_generation: lifetime.generation,
    })
}

fn original_is_gone(expected: &WindowIdentity, operation: Option<&Operation>) -> Result<bool> {
    check(operation)?;
    let hwnd = native_handle(expected.hwnd)?;
    if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
        return Ok(true);
    }
    let current = match read_identity(hwnd, operation) {
        Ok(current) => current,
        Err(_) if !unsafe { IsWindow(Some(hwnd)) }.as_bool() => return Ok(true),
        Err(error) => return Err(error),
    };
    if expected.tracker_epoch != current.tracker_epoch {
        bail!("Lifetime tracking was interrupted; destruction cannot be inferred");
    }
    Ok(expected != &current)
}

fn poll_close(
    mut result: WindowActionResult,
    operation: &Operation,
    mut observe: impl FnMut() -> Result<Option<WindowRecord>>,
) -> WindowActionResult {
    let mut last_failure = None;
    let stopped = loop {
        if let Err(error) = operation.check() {
            break error;
        }
        match observe() {
            Ok(None) => {
                result.observed = true;
                result.window = None;
                result.error = None;
                return result;
            }
            Ok(Some(window)) => {
                result.window = Some(window);
                last_failure = None;
            }
            Err(error) => {
                // DestroyWindow can clear the owner before IsWindow becomes
                // false. Failed identity reads are inconclusive, not closure.
                result.window = None;
                last_failure = Some(format!("{error:#}"));
            }
        }
        if let Err(error) = operation.wait(Duration::from_millis(25)) {
            break error;
        }
    };
    result.error = Some(match last_failure {
        Some(error) => format!(
            "{stopped:#}; closure could not be verified: {error}; the accepted WM_CLOSE may still take effect"
        ),
        None => format!(
            "{stopped:#}; closure was not observed; the accepted WM_CLOSE may still take effect"
        ),
    });
    result
}

struct WindowTitle {
    text: String,
    truncated: bool,
}

fn window_title(hwnd: HWND) -> Result<WindowTitle> {
    let mut buffer = [0u16; MAX_TITLE + 1];
    unsafe { SetLastError(WIN32_ERROR(0)) };
    // GetWindowText can dispatch WM_GETTEXT if a handle changes to an
    // in-process window after a PID check. The cached-caption API never
    // invokes application code, including on a reused or unresponsive HWND.
    let length = unsafe { InternalGetWindowText(hwnd, &mut buffer) };
    if length == 0 && unsafe { GetLastError() } != WIN32_ERROR(0) {
        bail!(
            "Window title is unavailable: {}",
            ::windows::core::Error::from_thread()
        );
    }
    let length = usize::try_from(length).context("Invalid native window title length")?;
    if length > MAX_TITLE {
        bail!("Native window title exceeded the bounded buffer");
    }
    Ok(WindowTitle {
        text: String::from_utf16_lossy(&buffer[..length]),
        truncated: length == MAX_TITLE,
    })
}

fn window_class(hwnd: HWND) -> Result<String> {
    let mut buffer = [0u16; MAX_CLASS + 1];
    let length = unsafe { GetClassNameW(hwnd, &mut buffer) };
    if length <= 0 || length as usize >= buffer.len() {
        bail!("Window class is unavailable or exceeds {MAX_CLASS} UTF-16 code units");
    }
    Ok(String::from_utf16_lossy(&buffer[..length as usize]))
}

fn rect_from_native(native: RECT) -> Result<Rect> {
    let bounds = Rect {
        x: native.left,
        y: native.top,
        width: u32::try_from(i64::from(native.right) - i64::from(native.left))
            .context("Invalid native window width")?,
        height: u32::try_from(i64::from(native.bottom) - i64::from(native.top))
            .context("Invalid native window height")?,
    };
    bounds.validate()?;
    Ok(bounds)
}

fn outer_bounds(hwnd: HWND) -> Result<Rect> {
    let mut rectangle = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut rectangle) }.context("Window rectangle is unavailable")?;
    rect_from_native(rectangle)
}

fn frame_bounds(hwnd: HWND, limitations: &mut Vec<String>) -> Result<(Rect, String)> {
    let mut rectangle = RECT::default();
    let extended = unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut rectangle as *mut _ as *mut _,
            std::mem::size_of_val(&rectangle) as u32,
        )
    };
    match extended {
        Ok(()) => match rect_from_native(rectangle) {
            Ok(bounds) => return Ok((bounds, "dwm_extended_frame".into())),
            Err(error) => limitations.push(format!(
                "DWM frame bounds are invalid ({error:#}); using physical GetWindowRect, which can include invisible resize borders"
            )),
        },
        Err(error) => limitations.push(format!(
            "DWM frame bounds unavailable ({error}); using physical GetWindowRect, which can include invisible resize borders"
        )),
    }
    Ok((outer_bounds(hwnd)?, "get_window_rect".into()))
}

struct Enumeration<'a> {
    handles: Vec<HWND>,
    operation: &'a Operation,
    truncated: bool,
    error: Option<anyhow::Error>,
}

unsafe extern "system" fn enumerate_window(hwnd: HWND, parameter: LPARAM) -> BOOL {
    let enumeration = unsafe { &mut *(parameter.0 as *mut Enumeration<'_>) };
    if let Err(error) = enumeration.operation.check() {
        enumeration.error = Some(error);
        return BOOL(0);
    }
    if enumeration.handles.len() >= MAX_ENUM_WINDOWS {
        enumeration.truncated = true;
        return BOOL(0);
    }
    enumeration.handles.push(hwnd);
    BOOL(1)
}

fn add_issue(result: &mut WindowListResult, issue: String) {
    if result.issues.len() < MAX_ISSUES {
        result.issues.push(issue);
    } else {
        result.truncated = true;
        if result.issues.len() == MAX_ISSUES {
            result.issues.push(
                "Further window errors were omitted because the issue limit was reached".into(),
            );
        }
    }
}

fn require_unique(result: &WindowListResult) -> Result<()> {
    if result.windows.len() > 1 {
        bail!("Ambiguous window query: more than one window matched; use window_ref or a narrower query");
    }
    if result.truncated || !result.issues.is_empty() {
        bail!(
            "Incomplete window query cannot establish uniqueness: {}",
            result.issues.join("; ")
        );
    }
    if result.windows.is_empty() {
        bail!("No window matches the query");
    }
    Ok(())
}

fn target_bounds(input: &WindowManageInput, before: Rect) -> Result<Rect> {
    let mut target = before;
    match input.action {
        WindowAction::Move => {
            target.x = input.x.context("move requires x")?;
            target.y = input.y.context("move requires y")?;
        }
        WindowAction::Resize => {
            target.width = input.width.context("resize requires width")?;
            target.height = input.height.context("resize requires height")?;
        }
        _ => return Ok(target),
    }
    target.validate()?;
    Ok(target)
}

fn native_geometry(hwnd: HWND, frame: &Rect, target: &Rect) -> Result<Rect> {
    let outer = outer_bounds(hwnd)?;
    frame_to_outer(&outer, frame, target)
}

fn frame_to_outer(outer: &Rect, frame: &Rect, target: &Rect) -> Result<Rect> {
    let result = Rect {
        x: i32::try_from(i64::from(target.x) + i64::from(outer.x) - i64::from(frame.x))
            .context("Physical move exceeds the native X coordinate range")?,
        y: i32::try_from(i64::from(target.y) + i64::from(outer.y) - i64::from(frame.y))
            .context("Physical move exceeds the native Y coordinate range")?,
        width: u32::try_from(
            i64::from(target.width) + i64::from(outer.width) - i64::from(frame.width),
        )
        .context("Physical resize produces an invalid native width")?,
        height: u32::try_from(
            i64::from(target.height) + i64::from(outer.height) - i64::from(frame.height),
        )
        .context("Physical resize produces an invalid native height")?,
    };
    result.validate()?;
    Ok(result)
}

fn geometry_changed(action: WindowAction, previous: Rect, adjusted: Rect) -> bool {
    match action {
        WindowAction::Move => previous.x != adjusted.x || previous.y != adjusted.y,
        WindowAction::Resize => {
            previous.width != adjusted.width || previous.height != adjusted.height
        }
        _ => false,
    }
}

fn set_native_geometry(hwnd: HWND, action: WindowAction, geometry: Rect) -> Result<()> {
    let flags = SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS;
    unsafe {
        SetWindowPos(
            hwnd,
            None,
            geometry.x,
            geometry.y,
            geometry.width as i32,
            geometry.height as i32,
            flags
                | if action == WindowAction::Move {
                    SWP_NOSIZE
                } else {
                    SWP_NOMOVE
                },
        )
    }
    .context("SetWindowPos did not accept the requested physical geometry")
}

fn postcondition(input: &WindowManageInput, target: &Rect) -> String {
    match input.action {
        WindowAction::Focus => {
            "The same live window is foreground, visible and not minimized or cloaked".into()
        }
        WindowAction::Move => format!("The physical frame origin is ({}, {})", target.x, target.y),
        WindowAction::Resize => format!(
            "The physical frame size is {} by {} pixels",
            target.width, target.height
        ),
        WindowAction::Minimize => "The same live window is minimized".into(),
        WindowAction::Maximize => "The same live window is visible and maximized".into(),
        WindowAction::Restore => {
            "The same live window is visible, not minimized and not maximized".into()
        }
        WindowAction::Close => {
            "The original window lifetime no longer exists; application exit is not inferred".into()
        }
    }
}

fn action_observed(action: WindowAction, window: &WindowRecord, target: &Rect) -> bool {
    match action {
        WindowAction::Focus => {
            (unsafe { GetForegroundWindow().0 as u64 == window.identity.hwnd })
                && window.visible
                && !window.minimized
                && !window.cloaked
        }
        WindowAction::Move => {
            !window.minimized
                && !window.maximized
                && window.bounds.x == target.x
                && window.bounds.y == target.y
        }
        WindowAction::Resize => {
            !window.minimized
                && !window.maximized
                && window.bounds.width == target.width
                && window.bounds.height == target.height
        }
        WindowAction::Minimize => window.minimized,
        WindowAction::Maximize => window.visible && window.maximized && !window.minimized,
        WindowAction::Restore => window.visible && !window.maximized && !window.minimized,
        WindowAction::Close => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::windows::core::PCWSTR;
    use ::windows::Win32::Foundation::{HINSTANCE, LRESULT};
    use ::windows::Win32::System::LibraryLoader::GetModuleHandleW;

    fn identity(lifetime: Lifetime) -> WindowIdentity {
        WindowIdentity {
            hwnd: 1234,
            pid: 55,
            process_created_100ns: 0x01dd_0000_ffff_ffff,
            session_id: 1,
            thread_id: 66,
            tracker_epoch: lifetime.epoch,
            window_generation: lifetime.generation,
        }
    }

    fn record() -> WindowRecord {
        WindowRecord {
            window_ref: format!("window_{}", uuid::Uuid::new_v4()),
            identity: identity(Lifetime {
                epoch: 1,
                generation: 1,
                alive: true,
            }),
            title: "Native Test Window".into(),
            title_truncated: false,
            class_name: "McpWindowTest".into(),
            bounds: Rect {
                x: -300,
                y: 20,
                width: 400,
                height: 200,
            },
            visible: true,
            minimized: false,
            maximized: false,
            enabled: true,
            cloaked: false,
            dpi: 96,
            bounds_source: "dwm_extended_frame".into(),
            limitations: Vec::new(),
        }
    }

    #[test]
    fn process_restart_with_the_same_pid_and_hwnd_rejects_the_reference() {
        let expected = record().identity;
        let mut restarted = expected.clone();
        restarted.process_created_100ns += 1u64 << 32;
        assert!(require_same_identity(&expected, &restarted).is_err());
        restarted = expected.clone();
        restarted.thread_id += 1;
        assert!(require_same_identity(&expected, &restarted).is_err());
        assert!(require_same_identity(&expected, &expected).is_ok());
    }

    #[test]
    fn process_creation_ticks_round_trip_as_decimal_strings_without_precision_loss() {
        let window = record().identity;
        let ticks = window.process_created_100ns;
        assert!(ticks > (1u64 << 53));
        let decimal = ticks.to_string();
        let mut encoded = serde_json::to_value(&window).unwrap();
        assert_eq!(
            encoded["process_created_100ns"].as_str(),
            Some(decimal.as_str())
        );
        assert_eq!(
            serde_json::from_value::<WindowIdentity>(encoded.clone()).unwrap(),
            window
        );
        encoded["process_created_100ns"] = serde_json::Value::from(ticks);
        assert_eq!(
            serde_json::from_value::<WindowIdentity>(encoded).unwrap(),
            window
        );
        let process = ProcessIdentity {
            pid: window.pid,
            process_created_100ns: ticks,
            session_id: window.session_id,
        };
        let encoded = serde_json::to_value(&process).unwrap();
        assert_eq!(
            encoded["process_created_100ns"].as_str(),
            Some(decimal.as_str())
        );
        assert_eq!(
            serde_json::from_value::<ProcessIdentity>(encoded).unwrap(),
            process
        );
        let query: WindowQuery = serde_json::from_value(serde_json::json!({
            "process_created_100ns": decimal,
        }))
        .unwrap();
        assert_eq!(query.process_created_100ns, Some(ticks));
        assert!(query.matches(&record()).unwrap());
        let schema = serde_json::to_value(schemars::schema_for!(WindowIdentity)).unwrap();
        assert_eq!(
            schema["properties"]["process_created_100ns"]["type"],
            "string"
        );
    }

    #[test]
    fn same_process_hwnd_reuse_and_tracker_gaps_reject_stale_references() {
        let mut state = LifetimeState::new(9999);
        let first = identity(state.snapshot(1234, true).unwrap());
        state.event(1234, EVENT_OBJECT_DESTROY);
        state.event(1234, EVENT_OBJECT_CREATE);
        let reused = identity(state.snapshot(1234, true).unwrap());
        assert_eq!(first.pid, reused.pid);
        assert_eq!(first.process_created_100ns, reused.process_created_100ns);
        assert_ne!(first.window_generation, reused.window_generation);
        assert!(require_same_identity(&first, &reused).is_err());
        state.invalidate();
        let after_gap = identity(state.snapshot(1234, true).unwrap());
        assert!(require_same_identity(&reused, &after_gap).is_err());
    }

    #[test]
    fn tracker_and_reference_retention_are_bounded() {
        let mut state = LifetimeState::new(9999);
        let first = state.snapshot(1234, true).unwrap();
        for hwnd in 10_000..10_000 + MAX_TRACKED_WINDOWS as u64 {
            state.snapshot(hwnd, true).unwrap();
        }
        assert!(state.windows.len() <= MAX_TRACKED_WINDOWS);
        assert_ne!(first.epoch, state.epoch);
        let mut references = References::default();
        let owner = record().identity;
        let original = references.retain(&owner);
        assert_eq!(original, references.retain(&owner));
        for hwnd in 20_000..20_000 + MAX_REFS as u64 {
            references.retain(&WindowIdentity {
                hwnd,
                ..owner.clone()
            });
        }
        assert_eq!(references.0.len(), MAX_REFS);
        assert!(references.get(&original).is_err());
        references.0.front_mut().unwrap().touched = Instant::now() - REF_TTL;
        references.prune();
        assert_eq!(references.0.len(), MAX_REFS - 1);
    }

    #[test]
    fn ambiguous_incomplete_and_empty_queries_never_choose_a_window() {
        let mut result = WindowListResult {
            windows: vec![record()],
            truncated: false,
            issues: Vec::new(),
        };
        assert!(require_unique(&result).is_ok());
        result.windows.push(record());
        assert!(require_unique(&result).is_err());
        result.windows.pop();
        result.truncated = true;
        assert!(require_unique(&result).is_err());
        result.truncated = false;
        result
            .issues
            .push("HWND 42, PID 9: inaccessible process identity".into());
        assert!(require_unique(&result).is_err());
        result.issues.clear();
        result.windows.clear();
        assert!(require_unique(&result).is_err());
    }

    #[test]
    fn visibility_is_an_equality_filter_and_class_names_are_exact() {
        let mut window = record();
        let query = WindowQuery::default();
        assert!(query.matches(&window).unwrap());
        window.visible = false;
        assert!(!query.matches(&window).unwrap());
        let mut query = WindowQuery {
            visible: Some(false),
            title: Some("test".into()),
            ..Default::default()
        };
        assert!(query.matches(&window).unwrap());
        query.class_name = Some("mcpwindowtest".into());
        assert!(!query.matches(&window).unwrap());
        query.class_name = Some("McpWindowTest".into());
        assert!(query.matches(&window).unwrap());
        window.title_truncated = true;
        query.title = Some("missing text".into());
        assert!(query.matches(&window).is_err());
    }

    #[test]
    fn numeric_strings_and_physical_bounds_are_validated() {
        let input: WindowManageInput = serde_json::from_str(
            r#"{"query":{"pid":"55","process_created_100ns":"133700000000000001","visible":false},"action":"move","x":"-1920","y":"100","timeout_ms":"2000","session_id":"1"}"#,
        ).unwrap();
        input.validate().unwrap();
        assert_eq!(input.x, Some(-1920));
        assert_eq!(input.query.as_ref().unwrap().pid, Some(55));
        let resize: WindowManageInput = serde_json::from_str(
            r#"{"query":{"class_name":"McpWindowTest"},"action":"resize","width":"640","height":"480"}"#,
        ).unwrap();
        resize.validate().unwrap();
        assert_eq!(resize.width, Some(640));
        let bounds: Rect =
            serde_json::from_str(r#"{"x":"-1920","y":"-200","width":"640","height":"480"}"#)
                .unwrap();
        bounds.validate().unwrap();
        assert_eq!(bounds.right(), -1280);
        let list: WindowListInput =
            serde_json::from_str(r#"{"limit":"2","timeout_ms":"1000"}"#).unwrap();
        assert_eq!(list.limit, Some(2));
        let mut invalid = resize;
        invalid.width = Some(0);
        assert!(invalid.validate().is_err());
        invalid.width = Some(u32::MAX);
        assert!(invalid.validate().is_err());
        let mut overflow = input;
        overflow.x = Some(i32::MAX);
        assert!(target_bounds(&overflow, bounds).is_err());
        for body in [
            r#"{"action":"close"}"#,
            r#"{"window_ref":"1234","action":"close"}"#,
            r#"{"query":{},"action":"move","x":1}"#,
            r#"{"query":{},"action":"resize","width":1,"height":1,"y":3}"#,
            r#"{"query":{},"action":"close","x":1}"#,
        ] {
            let input: WindowManageInput = serde_json::from_str(body).unwrap();
            assert!(input.validate().is_err(), "{body}");
        }
    }

    #[test]
    fn unknown_references_never_become_raw_hwnds() {
        let catalog = WindowCatalog::new();
        assert!(catalog.resolve("1234").is_err());
        assert!(catalog
            .resolve(&format!("window_{}", uuid::Uuid::new_v4()))
            .is_err());
        assert!(native_handle(0).is_err());
        assert!(native_handle(u64::MAX).is_err());
    }

    #[test]
    fn physical_frame_insets_and_changed_dpi_do_not_become_logical_coordinates() {
        let frame = Rect {
            x: -1920,
            y: 20,
            width: 1000,
            height: 600,
        };
        let outer = Rect {
            x: -1928,
            y: 20,
            width: 1016,
            height: 608,
        };
        let target = Rect {
            x: -1600,
            y: 50,
            width: 320,
            height: 200,
        };
        let native = frame_to_outer(&outer, &frame, &target).unwrap();
        assert_eq!(
            native,
            Rect {
                x: -1608,
                y: 50,
                width: 336,
                height: 208
            }
        );
        let changed_dpi = Rect {
            x: frame.x - 12,
            y: frame.y,
            width: frame.width + 24,
            height: frame.height + 12,
        };
        let adjusted = frame_to_outer(&changed_dpi, &frame, &target).unwrap();
        assert!(geometry_changed(WindowAction::Move, native, adjusted));
        assert!(geometry_changed(WindowAction::Resize, native, adjusted));
        assert!(!geometry_changed(WindowAction::Move, native, native));
        assert!(!geometry_changed(WindowAction::Resize, native, native));
    }

    #[test]
    fn requesting_a_state_is_not_observing_its_postcondition() {
        let mut window = record();
        let target = Rect {
            x: 500,
            y: 500,
            width: 800,
            height: 600,
        };
        assert!(!action_observed(WindowAction::Move, &window, &target));
        assert!(!action_observed(WindowAction::Resize, &window, &target));
        assert!(!action_observed(WindowAction::Minimize, &window, &target));
        assert!(!action_observed(WindowAction::Maximize, &window, &target));
        assert!(!action_observed(WindowAction::Close, &window, &target));
        window.bounds = target;
        assert!(action_observed(WindowAction::Move, &window, &target));
        assert!(action_observed(WindowAction::Resize, &window, &target));
        window.maximized = true;
        assert!(!action_observed(WindowAction::Resize, &window, &target));
        assert!(!action_observed(WindowAction::Restore, &window, &target));
        window.maximized = false;
        window.visible = false;
        assert!(!action_observed(WindowAction::Restore, &window, &target));
    }

    #[test]
    fn close_observation_retries_teardown_without_treating_identity_errors_as_closure() {
        let pending = || WindowActionResult {
            accepted: true,
            observed: false,
            action: WindowAction::Close,
            window: Some(record()),
            postcondition: "The original window lifetime no longer exists".into(),
            limitations: Vec::new(),
            error: None,
        };
        let mut observations = 0;
        let closed = poll_close(pending(), &Operation::new(1000).unwrap(), || {
            observations += 1;
            if observations == 1 {
                bail!("Stale window identity: HWND has no owning thread or process");
            }
            Ok(None)
        });
        assert_eq!(observations, 2);
        assert!(closed.accepted && closed.observed);
        assert!(closed.window.is_none());
        assert!(closed.error.is_none());

        let unavailable = poll_close(pending(), &Operation::new(50).unwrap(), || {
            bail!("OpenProcess access denied");
        });
        assert!(unavailable.accepted && !unavailable.observed);
        assert!(unavailable.window.is_none());
        assert!(unavailable
            .error
            .unwrap()
            .contains("OpenProcess access denied"));
    }

    const FIXTURE_STOP: u32 = WM_APP + 72;

    unsafe extern "system" fn fixture_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_CLOSE && unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } != 0 {
            return LRESULT(0);
        }
        unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
    }

    pub(crate) struct Fixture {
        pub(crate) hwnd: u64,
        pub(crate) button_hwnd: u64,
        pub(crate) edit_hwnd: u64,
        handles: Vec<u64>,
        child: u64,
        thread_id: u32,
        thread: Option<JoinHandle<()>>,
        title: String,
    }

    impl Fixture {
        pub(crate) fn start() -> Self {
            Self::start_internal(false)
        }

        pub(crate) fn accessible() -> Self {
            Self::start_internal(true)
        }

        fn start_internal(accessible: bool) -> Self {
            let title = format!("MCP hidden fixture {}", uuid::Uuid::new_v4());
            let name = title.clone();
            let (ready, response) = mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || {
                let _dpi = DpiScope::enter().unwrap();
                let text: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                let instance = HINSTANCE(unsafe { GetModuleHandleW(None) }.unwrap().0);
                let class = WNDCLASSW {
                    lpfnWndProc: Some(fixture_proc),
                    hInstance: instance,
                    lpszClassName: PCWSTR(text.as_ptr()),
                    ..Default::default()
                };
                assert_ne!(unsafe { RegisterClassW(&class) }, 0);
                let mut handles = Vec::new();
                for offset in [0, 100] {
                    let hwnd = unsafe {
                        CreateWindowExW(
                            WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_LAYERED | WS_EX_TRANSPARENT,
                            PCWSTR(text.as_ptr()),
                            PCWSTR(text.as_ptr()),
                            WS_POPUP,
                            -200 + offset,
                            120,
                            160,
                            90,
                            None,
                            None,
                            Some(instance),
                            None,
                        )
                    }
                    .unwrap();
                    unsafe {
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, isize::from(offset != 0));
                    }
                    handles.push(hwnd);
                }
                let child = unsafe {
                    CreateWindowExW(
                        WS_EX_NOACTIVATE,
                        w!("STATIC"),
                        w!("MCP hidden child fixture"),
                        WS_CHILD | WS_VISIBLE,
                        5,
                        5,
                        60,
                        20,
                        Some(handles[0]),
                        None,
                        Some(instance),
                        None,
                    )
                }
                .unwrap();
                let button = unsafe {
                    CreateWindowExW(
                        WS_EX_NOACTIVATE,
                        w!("BUTTON"),
                        w!("MCP fixture button"),
                        WS_CHILD | WS_VISIBLE,
                        5,
                        30,
                        100,
                        20,
                        Some(handles[0]),
                        Some(HMENU(1001usize as *mut _)),
                        Some(instance),
                        None,
                    )
                }
                .unwrap();
                let edit = unsafe {
                    CreateWindowExW(
                        WS_EX_NOACTIVATE,
                        w!("EDIT"),
                        w!("MCP fixture value"),
                        WS_CHILD | WS_VISIBLE,
                        5,
                        55,
                        100,
                        20,
                        Some(handles[0]),
                        Some(HMENU(1002usize as *mut _)),
                        Some(instance),
                        None,
                    )
                }
                .unwrap();
                if accessible {
                    // Win32 UIA omits hidden child windows. Keep the fixture
                    // fully transparent, nonactivating and click-through.
                    unsafe {
                        SetLayeredWindowAttributes(
                            handles[0],
                            ::windows::Win32::Foundation::COLORREF(0),
                            0,
                            LWA_ALPHA,
                        )
                    }
                    .unwrap();
                    unsafe {
                        let _ = ShowWindow(handles[0], SW_SHOWNOACTIVATE);
                    }
                }
                ready
                    .send((
                        handles.iter().map(|hwnd| hwnd.0 as u64).collect::<Vec<_>>(),
                        child.0 as u64,
                        button.0 as u64,
                        edit.0 as u64,
                        unsafe { GetCurrentThreadId() },
                    ))
                    .unwrap();
                let mut message = MSG::default();
                loop {
                    let status = unsafe { GetMessageW(&mut message, None, 0, 0) }.0;
                    if status <= 0 || message.message == FIXTURE_STOP {
                        break;
                    }
                    unsafe {
                        let _ = TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
                for hwnd in handles {
                    if unsafe { IsWindow(Some(hwnd)) }.as_bool() {
                        assert_eq!(window_class(hwnd).unwrap(), name);
                        assert_eq!(unsafe { GetWindowThreadProcessId(hwnd, None) }, unsafe {
                            GetCurrentThreadId()
                        },);
                        unsafe { DestroyWindow(hwnd) }.unwrap();
                    }
                }
                unsafe { UnregisterClassW(PCWSTR(text.as_ptr()), Some(instance)) }.unwrap();
            });
            let (handles, child, button_hwnd, edit_hwnd, thread_id) =
                response.recv_timeout(Duration::from_secs(3)).unwrap();
            Self {
                hwnd: handles[0],
                button_hwnd,
                edit_hwnd,
                handles,
                child,
                thread_id,
                thread: Some(thread),
                title,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, FIXTURE_STOP, WPARAM(0), LPARAM(0));
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[test]
    fn owned_hidden_windows_support_query_move_resize_close_and_stale_detection() {
        let fixture = super::Fixture::start();
        let catalog = WindowCatalog::new();
        let first = catalog.record_for_hwnd(fixture.hwnd).unwrap();
        let second = catalog.record_for_hwnd(fixture.handles[1]).unwrap();
        let child = catalog.record_for_hwnd(fixture.child).unwrap();
        assert_ne!(child.identity.hwnd, fixture.child);
        assert_eq!(child.identity, first.identity);
        assert_eq!(child.window_ref, first.window_ref);
        assert_eq!(child.bounds, first.bounds);
        for (hwnd, class) in [(fixture.button_hwnd, "Button"), (fixture.edit_hwnd, "Edit")] {
            let native = native_handle(hwnd).unwrap();
            assert!(!unsafe { IsWindowVisible(native) }.as_bool());
            assert_eq!(window_class(native).unwrap(), class);
            assert_eq!(
                catalog.record_for_hwnd(hwnd).unwrap().identity,
                first.identity
            );
        }
        assert!(!first.visible);
        assert!(!second.visible);
        assert_ne!(first.identity.process_created_100ns, 0);
        assert_eq!(
            first.window_ref,
            catalog.resolve(&first.window_ref).unwrap().window_ref
        );
        let query = WindowQuery {
            title: Some(fixture.title.clone()),
            class_name: Some(first.class_name.clone()),
            pid: Some(unsafe { GetCurrentProcessId() }),
            visible: Some(false),
            ..Default::default()
        };
        let found = catalog
            .list(
                &WindowListInput {
                    query: Some(query.clone()),
                    limit: Some(2),
                    ..Default::default()
                },
                &Operation::new(5000).unwrap(),
            )
            .unwrap();
        assert_eq!(found.windows.len(), 2, "{found:?}");
        assert!(found.issues.is_empty(), "{found:?}");
        let ambiguous = WindowManageInput {
            window_ref: None,
            query: Some(query),
            action: WindowAction::Move,
            x: Some(900),
            y: Some(900),
            width: None,
            height: None,
            timeout_ms: Some(2000),
            session_id: None,
        };
        assert!(catalog
            .manage(ambiguous, &Operation::new(5000).unwrap())
            .is_err());
        assert_eq!(
            catalog.resolve(&first.window_ref).unwrap().bounds,
            first.bounds
        );
        assert_eq!(
            catalog.resolve(&second.window_ref).unwrap().bounds,
            second.bounds
        );
        let movement = WindowManageInput {
            window_ref: Some(first.window_ref.clone()),
            query: None,
            action: WindowAction::Move,
            x: Some(-320),
            y: Some(180),
            width: None,
            height: None,
            timeout_ms: Some(2000),
            session_id: None,
        };
        let moved = catalog
            .manage(movement, &Operation::new(5000).unwrap())
            .unwrap();
        assert!(moved.accepted && moved.observed, "{moved:?}");
        assert!(!moved.window.unwrap().visible);
        let resize = WindowManageInput {
            window_ref: Some(first.window_ref.clone()),
            query: None,
            action: WindowAction::Resize,
            x: None,
            y: None,
            width: Some(213),
            height: Some(117),
            timeout_ms: Some(2000),
            session_id: None,
        };
        let resized = catalog
            .manage(resize, &Operation::new(5000).unwrap())
            .unwrap();
        assert!(resized.accepted && resized.observed, "{resized:?}");
        assert!(!resized.window.unwrap().visible);
        let close = WindowManageInput {
            window_ref: Some(first.window_ref.clone()),
            query: None,
            action: WindowAction::Close,
            x: None,
            y: None,
            width: None,
            height: None,
            timeout_ms: Some(2000),
            session_id: None,
        };
        let closed = catalog
            .manage(close, &Operation::new(5000).unwrap())
            .unwrap();
        assert!(closed.accepted && closed.observed, "{closed:?}");
        assert!(closed.window.is_none());
        assert!(catalog.resolve(&first.window_ref).is_err());
        assert!(catalog.record_for_hwnd(fixture.child).is_err());
        assert!(!catalog.resolve(&second.window_ref).unwrap().visible);
        let close = WindowManageInput {
            window_ref: Some(second.window_ref.clone()),
            query: None,
            action: WindowAction::Close,
            x: None,
            y: None,
            width: None,
            height: None,
            timeout_ms: Some(500),
            session_id: None,
        };
        let refused = catalog
            .manage(close, &Operation::new(500).unwrap())
            .unwrap();
        assert!(refused.accepted && !refused.observed, "{refused:?}");
        assert!(refused.error.is_some());
        assert!(!catalog.resolve(&second.window_ref).unwrap().visible);
    }
}
