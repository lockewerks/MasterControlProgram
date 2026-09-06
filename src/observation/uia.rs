use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, OnceLock,
    },
};

use anyhow::{bail, ensure, Context};
use serde_json::json;
use windows::{
    core::{implement, Interface, Ref},
    Win32::{
        Foundation::*,
        System::{Com::*, RemoteDesktop::ProcessIdToSessionId, Threading::*},
        UI::{Accessibility::*, WindowsAndMessaging::*},
    },
};

use super::{
    native::{self, Ready},
    RecordingScope, Sink, TargetIdentity,
};

struct Apartment;

impl Apartment {
    fn new() -> anyhow::Result<Self> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
        }
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

#[implement(IUIAutomationEventHandler)]
struct EventHandler {
    sink: Sink,
    scope: RecordingScope,
    accepting: Arc<AtomicBool>,
}

#[allow(non_snake_case, non_upper_case_globals)]
impl IUIAutomationEventHandler_Impl for EventHandler_Impl {
    fn HandleAutomationEvent(
        &self,
        sender: Ref<'_, IUIAutomationElement>,
        eventid: UIA_EVENT_ID,
    ) -> windows::core::Result<()> {
        if !self.accepting.load(Ordering::Acquire) || self.sink.control.is_canceled() {
            return Ok(());
        }
        let Some(sender) = sender.as_ref() else {
            self.sink
                .fail("UI Automation delivered an event without a sender".into());
            return Ok(());
        };
        // Cached properties avoid calling an application back from its event.
        // A closed element may have missing fields; report that loss explicitly.
        let mut errors = Vec::new();
        let pid = match unsafe { sender.CachedProcessId() } {
            Ok(pid) if pid > 0 => Some(pid as u32),
            Ok(_) => None,
            Err(error) => {
                errors.push(format!("process_id: {error}"));
                None
            }
        };
        let process = pid.map(|pid| native::process_identity(pid, None));
        if !self
            .scope
            .matches(process.as_ref(), u16::try_from(eventid.0).ok())
        {
            return Ok(());
        }
        let hwnd = match unsafe { sender.CachedNativeWindowHandle() } {
            Ok(hwnd) if !hwnd.0.is_null() => Some(hwnd.0 as usize as u64),
            Ok(_) => None,
            Err(error) => {
                errors.push(format!("hwnd: {error}"));
                None
            }
        };
        let name = match unsafe { sender.CachedName() } {
            Ok(name) => Some(String::from_utf16_lossy(&name[..name.len().min(2048)])),
            Err(error) => {
                errors.push(format!("name: {error}"));
                None
            }
        };
        let control_type = match unsafe { sender.CachedControlType() } {
            Ok(control_type) => Some(control_type.0),
            Err(error) => {
                errors.push(format!("control_type: {error}"));
                None
            }
        };
        let kind = match eventid {
            UIA_Window_WindowOpenedEventId => "ui_automation.window_opened",
            UIA_Window_WindowClosedEventId => "ui_automation.window_closed",
            UIA_Invoke_InvokedEventId => "ui_automation.invoked",
            UIA_SelectionItem_ElementSelectedEventId => "ui_automation.selection",
            UIA_Text_TextChangedEventId => "ui_automation.text_changed",
            _ => "ui_automation.event",
        };
        self.sink.emit(kind, TargetIdentity { process, hwnd, ..Default::default() }, json!({
            "event_id":eventid.0, "name":name, "control_type":control_type,
            "cache_errors":errors, "element_reference":"event_only_not_a_reusable_control_reference",
            "process_identity_resolution":"queried_at_callback; UI Automation does not supply a process creation timestamp"
        }), None);
        Ok(())
    }
}

struct Subscription {
    automation: IUIAutomation,
    root: IUIAutomationElement,
    handler: IUIAutomationEventHandler,
    events: Vec<UIA_EVENT_ID>,
    accepting: Arc<AtomicBool>,
}

impl Subscription {
    fn remove(&mut self) -> anyhow::Result<()> {
        self.accepting.store(false, Ordering::Release);
        let mut failures = Vec::new();
        let mut remaining = Vec::new();
        for event in self.events.drain(..) {
            if let Err(error) = unsafe {
                self.automation
                    .RemoveAutomationEventHandler(event, &self.root, &self.handler)
            } {
                failures.push(format!("event {}: {error}", event.0));
                remaining.push(event);
            }
        }
        self.events = remaining;
        ensure!(
            failures.is_empty(),
            "UI Automation unsubscribe failed: {}",
            failures.join("; ")
        );
        Ok(())
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::error!(%error, "removing UI Automation observation handlers");
        }
    }
}

fn subscribe(
    hwnd: Option<u64>,
    events: Vec<String>,
    scope: RecordingScope,
    sink: &Sink,
) -> anyhow::Result<(Subscription, Option<String>)> {
    let events = if events.is_empty() {
        vec!["window_opened".into(), "window_closed".into()]
    } else {
        events
    };
    let events = events
        .iter()
        .map(|event| {
            Ok(match event.as_str() {
                "window_opened" => UIA_Window_WindowOpenedEventId,
                "window_closed" => UIA_Window_WindowClosedEventId,
                "invoked" => UIA_Invoke_InvokedEventId,
                "selection" => UIA_SelectionItem_ElementSelectedEventId,
                "text_changed" => UIA_Text_TextChangedEventId,
                _ => bail!("unsupported UI Automation event {event}"),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let automation: IUIAutomation = unsafe {
        CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)
            .context("UI Automation is unavailable in the current Windows session")?
    };
    let deadlines: IUIAutomation2 = automation.cast()?;
    unsafe {
        deadlines.SetConnectionTimeout(2000)?;
        deadlines.SetTransactionTimeout(2000)?;
    }
    let mut session = 0;
    unsafe {
        ProcessIdToSessionId(std::process::id(), &mut session)?;
    }
    ensure!(
        session != 0,
        "UI Automation observation requires an interactive user session, not Session 0"
    );
    if let Some(wanted) = scope.session_id {
        ensure!(
            wanted == session,
            "UI Automation cannot observe another interactive session from this host"
        );
    }
    let root = if let Some(hwnd) = hwnd {
        ensure!(hwnd != 0 && hwnd <= usize::MAX as u64, "invalid HWND");
        let hwnd = HWND(hwnd as usize as *mut _);
        ensure!(
            unsafe { IsWindow(Some(hwnd)) }.as_bool(),
            "UI Automation target window is stale"
        );
        let mut pid = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }
        let identity = native::query_identity(pid, None)?;
        ensure!(
            scope.matches(Some(&identity), None)
                || (!scope.event_ids.is_empty()
                    && RecordingScope {
                        event_ids: Vec::new(),
                        ..scope.clone()
                    }
                    .matches(Some(&identity), None)),
            "window does not match the exact recording process/session scope"
        );
        unsafe { automation.ElementFromHandle(hwnd)? }
    } else {
        unsafe { automation.GetRootElement()? }
    };
    let cache = unsafe { automation.CreateCacheRequest()? };
    unsafe {
        cache.SetAutomationElementMode(AutomationElementMode_None)?;
        for property in [
            UIA_ProcessIdPropertyId,
            UIA_NativeWindowHandlePropertyId,
            UIA_NamePropertyId,
            UIA_ControlTypePropertyId,
        ] {
            cache.AddProperty(property)?;
        }
    }
    let accepting = Arc::new(AtomicBool::new(true));
    let handler: IUIAutomationEventHandler = EventHandler {
        sink: sink.clone(),
        scope,
        accepting: accepting.clone(),
    }
    .into();
    let mut subscription = Subscription {
        automation,
        root,
        handler,
        events: Vec::new(),
        accepting,
    };
    for id in events {
        if subscription.events.contains(&id) {
            continue;
        }
        if let Err(error) = unsafe {
            subscription.automation.AddAutomationEventHandler(
                id,
                &subscription.root,
                TreeScope_Subtree,
                &cache,
                &subscription.handler,
            )
        } {
            return Ok((
                subscription,
                Some(format!("AddAutomationEventHandler({}): {error}", id.0)),
            ));
        }
        subscription.events.push(id);
    }
    Ok((subscription, None))
}

enum Command {
    Subscribe {
        hwnd: Option<u64>,
        events: Vec<String>,
        scope: RecordingScope,
        sink: Sink,
        reply: SyncSender<Result<bool, String>>,
    },
    Remove {
        id: String,
        reply: SyncSender<Result<(), String>>,
    },
}

struct Worker {
    sender: SyncSender<Command>,
}

impl Worker {
    fn new() -> anyhow::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(64);
        let (ready, startup) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("observation-uia-subscriptions".into())
            .spawn(move || match Apartment::new() {
                Ok(_apartment) => {
                    let _ = ready.send(Ok(()));
                    subscription_loop(receiver);
                }
                Err(error) => {
                    let _ = ready.send(Err(format!("{error:#}")));
                }
            })?;
        startup
            .recv()
            .context("UI Automation subscription worker exited during startup")?
            .map_err(anyhow::Error::msg)?;
        Ok(Self { sender })
    }
}

fn subscription_loop(receiver: Receiver<Command>) {
    let mut subscriptions: BTreeMap<String, Subscription> = BTreeMap::new();
    while let Ok(command) = receiver.recv() {
        let pending = subscriptions
            .iter()
            .filter(|(_, subscription)| !subscription.accepting.load(Ordering::Acquire))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in pending {
            if let Some(subscription) = subscriptions.get_mut(&id) {
                match subscription.remove() {
                    Ok(()) => {
                        subscriptions.remove(&id);
                    }
                    Err(error) => {
                        tracing::error!(%error, "retrying incomplete UI Automation cleanup")
                    }
                }
            }
        }
        match command {
            Command::Subscribe {
                hwnd,
                events,
                scope,
                sink,
                reply,
            } => {
                if sink.control.is_canceled() {
                    let _ = reply.send(Ok(false));
                    continue;
                }
                if subscriptions.len() >= 32 {
                    let _ = reply.send(Err(
                        "UI Automation subscription limit reached, including any failed removals"
                            .into(),
                    ));
                    continue;
                }
                let result = subscribe(hwnd, events, scope, &sink)
                    .and_then(|(mut subscription, error)| {
                        if let Some(error) = error {
                            if let Err(cleanup) = subscription.remove() {
                                subscriptions.insert(sink.watch_id.clone(), subscription);
                                bail!("{error}; partial registration cleanup failed: {cleanup:#}");
                            }
                            bail!("{error}");
                        }
                        subscriptions.insert(sink.watch_id.clone(), subscription);
                        Ok(true)
                    })
                    .map_err(|error| format!("{error:#}"));
                let _ = reply.send(result);
            }
            Command::Remove { id, reply } => {
                let result = match subscriptions.get_mut(&id) {
                    Some(subscription) => {
                        subscription.remove().map_err(|error| format!("{error:#}"))
                    }
                    None => Err("UI Automation subscription is not registered".into()),
                };
                if result.is_ok() {
                    subscriptions.remove(&id);
                }
                let _ = reply.send(result);
            }
        }
    }
}

fn worker() -> anyhow::Result<&'static Worker> {
    static WORKER: OnceLock<Result<Worker, String>> = OnceLock::new();
    WORKER
        .get_or_init(|| Worker::new().map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

pub(super) fn run(
    hwnd: Option<u64>,
    events: Vec<String>,
    scope: RecordingScope,
    sink: &Sink,
    ready: &mut Option<Ready>,
) -> anyhow::Result<()> {
    let worker = worker()?;
    let (reply, result) = mpsc::sync_channel(1);
    worker
        .sender
        .try_send(Command::Subscribe {
            hwnd,
            events,
            scope,
            sink: sink.clone(),
            reply,
        })
        .map_err(|error| {
            anyhow::anyhow!("UI Automation subscription queue unavailable: {error}")
        })?;
    let subscribed = result
        .recv()
        .context("UI Automation subscription worker exited")?
        .map_err(anyhow::Error::msg)?;
    if !subscribed {
        return Ok(());
    }
    native::report_ready(sink, ready);
    let waited = unsafe { WaitForSingleObject(sink.control.handle(), INFINITE) };
    let (reply, result) = mpsc::sync_channel(1);
    // Teardown cannot be discarded when the setup queue is full. At most 32
    // watcher threads can wait here and their contexts stay owned by the worker.
    worker
        .sender
        .send(Command::Remove {
            id: sink.watch_id.clone(),
            reply,
        })
        .context("UI Automation subscription worker exited before removal")?;
    let removal = result
        .recv()
        .context("UI Automation subscription worker exited during removal")?
        .map_err(anyhow::Error::msg);
    ensure!(
        waited == WAIT_OBJECT_0,
        "UI Automation notification wait failed: {:?}",
        waited
    );
    removal
}
