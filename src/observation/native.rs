use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{anyhow, bail, ensure, Context};
use serde_json::json;
use tokio::sync::{oneshot, watch};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::*,
        Storage::FileSystem::*,
        System::{
            Registry::*, RemoteDesktop::ProcessIdToSessionId, Services::*, Threading::*, IO::*,
        },
    },
};

use super::{ProcessIdentity, Sink, Source, TargetIdentity};

pub(super) struct Handle(OwnedHandle);

impl Handle {
    pub(super) unsafe fn from_handle(handle: HANDLE) -> Self {
        Self(OwnedHandle::from_raw_handle(handle.0))
    }

    pub(super) fn raw(&self) -> HANDLE {
        HANDLE(self.0.as_raw_handle())
    }

    pub(super) fn event(manual_reset: bool) -> anyhow::Result<Self> {
        unsafe {
            Ok(Self::from_handle(CreateEventW(
                None,
                manual_reset,
                false,
                None,
            )?))
        }
    }
}

pub(super) struct Control {
    stop: Handle,
    canceled: AtomicBool,
    finished: watch::Sender<bool>,
}

impl Control {
    pub(super) fn new() -> anyhow::Result<Self> {
        Ok(Self {
            stop: Handle::event(true)?,
            canceled: AtomicBool::new(false),
            finished: watch::channel(false).0,
        })
    }

    pub(super) fn handle(&self) -> HANDLE {
        self.stop.raw()
    }

    pub(super) fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    pub(super) fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        if let Err(error) = unsafe { SetEvent(self.stop.raw()) } {
            tracing::error!(%error, "signaling observation shutdown");
        }
    }

    pub(super) fn mark_finished(&self) {
        self.finished.send_replace(true);
    }

    pub(super) fn is_finished(&self) -> bool {
        *self.finished.borrow()
    }

    pub(super) async fn finished(&self) {
        let mut receiver = self.finished.subscribe();
        let _ = receiver.wait_for(|done| *done).await;
    }
}

pub(super) type Ready = oneshot::Sender<Result<(), String>>;

fn ready(sink: &Sink, sender: &mut Option<Ready>) {
    sink.ready();
    if let Some(sender) = sender.take() {
        let _ = sender.send(Ok(()));
    }
}

pub(super) fn run(source: Source, sink: Sink, ready: Ready) -> anyhow::Result<()> {
    let mut ready = Some(ready);
    let result = match source {
        Source::Filesystem { path, recursive } => filesystem(&path, recursive, &sink, &mut ready),
        Source::Registry { path, recursive } => registry(&path, recursive, &sink, &mut ready),
        Source::Service { name } => service(&name, &sink, &mut ready),
        Source::Process { scope } => super::etw::run_process(scope, &sink, &mut ready),
        Source::Etw { providers, scope } => {
            super::etw::run(providers, scope, false, &sink, &mut ready)
        }
        Source::UiAutomation {
            hwnd,
            events,
            scope,
        } => super::uia::run(hwnd, events, scope, &sink, &mut ready),
    };
    if let Some(sender) = ready {
        let message = result.as_ref().err().map_or_else(
            || "provider stopped before setup completed".into(),
            |error| format!("{error:#}"),
        );
        let _ = sender.send(Err(message));
    }
    result
}

pub(super) fn report_ready(sink: &Sink, sender: &mut Option<Ready>) {
    ready(sink, sender);
}

pub(super) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

pub(super) fn win32(code: WIN32_ERROR, operation: &str) -> anyhow::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(anyhow!(
            "{operation}: {} (Win32 {})",
            windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(code.0))
                .message(),
            code.0
        ))
    }
}

pub(super) fn process_identity(pid: u32, event_timestamp: Option<u64>) -> ProcessIdentity {
    match query_identity(pid, event_timestamp) {
        Ok(identity) => identity,
        Err(error) => ProcessIdentity {
            pid,
            process_created_100ns: None,
            session_id: None,
            identity_error: Some(format!("{error:#}")),
        },
    }
}

pub(super) fn query_identity(
    pid: u32,
    event_timestamp: Option<u64>,
) -> anyhow::Result<ProcessIdentity> {
    unsafe {
        let handle =
            Handle::from_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?);
        let (mut created, mut exited, mut kernel, mut user) = Default::default();
        GetProcessTimes(
            handle.raw(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )?;
        let created = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
        ensure!(
            event_timestamp.is_none_or(|timestamp| created <= timestamp),
            "PID was reused after the event timestamp"
        );
        let mut session = 0;
        ProcessIdToSessionId(pid, &mut session)?;
        Ok(ProcessIdentity {
            pid,
            process_created_100ns: Some(created),
            session_id: Some(session),
            identity_error: None,
        })
    }
}

fn filesystem(
    path: &str,
    recursive: bool,
    sink: &Sink,
    readiness: &mut Option<Ready>,
) -> anyhow::Result<()> {
    let root = std::fs::canonicalize(path).context("opening filesystem watch directory")?;
    ensure!(root.is_dir(), "filesystem watch target must be a directory");
    let wide_path = wide(&root.to_string_lossy());
    let directory = unsafe {
        Handle::from_handle(
            CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                FILE_LIST_DIRECTORY.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                None,
            )
            .context("ReadDirectoryChangesW directory access")?,
        )
    };
    let completion = Handle::event(true)?;
    let mut buffer = vec![0u32; 16 * 1024];
    let mut overlapped = OVERLAPPED {
        hEvent: completion.raw(),
        ..Default::default()
    };
    loop {
        if sink.control.is_canceled() {
            return Ok(());
        }
        unsafe {
            ResetEvent(completion.raw())?;
        }
        unsafe {
            ReadDirectoryChangesW(
                directory.raw(),
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 4) as u32,
                recursive,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SECURITY,
                None,
                Some(&mut overlapped),
                None,
            )
            .context("ReadDirectoryChangesW")?;
        }
        ready(sink, readiness);
        let waited = unsafe {
            WaitForMultipleObjects(&[sink.control.handle(), completion.raw()], false, INFINITE)
        };
        if waited != WAIT_EVENT(WAIT_OBJECT_0.0 + 1) {
            // OVERLAPPED and its buffer must outlive the canceled I/O completion.
            let canceled = unsafe { CancelIoEx(directory.raw(), Some(&overlapped)) };
            let mut ignored = 0;
            let drained =
                unsafe { GetOverlappedResult(directory.raw(), &overlapped, &mut ignored, true) };
            if let Err(error) = canceled {
                if error.code() != windows::core::HRESULT::from_win32(ERROR_NOT_FOUND.0) {
                    return Err(error).context("canceling directory notification");
                }
            }
            if let Err(error) = drained {
                if error.code() != windows::core::HRESULT::from_win32(ERROR_OPERATION_ABORTED.0) {
                    return Err(error).context("draining directory notification");
                }
            }
            ensure!(
                waited == WAIT_OBJECT_0,
                "filesystem notification wait failed: {:?}",
                waited
            );
            return Ok(());
        }
        let mut bytes = 0;
        if let Err(error) =
            unsafe { GetOverlappedResult(directory.raw(), &overlapped, &mut bytes, false) }
        {
            if error.code() == windows::core::HRESULT::from_win32(ERROR_NOTIFY_ENUM_DIR.0) {
                sink.lost(
                    None,
                    Some(1),
                    "filesystem_notification_overflow_unknown_event_count",
                );
                continue;
            }
            return Err(error).context("reading directory notification completion");
        }
        ensure!(
            bytes as usize <= buffer.len() * 4,
            "directory notification exceeded its allocation"
        );
        if bytes == 0 {
            sink.lost(
                None,
                Some(1),
                "filesystem_notification_overflow_unknown_event_count",
            );
            continue;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), bytes as usize) };
        for (action, name) in parse_directory_changes(bytes)? {
            let kind = match action {
                1 => "filesystem.added",
                2 => "filesystem.removed",
                3 => "filesystem.modified",
                4 => "filesystem.renamed_from",
                5 => "filesystem.renamed_to",
                _ => "filesystem.unknown_action",
            };
            let target = root.join(Path::new(&name)).to_string_lossy().into_owned();
            sink.emit(kind, TargetIdentity { path: Some(target), ..Default::default() },
                json!({"action": action, "relative_path": name, "root": root.to_string_lossy(), "rename_pairing":"not_assumed"}), None);
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .context("truncated notification header")?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn parse_directory_changes(bytes: &[u8]) -> anyhow::Result<Vec<(u32, String)>> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    loop {
        let next = read_u32(bytes, offset)? as usize;
        let action = read_u32(bytes, offset + 4)?;
        let length = read_u32(bytes, offset + 8)? as usize;
        ensure!(
            length.is_multiple_of(2),
            "odd UTF-16 filename length in directory notification"
        );
        let end = offset
            .checked_add(12)
            .and_then(|n| n.checked_add(length))
            .context("directory notification offset overflow")?;
        let raw = bytes
            .get(offset + 12..end)
            .context("truncated directory filename")?;
        let utf16: Vec<_> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let name = String::from_utf16_lossy(&utf16);
        ensure!(
            !name.contains('\0') && !Path::new(&name).is_absolute(),
            "invalid notification relative path"
        );
        result.push((action, name));
        if next == 0 {
            break;
        }
        ensure!(
            next.is_multiple_of(4) && next >= 12 + length,
            "invalid directory entry offset"
        );
        offset = offset
            .checked_add(next)
            .context("directory entry offset overflow")?;
        ensure!(
            offset < bytes.len(),
            "directory entry offset outside buffer"
        );
    }
    Ok(result)
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        let status = unsafe { RegCloseKey(self.0) };
        if status != ERROR_SUCCESS {
            tracing::error!(code = status.0, "closing observation registry key");
        }
    }
}

fn registry_path(path: &str) -> anyhow::Result<(HKEY, &str)> {
    let path = path.strip_prefix("Computer\\").unwrap_or(path);
    let (name, subpath) = path.split_once('\\').unwrap_or((path, ""));
    let hive = match name.trim_end_matches(':').to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        "HKCC" | "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
        _ => bail!("unknown registry hive: {name}"),
    };
    Ok((hive, subpath))
}

fn registry(
    path: &str,
    recursive: bool,
    sink: &Sink,
    readiness: &mut Option<Ready>,
) -> anyhow::Result<()> {
    let (hive, subpath) = registry_path(path)?;
    let subpath = wide(subpath);
    let mut raw = HKEY::default();
    win32(
        unsafe { RegOpenKeyExW(hive, PCWSTR(subpath.as_ptr()), None, KEY_NOTIFY, &mut raw) },
        "RegOpenKeyExW",
    )?;
    let key = RegistryKey(raw);
    let notification = Handle::event(false)?;
    loop {
        if sink.control.is_canceled() {
            return Ok(());
        }
        win32(
            unsafe {
                RegNotifyChangeKeyValue(
                    key.0,
                    recursive,
                    REG_NOTIFY_CHANGE_NAME
                        | REG_NOTIFY_CHANGE_ATTRIBUTES
                        | REG_NOTIFY_CHANGE_LAST_SET
                        | REG_NOTIFY_CHANGE_SECURITY,
                    Some(notification.raw()),
                    true,
                )
            },
            "RegNotifyChangeKeyValue",
        )?;
        ready(sink, readiness);
        let waited = unsafe {
            WaitForMultipleObjects(
                &[sink.control.handle(), notification.raw()],
                false,
                INFINITE,
            )
        };
        if waited == WAIT_OBJECT_0 {
            return Ok(());
        }
        ensure!(
            waited == WAIT_EVENT(WAIT_OBJECT_0.0 + 1),
            "registry notification wait failed: {:?}",
            waited
        );
        sink.emit("registry.changed", TargetIdentity { registry_key: Some(path.into()), ..Default::default() },
            json!({"recursive":recursive, "coalesced":true, "changed_value_names":"not_provided_by_RegNotifyChangeKeyValue"}), None);
    }
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseServiceHandle(self.0) } {
            tracing::error!(%error, "closing observation service handle");
        }
    }
}

#[derive(Default)]
struct ServiceCallback {
    pending: Option<(u32, SERVICE_STATUS_PROCESS, u32)>,
}

unsafe extern "system" fn service_callback(parameter: *const c_void) {
    // SCM queues an APC to the registering thread and passes SERVICE_NOTIFY, not
    // pContext. The context is read only while that same thread is alertable.
    if parameter.is_null() {
        return;
    }
    let notification = &*parameter.cast::<SERVICE_NOTIFY_2W>();
    let context = &mut *notification.pContext.cast::<ServiceCallback>();
    context.pending = Some((
        notification.dwNotificationStatus,
        notification.ServiceStatus,
        notification.dwNotificationTriggered,
    ));
}

fn state_mask(state: SERVICE_STATUS_CURRENT_STATE) -> u32 {
    match state {
        SERVICE_STOPPED => SERVICE_NOTIFY_STOPPED.0,
        SERVICE_START_PENDING => SERVICE_NOTIFY_START_PENDING.0,
        SERVICE_STOP_PENDING => SERVICE_NOTIFY_STOP_PENDING.0,
        SERVICE_RUNNING => SERVICE_NOTIFY_RUNNING.0,
        SERVICE_CONTINUE_PENDING => SERVICE_NOTIFY_CONTINUE_PENDING.0,
        SERVICE_PAUSE_PENDING => SERVICE_NOTIFY_PAUSE_PENDING.0,
        SERVICE_PAUSED => SERVICE_NOTIFY_PAUSED.0,
        _ => 0,
    }
}

fn service(name: &str, sink: &Sink, readiness: &mut Option<Ready>) -> anyhow::Result<()> {
    let name_wide = wide(name);
    let manager = ServiceHandle(unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? });
    let mut context = Box::<ServiceCallback>::default();
    let notification = Box::new(SERVICE_NOTIFY_2W {
        dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
        pfnNotifyCallback: Some(service_callback),
        pContext: (&mut *context as *mut ServiceCallback).cast(),
        ..Default::default()
    });
    // This handle drops before the callback storage. No alertable wait occurs
    // after it closes, so a queued APC cannot observe released context.
    let service = ServiceHandle(unsafe {
        OpenServiceW(manager.0, PCWSTR(name_wide.as_ptr()), SERVICE_QUERY_STATUS)?
    });
    let mut initial = SERVICE_STATUS::default();
    unsafe {
        QueryServiceStatus(service.0, &mut initial)?;
    }
    let mut current = initial.dwCurrentState;
    let all = SERVICE_NOTIFY_STOPPED
        | SERVICE_NOTIFY_START_PENDING
        | SERVICE_NOTIFY_STOP_PENDING
        | SERVICE_NOTIFY_RUNNING
        | SERVICE_NOTIFY_CONTINUE_PENDING
        | SERVICE_NOTIFY_PAUSE_PENDING
        | SERVICE_NOTIFY_PAUSED
        | SERVICE_NOTIFY_DELETE_PENDING;
    loop {
        if sink.control.is_canceled() {
            return Ok(());
        }
        let mask = SERVICE_NOTIFY(all.0 & !state_mask(current));
        let code = unsafe { NotifyServiceStatusChangeW(service.0, mask, &*notification) };
        ensure!(
            code == ERROR_SUCCESS.0,
            "NotifyServiceStatusChangeW failed: Win32 {code}"
        );
        ready(sink, readiness);
        loop {
            let waited = unsafe {
                WaitForMultipleObjectsEx(&[sink.control.handle()], false, INFINITE, true)
            };
            if waited == WAIT_OBJECT_0 {
                return Ok(());
            }
            ensure!(
                waited == WAIT_IO_COMPLETION,
                "service notification wait failed: {:?}",
                waited
            );
            if let Some((status, state, triggered)) = context.pending.take() {
                ensure!(
                    status == ERROR_SUCCESS.0,
                    "service notification failed: Win32 {status}"
                );
                current = state.dwCurrentState;
                let identity =
                    (state.dwProcessId != 0).then(|| process_identity(state.dwProcessId, None));
                sink.emit(
                    "service.status_changed",
                    TargetIdentity {
                        service: Some(name.into()),
                        process: identity,
                        ..Default::default()
                    },
                    json!({
                        "state":state.dwCurrentState.0, "notification_mask":triggered,
                        "win32_exit_code":state.dwWin32ExitCode,
                        "service_specific_exit_code":state.dwServiceSpecificExitCode,
                        "checkpoint":state.dwCheckPoint, "wait_hint_ms":state.dwWaitHint
                    }),
                    None,
                );
                if triggered & SERVICE_NOTIFY_DELETE_PENDING.0 != 0 {
                    bail!("service was marked for deletion; observation ended");
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_buffers_are_length_checked_without_alignment_assumptions() {
        let mut bytes = vec![0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0];
        bytes.extend("a.b".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(
            parse_directory_changes(&bytes).unwrap(),
            vec![(1, "a.b".into())]
        );
        let mut unaligned = vec![255];
        unaligned.extend_from_slice(&bytes);
        assert_eq!(parse_directory_changes(&unaligned[1..]).unwrap().len(), 1);
        bytes[8] = 7;
        assert!(parse_directory_changes(&bytes).is_err());
        bytes[8] = 6;
        bytes[0] = 4;
        assert!(parse_directory_changes(&bytes).is_err());
        assert!(parse_directory_changes(&[0; 11]).is_err());
    }

    #[test]
    fn registry_paths_keep_private_handle_ownership() {
        assert_eq!(
            registry_path("Computer\\HKCU:\\Software\\Test").unwrap().1,
            "Software\\Test"
        );
        assert!(registry_path("not-a-hive\\Test").is_err());
    }

    #[test]
    fn service_callback_receives_service_notify_not_its_context() {
        let mut context = Box::<ServiceCallback>::default();
        let notification = SERVICE_NOTIFY_2W {
            pContext: (&mut *context as *mut ServiceCallback).cast(),
            dwNotificationStatus: ERROR_SUCCESS.0,
            dwNotificationTriggered: SERVICE_NOTIFY_RUNNING.0,
            ServiceStatus: SERVICE_STATUS_PROCESS {
                dwCurrentState: SERVICE_RUNNING,
                dwProcessId: 123,
                ..Default::default()
            },
            ..Default::default()
        };
        unsafe {
            service_callback((&notification as *const SERVICE_NOTIFY_2W).cast());
        }
        let (status, current, triggered) = context.pending.take().unwrap();
        assert_eq!(status, ERROR_SUCCESS.0);
        assert_eq!(current.dwProcessId, 123);
        assert_eq!(triggered, SERVICE_NOTIFY_RUNNING.0);
    }

    #[tokio::test]
    async fn passive_service_and_uia_subscriptions_can_shutdown_without_mutating_targets() {
        use crate::observation::{ObservationState, WatchInput, WatchStatus};
        use std::sync::Arc;
        let state = Arc::new(ObservationState::new(false));
        for source in [
            json!({"kind":"service","name":"EventLog"}),
            json!({"kind":"ui_automation","events":["window_opened","window_closed"]}),
        ] {
            let input: WatchInput =
                serde_json::from_value(json!({"source":source,"max_duration_ms":3000})).unwrap();
            let record = state.create(input, "passive-test").await.unwrap();
            if record.status == WatchStatus::Failed {
                eprintln!(
                    "passive provider unavailable in this session: {}",
                    record.error.unwrap()
                );
            } else {
                let stopped = state
                    .remove(&record.id, "passive-test", false)
                    .await
                    .unwrap();
                assert_eq!(stopped.status, WatchStatus::Stopped, "{:?}", stopped.error);
            }
        }
        state.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_uia_watches_share_registration_and_teardown_worker() {
        use crate::observation::{ObservationState, WatchInput, WatchStatus};
        use std::sync::Arc;
        let state = Arc::new(ObservationState::new(false));
        let input: WatchInput = serde_json::from_value(json!({
            "source":{"kind":"ui_automation","events":["window_opened"]},
            "max_duration_ms":5000
        }))
        .unwrap();
        let (first, second) = tokio::join!(
            state.create(input.clone(), "uia-concurrency"),
            state.create(input, "uia-concurrency")
        );
        let first = first.unwrap();
        let second = second.unwrap();
        if first.status == WatchStatus::Failed || second.status == WatchStatus::Failed {
            eprintln!(
                "UI Automation unavailable: {:?}; {:?}",
                first.error, second.error
            );
        } else {
            let (first, second) = tokio::join!(
                state.remove(&first.id, "uia-concurrency", false),
                state.remove(&second.id, "uia-concurrency", false)
            );
            assert_eq!(first.unwrap().status, WatchStatus::Stopped);
            assert_eq!(second.unwrap().status, WatchStatus::Stopped);
        }
        state.shutdown().await;
    }

    #[test]
    fn process_identity_includes_creation_and_session() {
        let identity = query_identity(std::process::id(), None).unwrap();
        assert!(identity.process_created_100ns.unwrap() > 0);
        assert!(identity.session_id.is_some());
        assert!(query_identity(std::process::id(), Some(1)).is_err());
    }

    struct RegistryFixture {
        key: RegistryKey,
        path: Vec<u16>,
    }

    impl Drop for RegistryFixture {
        fn drop(&mut self) {
            let result = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(self.path.as_ptr())) };
            if result != ERROR_SUCCESS {
                eprintln!("removing private registry fixture: Win32 {}", result.0);
            }
        }
    }

    #[tokio::test]
    async fn registry_notifications_and_shutdown_use_a_private_disposable_key() {
        use crate::observation::{
            Cancellation, EventFilter, Lifetime, ObservationState, Outcome, WaitInput, WatchInput,
            WatchStatus,
        };
        use std::sync::Arc;

        let subpath = format!("Software\\MCP-Observation-Test-{}", uuid::Uuid::new_v4());
        let path = wide(&subpath);
        let mut key = HKEY::default();
        win32(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(path.as_ptr()),
                    None,
                    None,
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE | KEY_NOTIFY,
                    None,
                    &mut key,
                    None,
                )
            },
            "creating private test key",
        )
        .unwrap();
        let fixture = RegistryFixture {
            key: RegistryKey(key),
            path,
        };
        let state = Arc::new(ObservationState::new(false));
        let input: WatchInput = serde_json::from_value(json!({
            "source":{"kind":"registry","path":format!("HKCU\\{subpath}")},
            "max_duration_ms":10000
        }))
        .unwrap();
        let record = state.create(input, "registry-test").await.unwrap();
        assert_eq!(record.status, WatchStatus::Recording, "{:?}", record.error);
        let wait = state
            .start_wait(
                WaitInput {
                    lifetime: Lifetime::Connection,
                    filter: EventFilter {
                        watch_id: Some(record.id.clone()),
                        kind: Some("registry.changed".into()),
                        ..Default::default()
                    },
                    after: Some(record.start_cursor),
                    deadline_unix_ms: crate::observation::now_ms() + 3000,
                    background: true,
                },
                "registry-test",
            )
            .await
            .unwrap();
        let name = wide("owned-test-value");
        win32(
            unsafe {
                RegSetValueExW(
                    fixture.key.0,
                    PCWSTR(name.as_ptr()),
                    None,
                    REG_DWORD,
                    Some(&42u32.to_le_bytes()),
                )
            },
            "setting private test value",
        )
        .unwrap();
        let result = state
            .await_wait(&wait.id, "registry-test", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(result.outcome, Outcome::Satisfied, "{:?}", result.error);
        assert_eq!(result.event.unwrap().payload["coalesced"], true);
        let record = state
            .remove(&record.id, "registry-test", false)
            .await
            .unwrap();
        assert_eq!(record.status, WatchStatus::Stopped, "{:?}", record.error);
    }

    #[test]
    #[ignore = "helper process launched only by the native process-event fixture"]
    fn process_fixture() {
        use std::io::Read;
        let mut byte = [0u8];
        let _ = std::io::stdin().read(&mut byte).unwrap();
    }

    use crate::observation::test_support::ChildFixture;

    #[tokio::test]
    async fn process_trace_observes_owned_child_or_reports_native_prerequisites() {
        use crate::observation::{
            Cancellation, EventFilter, Lifetime, ObservationState, Outcome, WaitInput, WatchInput,
            WatchStatus,
        };
        use std::{
            process::{Command, Stdio},
            sync::Arc,
        };

        let state = Arc::new(ObservationState::new(false));
        let input: WatchInput = serde_json::from_value(json!({
            "source":{"kind":"process"}, "max_duration_ms":10000
        }))
        .unwrap();
        let record = state.create(input, "process-test").await.unwrap();
        if record.status == WatchStatus::Failed {
            let error = record.error.as_deref().unwrap();
            assert!(
                error.contains("StartTraceW")
                    || error.contains("EnableTraceEx2")
                    || error.contains("not registered"),
                "{error}"
            );
            eprintln!("process observation prerequisite unavailable: {error}");
            state.shutdown().await;
            return;
        }
        assert_eq!(record.status, WatchStatus::Recording, "{:?}", record.error);
        let mut child = ChildFixture(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "observation::native::tests::process_fixture",
                    "--ignored",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let identity = query_identity(child.0.id(), None).unwrap();
        let wait = state
            .start_wait(
                WaitInput {
                    lifetime: Lifetime::Connection,
                    filter: EventFilter {
                        watch_id: Some(record.id.clone()),
                        kind: Some("process.created".into()),
                        process: Some(identity.clone()),
                        ..Default::default()
                    },
                    after: Some(record.start_cursor),
                    deadline_unix_ms: crate::observation::now_ms() + 5000,
                    background: true,
                },
                "process-test",
            )
            .await
            .unwrap();
        let created = state
            .await_wait(&wait.id, "process-test", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(created.outcome, Outcome::Satisfied, "{:?}", created.error);
        let wait = state
            .start_wait(
                WaitInput {
                    lifetime: Lifetime::Connection,
                    filter: EventFilter {
                        watch_id: Some(record.id.clone()),
                        kind: Some("process.exited".into()),
                        process: Some(identity),
                        ..Default::default()
                    },
                    after: Some(created.cursor),
                    deadline_unix_ms: crate::observation::now_ms() + 5000,
                    background: true,
                },
                "process-test",
            )
            .await
            .unwrap();
        child.0.stdin.take();
        assert!(child.0.wait().unwrap().success());
        let exited = state
            .await_wait(&wait.id, "process-test", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(exited.outcome, Outcome::Satisfied, "{:?}", exited.error);
        let stopped = state
            .remove(&record.id, "process-test", false)
            .await
            .unwrap();
        assert_eq!(stopped.status, WatchStatus::Stopped, "{:?}", stopped.error);
    }
}
