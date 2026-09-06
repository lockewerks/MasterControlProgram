//! Native, exact-name service control and configuration.

use super::{from_wide, pretty, to_wide};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::DELETE;
use windows::Win32::System::Services::*;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 300_000;
const MAX_TEXT_UNITS: usize = 32_767;
const MAX_QUERY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStartType {
    #[serde(alias = "auto")]
    Automatic,
    Manual,
    Disabled,
}

impl ServiceStartType {
    fn native(self) -> SERVICE_START_TYPE {
        match self {
            Self::Automatic => SERVICE_AUTO_START,
            Self::Manual => SERVICE_DEMAND_START,
            Self::Disabled => SERVICE_DISABLED,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceProcessType {
    OwnProcess,
    SharedProcess,
}

impl ServiceProcessType {
    fn native(self) -> ENUM_SERVICE_TYPE {
        match self {
            Self::OwnProcess => SERVICE_WIN32_OWN_PROCESS,
            Self::SharedProcess => SERVICE_WIN32_SHARE_PROCESS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceErrorControl {
    Ignore,
    Normal,
    Severe,
    Critical,
}

impl ServiceErrorControl {
    fn native(self) -> SERVICE_ERROR {
        match self {
            Self::Ignore => SERVICE_ERROR_IGNORE,
            Self::Normal => SERVICE_ERROR_NORMAL,
            Self::Severe => SERVICE_ERROR_SEVERE,
            Self::Critical => SERVICE_ERROR_CRITICAL,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceSidType {
    None,
    Unrestricted,
    Restricted,
}

impl ServiceSidType {
    fn native(self) -> u32 {
        match self {
            Self::None => SERVICE_SID_TYPE_NONE,
            Self::Unrestricted => SERVICE_SID_TYPE_UNRESTRICTED,
            // The SDK defines RESTRICTED as UNRESTRICTED | 0x2.
            Self::Restricted => SERVICE_SID_TYPE_UNRESTRICTED | 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRecoveryAction {
    None,
    Restart,
    Reboot,
    RunCommand,
}

impl ServiceRecoveryAction {
    fn native(self) -> SC_ACTION_TYPE {
        match self {
            Self::None => SC_ACTION_NONE,
            Self::Restart => SC_ACTION_RESTART,
            Self::Reboot => SC_ACTION_REBOOT,
            Self::RunCommand => SC_ACTION_RUN_COMMAND,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecoveryActionInput {
    pub action: ServiceRecoveryAction,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub delay_ms: u32,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecoveryInput {
    /// Seconds before resetting the failure count. 4294967295 means never.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub reset_period_seconds: Option<u32>,
    /// Omit to retain actions; an empty array clears actions and the reset period.
    pub actions: Option<Vec<ServiceRecoveryActionInput>>,
    /// Omit to retain the command; an empty string clears it.
    pub command: Option<String>,
    /// Omit to retain the reboot message; an empty string clears it.
    pub reboot_message: Option<String>,
}

/// A write-only credential. It is deliberately neither Debug nor Serialize.
#[derive(JsonSchema)]
#[schemars(transparent)]
pub struct ServicePassword(String);

impl<'de> Deserialize<'de> for ServicePassword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("password must be a string"))
    }
}

impl Drop for ServicePassword {
    fn drop(&mut self) {
        // Volatile writes keep credential cleanup from being optimized away.
        unsafe {
            for byte in self.0.as_bytes_mut() {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

struct WidePassword(Vec<u16>);

impl Drop for WidePassword {
    fn drop(&mut self) {
        for unit in &mut self.0 {
            unsafe { std::ptr::write_volatile(unit, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceCreateInput {
    /// Exact SCM name, not a display name or pattern. Maximum 256 UTF-16 units.
    pub name: String,
    /// Complete executable command line. Quote executable paths containing spaces.
    pub binary_path: String,
    pub display_name: Option<String>,
    /// Defaults to manual. Driver boot/system start types are not supported.
    pub startup_type: Option<ServiceStartType>,
    /// Defaults to own_process. Drivers and interactive services are not supported.
    pub service_type: Option<ServiceProcessType>,
    /// Defaults to normal.
    pub error_control: Option<ServiceErrorControl>,
    /// Exact service names or +load-order-group names.
    pub dependencies: Option<Vec<String>>,
    /// Omit for LocalSystem.
    pub account: Option<String>,
    /// Omitted is NULL; an explicit empty string is an empty password.
    pub password: Option<ServicePassword>,
    pub description: Option<String>,
    /// True requires automatic startup.
    pub delayed_auto_start: Option<bool>,
    pub recovery: Option<ServiceRecoveryInput>,
    pub failure_actions_on_non_crash_failures: Option<bool>,
    pub sid_type: Option<ServiceSidType>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfigureInput {
    /// Exact SCM name, not a display name or pattern.
    pub name: String,
    pub binary_path: Option<String>,
    pub display_name: Option<String>,
    pub startup_type: Option<ServiceStartType>,
    pub service_type: Option<ServiceProcessType>,
    pub error_control: Option<ServiceErrorControl>,
    /// Omit to retain dependencies; an empty array removes all dependencies.
    pub dependencies: Option<Vec<String>>,
    pub account: Option<String>,
    /// Omit to retain the password; an explicit empty string sets an empty password.
    pub password: Option<ServicePassword>,
    /// Omit to retain the description; an empty string clears it.
    pub description: Option<String>,
    /// True requires the resulting startup type to be automatic.
    pub delayed_auto_start: Option<bool>,
    pub recovery: Option<ServiceRecoveryInput>,
    pub failure_actions_on_non_crash_failures: Option<bool>,
    pub sid_type: Option<ServiceSidType>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTransitionAction {
    Start,
    Stop,
    Restart,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceTransitionInput {
    pub name: String,
    pub action: ServiceTransitionAction,
    /// Defaults to true. False observes once after acceptance and reports pending as an error.
    pub wait: Option<bool>,
    /// 1..=300000 milliseconds, default 30000, shared by both restart phases.
    /// Synchronous SCM calls cannot be interrupted by the polling deadline.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceDeleteInput {
    pub name: String,
    /// Defaults to false. Deletion never stops a service or terminates its process.
    pub wait: Option<bool>,
    /// 1..=300000 milliseconds, default 30000. Bounds polling, not native call latency.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

struct ScmHandle(SC_HANDLE);

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

fn open_scm(access: u32) -> windows::core::Result<ScmHandle> {
    unsafe { OpenSCManagerW(None, None, access).map(ScmHandle) }
}

fn open_service(scm: &ScmHandle, name: &str, access: u32) -> windows::core::Result<ScmHandle> {
    let name = to_wide(name);
    unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), access).map(ScmHandle) }
}

fn validate_text(field: &str, text: &str, max: usize, empty: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        empty || !text.trim().is_empty(),
        "{field} must not be empty"
    );
    anyhow::ensure!(!text.contains('\0'), "{field} must not contain NUL");
    anyhow::ensure!(
        text.encode_utf16().count() <= max,
        "{field} exceeds the UTF-16 length limit of {max}"
    );
    Ok(())
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    validate_text("name", name, 256, false)?;
    anyhow::ensure!(
        !name.contains(['\\', '/', '*', '?']),
        "name must be an exact service name without slashes or wildcard characters"
    );
    Ok(())
}

fn timeout_ms(value: Option<u64>) -> anyhow::Result<u64> {
    let value = value.unwrap_or(DEFAULT_TIMEOUT_MS);
    anyhow::ensure!(
        (1..=MAX_TIMEOUT_MS).contains(&value),
        "timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"
    );
    Ok(value)
}

fn status_str(state: SERVICE_STATUS_CURRENT_STATE) -> &'static str {
    match state {
        SERVICE_STOPPED => "Stopped",
        SERVICE_START_PENDING => "StartPending",
        SERVICE_STOP_PENDING => "StopPending",
        SERVICE_RUNNING => "Running",
        SERVICE_CONTINUE_PENDING => "ContinuePending",
        SERVICE_PAUSE_PENDING => "PausePending",
        SERVICE_PAUSED => "Paused",
        _ => "Unknown",
    }
}

fn start_type_str(value: u32) -> &'static str {
    match value {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

fn is_win32(error: &windows::core::Error, code: WIN32_ERROR) -> bool {
    error.code() == windows::core::HRESULT::from_win32(code.0)
}

#[derive(Clone, Debug, Serialize)]
struct ServiceError {
    operation: &'static str,
    message: String,
    hresult: Option<i32>,
    win32_error: Option<u32>,
    interrupted: bool,
}

impl ServiceError {
    fn native(operation: &'static str, error: windows::core::Error) -> Self {
        let code = error.code().0 as u32;
        Self {
            operation,
            message: error.to_string(),
            hresult: Some(error.code().0),
            win32_error: ((code & 0xffff_0000) == 0x8007_0000).then_some(code & 0xffff),
            interrupted: false,
        }
    }

    fn local(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            hresult: None,
            win32_error: None,
            interrupted: false,
        }
    }

    fn interrupted(operation: &'static str, error: anyhow::Error) -> Self {
        Self {
            operation,
            message: error.to_string(),
            hresult: None,
            win32_error: None,
            interrupted: true,
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.message)
    }
}

impl std::error::Error for ServiceError {}

type NativeResult<T> = Result<T, ServiceError>;

fn checkpoint() -> NativeResult<()> {
    crate::runtime::checkpoint()
        .map_err(|error| ServiceError::interrupted("runtime::checkpoint", error))
}

#[derive(Clone, Debug, Serialize)]
struct ObservedStatus {
    state: &'static str,
    state_code: u32,
    process_id: u32,
    controls_accepted: u32,
    checkpoint: u32,
    wait_hint_ms: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
}

impl ObservedStatus {
    fn pending(&self) -> bool {
        matches!(
            SERVICE_STATUS_CURRENT_STATE(self.state_code),
            SERVICE_START_PENDING
                | SERVICE_STOP_PENDING
                | SERVICE_PAUSE_PENDING
                | SERVICE_CONTINUE_PENDING
        )
    }

    fn terminal(&self) -> bool {
        matches!(
            SERVICE_STATUS_CURRENT_STATE(self.state_code),
            SERVICE_RUNNING | SERVICE_STOPPED | SERVICE_PAUSED
        )
    }
}

fn query_status(service: &ScmHandle) -> NativeResult<ObservedStatus> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut needed,
        )
    }
    .map_err(|error| ServiceError::native("QueryServiceStatusEx", error))?;
    Ok(ObservedStatus {
        state: status_str(status.dwCurrentState),
        state_code: status.dwCurrentState.0,
        process_id: status.dwProcessId,
        controls_accepted: status.dwControlsAccepted,
        checkpoint: status.dwCheckPoint,
        wait_hint_ms: status.dwWaitHint,
        win32_exit_code: status.dwWin32ExitCode,
        service_specific_exit_code: status.dwServiceSpecificExitCode,
    })
}

// Native query results contain pointers and require pointer-aligned storage.
struct QueryBuffer(Vec<usize>);

impl QueryBuffer {
    fn new(bytes: usize) -> NativeResult<Self> {
        if bytes == 0 || bytes > MAX_QUERY_BYTES {
            return Err(ServiceError::local(
                "query",
                "Invalid native query buffer size",
            ));
        }
        Ok(Self(vec![0; bytes.div_ceil(std::mem::size_of::<usize>())]))
    }

    fn bytes(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.0.as_mut_ptr().cast(),
                self.0.len() * std::mem::size_of::<usize>(),
            )
        }
    }

    fn read<T: Copy>(&self) -> NativeResult<T> {
        if std::mem::size_of::<T>() > self.0.len() * std::mem::size_of::<usize>() {
            return Err(ServiceError::local(
                "query",
                "Native query result is truncated",
            ));
        }
        Ok(unsafe { std::ptr::read(self.0.as_ptr().cast::<T>()) })
    }
}

fn query_buffer(
    operation: &'static str,
    mut query: impl FnMut(Option<&mut [u8]>, &mut u32) -> windows::core::Result<()>,
) -> NativeResult<QueryBuffer> {
    let mut needed = 0;
    if let Err(error) = query(None, &mut needed) {
        if !is_win32(&error, ERROR_INSUFFICIENT_BUFFER) {
            return Err(ServiceError::native(operation, error));
        }
    }
    let mut last_error = None;
    for _ in 0..4 {
        let mut buffer = QueryBuffer::new(needed as usize)?;
        match query(Some(buffer.bytes()), &mut needed) {
            Ok(()) => return Ok(buffer),
            Err(error) if is_win32(&error, ERROR_INSUFFICIENT_BUFFER) => {
                last_error = Some(ServiceError::native(operation, error));
            }
            Err(error) => return Err(ServiceError::native(operation, error)),
        }
    }
    Err(last_error.expect("each unsuccessful query attempt records its native error"))
}

fn query_config2(service: &ScmHandle, level: SERVICE_CONFIG) -> NativeResult<QueryBuffer> {
    let operation = match level {
        SERVICE_CONFIG_DESCRIPTION => "QueryServiceConfig2W(description)",
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO => "QueryServiceConfig2W(delayed_auto_start)",
        SERVICE_CONFIG_FAILURE_ACTIONS => "QueryServiceConfig2W(recovery)",
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG => "QueryServiceConfig2W(failure_actions_flag)",
        SERVICE_CONFIG_SERVICE_SID_INFO => "QueryServiceConfig2W(sid_type)",
        _ => "QueryServiceConfig2W",
    };
    query_buffer(operation, |buffer, needed| unsafe {
        QueryServiceConfig2W(service.0, level, buffer, needed)
    })
}

unsafe fn from_multi_wide(mut pointer: *const u16) -> Vec<String> {
    let mut values = Vec::new();
    if !pointer.is_null() {
        while *pointer != 0 {
            let mut length = 0;
            while *pointer.add(length) != 0 {
                length += 1;
            }
            values.push(from_wide(pointer));
            pointer = pointer.add(length + 1);
        }
    }
    values
}

#[derive(Debug, Serialize)]
struct BasicConfiguration {
    display_name: String,
    binary_path: String,
    account: String,
    service_type: u32,
    startup_type: &'static str,
    start_type_code: u32,
    error_control: u32,
    load_order_group: String,
    tag_id: u32,
    dependencies: Vec<String>,
}

fn query_basic(service: &ScmHandle) -> NativeResult<BasicConfiguration> {
    let buffer = query_buffer("QueryServiceConfigW", |buffer, needed| unsafe {
        match buffer {
            Some(buffer) => QueryServiceConfigW(
                service.0,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
                needed,
            ),
            None => QueryServiceConfigW(service.0, None, 0, needed),
        }
    })?;
    let config = buffer.read::<QUERY_SERVICE_CONFIGW>()?;
    Ok(unsafe {
        BasicConfiguration {
            display_name: from_wide(config.lpDisplayName.0),
            binary_path: from_wide(config.lpBinaryPathName.0),
            account: from_wide(config.lpServiceStartName.0),
            service_type: config.dwServiceType.0,
            startup_type: start_type_str(config.dwStartType.0),
            start_type_code: config.dwStartType.0,
            error_control: config.dwErrorControl.0,
            load_order_group: from_wide(config.lpLoadOrderGroup.0),
            tag_id: config.dwTagId,
            dependencies: from_multi_wide(config.lpDependencies.0),
        }
    })
}

#[derive(Clone, Debug, Serialize)]
struct RecoveryActionConfiguration {
    action: &'static str,
    action_code: i32,
    delay_ms: u32,
}

#[derive(Debug, Default, Serialize)]
struct RecoveryConfiguration {
    reset_period_seconds: u32,
    actions: Vec<RecoveryActionConfiguration>,
    command: String,
    reboot_message: String,
}

fn query_recovery(service: &ScmHandle) -> NativeResult<RecoveryConfiguration> {
    let buffer = query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    let recovery = buffer.read::<SERVICE_FAILURE_ACTIONSW>()?;
    let actions = if recovery.cActions == 0 {
        &[][..]
    } else {
        if recovery.lpsaActions.is_null()
            || recovery.cActions as usize > MAX_QUERY_BYTES / std::mem::size_of::<SC_ACTION>()
        {
            return Err(ServiceError::local(
                "QueryServiceConfig2W",
                "Invalid recovery action array",
            ));
        }
        unsafe { std::slice::from_raw_parts(recovery.lpsaActions, recovery.cActions as usize) }
    };
    Ok(RecoveryConfiguration {
        reset_period_seconds: recovery.dwResetPeriod,
        actions: actions
            .iter()
            .map(|action| RecoveryActionConfiguration {
                action: match action.Type {
                    SC_ACTION_NONE => "none",
                    SC_ACTION_RESTART => "restart",
                    SC_ACTION_REBOOT => "reboot",
                    SC_ACTION_RUN_COMMAND => "run_command",
                    SC_ACTION_OWN_RESTART => "own_restart",
                    _ => "unknown",
                },
                action_code: action.Type.0,
                delay_ms: action.Delay,
            })
            .collect(),
        command: unsafe { from_wide(recovery.lpCommand.0) },
        reboot_message: unsafe { from_wide(recovery.lpRebootMsg.0) },
    })
}

#[derive(Serialize)]
struct ServiceSnapshot {
    config: Option<BasicConfiguration>,
    status: Option<ObservedStatus>,
    description: Option<String>,
    delayed_auto_start: Option<bool>,
    recovery: Option<RecoveryConfiguration>,
    failure_actions_on_non_crash_failures: Option<bool>,
    sid_type: Option<u32>,
    query_errors: Vec<ServiceError>,
}

fn capture<T>(result: NativeResult<T>, errors: &mut Vec<ServiceError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(error);
            None
        }
    }
}

fn snapshot(service: &ScmHandle) -> ServiceSnapshot {
    // Read-only snapshots still report the effects of actions accepted before cancellation.
    let mut errors = Vec::new();
    let config = capture(query_basic(service), &mut errors);
    let status = capture(query_status(service), &mut errors);
    let description = capture(
        (|| {
            let buffer = query_config2(service, SERVICE_CONFIG_DESCRIPTION)?;
            let description = buffer.read::<SERVICE_DESCRIPTIONW>()?;
            Ok(unsafe { from_wide(description.lpDescription.0) })
        })(),
        &mut errors,
    );
    let delayed_auto_start = capture(
        (|| {
            let buffer = query_config2(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO)?;
            Ok(buffer
                .read::<SERVICE_DELAYED_AUTO_START_INFO>()?
                .fDelayedAutostart
                .as_bool())
        })(),
        &mut errors,
    );
    let recovery = capture(query_recovery(service), &mut errors);
    let failure_actions_on_non_crash_failures = capture(
        (|| {
            let buffer = query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)?;
            Ok(buffer
                .read::<SERVICE_FAILURE_ACTIONS_FLAG>()?
                .fFailureActionsOnNonCrashFailures
                .as_bool())
        })(),
        &mut errors,
    );
    let sid_type = capture(
        (|| {
            let buffer = query_config2(service, SERVICE_CONFIG_SERVICE_SID_INFO)?;
            Ok(buffer.read::<SERVICE_SID_INFO>()?.dwServiceSidType)
        })(),
        &mut errors,
    );
    ServiceSnapshot {
        config,
        status,
        description,
        delayed_auto_start,
        recovery,
        failure_actions_on_non_crash_failures,
        sid_type,
        query_errors: errors,
    }
}

pub fn list() -> anyhow::Result<String> {
    checkpoint()?;
    let scm = open_scm(SC_MANAGER_ENUMERATE_SERVICE)?;
    let mut buffer = QueryBuffer::new(256 * 1024)?;
    let mut resume = 0;
    let mut entries = Vec::new();
    loop {
        checkpoint()?;
        let mut needed = 0;
        let mut count = 0;
        let result = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(buffer.bytes()),
                &mut needed,
                &mut count,
                Some(&mut resume),
                None,
            )
        };
        if let Err(error) = &result {
            if !is_win32(error, ERROR_MORE_DATA) {
                return Err(ServiceError::native("EnumServicesStatusExW", error.clone()).into());
            }
        }
        anyhow::ensure!(
            count as usize
                <= buffer.bytes().len() / std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>(),
            "Invalid service enumeration result"
        );
        let services = unsafe {
            std::slice::from_raw_parts(
                buffer.0.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                count as usize,
            )
        };
        for service in services {
            entries.push(unsafe {
                json!({
                    "Name": from_wide(service.lpServiceName.0),
                    "DisplayName": from_wide(service.lpDisplayName.0),
                    "Status": status_str(service.ServiceStatusProcess.dwCurrentState),
                    "PID": service.ServiceStatusProcess.dwProcessId,
                })
            });
        }
        if result.is_ok() {
            break;
        }
        if count == 0 {
            return Err(ServiceError::native("EnumServicesStatusExW", result.unwrap_err()).into());
        }
    }
    entries.sort_by(|a, b| a["Name"].as_str().cmp(&b["Name"].as_str()));
    Ok(pretty(&json!(entries)))
}

pub fn detail(name: &str) -> anyhow::Result<String> {
    validate_name(name)?;
    checkpoint()?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let service = open_service(&scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    let actual = snapshot(&service);
    let config = actual.config.as_ref().ok_or_else(|| {
        anyhow::anyhow!(pretty(&json!({
            "Name": name, "success": false, "actual": actual,
        })))
    })?;
    let status = actual.status.as_ref().ok_or_else(|| {
        anyhow::anyhow!(pretty(&json!({
            "Name": name, "success": false, "actual": actual,
        })))
    })?;
    Ok(pretty(&json!({
        "Name": name,
        "DisplayName": config.display_name,
        "State": status.state,
        "StartType": config.startup_type,
        "BinaryPath": config.binary_path,
        "ServiceAccount": config.account,
        "PID": status.process_id,
        "Dependencies": config.dependencies,
        "Description": actual.description,
        "DelayedAutoStart": actual.delayed_auto_start,
        "Recovery": actual.recovery,
        "FailureActionsOnNonCrashFailures": actual.failure_actions_on_non_crash_failures,
        "SidType": actual.sid_type,
        "observed": status,
        "query_errors": actual.query_errors,
    })))
}

fn redact_value(value: &mut Value, secret: &str) {
    if secret.is_empty() {
        return;
    }
    match value {
        Value::String(text) => *text = text.replace(secret, "[REDACTED]"),
        Value::Array(values) => {
            for value in values {
                redact_value(value, secret);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                redact_value(value, secret);
            }
        }
        _ => {}
    }
}

fn finish(
    mut value: Value,
    success: bool,
    password: Option<&ServicePassword>,
) -> anyhow::Result<String> {
    if let Some(password) = password {
        redact_value(&mut value, &password.0);
    }
    let text = pretty(&value);
    if success {
        Ok(text)
    } else {
        Err(anyhow::anyhow!(text))
    }
}

struct Settings<'a> {
    binary_path: Option<&'a str>,
    display_name: Option<&'a str>,
    startup_type: Option<ServiceStartType>,
    service_type: Option<ServiceProcessType>,
    error_control: Option<ServiceErrorControl>,
    dependencies: Option<&'a [String]>,
    account: Option<&'a str>,
    password: Option<&'a ServicePassword>,
    description: Option<&'a str>,
    delayed_auto_start: Option<bool>,
    recovery: Option<&'a ServiceRecoveryInput>,
    failure_actions_on_non_crash_failures: Option<bool>,
    sid_type: Option<ServiceSidType>,
}

impl ServiceCreateInput {
    fn settings(&self) -> Settings<'_> {
        Settings {
            binary_path: Some(&self.binary_path),
            display_name: self.display_name.as_deref(),
            startup_type: self.startup_type,
            service_type: self.service_type,
            error_control: self.error_control,
            dependencies: self.dependencies.as_deref(),
            account: self.account.as_deref(),
            password: self.password.as_ref(),
            description: self.description.as_deref(),
            delayed_auto_start: self.delayed_auto_start,
            recovery: self.recovery.as_ref(),
            failure_actions_on_non_crash_failures: self.failure_actions_on_non_crash_failures,
            sid_type: self.sid_type,
        }
    }
}

impl ServiceConfigureInput {
    fn settings(&self) -> Settings<'_> {
        Settings {
            binary_path: self.binary_path.as_deref(),
            display_name: self.display_name.as_deref(),
            startup_type: self.startup_type,
            service_type: self.service_type,
            error_control: self.error_control,
            dependencies: self.dependencies.as_deref(),
            account: self.account.as_deref(),
            password: self.password.as_ref(),
            description: self.description.as_deref(),
            delayed_auto_start: self.delayed_auto_start,
            recovery: self.recovery.as_ref(),
            failure_actions_on_non_crash_failures: self.failure_actions_on_non_crash_failures,
            sid_type: self.sid_type,
        }
    }
}

impl Settings<'_> {
    fn has_basic(&self) -> bool {
        self.binary_path.is_some()
            || self.display_name.is_some()
            || self.startup_type.is_some()
            || self.service_type.is_some()
            || self.error_control.is_some()
            || self.dependencies.is_some()
            || self.account.is_some()
            || self.password.is_some()
    }

    fn validate(&self, name: &str) -> anyhow::Result<()> {
        validate_name(name)?;
        anyhow::ensure!(
            self.has_basic()
                || self.description.is_some()
                || self.delayed_auto_start.is_some()
                || self.recovery.is_some()
                || self.failure_actions_on_non_crash_failures.is_some()
                || self.sid_type.is_some(),
            "At least one configuration setting is required"
        );
        for (field, value, max, empty) in [
            ("binary_path", self.binary_path, MAX_TEXT_UNITS, false),
            ("display_name", self.display_name, 256, true),
            ("account", self.account, MAX_TEXT_UNITS, false),
            ("description", self.description, MAX_TEXT_UNITS, true),
            (
                "password",
                self.password.map(|password| password.0.as_str()),
                MAX_TEXT_UNITS,
                true,
            ),
        ] {
            if let Some(value) = value {
                validate_text(field, value, max, empty)?;
            }
        }
        if let Some(dependencies) = self.dependencies {
            let mut units = 1;
            for (index, dependency) in dependencies.iter().enumerate() {
                let dependency_name = dependency.strip_prefix('+').unwrap_or(dependency);
                validate_name(dependency_name)?;
                anyhow::ensure!(
                    dependency.starts_with('+') || !dependency.eq_ignore_ascii_case(name),
                    "A service cannot depend on itself"
                );
                anyhow::ensure!(
                    !dependencies[..index]
                        .iter()
                        .any(|other| other.eq_ignore_ascii_case(dependency)),
                    "dependencies must not contain duplicate names"
                );
                units += dependency.encode_utf16().count() + 1;
                anyhow::ensure!(
                    units <= MAX_TEXT_UNITS,
                    "dependencies exceed the UTF-16 length limit"
                );
            }
        }
        if let Some(recovery) = self.recovery {
            anyhow::ensure!(
                recovery.reset_period_seconds.is_some()
                    || recovery.actions.is_some()
                    || recovery.command.is_some()
                    || recovery.reboot_message.is_some(),
                "recovery must contain at least one setting"
            );
            for (field, value) in [
                ("recovery.command", recovery.command.as_deref()),
                (
                    "recovery.reboot_message",
                    recovery.reboot_message.as_deref(),
                ),
            ] {
                if let Some(value) = value {
                    validate_text(field, value, MAX_TEXT_UNITS, true)?;
                }
            }
            if let Some(actions) = &recovery.actions {
                anyhow::ensure!(
                    actions.len() <= 128,
                    "recovery.actions may contain at most 128 actions"
                );
                anyhow::ensure!(
                    !actions.is_empty() || recovery.reset_period_seconds.unwrap_or(0) == 0,
                    "Clearing recovery actions also clears the reset period"
                );
            }
        }
        Ok(())
    }

    fn plan(
        &self,
        current: Option<&BasicConfiguration>,
        recovery: Option<&RecoveryConfiguration>,
    ) -> anyhow::Result<ConfigurationPlan> {
        let service_type = self
            .service_type
            .map(|value| value.native().0)
            .or_else(|| current.map(|value| value.service_type))
            .unwrap_or(SERVICE_WIN32_OWN_PROCESS.0);
        anyhow::ensure!(
            matches!(ENUM_SERVICE_TYPE(service_type), SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS),
            "Only Win32 own-process and shared-process services are supported by this configuration API"
        );
        // Refuse converting drivers, per-user services or interactive services as a side effect.
        if let Some(current) = current {
            anyhow::ensure!(
                matches!(
                    ENUM_SERVICE_TYPE(current.service_type),
                    SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
                ),
                "Configuring this existing service type is not supported"
            );
        }
        let start_type = self
            .startup_type
            .map(|value| value.native().0)
            .or_else(|| current.map(|value| value.start_type_code))
            .unwrap_or(SERVICE_DEMAND_START.0);
        anyhow::ensure!(
            self.delayed_auto_start != Some(true) || start_type == SERVICE_AUTO_START.0,
            "delayed_auto_start=true requires automatic startup"
        );
        anyhow::ensure!(
            self.delayed_auto_start != Some(true)
                || current.is_none_or(|config| config.load_order_group.is_empty()),
            "delayed_auto_start=true is unsupported for a service in a load-order group"
        );
        Ok(ConfigurationPlan {
            description: self.description.map(to_wide),
            delayed_auto_start: self.delayed_auto_start,
            recovery: self
                .recovery
                .map(|input| RecoveryPlan::new(input, recovery))
                .transpose()?,
            non_crash: self.failure_actions_on_non_crash_failures,
            sid_type: self.sid_type,
        })
    }
}

fn to_multi_wide(values: &[String]) -> Vec<u16> {
    let mut result = Vec::new();
    for value in values {
        result.extend(to_wide(value));
    }
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    result
}

fn wide_pointer(value: Option<&[u16]>) -> PCWSTR {
    value
        .map(|value| PCWSTR(value.as_ptr()))
        .unwrap_or(PCWSTR::null())
}

struct WideSettings {
    binary_path: Option<Vec<u16>>,
    display_name: Option<Vec<u16>>,
    dependencies: Option<Vec<u16>>,
    account: Option<Vec<u16>>,
    password: Option<WidePassword>,
}

impl WideSettings {
    fn new(settings: &Settings<'_>) -> Self {
        Self {
            binary_path: settings.binary_path.map(to_wide),
            display_name: settings.display_name.map(to_wide),
            dependencies: settings.dependencies.map(to_multi_wide),
            account: settings.account.map(to_wide),
            password: settings
                .password
                .map(|value| WidePassword(to_wide(&value.0))),
        }
    }

    fn password_pointer(&self) -> PCWSTR {
        wide_pointer(self.password.as_ref().map(|value| value.0.as_slice()))
    }
}

struct RecoveryPlan {
    reset_period_seconds: u32,
    actions: Option<Vec<SC_ACTION>>,
    command: Option<Vec<u16>>,
    reboot_message: Option<Vec<u16>>,
}

impl RecoveryPlan {
    fn new(
        input: &ServiceRecoveryInput,
        current: Option<&RecoveryConfiguration>,
    ) -> anyhow::Result<Self> {
        let actions = if let Some(actions) = &input.actions {
            Some(
                actions
                    .iter()
                    .map(|action| SC_ACTION {
                        Type: action.action.native(),
                        Delay: action.delay_ms,
                    })
                    .collect::<Vec<_>>(),
            )
        } else if input.reset_period_seconds.is_some() {
            // NULL actions makes Windows ignore the reset period, so retain the actual array.
            Some(
                current
                    .map(|current| {
                        current
                            .actions
                            .iter()
                            .map(|action| SC_ACTION {
                                Type: SC_ACTION_TYPE(action.action_code),
                                Delay: action.delay_ms,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        if let Some(actions) = &actions {
            anyhow::ensure!(
                actions.iter().all(|action| matches!(
                    action.Type,
                    SC_ACTION_NONE | SC_ACTION_RESTART | SC_ACTION_REBOOT | SC_ACTION_RUN_COMMAND
                )),
                "Retaining an unsupported recovery action is not supported"
            );
            anyhow::ensure!(
                !actions.is_empty() || input.reset_period_seconds.unwrap_or(0) == 0,
                "A nonzero reset period requires at least one recovery action"
            );
        }
        let runs_command = actions
            .as_ref()
            .map(|actions| {
                actions
                    .iter()
                    .any(|action| action.Type == SC_ACTION_RUN_COMMAND)
            })
            .unwrap_or_else(|| {
                current.is_some_and(|current| {
                    current
                        .actions
                        .iter()
                        .any(|action| action.action_code == SC_ACTION_RUN_COMMAND.0)
                })
            });
        let command = input
            .command
            .as_deref()
            .or_else(|| current.map(|current| current.command.as_str()))
            .unwrap_or("");
        anyhow::ensure!(
            !runs_command || !command.trim().is_empty(),
            "run_command recovery actions require a nonempty command"
        );
        let reset_period_seconds = if actions.as_ref().is_some_and(Vec::is_empty) {
            0
        } else {
            input
                .reset_period_seconds
                .or_else(|| current.map(|current| current.reset_period_seconds))
                .unwrap_or(0)
        };
        Ok(Self {
            reset_period_seconds,
            actions,
            command: input.command.as_deref().map(to_wide),
            reboot_message: input.reboot_message.as_deref().map(to_wide),
        })
    }

    fn needs_start_access(&self) -> bool {
        self.actions.as_ref().is_some_and(|actions| {
            actions
                .iter()
                .any(|action| action.Type == SC_ACTION_RESTART)
        })
    }

    fn apply(&mut self, service: &ScmHandle) -> NativeResult<()> {
        let mut empty_action = SC_ACTION::default();
        let (actions, count) = match self.actions.as_mut() {
            None => (std::ptr::null_mut(), 0),
            Some(actions) if actions.is_empty() => (&mut empty_action as *mut _, 0),
            Some(actions) => (actions.as_mut_ptr(), actions.len() as u32),
        };
        let config = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: self.reset_period_seconds,
            lpRebootMsg: PWSTR(wide_pointer(self.reboot_message.as_deref()).0 as *mut _),
            lpCommand: PWSTR(wide_pointer(self.command.as_deref()).0 as *mut _),
            cActions: count,
            lpsaActions: actions,
        };
        change_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &config, "recovery")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigurationStep {
    Basic,
    Description,
    DelayedAutoStart,
    Recovery,
    FailureActionsFlag,
    SidType,
}

impl ConfigurationStep {
    fn name(self) -> &'static str {
        match self {
            Self::Basic => "basic_config",
            Self::Description => "description",
            Self::DelayedAutoStart => "delayed_auto_start",
            Self::Recovery => "recovery",
            Self::FailureActionsFlag => "failure_actions_on_non_crash_failures",
            Self::SidType => "sid_type",
        }
    }
}

struct ConfigurationPlan {
    description: Option<Vec<u16>>,
    delayed_auto_start: Option<bool>,
    recovery: Option<RecoveryPlan>,
    non_crash: Option<bool>,
    sid_type: Option<ServiceSidType>,
}

fn change_config2<T>(
    service: &ScmHandle,
    level: SERVICE_CONFIG,
    config: &T,
    step: &'static str,
) -> NativeResult<()> {
    checkpoint()?;
    unsafe { ChangeServiceConfig2W(service.0, level, Some(config as *const T as *const _)) }
        .map_err(|error| ServiceError::native(step, error))
}

impl ConfigurationPlan {
    fn steps(&self, basic: bool) -> Vec<ConfigurationStep> {
        let mut steps = Vec::new();
        if basic {
            steps.push(ConfigurationStep::Basic);
        }
        if self.description.is_some() {
            steps.push(ConfigurationStep::Description);
        }
        if self.delayed_auto_start.is_some() {
            steps.push(ConfigurationStep::DelayedAutoStart);
        }
        if self.recovery.is_some() {
            steps.push(ConfigurationStep::Recovery);
        }
        if self.non_crash.is_some() {
            steps.push(ConfigurationStep::FailureActionsFlag);
        }
        if self.sid_type.is_some() {
            steps.push(ConfigurationStep::SidType);
        }
        steps
    }

    fn access(&self) -> u32 {
        let mut access = SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS;
        if self
            .recovery
            .as_ref()
            .is_some_and(RecoveryPlan::needs_start_access)
        {
            access |= SERVICE_START;
        }
        access
    }

    fn apply(
        &mut self,
        step: ConfigurationStep,
        service: &ScmHandle,
        settings: &Settings<'_>,
    ) -> NativeResult<()> {
        match step {
            ConfigurationStep::Basic => {
                let wide = WideSettings::new(settings);
                checkpoint()?;
                unsafe {
                    ChangeServiceConfigW(
                        service.0,
                        settings
                            .service_type
                            .map(ServiceProcessType::native)
                            .unwrap_or(ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE)),
                        settings
                            .startup_type
                            .map(ServiceStartType::native)
                            .unwrap_or(SERVICE_START_TYPE(SERVICE_NO_CHANGE)),
                        settings
                            .error_control
                            .map(ServiceErrorControl::native)
                            .unwrap_or(SERVICE_ERROR(SERVICE_NO_CHANGE)),
                        wide_pointer(wide.binary_path.as_deref()),
                        None,
                        None,
                        wide_pointer(wide.dependencies.as_deref()),
                        wide_pointer(wide.account.as_deref()),
                        wide.password_pointer(),
                        wide_pointer(wide.display_name.as_deref()),
                    )
                }
                .map_err(|error| ServiceError::native("ChangeServiceConfigW", error))
            }
            ConfigurationStep::Description => {
                let description = SERVICE_DESCRIPTIONW {
                    lpDescription: PWSTR(self.description.as_mut().unwrap().as_mut_ptr()),
                };
                change_config2(
                    service,
                    SERVICE_CONFIG_DESCRIPTION,
                    &description,
                    step.name(),
                )
            }
            ConfigurationStep::DelayedAutoStart => change_config2(
                service,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                &SERVICE_DELAYED_AUTO_START_INFO {
                    fDelayedAutostart: self.delayed_auto_start.unwrap().into(),
                },
                step.name(),
            ),
            ConfigurationStep::Recovery => self.recovery.as_mut().unwrap().apply(service),
            ConfigurationStep::FailureActionsFlag => change_config2(
                service,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                &SERVICE_FAILURE_ACTIONS_FLAG {
                    fFailureActionsOnNonCrashFailures: self.non_crash.unwrap().into(),
                },
                step.name(),
            ),
            ConfigurationStep::SidType => change_config2(
                service,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                &SERVICE_SID_INFO {
                    dwServiceSidType: self.sid_type.unwrap().native(),
                },
                step.name(),
            ),
        }
    }
}

fn execute_configuration(
    steps: &[ConfigurationStep],
    mut applied: Vec<&'static str>,
    mut check: impl FnMut() -> NativeResult<()>,
    mut apply: impl FnMut(ConfigurationStep) -> NativeResult<()>,
) -> (Vec<&'static str>, Vec<ServiceError>) {
    for step in steps {
        if let Err(error) = check() {
            return (applied, vec![error]);
        }
        match apply(*step) {
            Ok(()) => applied.push(step.name()),
            Err(error) => return (applied, vec![error]),
        }
    }
    if let Err(error) = check() {
        return (applied, vec![error]);
    }
    (applied, Vec::new())
}

fn configuration_result(
    name: &str,
    operation: &'static str,
    applied: Vec<&'static str>,
    errors: Vec<ServiceError>,
    actual: ServiceSnapshot,
    password: Option<&ServicePassword>,
) -> anyhow::Result<String> {
    let success = errors.is_empty();
    let outcome = if success {
        "applied"
    } else if applied.is_empty() {
        "failed"
    } else {
        "partial"
    };
    finish(
        json!({
            "Name": name, "operation": operation, "success": success, "outcome": outcome,
            "accepted": !applied.is_empty(), "applied_steps": applied, "errors": errors,
            "configuration_verified": actual.query_errors.is_empty(), "actual": actual,
        }),
        success,
        password,
    )
}

fn finish_operation(
    name: &str,
    operation: &'static str,
    result: anyhow::Result<String>,
    password: Option<&ServicePassword>,
) -> anyhow::Result<String> {
    match result {
        Ok(text) => Ok(text),
        Err(error) => {
            if let Ok(value) = serde_json::from_str::<Value>(&error.to_string()) {
                if value.get("success") == Some(&Value::Bool(false))
                    && value.get("accepted").is_some_and(Value::is_boolean)
                {
                    return finish(value, false, password);
                }
            }
            let detail = if let Some(detail) = error.downcast_ref::<ServiceError>() {
                detail.clone()
            } else if let Some(native) = error.downcast_ref::<windows::core::Error>() {
                ServiceError::native(operation, native.clone())
            } else {
                ServiceError::local(operation, format!("{error:#}"))
            };
            let name_in_bounds = name.encode_utf16().take(257).count() <= 256;
            finish(
                json!({
                    "Name": name_in_bounds.then_some(name), "name_omitted": !name_in_bounds,
                    "operation": operation, "success": false,
                    "outcome": if detail.interrupted { "interrupted" } else { "failed" },
                    "accepted": false, "applied_steps": [], "actual": null,
                    "configuration_verified": false, "errors": [detail],
                }),
                false,
                password,
            )
        }
    }
}

pub fn create(input: ServiceCreateInput) -> anyhow::Result<String> {
    finish_operation(
        &input.name,
        "create",
        create_inner(&input),
        input.password.as_ref(),
    )
}

fn create_inner(input: &ServiceCreateInput) -> anyhow::Result<String> {
    let settings = input.settings();
    settings.validate(&input.name)?;
    let mut plan = settings.plan(None, None)?;
    checkpoint()?;
    let scm = open_scm(SC_MANAGER_CREATE_SERVICE)
        .map_err(|error| ServiceError::native("OpenSCManagerW", error))?;
    let name = to_wide(&input.name);
    let wide = WideSettings::new(&settings);
    checkpoint()?;
    let service = ScmHandle(
        unsafe {
            CreateServiceW(
                scm.0,
                PCWSTR(name.as_ptr()),
                wide_pointer(wide.display_name.as_deref()),
                plan.access(),
                input
                    .service_type
                    .unwrap_or(ServiceProcessType::OwnProcess)
                    .native(),
                input
                    .startup_type
                    .unwrap_or(ServiceStartType::Manual)
                    .native(),
                input
                    .error_control
                    .unwrap_or(ServiceErrorControl::Normal)
                    .native(),
                wide_pointer(wide.binary_path.as_deref()),
                None,
                None,
                wide_pointer(wide.dependencies.as_deref()),
                wide_pointer(wide.account.as_deref()),
                wide.password_pointer(),
            )
        }
        .map_err(|error| ServiceError::native("CreateServiceW", error))?,
    );
    drop(wide);
    let steps = plan.steps(false);
    let (applied, errors) = execute_configuration(&steps, vec!["create"], checkpoint, |step| {
        plan.apply(step, &service, &settings)
    });
    configuration_result(
        &input.name,
        "create",
        applied,
        errors,
        snapshot(&service),
        settings.password,
    )
}

pub fn configure(input: ServiceConfigureInput) -> anyhow::Result<String> {
    finish_operation(
        &input.name,
        "configure",
        configure_inner(&input),
        input.password.as_ref(),
    )
}

fn configure_inner(input: &ServiceConfigureInput) -> anyhow::Result<String> {
    let settings = input.settings();
    settings.validate(&input.name)?;
    checkpoint()?;
    let scm = open_scm(SC_MANAGER_CONNECT)
        .map_err(|error| ServiceError::native("OpenSCManagerW", error))?;
    let read_handle = open_service(
        &scm,
        &input.name,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
    )
    .map_err(|error| ServiceError::native("OpenServiceW", error))?;
    let before = snapshot(&read_handle);
    let readable = before.config.is_some()
        && (settings.description.is_none() || before.description.is_some())
        && (settings.delayed_auto_start.is_none() || before.delayed_auto_start.is_some())
        && (settings.recovery.is_none() || before.recovery.is_some())
        && (settings.failure_actions_on_non_crash_failures.is_none()
            || before.failure_actions_on_non_crash_failures.is_some())
        && (settings.sid_type.is_none() || before.sid_type.is_some());
    if !readable {
        return configuration_result(
            &input.name,
            "configure",
            Vec::new(),
            before.query_errors.clone(),
            before,
            settings.password,
        );
    }
    let mut plan = settings.plan(before.config.as_ref(), before.recovery.as_ref())?;
    checkpoint()?;
    // Keep the read handle open until the mutation handle exists, pinning this service instance.
    let service = match open_service(&scm, &input.name, plan.access()) {
        Ok(service) => service,
        Err(error) => {
            return configuration_result(
                &input.name,
                "configure",
                Vec::new(),
                vec![ServiceError::native("OpenServiceW", error)],
                before,
                settings.password,
            )
        }
    };
    drop(read_handle);
    let steps = plan.steps(settings.has_basic());
    let (applied, errors) = execute_configuration(&steps, Vec::new(), checkpoint, |step| {
        plan.apply(step, &service, &settings)
    });
    configuration_result(
        &input.name,
        "configure",
        applied,
        errors,
        snapshot(&service),
        settings.password,
    )
}

pub fn set_startup(name: &str, startup_type: &str) -> anyhow::Result<String> {
    finish_operation(
        name,
        "set_startup",
        set_startup_inner(name, startup_type),
        None,
    )
}

fn set_startup_inner(name: &str, startup_type: &str) -> anyhow::Result<String> {
    validate_name(name)?;
    let start_type = match startup_type.to_ascii_lowercase().as_str() {
        "automatic" | "auto" => SERVICE_AUTO_START,
        "manual" => SERVICE_DEMAND_START,
        "disabled" => SERVICE_DISABLED,
        _ => anyhow::bail!("Unknown startup type. Use Automatic, Manual, or Disabled"),
    };
    checkpoint()?;
    let scm = open_scm(SC_MANAGER_CONNECT)
        .map_err(|error| ServiceError::native("OpenSCManagerW", error))?;
    let service = open_service(&scm, name, SERVICE_CHANGE_CONFIG)
        .map_err(|error| ServiceError::native("OpenServiceW", error))?;
    checkpoint()?;
    unsafe {
        ChangeServiceConfigW(
            service.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start_type,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }
    .map_err(|error| ServiceError::native("ChangeServiceConfigW", error))?;
    let (actual, query_errors) =
        match open_service(&scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) {
            Ok(reader) => (Some(snapshot(&reader)), Vec::new()),
            Err(error) => (None, vec![ServiceError::native("OpenServiceW", error)]),
        };
    Ok(pretty(&json!({
        "Name": name, "StartupType": startup_type,
        "success": true, "accepted": true, "outcome": "applied", "actual": actual, "query_errors": query_errors,
    })))
}

trait Clock {
    fn now_ms(&self) -> u64;
    fn checkpoint(&mut self) -> NativeResult<()>;
    fn sleep_ms(&mut self, milliseconds: u64) -> NativeResult<()>;
}

struct SystemClock(Instant);

impl SystemClock {
    fn new() -> Self {
        Self(Instant::now())
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn checkpoint(&mut self) -> NativeResult<()> {
        checkpoint()
    }

    fn sleep_ms(&mut self, milliseconds: u64) -> NativeResult<()> {
        crate::runtime::sleep(Duration::from_millis(milliseconds))
            .map_err(|error| ServiceError::interrupted("runtime::sleep", error))
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StepAction {
    Start,
    Stop,
}

impl StepAction {
    fn goal(self) -> SERVICE_STATUS_CURRENT_STATE {
        match self {
            Self::Start => SERVICE_RUNNING,
            Self::Stop => SERVICE_STOPPED,
        }
    }

    fn pending(self) -> SERVICE_STATUS_CURRENT_STATE {
        match self {
            Self::Start => SERVICE_START_PENDING,
            Self::Stop => SERVICE_STOP_PENDING,
        }
    }
}

trait ServiceController {
    fn query(&mut self) -> NativeResult<ObservedStatus>;
    fn request(&mut self, action: StepAction) -> NativeResult<()>;
}

struct NativeController<'a>(&'a ScmHandle);

impl ServiceController for NativeController<'_> {
    fn query(&mut self) -> NativeResult<ObservedStatus> {
        query_status(self.0)
    }

    fn request(&mut self, action: StepAction) -> NativeResult<()> {
        checkpoint()?;
        match action {
            StepAction::Start => unsafe { StartServiceW(self.0 .0, None) }
                .map_err(|error| ServiceError::native("StartServiceW", error)),
            StepAction::Stop => {
                let mut status = SERVICE_STATUS::default();
                unsafe { ControlService(self.0 .0, SERVICE_CONTROL_STOP, &mut status) }
                    .map_err(|error| ServiceError::native("ControlService(STOP)", error))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TransitionOutcome {
    Reached,
    AlreadyInState,
    Pending,
    TimedOut,
    NoProgress,
    Failed,
    RequestFailed,
    QueryFailed,
    Interrupted,
}

impl TransitionOutcome {
    fn success(self) -> bool {
        matches!(self, Self::Reached | Self::AlreadyInState)
    }
}

#[derive(Debug, Serialize)]
struct TransitionStep {
    action: StepAction,
    outcome: TransitionOutcome,
    accepted: bool,
    observed: Option<ObservedStatus>,
    errors: Vec<ServiceError>,
    elapsed_ms: u64,
}

impl TransitionStep {
    fn end(mut self, outcome: TransitionOutcome, started: u64, now: u64) -> Self {
        self.outcome = outcome;
        self.elapsed_ms = now.saturating_sub(started);
        self
    }

    fn fail(
        self,
        outcome: TransitionOutcome,
        message: &'static str,
        started: u64,
        now: u64,
    ) -> Self {
        let mut result = self;
        result
            .errors
            .push(ServiceError::local("transition", message));
        result.end(outcome, started, now)
    }

    fn interrupt(mut self, error: ServiceError, started: u64, now: u64) -> Self {
        self.errors.push(error);
        self.end(TransitionOutcome::Interrupted, started, now)
    }
}

struct Progress {
    state: u32,
    checkpoint: u32,
    deadline_ms: u64,
}

impl Progress {
    fn new(status: &ObservedStatus, now: u64) -> Self {
        Self {
            state: status.state_code,
            checkpoint: status.checkpoint,
            deadline_ms: now.saturating_add(if status.wait_hint_ms == 0 {
                1000
            } else {
                status.wait_hint_ms as u64
            }),
        }
    }

    fn observe(&mut self, status: &ObservedStatus, now: u64) {
        // A larger wait hint without a checkpoint is not evidence of progress.
        if status.state_code != self.state || status.checkpoint > self.checkpoint {
            *self = Self::new(status, now);
        }
    }
}

fn transition_step(
    controller: &mut impl ServiceController,
    clock: &mut impl Clock,
    action: StepAction,
    wait: bool,
    deadline_ms: u64,
) -> TransitionStep {
    let started = clock.now_ms();
    let mut result = TransitionStep {
        action,
        outcome: TransitionOutcome::Pending,
        accepted: false,
        observed: None,
        errors: Vec::new(),
        elapsed_ms: 0,
    };
    if let Err(error) = clock.checkpoint() {
        return result.interrupt(error, started, clock.now_ms());
    }
    let mut status = match controller.query() {
        Ok(status) => status,
        Err(error) => {
            result.errors.push(error);
            return result.end(TransitionOutcome::QueryFailed, started, clock.now_ms());
        }
    };
    let mut first = true;
    let mut expected_pending_seen = false;
    let mut pending_after_request = false;
    let mut progress: Option<Progress> = None;
    loop {
        result.observed = Some(status.clone());
        if let Err(error) = clock.checkpoint() {
            return result.interrupt(error, started, clock.now_ms());
        }
        let now = clock.now_ms();
        if now > deadline_ms {
            return result.fail(
                TransitionOutcome::TimedOut,
                "Overall service transition deadline expired",
                started,
                now,
            );
        }
        if status.state_code == action.goal().0 {
            if !first && action == StepAction::Stop && status.win32_exit_code != 0 {
                return result.fail(
                    TransitionOutcome::Failed,
                    "Service stopped with a nonzero Win32 exit code",
                    started,
                    now,
                );
            }
            return result.end(
                if first {
                    TransitionOutcome::AlreadyInState
                } else {
                    TransitionOutcome::Reached
                },
                started,
                now,
            );
        }
        if now >= deadline_ms {
            return result.fail(
                TransitionOutcome::TimedOut,
                "Overall service transition deadline expired",
                started,
                now,
            );
        }
        if !status.pending() && !status.terminal() {
            return result.fail(
                TransitionOutcome::Failed,
                "Service reported an unknown state",
                started,
                now,
            );
        }
        if status.pending() {
            expected_pending_seen |= status.state_code == action.pending().0;
            pending_after_request |= result.accepted;
        } else if result.accepted {
            if action == StepAction::Start || pending_after_request {
                return result.fail(
                    TransitionOutcome::Failed,
                    "Service settled in a state other than the requested state",
                    started,
                    now,
                );
            }
        } else {
            if expected_pending_seen {
                return result.fail(
                    TransitionOutcome::Failed,
                    "Existing transition failed to reach the requested state",
                    started,
                    now,
                );
            }
            if let Err(error) = clock.checkpoint() {
                return result.interrupt(error, started, clock.now_ms());
            }
            match controller.request(action) {
                Ok(()) => result.accepted = true,
                Err(error) => {
                    if error.interrupted {
                        return result.interrupt(error, started, clock.now_ms());
                    }
                    result.errors.push(error);
                    match controller.query() {
                        Ok(status) => result.observed = Some(status),
                        Err(error) => result.errors.push(error),
                    }
                    return result.end(TransitionOutcome::RequestFailed, started, clock.now_ms());
                }
            }
            first = false;
            progress = None;
            match controller.query() {
                Ok(next) => status = next,
                Err(error) => {
                    result.errors.push(error);
                    return result.end(TransitionOutcome::QueryFailed, started, clock.now_ms());
                }
            }
            continue;
        }
        if !wait {
            return result.fail(
                TransitionOutcome::Pending,
                "Desired state has not been observed; further waiting was not requested",
                started,
                now,
            );
        }
        let progress = progress.get_or_insert_with(|| Progress::new(&status, now));
        progress.observe(&status, now);
        if now >= progress.deadline_ms {
            return result.fail(
                TransitionOutcome::NoProgress,
                "Service checkpoint did not advance within its wait hint",
                started,
                now,
            );
        }
        let interval = (status.wait_hint_ms as u64 / 10)
            .clamp(100, 1000)
            .min(deadline_ms - now)
            .min(progress.deadline_ms - now);
        if let Err(error) = clock.sleep_ms(interval) {
            return result.interrupt(error, started, clock.now_ms());
        }
        if let Err(error) = clock.checkpoint() {
            return result.interrupt(error, started, clock.now_ms());
        }
        first = false;
        match controller.query() {
            Ok(next) => status = next,
            Err(error) => {
                result.errors.push(error);
                return result.end(TransitionOutcome::QueryFailed, started, clock.now_ms());
            }
        }
    }
}

fn transition_steps(
    controller: &mut impl ServiceController,
    clock: &mut impl Clock,
    action: ServiceTransitionAction,
    wait: bool,
    deadline_ms: u64,
) -> Vec<TransitionStep> {
    match action {
        ServiceTransitionAction::Start => vec![transition_step(
            controller,
            clock,
            StepAction::Start,
            wait,
            deadline_ms,
        )],
        ServiceTransitionAction::Stop => vec![transition_step(
            controller,
            clock,
            StepAction::Stop,
            wait,
            deadline_ms,
        )],
        ServiceTransitionAction::Restart => {
            let stop = transition_step(controller, clock, StepAction::Stop, wait, deadline_ms);
            if !stop.outcome.success() {
                return vec![stop];
            }
            // No start request is possible until this exact handle was observed stopped.
            let mut start =
                transition_step(controller, clock, StepAction::Start, wait, deadline_ms);
            if start.observed.is_none() {
                start.observed = stop.observed.clone();
            }
            vec![stop, start]
        }
    }
}

fn transition_result(
    name: &str,
    action: ServiceTransitionAction,
    steps: Vec<TransitionStep>,
    elapsed_ms: u64,
) -> anyhow::Result<String> {
    let last = steps
        .last()
        .expect("a transition always has at least one step");
    let success = last.outcome.success();
    finish(
        json!({
            "Name": name,
            "Status": last.observed.as_ref().map(|status| status.state),
            "action": action,
            "success": success,
            "outcome": last.outcome,
            "accepted": steps.iter().any(|step| step.accepted),
            "observed": last.observed,
            "terminal_state_observed": last.observed.as_ref().is_some_and(ObservedStatus::terminal),
            "elapsed_ms": elapsed_ms,
            "steps": steps,
        }),
        success,
        None,
    )
}

pub fn transition(input: ServiceTransitionInput) -> anyhow::Result<String> {
    finish_operation(&input.name, "transition", transition_inner(&input), None)
}

fn transition_inner(input: &ServiceTransitionInput) -> anyhow::Result<String> {
    validate_name(&input.name)?;
    let timeout = timeout_ms(input.timeout_ms)?;
    checkpoint()?;
    let mut clock = SystemClock::new();
    let scm = open_scm(SC_MANAGER_CONNECT)
        .map_err(|error| ServiceError::native("OpenSCManagerW", error))?;
    let access = SERVICE_QUERY_STATUS
        | match input.action {
            ServiceTransitionAction::Start => SERVICE_START,
            ServiceTransitionAction::Stop => SERVICE_STOP,
            ServiceTransitionAction::Restart => SERVICE_START | SERVICE_STOP,
        };
    let service = open_service(&scm, &input.name, access)
        .map_err(|error| ServiceError::native("OpenServiceW", error))?;
    let steps = transition_steps(
        &mut NativeController(&service),
        &mut clock,
        input.action,
        input.wait.unwrap_or(true),
        timeout,
    );
    transition_result(&input.name, input.action, steps, clock.now_ms())
}

pub fn start(name: &str) -> anyhow::Result<String> {
    transition(ServiceTransitionInput {
        name: name.to_owned(),
        action: ServiceTransitionAction::Start,
        wait: None,
        timeout_ms: None,
    })
}

pub fn stop(name: &str) -> anyhow::Result<String> {
    transition(ServiceTransitionInput {
        name: name.to_owned(),
        action: ServiceTransitionAction::Stop,
        wait: None,
        timeout_ms: None,
    })
}

pub fn restart(name: &str) -> anyhow::Result<String> {
    transition(ServiceTransitionInput {
        name: name.to_owned(),
        action: ServiceTransitionAction::Restart,
        wait: None,
        timeout_ms: None,
    })
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ServicePresence {
    Absent,
    MarkedForDeletion {
        error: ServiceError,
    },
    // SCM exposes no generation identifier. A newly opened handle may be a replacement.
    PresentOrReplaced {
        observed: Option<ObservedStatus>,
        query_errors: Vec<ServiceError>,
    },
}

fn probe_service(scm: &ScmHandle, name: &str) -> NativeResult<ServicePresence> {
    match open_service(scm, name, SERVICE_QUERY_STATUS) {
        Ok(service) => {
            let mut errors = Vec::new();
            let observed = capture(query_status(&service), &mut errors);
            drop(service);
            Ok(ServicePresence::PresentOrReplaced {
                observed,
                query_errors: errors,
            })
        }
        Err(error) if is_win32(&error, ERROR_SERVICE_DOES_NOT_EXIST) => Ok(ServicePresence::Absent),
        Err(error) if is_win32(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            Ok(ServicePresence::MarkedForDeletion {
                error: ServiceError::native("OpenServiceW", error),
            })
        }
        Err(error) => Err(ServiceError::native("OpenServiceW", error)),
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeleteOutcome {
    Absent,
    AlreadyAbsent,
    Pending,
    TimedOut,
    QueryFailed,
    RequestFailed,
    Interrupted,
}

impl DeleteOutcome {
    fn success(self) -> bool {
        matches!(self, Self::Absent | Self::AlreadyAbsent)
    }
}

struct DeletionObservation {
    outcome: DeleteOutcome,
    presence: Option<ServicePresence>,
    errors: Vec<ServiceError>,
}

fn wait_for_absence(
    mut probe: impl FnMut() -> NativeResult<ServicePresence>,
    clock: &mut impl Clock,
    wait: bool,
    deadline_ms: u64,
) -> DeletionObservation {
    let mut last_presence = None;
    loop {
        if let Err(error) = clock.checkpoint() {
            return DeletionObservation {
                outcome: DeleteOutcome::Interrupted,
                presence: last_presence,
                errors: vec![error],
            };
        }
        let presence = match probe() {
            Ok(presence) => presence,
            Err(error) => {
                return DeletionObservation {
                    outcome: if error.interrupted {
                        DeleteOutcome::Interrupted
                    } else {
                        DeleteOutcome::QueryFailed
                    },
                    presence: last_presence,
                    errors: vec![error],
                }
            }
        };
        last_presence = Some(presence);
        if matches!(last_presence, Some(ServicePresence::Absent)) {
            return DeletionObservation {
                outcome: DeleteOutcome::Absent,
                presence: last_presence,
                errors: Vec::new(),
            };
        }
        let now = clock.now_ms();
        if now >= deadline_ms {
            return DeletionObservation {
                outcome: DeleteOutcome::TimedOut,
                presence: last_presence,
                errors: vec![ServiceError::local(
                    "delete",
                    "Deletion deadline expired without observing the name absent",
                )],
            };
        }
        if !wait {
            return DeletionObservation {
                outcome: DeleteOutcome::Pending, presence: last_presence,
                errors: vec![ServiceError::local(
                    "delete", "The service name is not absent. It may be marked for deletion or may identify a replacement",
                )],
            };
        }
        if let Err(error) = clock.sleep_ms(250.min(deadline_ms - now)) {
            return DeletionObservation {
                outcome: DeleteOutcome::Interrupted,
                presence: last_presence,
                errors: vec![error],
            };
        }
    }
}

struct DeleteContext<'a> {
    name: &'a str,
    accepted: bool,
    marked: bool,
    request_error: Option<ServiceError>,
    original_status: Option<ObservedStatus>,
    original_query_errors: Vec<ServiceError>,
}

fn delete_result(
    context: DeleteContext<'_>,
    result: DeletionObservation,
    elapsed_ms: u64,
) -> anyhow::Result<String> {
    let success = result.outcome.success();
    finish(
        json!({
            "Name": context.name, "operation": "delete", "success": success,
            "outcome": result.outcome, "accepted": context.accepted,
            "original_marked_for_deletion": context.marked, "delete_request_error": context.request_error,
            "presence": result.presence, "original_status": context.original_status,
            "original_query_errors": context.original_query_errors,
            "errors": result.errors, "elapsed_ms": elapsed_ms,
        }),
        success,
        None,
    )
}

pub fn delete(input: ServiceDeleteInput) -> anyhow::Result<String> {
    finish_operation(&input.name, "delete", delete_inner(&input), None)
}

fn delete_inner(input: &ServiceDeleteInput) -> anyhow::Result<String> {
    validate_name(&input.name)?;
    let timeout = timeout_ms(input.timeout_ms)?;
    checkpoint()?;
    let mut clock = SystemClock::new();
    let scm = open_scm(SC_MANAGER_CONNECT)
        .map_err(|error| ServiceError::native("OpenSCManagerW", error))?;
    let mut context = DeleteContext {
        name: &input.name,
        accepted: false,
        marked: false,
        request_error: None,
        original_status: None,
        original_query_errors: Vec::new(),
    };
    let service = match open_service(&scm, &input.name, DELETE.0) {
        Ok(service) => Some(service),
        Err(error) if is_win32(&error, ERROR_SERVICE_DOES_NOT_EXIST) => {
            return delete_result(
                context,
                DeletionObservation {
                    outcome: DeleteOutcome::AlreadyAbsent,
                    presence: Some(ServicePresence::Absent),
                    errors: Vec::new(),
                },
                clock.now_ms(),
            );
        }
        Err(error) if is_win32(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            context.marked = true;
            context.request_error = Some(ServiceError::native("OpenServiceW", error));
            None
        }
        Err(error) => return Err(ServiceError::native("OpenServiceW", error).into()),
    };
    if let Some(service) = service {
        match open_service(&scm, &input.name, SERVICE_QUERY_STATUS) {
            Ok(reader) => {
                context.original_status =
                    capture(query_status(&reader), &mut context.original_query_errors);
            }
            Err(error) => context
                .original_query_errors
                .push(ServiceError::native("OpenServiceW", error)),
        }
        if clock.now_ms() >= timeout {
            drop(service);
            return delete_result(
                context,
                DeletionObservation {
                    outcome: DeleteOutcome::TimedOut,
                    presence: None,
                    errors: vec![ServiceError::local(
                        "delete",
                        "Deadline expired before issuing DeleteService",
                    )],
                },
                clock.now_ms(),
            );
        }
        if let Err(error) = checkpoint() {
            drop(service);
            return delete_result(
                context,
                DeletionObservation {
                    outcome: DeleteOutcome::Interrupted,
                    presence: None,
                    errors: vec![error],
                },
                clock.now_ms(),
            );
        }
        let deletion = unsafe { DeleteService(service.0) };
        // This handle must not keep the deleted service alive while probing by name.
        drop(service);
        match deletion {
            Ok(()) => {
                context.accepted = true;
                context.marked = true;
            }
            Err(error) if is_win32(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
                context.marked = true;
                context.request_error = Some(ServiceError::native("DeleteService", error));
            }
            Err(error) => {
                return delete_result(
                    context,
                    DeletionObservation {
                        outcome: DeleteOutcome::RequestFailed,
                        presence: None,
                        errors: vec![ServiceError::native("DeleteService", error)],
                    },
                    clock.now_ms(),
                )
            }
        }
    }
    // Probes are read-only. Never send another delete request to a reopened name.
    let observed = wait_for_absence(
        || probe_service(&scm, &input.name),
        &mut clock,
        input.wait.unwrap_or(false),
        timeout,
    );
    delete_result(context, observed, clock.now_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeClock {
        now: u64,
        sleeps: Vec<u64>,
        checks: usize,
        interrupt_on_check: Option<usize>,
        interrupt_sleep: bool,
    }

    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn checkpoint(&mut self) -> NativeResult<()> {
            self.checks += 1;
            if self
                .interrupt_on_check
                .is_some_and(|check| self.checks >= check)
            {
                Err(interrupted())
            } else {
                Ok(())
            }
        }

        fn sleep_ms(&mut self, milliseconds: u64) -> NativeResult<()> {
            assert!(milliseconds > 0);
            self.sleeps.push(milliseconds);
            if self.interrupt_sleep {
                self.now += milliseconds / 2;
                return Err(interrupted());
            }
            self.now += milliseconds;
            Ok(())
        }
    }

    fn interrupted() -> ServiceError {
        ServiceError::interrupted(
            "runtime::checkpoint",
            anyhow::anyhow!("Operation cancelled"),
        )
    }

    fn state(state: SERVICE_STATUS_CURRENT_STATE, checkpoint: u32, hint: u32) -> ObservedStatus {
        ObservedStatus {
            state: status_str(state),
            state_code: state.0,
            process_id: 0,
            controls_accepted: 0,
            checkpoint,
            wait_hint_ms: hint,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
        }
    }

    fn denied(operation: &'static str) -> ServiceError {
        ServiceError::native(
            operation,
            windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(5)),
        )
    }

    struct FakeController {
        states: VecDeque<NativeResult<ObservedStatus>>,
        last: ObservedStatus,
        requests: Vec<StepAction>,
        start_error: Option<ServiceError>,
        stop_error: Option<ServiceError>,
    }

    impl FakeController {
        fn new(states: Vec<ObservedStatus>) -> Self {
            Self {
                last: states[0].clone(),
                states: states.into_iter().map(Ok).collect(),
                requests: Vec::new(),
                start_error: None,
                stop_error: None,
            }
        }
    }

    impl ServiceController for FakeController {
        fn query(&mut self) -> NativeResult<ObservedStatus> {
            if let Some(next) = self.states.pop_front() {
                self.last = next?;
            }
            Ok(self.last.clone())
        }

        fn request(&mut self, action: StepAction) -> NativeResult<()> {
            self.requests.push(action);
            match action {
                StepAction::Start => self.start_error.clone().map_or(Ok(()), Err),
                StepAction::Stop => self.stop_error.clone().map_or(Ok(()), Err),
            }
        }
    }

    fn create_input(extra: Value) -> ServiceCreateInput {
        let mut value =
            json!({ "name": "unit-service", "binary_path": "\"C:\\unit\\worker.exe\"" });
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).expect("valid create fixture")
    }

    fn basic() -> BasicConfiguration {
        BasicConfiguration {
            display_name: "Unit".into(),
            binary_path: "unit.exe".into(),
            account: "LocalSystem".into(),
            service_type: SERVICE_WIN32_OWN_PROCESS.0,
            startup_type: "Automatic",
            start_type_code: SERVICE_AUTO_START.0,
            error_control: 1,
            load_order_group: String::new(),
            tag_id: 0,
            dependencies: Vec::new(),
        }
    }

    fn actual() -> ServiceSnapshot {
        ServiceSnapshot {
            config: Some(basic()),
            status: Some(state(SERVICE_STOPPED, 0, 0)),
            description: Some(String::new()),
            delayed_auto_start: Some(false),
            recovery: Some(RecoveryConfiguration::default()),
            failure_actions_on_non_crash_failures: Some(false),
            sid_type: Some(0),
            query_errors: Vec::new(),
        }
    }

    #[test]
    fn start_observes_checkpoints_and_running() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_START_PENDING, 1, 200),
            state(SERVICE_START_PENDING, 2, 200),
            state(SERVICE_START_PENDING, 3, 200),
            state(SERVICE_RUNNING, 0, 0),
        ]);
        let mut clock = FakeClock::default();
        let result = transition_step(&mut controller, &mut clock, StepAction::Start, true, 1000);
        assert_eq!(result.outcome, TransitionOutcome::Reached);
        assert!(result.accepted);
        assert_eq!(clock.now, 300);
        assert_eq!(controller.requests, vec![StepAction::Start]);
        assert_eq!(result.observed.unwrap().state, "Running");
    }

    #[test]
    fn existing_transition_and_already_running_do_not_send_start() {
        for states in [
            vec![state(SERVICE_RUNNING, 0, 0)],
            vec![
                state(SERVICE_START_PENDING, 1, 1000),
                state(SERVICE_RUNNING, 0, 0),
            ],
        ] {
            let mut controller = FakeController::new(states);
            let result = transition_step(
                &mut controller,
                &mut FakeClock::default(),
                StepAction::Start,
                true,
                1000,
            );
            assert!(result.outcome.success());
            assert!(!result.accepted);
            assert!(controller.requests.is_empty());
        }
    }

    #[test]
    fn acceptance_without_observed_goal_is_an_error() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_START_PENDING, 1, 1000),
        ]);
        let mut clock = FakeClock::default();
        let result = transition_step(&mut controller, &mut clock, StepAction::Start, false, 1000);
        assert_eq!(result.outcome, TransitionOutcome::Pending);
        assert!(result.accepted);
        assert!(clock.sleeps.is_empty());
        let error =
            transition_result("unit", ServiceTransitionAction::Start, vec![result], 0).unwrap_err();
        let report: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(report["success"], false);
        assert_eq!(report["accepted"], true);
        assert_eq!(report["Status"], "StartPending");
    }

    #[test]
    fn stalled_checkpoint_and_inflated_wait_hint_do_not_extend_progress() {
        for hint in [200, 10_000] {
            let mut controller = FakeController::new(vec![
                state(SERVICE_STOPPED, 0, 0),
                state(SERVICE_START_PENDING, 1, 200),
                state(SERVICE_START_PENDING, 1, hint),
            ]);
            let mut clock = FakeClock::default();
            let result =
                transition_step(&mut controller, &mut clock, StepAction::Start, true, 30_000);
            assert_eq!(result.outcome, TransitionOutcome::NoProgress);
            assert_eq!(clock.now, 200);
        }
    }

    #[test]
    fn zero_wait_hint_uses_a_bounded_progress_window() {
        let mut controller = FakeController::new(vec![state(SERVICE_START_PENDING, 0, 0)]);
        let mut clock = FakeClock::default();
        let result = transition_step(&mut controller, &mut clock, StepAction::Start, true, 30_000);
        assert_eq!(result.outcome, TransitionOutcome::NoProgress);
        assert_eq!(clock.now, 1000);
    }

    #[test]
    fn overall_deadline_wins_over_checkpoint_progress() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_START_PENDING, 1, 1000),
            state(SERVICE_START_PENDING, 2, 1000),
            state(SERVICE_START_PENDING, 3, 1000),
            state(SERVICE_START_PENDING, 4, 1000),
        ]);
        let mut clock = FakeClock::default();
        let result = transition_step(&mut controller, &mut clock, StepAction::Start, true, 250);
        assert_eq!(result.outcome, TransitionOutcome::TimedOut);
        assert_eq!(clock.now, 250);
    }

    #[test]
    fn service_exit_codes_survive_failed_start() {
        let mut failed = state(SERVICE_STOPPED, 0, 0);
        failed.win32_exit_code = 1066;
        failed.service_specific_exit_code = 42;
        let mut controller = FakeController::new(vec![
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_START_PENDING, 1, 1000),
            failed,
        ]);
        let result = transition_step(
            &mut controller,
            &mut FakeClock::default(),
            StepAction::Start,
            true,
            1000,
        );
        assert_eq!(result.outcome, TransitionOutcome::Failed);
        assert!(result.accepted);
        let observed = result.observed.unwrap();
        assert_eq!(observed.win32_exit_code, 1066);
        assert_eq!(observed.service_specific_exit_code, 42);
    }

    #[test]
    fn existing_failed_start_is_not_reissued() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_START_PENDING, 1, 1000),
            state(SERVICE_STOPPED, 0, 0),
        ]);
        let result = transition_step(
            &mut controller,
            &mut FakeClock::default(),
            StepAction::Start,
            true,
            1000,
        );
        assert_eq!(result.outcome, TransitionOutcome::Failed);
        assert!(!result.accepted);
        assert!(controller.requests.is_empty());
    }

    #[test]
    fn restart_preserves_stop_error_even_if_status_races_to_stopped() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_RUNNING, 0, 0),
            state(SERVICE_STOPPED, 0, 0),
        ]);
        controller.stop_error = Some(denied("ControlService(STOP)"));
        let steps = transition_steps(
            &mut controller,
            &mut FakeClock::default(),
            ServiceTransitionAction::Restart,
            true,
            1000,
        );
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].outcome, TransitionOutcome::RequestFailed);
        assert_eq!(steps[0].errors[0].win32_error, Some(5));
        assert_eq!(controller.requests, vec![StepAction::Stop]);
        assert_eq!(steps[0].observed.as_ref().unwrap().state, "Stopped");
    }

    #[test]
    fn restart_never_starts_after_pending_stalled_or_failed_stop() {
        for (wait, stopped_error) in [(false, false), (true, false), (true, true)] {
            let mut states = vec![
                state(SERVICE_RUNNING, 0, 0),
                state(SERVICE_STOP_PENDING, 1, 200),
            ];
            if stopped_error {
                let mut stopped = state(SERVICE_STOPPED, 0, 0);
                stopped.win32_exit_code = 1066;
                stopped.service_specific_exit_code = 7;
                states.push(stopped);
            }
            let mut controller = FakeController::new(states);
            let steps = transition_steps(
                &mut controller,
                &mut FakeClock::default(),
                ServiceTransitionAction::Restart,
                wait,
                1000,
            );
            assert_eq!(steps.len(), 1);
            assert!(!steps[0].outcome.success());
            assert_eq!(controller.requests, vec![StepAction::Stop]);
        }
    }

    #[test]
    fn restart_observes_stopped_before_starting() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_RUNNING, 0, 0),
            state(SERVICE_STOP_PENDING, 1, 1000),
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_START_PENDING, 1, 1000),
            state(SERVICE_RUNNING, 0, 0),
        ]);
        let steps = transition_steps(
            &mut controller,
            &mut FakeClock::default(),
            ServiceTransitionAction::Restart,
            true,
            1000,
        );
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|step| step.outcome.success()));
        assert_eq!(steps[0].observed.as_ref().unwrap().state, "Stopped");
        assert_eq!(
            controller.requests,
            vec![StepAction::Stop, StepAction::Start]
        );
    }

    #[test]
    fn restart_uses_one_deadline_for_both_phases() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_RUNNING, 0, 0),
            state(SERVICE_STOP_PENDING, 1, 1000),
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_STOPPED, 0, 0),
        ]);
        let mut clock = FakeClock::default();
        let steps = transition_steps(
            &mut controller,
            &mut clock,
            ServiceTransitionAction::Restart,
            true,
            100,
        );
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[1].outcome, TransitionOutcome::TimedOut);
        assert_eq!(clock.now, 100);
        assert_eq!(controller.requests, vec![StepAction::Stop]);
    }

    #[test]
    fn start_waits_for_an_existing_stop_transition() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_STOP_PENDING, 1, 1000),
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_RUNNING, 0, 0),
        ]);
        let mut clock = FakeClock::default();
        let result = transition_step(&mut controller, &mut clock, StepAction::Start, true, 1000);
        assert_eq!(result.outcome, TransitionOutcome::Reached);
        assert_eq!(clock.now, 100);
        assert_eq!(controller.requests, vec![StepAction::Start]);
    }

    #[test]
    fn query_failure_after_acceptance_is_not_success() {
        let mut controller = FakeController::new(vec![state(SERVICE_STOPPED, 0, 0)]);
        controller
            .states
            .push_back(Err(denied("QueryServiceStatusEx")));
        let result = transition_step(
            &mut controller,
            &mut FakeClock::default(),
            StepAction::Start,
            true,
            1000,
        );
        assert_eq!(result.outcome, TransitionOutcome::QueryFailed);
        assert!(result.accepted);
        assert_eq!(result.errors[0].win32_error, Some(5));
    }

    #[test]
    fn cancellation_checks_prevent_transition_requests() {
        for check in 1..=3 {
            let mut controller = FakeController::new(vec![state(SERVICE_STOPPED, 0, 0)]);
            let mut clock = FakeClock {
                interrupt_on_check: Some(check),
                ..Default::default()
            };
            let result =
                transition_step(&mut controller, &mut clock, StepAction::Start, true, 1000);
            assert_eq!(result.outcome, TransitionOutcome::Interrupted);
            assert!(!result.accepted);
            assert!(result.errors[0].interrupted);
            assert!(controller.requests.is_empty());
        }
    }

    #[test]
    fn cancelled_native_request_is_distinct_from_a_win32_failure() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_RUNNING, 0, 0),
        ]);
        controller.start_error = Some(interrupted());
        let result = transition_step(
            &mut controller,
            &mut FakeClock::default(),
            StepAction::Start,
            true,
            1000,
        );
        assert_eq!(result.outcome, TransitionOutcome::Interrupted);
        assert!(!result.accepted);
        assert_eq!(result.observed.unwrap().state, "Stopped");
        assert_eq!(controller.states.len(), 1);
    }

    #[test]
    fn cancellation_after_acceptance_preserves_the_last_observation() {
        for interrupt_sleep in [false, true] {
            let mut controller = FakeController::new(vec![
                state(SERVICE_STOPPED, 0, 0),
                state(SERVICE_START_PENDING, 1, 1000),
                state(SERVICE_RUNNING, 0, 0),
            ]);
            let mut clock = FakeClock {
                interrupt_on_check: if interrupt_sleep { None } else { Some(4) },
                interrupt_sleep,
                ..Default::default()
            };
            let result =
                transition_step(&mut controller, &mut clock, StepAction::Start, true, 1000);
            assert_eq!(result.outcome, TransitionOutcome::Interrupted);
            assert!(result.accepted);
            assert_eq!(result.observed.as_ref().unwrap().state, "StartPending");
            assert_eq!(controller.states.len(), 1);
            let error = transition_result(
                "unit",
                ServiceTransitionAction::Start,
                vec![result],
                clock.now,
            )
            .unwrap_err()
            .to_string();
            let report: Value = serde_json::from_str(&error).unwrap();
            assert_eq!(report["success"], false);
            assert_eq!(report["accepted"], true);
            assert_eq!(report["outcome"], "interrupted");
        }
    }

    #[test]
    fn cancellation_between_restart_phases_refuses_start() {
        let mut controller = FakeController::new(vec![
            state(SERVICE_RUNNING, 0, 0),
            state(SERVICE_STOPPED, 0, 0),
            state(SERVICE_STOPPED, 0, 0),
        ]);
        let mut clock = FakeClock {
            interrupt_on_check: Some(5),
            ..Default::default()
        };
        let steps = transition_steps(
            &mut controller,
            &mut clock,
            ServiceTransitionAction::Restart,
            true,
            1000,
        );
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].outcome, TransitionOutcome::Reached);
        assert_eq!(steps[1].outcome, TransitionOutcome::Interrupted);
        assert_eq!(steps[1].observed.as_ref().unwrap().state, "Stopped");
        assert_eq!(controller.requests, vec![StepAction::Stop]);
    }

    #[test]
    fn numeric_strings_are_coerced_without_losing_unsigned_limits() {
        let input: ServiceTransitionInput = serde_json::from_value(json!({
            "name": "unit", "action": "restart", "timeout_ms": "2500",
        }))
        .ok()
        .unwrap();
        assert_eq!(input.timeout_ms, Some(2500));
        let input: ServiceDeleteInput = serde_json::from_value(json!({
            "name": "unit", "timeout_ms": "300000",
        }))
        .ok()
        .unwrap();
        assert_eq!(timeout_ms(input.timeout_ms).unwrap(), 300_000);
        let input = create_input(json!({ "recovery": {
            "reset_period_seconds": "4294967295",
            "actions": [{ "action": "restart", "delay_ms": "4294967295" }],
        }}));
        let recovery = input.recovery.as_ref().unwrap();
        assert_eq!(recovery.reset_period_seconds, Some(u32::MAX));
        assert_eq!(recovery.actions.as_ref().unwrap()[0].delay_ms, u32::MAX);
    }

    #[test]
    fn numeric_negative_overflow_fractional_and_wrong_types_are_rejected() {
        for value in [
            json!(-1),
            json!("-1"),
            json!("18446744073709551616"),
            json!(1.5),
            json!(true),
        ] {
            assert!(serde_json::from_value::<ServiceTransitionInput>(json!({
                "name": "unit", "action": "start", "timeout_ms": value,
            }))
            .is_err());
        }
        for value in [
            json!(-1),
            json!("-1"),
            json!(4294967296u64),
            json!("4294967296"),
            json!(false),
        ] {
            assert!(serde_json::from_value::<ServiceRecoveryActionInput>(json!({
                "action": "restart", "delay_ms": value,
            }))
            .is_err());
            assert!(serde_json::from_value::<ServiceRecoveryInput>(json!({
                "reset_period_seconds": value,
            }))
            .is_err());
        }
        for value in [0, MAX_TIMEOUT_MS + 1, u64::MAX] {
            assert!(timeout_ms(Some(value)).is_err());
        }
    }

    #[test]
    fn names_and_dependencies_are_validated_as_exact_utf16_names() {
        for name in ["", " ", "a\0b", "a\\b", "a/b", "*", "svc?"] {
            assert!(validate_name(name).is_err());
        }
        assert!(validate_name(&"a".repeat(257)).is_err());
        assert!(validate_name(&"\u{1f600}".repeat(128)).is_ok());
        assert!(validate_name(&"\u{1f600}".repeat(129)).is_err());
        for dependencies in [
            json!([""]),
            json!(["+"]),
            json!(["a\0b"]),
            json!(["UNIT-SERVICE"]),
            json!(["Tcpip", "TCPIP"]),
        ] {
            let input = create_input(json!({ "dependencies": dependencies }));
            assert!(input.settings().validate(&input.name).is_err());
        }
        let input = create_input(json!({ "dependencies": ["Tcpip", "+NetworkProvider"] }));
        input.settings().validate(&input.name).unwrap();
    }

    #[test]
    fn absent_and_empty_values_produce_distinct_native_pointers() {
        let absent = create_input(json!({}));
        let absent_wide = WideSettings::new(&absent.settings());
        assert!(absent_wide.password_pointer().is_null());
        assert!(wide_pointer(absent_wide.dependencies.as_deref()).is_null());
        assert!(absent
            .settings()
            .plan(None, None)
            .unwrap()
            .description
            .is_none());
        let empty = create_input(json!({ "password": "", "dependencies": [], "description": "" }));
        let wide = WideSettings::new(&empty.settings());
        assert!(!wide.password_pointer().is_null());
        assert_eq!(wide.password.as_ref().unwrap().0, vec![0]);
        assert_eq!(wide.dependencies.as_ref().unwrap(), &vec![0, 0]);
        assert_eq!(
            empty.settings().plan(None, None).unwrap().description,
            Some(vec![0])
        );
        assert_eq!(
            to_multi_wide(&["Tcpip".into(), "+Net".into()]),
            to_wide("Tcpip\0+Net\0")
        );
    }

    #[test]
    fn unsupported_and_conflicting_settings_fail_before_mutation() {
        for extra in [
            json!({ "service_type": "kernel_driver" }),
            json!({ "startup_type": "boot" }),
            json!({ "sid_type": "unsupported" }),
            json!({ "required_privileges": ["SeDebugPrivilege"] }),
        ] {
            let mut value = json!({ "name": "unit", "binary_path": "unit.exe" });
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(serde_json::from_value::<ServiceCreateInput>(value).is_err());
        }
        for extra in [
            json!({ "binary_path": "" }),
            json!({ "account": "" }),
            json!({ "description": "bad\0description" }),
            json!({ "display_name": "a".repeat(257) }),
            json!({ "recovery": {} }),
            json!({ "recovery": { "actions": [], "reset_period_seconds": 60 } }),
        ] {
            let input = create_input(extra);
            assert!(input.settings().validate(&input.name).is_err());
        }
        let input = create_input(json!({ "delayed_auto_start": true }));
        assert!(input.settings().plan(None, None).is_err());
        let input =
            create_input(json!({ "delayed_auto_start": true, "startup_type": "automatic" }));
        assert!(input.settings().plan(None, None).is_ok());
        let input: ServiceConfigureInput = serde_json::from_value(json!({ "name": "unit" }))
            .ok()
            .unwrap();
        assert!(input.settings().validate(&input.name).is_err());
    }

    #[test]
    fn delayed_start_rejects_load_order_groups_during_planning() {
        let input = create_input(json!({
            "startup_type": "automatic", "delayed_auto_start": true,
            "display_name": "Would otherwise change", "description": "Must not be applied",
        }));
        let mut current = basic();
        current.load_order_group = "Example Group".to_owned();
        assert!(input.settings().validate(&input.name).is_ok());
        let error = input.settings().plan(Some(&current), None).err().unwrap();
        assert!(error.to_string().contains("load-order group"));
        current.load_order_group.clear();
        assert!(input.settings().plan(Some(&current), None).is_ok());
    }

    #[test]
    fn early_mutation_failures_have_structured_errors_and_native_codes() {
        let native = windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
            windows::Win32::Foundation::ERROR_SERVICE_EXISTS.0,
        ));
        let error = finish_operation(
            "unit-service",
            "create",
            Err(ServiceError::native("CreateServiceW", native).into()),
            None,
        )
        .unwrap_err();
        let result: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["accepted"], false);
        assert_eq!(result["outcome"], "failed");
        assert_eq!(result["errors"][0]["operation"], "CreateServiceW");
        assert_eq!(result["errors"][0]["win32_error"], 1073);
        assert!(result["errors"][0]["hresult"].is_i64());

        let result = finish_operation("unit-service", "delete", Err(interrupted().into()), None)
            .unwrap_err();
        let result: Value = serde_json::from_str(&result.to_string()).unwrap();
        assert_eq!(result["outcome"], "interrupted");
        assert_eq!(result["accepted"], false);
    }

    #[test]
    fn public_mutation_validation_uses_the_same_error_envelope() {
        let mut create_request = create_input(json!({"password": "SENTINEL"}));
        create_request.name = "SENTINEL\0".to_owned();
        let configure_request: ServiceConfigureInput =
            serde_json::from_value(json!({"name":"", "description":"unused"})).unwrap();
        let errors = [
            create(create_request).unwrap_err(),
            configure(configure_request).unwrap_err(),
            transition(ServiceTransitionInput {
                name: String::new(),
                action: ServiceTransitionAction::Start,
                wait: None,
                timeout_ms: None,
            })
            .unwrap_err(),
            delete(ServiceDeleteInput {
                name: String::new(),
                wait: None,
                timeout_ms: None,
            })
            .unwrap_err(),
            set_startup("", "Automatic").unwrap_err(),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(!text.contains("SENTINEL"));
            let result: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(result["success"], false);
            assert_eq!(result["accepted"], false);
            assert_eq!(result["outcome"], "failed");
            assert!(result["errors"].is_array());
        }
        let mut request = create_input(json!({}));
        request.name = "a".repeat(10_000);
        let result: Value =
            serde_json::from_str(&create(request).unwrap_err().to_string()).unwrap();
        assert_eq!(result["name_omitted"], true);
        assert!(result["Name"].is_null());
    }

    #[test]
    fn existing_partial_mutation_results_are_not_rewrapped() {
        let partial = json!({
            "Name": "unit-service", "operation": "configure", "success": false,
            "outcome": "partial", "accepted": true, "applied_steps": ["description"],
            "actual": {"description":"changed"}, "errors": [{"operation":"delayed_auto_start"}],
        });
        let error = finish_operation(
            "unit-service",
            "configure",
            finish(partial.clone(), false, None),
            None,
        )
        .unwrap_err();
        let result: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(result, partial);
    }

    #[test]
    fn recovery_reset_only_preserves_actions_and_empty_actions_clear() {
        let current = RecoveryConfiguration {
            reset_period_seconds: 86400,
            actions: vec![RecoveryActionConfiguration {
                action: "restart",
                action_code: 1,
                delay_ms: 2000,
            }],
            command: String::new(),
            reboot_message: "Keep".into(),
        };
        let input: ServiceRecoveryInput =
            serde_json::from_value(json!({ "reset_period_seconds": "60" }))
                .ok()
                .unwrap();
        let plan = RecoveryPlan::new(&input, Some(&current)).unwrap();
        assert_eq!(plan.reset_period_seconds, 60);
        assert_eq!(plan.actions.as_ref().unwrap()[0].Delay, 2000);
        assert!(plan.needs_start_access());
        assert!(plan.command.is_none());
        assert!(plan.reboot_message.is_none());
        let input: ServiceRecoveryInput = serde_json::from_value(json!({ "actions": [] }))
            .ok()
            .unwrap();
        let plan = RecoveryPlan::new(&input, Some(&current)).unwrap();
        assert_eq!(plan.reset_period_seconds, 0);
        assert!(plan.actions.as_ref().unwrap().is_empty());
        let input: ServiceRecoveryInput = serde_json::from_value(json!({ "command": "" }))
            .ok()
            .unwrap();
        let plan = RecoveryPlan::new(&input, Some(&current)).unwrap();
        assert!(plan.actions.is_none());
        assert_eq!(plan.command, Some(vec![0]));
    }

    #[test]
    fn run_command_and_reset_period_need_effective_actions_and_command() {
        let input = create_input(
            json!({ "recovery": { "actions": [{ "action": "run_command", "delay_ms": 0 }] } }),
        );
        assert!(input.settings().plan(None, None).is_err());
        let input = create_input(json!({ "recovery": { "reset_period_seconds": 60 } }));
        assert!(input.settings().plan(None, None).is_err());
        let input = create_input(json!({ "recovery": {
            "actions": [{ "action": "run_command", "delay_ms": 0 }], "command": "unit.exe",
        }}));
        assert!(input.settings().plan(None, None).is_ok());
    }

    #[test]
    fn configuration_stops_after_error_and_returns_actual_partial_state() {
        let steps = [
            ConfigurationStep::Description,
            ConfigurationStep::Recovery,
            ConfigurationStep::SidType,
        ];
        let mut calls = Vec::new();
        let (applied, errors) = execute_configuration(&steps, vec!["create"], checkpoint, |step| {
            calls.push(step);
            if step == ConfigurationStep::Recovery {
                Err(denied("recovery"))
            } else {
                Ok(())
            }
        });
        assert_eq!(applied, vec!["create", "description"]);
        assert_eq!(
            calls,
            vec![ConfigurationStep::Description, ConfigurationStep::Recovery]
        );
        let error =
            configuration_result("unit", "create", applied, errors, actual(), None).unwrap_err();
        let report: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(report["outcome"], "partial");
        assert_eq!(report["success"], false);
        assert_eq!(report["errors"][0]["win32_error"], 5);
        assert_eq!(report["actual"]["status"]["state"], "Stopped");
    }

    #[test]
    fn configuration_cancellation_retains_applied_steps_and_skips_later_mutations() {
        let steps = [ConfigurationStep::Description, ConfigurationStep::Recovery];
        let mut checks = 0;
        let mut mutations = Vec::new();
        let (applied, errors) = execute_configuration(
            &steps,
            vec!["create"],
            || {
                checks += 1;
                if checks == 2 {
                    Err(interrupted())
                } else {
                    Ok(())
                }
            },
            |step| {
                mutations.push(step);
                Ok(())
            },
        );
        assert_eq!(mutations, vec![ConfigurationStep::Description]);
        assert_eq!(applied, vec!["create", "description"]);
        assert!(errors[0].interrupted);
        let error = configuration_result("unit", "create", applied, errors, actual(), None)
            .unwrap_err()
            .to_string();
        let report: Value = serde_json::from_str(&error).unwrap();
        assert_eq!(report["success"], false);
        assert_eq!(report["outcome"], "partial");
        assert_eq!(report["actual"]["status"]["state"], "Stopped");

        let (applied, errors) = execute_configuration(
            &[],
            vec!["create"],
            || Err(interrupted()),
            |_| panic!("no settings remain"),
        );
        assert_eq!(applied, vec!["create"]);
        assert!(errors[0].interrupted);
    }

    #[test]
    fn password_errors_and_partial_results_are_redacted() {
        let secret = "SENTINEL\n\"password\\";
        let input = create_input(json!({ "password": secret }));
        let mut resulting = actual();
        resulting.config.as_mut().unwrap().binary_path = format!("prefix {secret} suffix");
        let error = configuration_result(
            "unit",
            "configure",
            vec!["basic_config"],
            vec![ServiceError::local("configure", format!("bad {secret}"))],
            resulting,
            input.password.as_ref(),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("SENTINEL"));
        assert!(error.contains("[REDACTED]"));
        let input = create_input(json!({ "password": "SENTINEL\0password" }));
        let error = input
            .settings()
            .validate(&input.name)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SENTINEL"));
        let malformed = serde_json::from_value::<ServiceCreateInput>(json!({
            "name": "unit", "binary_path": "unit.exe", "password": 987654321,
        }))
        .err()
        .unwrap()
        .to_string();
        assert!(!malformed.contains("987654321"));
        assert!(malformed.contains("password must be a string"));
    }

    fn marked() -> ServicePresence {
        ServicePresence::MarkedForDeletion {
            error: ServiceError::native(
                "OpenServiceW",
                windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
                    ERROR_SERVICE_MARKED_FOR_DELETE.0,
                )),
            ),
        }
    }

    #[test]
    fn deletion_waits_for_absence_without_mutating_reopened_names() {
        let mut probes = VecDeque::from([
            marked(),
            ServicePresence::PresentOrReplaced {
                observed: Some(state(SERVICE_RUNNING, 0, 0)),
                query_errors: Vec::new(),
            },
            ServicePresence::Absent,
        ]);
        let mut clock = FakeClock::default();
        let result = wait_for_absence(|| Ok(probes.pop_front().unwrap()), &mut clock, true, 1000);
        assert_eq!(result.outcome, DeleteOutcome::Absent);
        assert_eq!(clock.now, 500);
        assert!(probes.is_empty());
    }

    #[test]
    fn deletion_pending_timeout_and_probe_errors_are_not_success() {
        let pending = wait_for_absence(|| Ok(marked()), &mut FakeClock::default(), false, 1000);
        assert_eq!(pending.outcome, DeleteOutcome::Pending);
        let mut clock = FakeClock::default();
        let timed_out = wait_for_absence(|| Ok(marked()), &mut clock, true, 600);
        assert_eq!(timed_out.outcome, DeleteOutcome::TimedOut);
        assert_eq!(clock.now, 600);
        let failed = wait_for_absence(
            || Err(denied("OpenServiceW")),
            &mut FakeClock::default(),
            true,
            1000,
        );
        assert_eq!(failed.outcome, DeleteOutcome::QueryFailed);
        assert_eq!(failed.errors[0].win32_error, Some(5));
        let error = delete_result(
            DeleteContext {
                name: "unit",
                accepted: true,
                marked: true,
                request_error: None,
                original_status: None,
                original_query_errors: Vec::new(),
            },
            pending,
            0,
        )
        .unwrap_err();
        let report: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(report["success"], false);
        assert_eq!(report["accepted"], true);
        assert_eq!(report["presence"]["error"]["win32_error"], 1072);
    }

    #[test]
    fn deletion_cancellation_stops_probing_and_preserves_pending_presence() {
        let mut probes = VecDeque::from([marked(), ServicePresence::Absent]);
        let mut clock = FakeClock {
            interrupt_sleep: true,
            ..Default::default()
        };
        let result = wait_for_absence(|| Ok(probes.pop_front().unwrap()), &mut clock, true, 1000);
        assert_eq!(result.outcome, DeleteOutcome::Interrupted);
        assert!(matches!(
            result.presence,
            Some(ServicePresence::MarkedForDeletion { .. })
        ));
        assert_eq!(probes.len(), 1);
        assert!(result.errors[0].interrupted);

        let mut clock = FakeClock {
            interrupt_on_check: Some(1),
            ..Default::default()
        };
        let result = wait_for_absence(
            || panic!("cancelled probe must not run"),
            &mut clock,
            true,
            1000,
        );
        assert_eq!(result.outcome, DeleteOutcome::Interrupted);
        assert!(result.presence.is_none());
    }

    #[test]
    fn changing_query_sizes_preserve_the_final_native_error() {
        let mut calls = 0;
        let result = query_buffer("mock_query", |_buffer, needed| {
            calls += 1;
            *needed = calls * 64;
            Err(windows::core::Error::from_hresult(
                windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0),
            ))
        });
        assert_eq!(calls, 5);
        assert_eq!(result.err().unwrap().win32_error, Some(122));
    }

    #[test]
    fn credential_is_redacted_in_success_and_early_errors() {
        let input = create_input(json!({ "password": "SENTINEL" }));
        let output = finish(
            json!({ "actual": { "description": "SENTINEL" } }),
            true,
            input.password.as_ref(),
        )
        .unwrap();
        assert!(!output.contains("SENTINEL"));
        let error = finish_operation(
            "unit-service",
            "create",
            Err(anyhow::anyhow!("early SENTINEL failure")),
            input.password.as_ref(),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("SENTINEL"));
        let result: Value = serde_json::from_str(&error).unwrap();
        assert_eq!(result["accepted"], false);
        assert_eq!(result["errors"][0]["message"], "early [REDACTED] failure");
    }

    #[test]
    fn request_schemas_expose_only_supported_settings() {
        let schema = serde_json::to_value(schemars::schema_for!(ServiceCreateInput)).unwrap();
        let properties = schema["properties"].as_object().unwrap();
        assert!(properties.contains_key("password"));
        assert!(properties.contains_key("dependencies"));
        assert!(properties.contains_key("recovery"));
        assert_eq!(schema["additionalProperties"], false);
        let schema = serde_json::to_value(schemars::schema_for!(ServiceTransitionInput)).unwrap();
        assert!(schema["properties"]["timeout_ms"].is_object());
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    #[ignore = "read-only integration test against the local Windows SCM"]
    fn native_read_only_queries() {
        let entries: Value = serde_json::from_str(&list().unwrap()).unwrap();
        assert!(!entries.as_array().unwrap().is_empty());
        let result: Value = serde_json::from_str(&detail("EventLog").unwrap()).unwrap();
        assert_eq!(result["Name"], "EventLog");
        assert!(result["BinaryPath"].is_string());
        assert!(result["observed"]["state_code"].is_u64());
        assert_eq!(result["query_errors"], json!([]));
        assert!(result["Recovery"]["actions"].is_array());
        assert!(result["Dependencies"].is_array());
        assert!(result["Description"].is_string());
        assert!(result["DelayedAutoStart"].is_boolean());
        assert!(result["SidType"].is_u64());
    }
}
