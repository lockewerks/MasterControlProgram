use super::admin_common::{
    absolute_path, guid, guid_string, result_limit, text, wide, win32_error, AdminContext,
    NativeError, MAX_NATIVE_BYTES,
};
use anyhow::{bail, Context, Result};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows::core::{BOOL, GUID, HRESULT, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::*;
use windows::Win32::Devices::Properties::*;
use windows::Win32::Foundation::{
    GetLastError, DEVPROPKEY, ERROR_GEN_FAILURE, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND,
    ERROR_NO_MORE_ITEMS, WIN32_ERROR,
};
use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;

const MAX_DEVICE_SCAN: u32 = 65_536;
const MAX_PROPERTY_BYTES: usize = 65_536;
const MAX_CLASS_GUIDS: usize = 64;
const MAX_PATH_UNITS: usize = 32_768;
const MAX_READ_ATTEMPTS: usize = 4;
const MAX_STATE_POLLS: usize = 20;
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const INSTALL_FLAGS: DIINSTALLDRIVER_FLAGS = DIINSTALLDRIVER_FLAGS(0);
const REMOVE_FLAGS: u32 = 0;

fn default_present_only() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceListInput {
    pub instance_id: Option<String>,
    /// Exact setup class GUID. Mutually exclusive with class_name.
    pub class_guid: Option<String>,
    /// Exact setup class name, not a localized description or wildcard.
    pub class_name: Option<String>,
    #[serde(default = "default_present_only")]
    pub present_only: bool,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStateAction {
    Enable,
    Disable,
    Restart,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceStateInput {
    pub instance_id: String,
    pub action: DeviceStateAction,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverListInput {
    pub instance_id: Option<String>,
    pub class_guid: Option<String>,
    pub class_name: Option<String>,
    /// Exact published INF basename, including inbox names such as machine.inf.
    pub published_inf: Option<String>,
    #[serde(default)]
    pub present_only: bool,
    /// Maximum device-driver associations, not a count of unique packages.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriverPackageAction {
    Stage,
    Install,
    Remove,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPackageInput {
    pub action: DriverPackageAction,
    /// Fully qualified INF file path, required only for stage and install.
    pub inf_path: Option<String>,
    /// Exact oemN.inf basename, required only for remove. In-use packages are refused.
    pub published_inf: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Reading<T> {
    Available { value: T },
    Absent { native_error: NativeError },
    Unavailable { native_error: NativeError },
    NotApplicable { reason: &'static str },
}

impl<T> Reading<T> {
    fn available(value: T) -> Self {
        Self::Available { value }
    }

    fn value(&self) -> Option<&T> {
        match self {
            Self::Available { value } => Some(value),
            _ => None,
        }
    }
}

fn unavailable<T>(error: anyhow::Error) -> Result<Reading<T>> {
    match error.downcast::<NativeError>() {
        Ok(native_error) => Ok(Reading::Unavailable { native_error }),
        Err(error) => Err(error),
    }
}

fn setup_error(api: &str, error: windows::core::Error) -> NativeError {
    let hresult = error.code().0 as u32;
    let (domain, code) = if hresult & 0xffff_0000 == 0x8007_0000 {
        ("win32", hresult & 0xffff)
    } else if hresult & 0xffff_0000 == 0xe000_0000 {
        ("win32", hresult)
    } else {
        ("hresult", hresult)
    };
    NativeError {
        api: api.into(),
        domain: domain.into(),
        code,
        message: error.message(),
    }
}

fn is_win32(error: &windows::core::Error, code: WIN32_ERROR) -> bool {
    error.code() == HRESULT::from_win32(code.0)
}

fn cm_error(api: &str, code: CONFIGRET) -> NativeError {
    let mapped = unsafe { CM_MapCrToWin32Err(code, ERROR_GEN_FAILURE.0) };
    let message = windows::core::Error::from_hresult(HRESULT::from_win32(mapped)).message();
    NativeError {
        api: api.into(),
        domain: "configret".into(),
        code: code.0,
        message: format!("{message} (mapped Win32 code {mapped})"),
    }
}

fn check_cm(api: &str, code: CONFIGRET) -> Result<()> {
    if code != CR_SUCCESS {
        return Err(cm_error(api, code).into());
    }
    Ok(())
}

fn validate_instance_id(value: &str) -> Result<()> {
    text(value, "instance_id", MAX_DEVICE_ID_LEN as usize - 1)?;
    let parts: Vec<_> = value.split('\\').collect();
    if value.trim() != value
        || value.chars().any(|ch| ch.is_control() || "?/".contains(ch))
        || parts.len() != 3
        || parts.iter().any(|part| part.is_empty())
    {
        bail!("instance_id must be an exact enumerator\\device\\instance identifier, without wildcards");
    }
    // Legacy root-enumerated IDs can contain a literal leading star, such as *PNP0501.
    if parts[0].contains('*')
        || parts[2].contains('*')
        || parts[1].trim_start_matches('*').is_empty()
        || parts[1].strip_prefix('*').unwrap_or(parts[1]).contains('*')
    {
        bail!("instance_id must be an exact device instance, not a wildcard expression");
    }
    Ok(())
}

fn validate_inf_name(value: &str) -> Result<()> {
    text(value, "published_inf", 255)?;
    if value.trim() != value
        || value
            .chars()
            .any(|ch| ch.is_control() || "\\/:*?\"<>|".contains(ch))
        || value.len() <= 4
        || !value.to_ascii_lowercase().ends_with(".inf")
    {
        bail!("published_inf must be an exact INF basename, without a path or wildcards");
    }
    Ok(())
}

fn validate_oem_inf(value: &str) -> Result<()> {
    validate_inf_name(value)?;
    let lower = value.to_ascii_lowercase();
    let number = lower
        .strip_prefix("oem")
        .and_then(|rest| rest.strip_suffix(".inf"))
        .filter(|number| !number.is_empty() && number.bytes().all(|ch| ch.is_ascii_digit()));
    if number
        .and_then(|number| number.parse::<u32>().ok())
        .is_none()
    {
        bail!("removal requires the exact published oemN.inf name; inbox and source INF names are not accepted");
    }
    Ok(())
}

fn validate_inf_path(value: &str) -> Result<PathBuf> {
    let path = absolute_path(value, "inf_path")?;
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("inf"))
    {
        bail!("inf_path must name an .inf file");
    }
    Ok(path)
}

fn terminated_string(units: &[u16]) -> Result<String> {
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .context("Native UTF-16 string has no terminator within its reported buffer")?;
    if units[end..].iter().any(|&unit| unit != 0) {
        bail!("Native UTF-16 string contains data after its terminator");
    }
    String::from_utf16(&units[..end]).context("Native string contains invalid UTF-16")
}

fn utf16_units(bytes: &[u8]) -> Result<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        bail!("Native UTF-16 property has an odd byte length");
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    Ok(pairs.iter().copied().map(u16::from_le_bytes).collect())
}

fn decode_string(bytes: &[u8]) -> Result<String> {
    terminated_string(&utf16_units(bytes)?)
}

fn decode_string_list(bytes: &[u8]) -> Result<Vec<String>> {
    let units = utf16_units(bytes)?;
    if units.len() < 2 || units[units.len() - 2..] != [0, 0] {
        bail!("Native string-list property is not double-NUL terminated");
    }
    let mut result = Vec::new();
    let mut offset = 0;
    for part in units.split(|&unit| unit == 0) {
        if part.is_empty() {
            if units[offset..].iter().any(|&unit| unit != 0) {
                bail!("Native string-list property contains data after its terminator");
            }
            break;
        }
        result
            .push(String::from_utf16(part).context("Native string list contains invalid UTF-16")?);
        offset += part.len() + 1;
    }
    Ok(result)
}

fn decode_bool(bytes: &[u8]) -> Result<bool> {
    match bytes {
        [0] => Ok(false),
        [0xff] => Ok(true),
        _ => bail!("Native DEVPROP_TYPE_BOOLEAN property has an invalid value or length"),
    }
}

fn decode_filetime(bytes: &[u8]) -> Result<String> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Native FILETIME property does not contain eight bytes"))?;
    // A decimal string preserves all 64 bits for JSON clients using floating-point numbers.
    Ok(u64::from_le_bytes(value).to_string())
}

struct DeviceInfoSet(HDEVINFO);

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        if let Err(error) = unsafe { SetupDiDestroyDeviceInfoList(self.0) } {
            tracing::warn!(
                native_code = error.code().0 as u32,
                error = %error,
                "SetupDiDestroyDeviceInfoList failed"
            );
        }
    }
}

fn device_info() -> SP_DEVINFO_DATA {
    SP_DEVINFO_DATA {
        cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    }
}

fn instance_id(context: &AdminContext, set: HDEVINFO, info: &SP_DEVINFO_DATA) -> Result<String> {
    context.check()?;
    let mut buffer = [0u16; MAX_DEVICE_ID_LEN as usize];
    let mut required = 0u32;
    unsafe {
        SetupDiGetDeviceInstanceIdW(set, info, Some(&mut buffer), Some(&mut required))
            .map_err(|error| setup_error("SetupDiGetDeviceInstanceIdW", error))?;
    }
    if required == 0 || required as usize > buffer.len() {
        bail!("SetupDiGetDeviceInstanceIdW returned an invalid character count");
    }
    terminated_string(&buffer[..required as usize])
}

fn open_exact(
    context: &AdminContext,
    requested: &str,
) -> Result<(DeviceInfoSet, SP_DEVINFO_DATA, String)> {
    validate_instance_id(requested)?;
    let wide_id = wide(requested, "instance_id", MAX_DEVICE_ID_LEN as usize - 1)?;
    context.check()?;
    let set = DeviceInfoSet(unsafe {
        SetupDiCreateDeviceInfoList(None, None)
            .map_err(|error| setup_error("SetupDiCreateDeviceInfoList", error))?
    });
    let mut info = device_info();
    context.check()?;
    unsafe {
        SetupDiOpenDeviceInfoW(set.0, PCWSTR(wide_id.as_ptr()), None, 0, Some(&mut info))
            .map_err(|error| setup_error("SetupDiOpenDeviceInfoW", error))?;
    }
    let actual = instance_id(context, set.0, &info)?;
    if !actual.eq_ignore_ascii_case(requested) {
        bail!("SetupDiOpenDeviceInfoW returned a different device instance; no mutation attempted");
    }
    Ok((set, info, actual))
}

fn property<T>(
    context: &AdminContext,
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    key: &DEVPROPKEY,
    expected_type: DEVPROPTYPE,
    decode: fn(&[u8]) -> Result<T>,
) -> Result<Reading<T>> {
    let mut buffer = vec![0u8; 256];
    for _ in 0..MAX_READ_ATTEMPTS {
        context.check()?;
        let mut property_type = DEVPROPTYPE::default();
        let mut required = 0u32;
        let result = unsafe {
            SetupDiGetDevicePropertyW(
                set,
                info,
                key,
                &mut property_type,
                Some(&mut buffer),
                Some(&mut required),
                0,
            )
        };
        match result {
            Ok(()) => {
                if required as usize > buffer.len() || property_type != expected_type {
                    bail!(
                        "SetupDiGetDevicePropertyW returned an invalid size or type for {}:{}",
                        guid_string(key.fmtid),
                        key.pid
                    );
                }
                let value = decode(&buffer[..required as usize]).with_context(|| {
                    format!(
                        "Invalid device property {}:{}",
                        guid_string(key.fmtid),
                        key.pid
                    )
                })?;
                return Ok(Reading::available(value));
            }
            Err(error) if is_win32(&error, ERROR_INSUFFICIENT_BUFFER) => {
                let required = required as usize;
                if required <= buffer.len()
                    || required > MAX_PROPERTY_BYTES
                    || required > MAX_NATIVE_BYTES
                {
                    bail!("SetupDiGetDevicePropertyW requested an invalid or oversized property buffer");
                }
                buffer.resize(required, 0);
            }
            Err(error) if is_win32(&error, ERROR_NOT_FOUND) => {
                return Ok(Reading::Absent {
                    native_error: setup_error("SetupDiGetDevicePropertyW", error),
                });
            }
            Err(error) => {
                return Ok(Reading::Unavailable {
                    native_error: setup_error("SetupDiGetDevicePropertyW", error),
                });
            }
        }
    }
    bail!("Device property kept changing size during bounded reads")
}

fn string_property(
    context: &AdminContext,
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    key: &DEVPROPKEY,
) -> Result<Reading<String>> {
    property(context, set, info, key, DEVPROP_TYPE_STRING, decode_string)
}

#[derive(Debug, Clone, Copy, Serialize)]
struct CmState {
    devinst: u32,
    status: u32,
    problem_code: u32,
    started: bool,
    has_problem: bool,
    disableable: bool,
    software_disabled: bool,
    hardware_disabled: bool,
    needs_restart: bool,
    configret: u32,
}

fn state_from_native(devinst: u32, status: CM_DEVNODE_STATUS_FLAGS, problem: CM_PROB) -> CmState {
    CmState {
        devinst,
        status: status.0,
        problem_code: problem.0,
        started: status.0 & DN_STARTED.0 != 0,
        has_problem: status.0 & DN_HAS_PROBLEM.0 != 0,
        disableable: status.0 & DN_DISABLEABLE.0 != 0,
        software_disabled: problem == CM_PROB_DISABLED,
        hardware_disabled: problem == CM_PROB_HARDWARE_DISABLED,
        needs_restart: status.0 & DN_NEED_RESTART.0 != 0 || problem == CM_PROB_NEED_RESTART,
        configret: CR_SUCCESS.0,
    }
}

fn cm_state(context: &AdminContext, devinst: u32) -> Result<CmState> {
    context.check()?;
    let mut status = CM_DEVNODE_STATUS_FLAGS::default();
    let mut problem = CM_PROB::default();
    check_cm("CM_Get_DevNode_Status", unsafe {
        CM_Get_DevNode_Status(&mut status, &mut problem, devinst, 0)
    })?;
    Ok(state_from_native(devinst, status, problem))
}

fn locate_live(context: &AdminContext, id: Option<&str>) -> Result<u32> {
    let wide_id = id
        .map(|id| wide(id, "instance_id", MAX_DEVICE_ID_LEN as usize - 1))
        .transpose()?;
    let pointer = wide_id
        .as_ref()
        .map_or(PCWSTR::null(), |id| PCWSTR(id.as_ptr()));
    let mut devinst = 0u32;
    context.check()?;
    check_cm("CM_Locate_DevNodeW", unsafe {
        CM_Locate_DevNodeW(&mut devinst, pointer, CM_LOCATE_DEVNODE_NORMAL)
    })?;
    Ok(devinst)
}

fn cm_instance_id(context: &AdminContext, devinst: u32) -> Result<String> {
    let mut length = 0u32;
    context.check()?;
    check_cm("CM_Get_Device_ID_Size", unsafe {
        CM_Get_Device_ID_Size(&mut length, devinst, 0)
    })?;
    if length == 0 || length >= MAX_DEVICE_ID_LEN {
        bail!("CM_Get_Device_ID_Size returned an invalid instance identifier length");
    }
    let mut buffer = vec![0u16; length as usize + 1];
    context.check()?;
    check_cm("CM_Get_Device_IDW", unsafe {
        CM_Get_Device_IDW(devinst, &mut buffer, 0)
    })?;
    terminated_string(&buffer)
}

fn parent_id(context: &AdminContext, devinst: u32, root: u32) -> Result<Reading<String>> {
    context.check()?;
    if devinst == root {
        return Ok(Reading::NotApplicable {
            reason: "root_devnode",
        });
    }
    let mut parent = 0u32;
    let result = unsafe { CM_Get_Parent(&mut parent, devinst, 0) };
    if result != CR_SUCCESS {
        return Ok(Reading::Unavailable {
            native_error: cm_error("CM_Get_Parent", result),
        });
    }
    match cm_instance_id(context, parent) {
        Ok(id) => Ok(Reading::available(id)),
        Err(error) => unavailable(error),
    }
}

#[derive(Serialize)]
struct DriverDetail {
    published_inf: Reading<String>,
    registry_key: Reading<String>,
    provider: Reading<String>,
    description: Reading<String>,
    version: Reading<String>,
    date_filetime_100ns_since_1601_utc: Reading<String>,
    inf_section: Reading<String>,
    inf_section_extension: Reading<String>,
    matching_device_id: Reading<String>,
}

fn driver_detail(
    context: &AdminContext,
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    published_inf: Reading<String>,
) -> Result<DriverDetail> {
    Ok(DriverDetail {
        published_inf,
        registry_key: string_property(context, set, info, &DEVPKEY_Device_Driver)?,
        provider: string_property(context, set, info, &DEVPKEY_Device_DriverProvider)?,
        description: string_property(context, set, info, &DEVPKEY_Device_DriverDesc)?,
        version: string_property(context, set, info, &DEVPKEY_Device_DriverVersion)?,
        date_filetime_100ns_since_1601_utc: property(
            context,
            set,
            info,
            &DEVPKEY_Device_DriverDate,
            DEVPROP_TYPE_FILETIME,
            decode_filetime,
        )?,
        inf_section: string_property(context, set, info, &DEVPKEY_Device_DriverInfSection)?,
        inf_section_extension: string_property(
            context,
            set,
            info,
            &DEVPKEY_Device_DriverInfSectionExt,
        )?,
        matching_device_id: string_property(context, set, info, &DEVPKEY_Device_MatchingDeviceId)?,
    })
}

#[derive(Serialize)]
struct DeviceNode {
    instance_id: String,
    parent: Reading<String>,
    class_guid: String,
    class_name: Reading<String>,
    friendly_name: Reading<String>,
    description: Reading<String>,
    manufacturer: Reading<String>,
    service: Reading<String>,
    hardware_ids: Reading<Vec<String>>,
    present: Reading<bool>,
    cm: Reading<CmState>,
    driver: DriverDetail,
}

fn read_node(
    context: &AdminContext,
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    id: String,
    root: u32,
) -> Result<DeviceNode> {
    let cm = match cm_state(context, info.DevInst) {
        Ok(state) => Reading::available(state),
        Err(error) => unavailable(error)?,
    };
    let inf = string_property(context, set, info, &DEVPKEY_Device_DriverInfPath)?;
    Ok(DeviceNode {
        instance_id: id,
        parent: parent_id(context, info.DevInst, root)?,
        class_guid: guid_string(info.ClassGuid),
        class_name: string_property(context, set, info, &DEVPKEY_Device_Class)?,
        friendly_name: string_property(context, set, info, &DEVPKEY_Device_FriendlyName)?,
        description: string_property(context, set, info, &DEVPKEY_Device_DeviceDesc)?,
        manufacturer: string_property(context, set, info, &DEVPKEY_Device_Manufacturer)?,
        service: string_property(context, set, info, &DEVPKEY_Device_Service)?,
        hardware_ids: property(
            context,
            set,
            info,
            &DEVPKEY_Device_HardwareIds,
            DEVPROP_TYPE_STRING_LIST,
            decode_string_list,
        )?,
        present: property(
            context,
            set,
            info,
            &DEVPKEY_Device_IsPresent,
            DEVPROP_TYPE_BOOLEAN,
            decode_bool,
        )?,
        cm,
        driver: driver_detail(context, set, info, inf)?,
    })
}

struct Selector<'a> {
    instance_id: Option<&'a str>,
    class_guid: Option<&'a str>,
    class_name: Option<&'a str>,
    present_only: bool,
}

fn selected_classes(context: &AdminContext, selector: &Selector<'_>) -> Result<Vec<GUID>> {
    if selector.class_guid.is_some() && selector.class_name.is_some() {
        bail!("Specify class_guid or class_name, not both");
    }
    if let Some(value) = selector.class_guid {
        return Ok(vec![guid(value, "class_guid")?]);
    }
    let Some(name) = selector.class_name else {
        return Ok(Vec::new());
    };
    let name = wide(name, "class_name", 255)?;
    let mut classes = vec![GUID::zeroed(); MAX_CLASS_GUIDS];
    let mut required = 0u32;
    context.check()?;
    unsafe {
        SetupDiClassGuidsFromNameW(PCWSTR(name.as_ptr()), &mut classes, &mut required)
            .map_err(|error| setup_error("SetupDiClassGuidsFromNameW", error))?;
    }
    if required == 0 || required as usize > classes.len() {
        bail!("class_name did not resolve to a bounded, nonempty set of installed setup classes");
    }
    classes.truncate(required as usize);
    Ok(classes)
}

#[derive(Serialize)]
struct WalkStats {
    enumerated_devices: u32,
    complete: bool,
    truncation_reason: Option<&'static str>,
}

fn walk_devices(
    context: &AdminContext,
    selector: &Selector<'_>,
    mut visitor: impl FnMut(HDEVINFO, &SP_DEVINFO_DATA, String) -> Result<Option<&'static str>>,
) -> Result<WalkStats> {
    context.check()?;
    let classes = selected_classes(context, selector)?;
    let mut stats = WalkStats {
        enumerated_devices: 0,
        complete: true,
        truncation_reason: None,
    };
    if let Some(requested) = selector.instance_id {
        let (set, info, id) = open_exact(context, requested)?;
        stats.enumerated_devices = 1;
        let class_guid = info.ClassGuid;
        if !classes.is_empty() && !classes.contains(&class_guid) {
            return Ok(stats);
        }
        if selector.present_only {
            match locate_live(context, Some(&id)) {
                Ok(_) => {}
                Err(error)
                    if error.downcast_ref::<NativeError>().is_some_and(|error| {
                        error.domain == "configret" && error.code == CR_NO_SUCH_DEVNODE.0
                    }) =>
                {
                    return Ok(stats);
                }
                Err(error) => return Err(error),
            }
        }
        stats.truncation_reason = visitor(set.0, &info, id)?;
        stats.complete = stats.truncation_reason.is_none();
        return Ok(stats);
    }
    let mut flags = if classes.len() == 1 {
        SETUP_DI_GET_CLASS_DEVS_FLAGS(0)
    } else {
        DIGCF_ALLCLASSES
    };
    if selector.present_only {
        flags |= DIGCF_PRESENT;
    }
    let class_pointer = (classes.len() == 1).then(|| &classes[0] as *const GUID);
    context.check()?;
    let set = DeviceInfoSet(unsafe {
        SetupDiGetClassDevsW(class_pointer, PCWSTR::null(), None, flags)
            .map_err(|error| setup_error("SetupDiGetClassDevsW", error))?
    });
    for index in 0..=MAX_DEVICE_SCAN {
        context.check()?;
        let mut info = device_info();
        match unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut info) } {
            Ok(()) => {}
            Err(error) if is_win32(&error, ERROR_NO_MORE_ITEMS) => return Ok(stats),
            Err(error) => return Err(setup_error("SetupDiEnumDeviceInfo", error).into()),
        }
        if index == MAX_DEVICE_SCAN {
            stats.complete = false;
            stats.truncation_reason = Some("scan_limit");
            return Ok(stats);
        }
        stats.enumerated_devices += 1;
        let class_guid = info.ClassGuid;
        if !classes.is_empty() && !classes.contains(&class_guid) {
            continue;
        }
        let id = instance_id(context, set.0, &info)?;
        if let Some(reason) = visitor(set.0, &info, id)? {
            stats.complete = false;
            stats.truncation_reason = Some(reason);
            return Ok(stats);
        }
    }
    unreachable!("bounded device enumeration returns at its lookahead entry")
}

fn push_bounded<T: Serialize>(
    rows: &mut Vec<T>,
    used_bytes: &mut usize,
    row: T,
) -> Result<Option<&'static str>> {
    let size = serde_json::to_vec(&row)?.len();
    let Some(total) = used_bytes.checked_add(size) else {
        return Ok(Some("byte_limit"));
    };
    if total > MAX_NATIVE_BYTES {
        return Ok(Some("byte_limit"));
    }
    rows.push(row);
    *used_bytes = total;
    Ok(None)
}

pub fn list(context: &AdminContext, input: DeviceListInput) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    let selector = Selector {
        instance_id: input.instance_id.as_deref(),
        class_guid: input.class_guid.as_deref(),
        class_name: input.class_name.as_deref(),
        present_only: input.present_only,
    };
    let root = locate_live(context, None)?;
    let mut nodes = Vec::new();
    let mut used_bytes = 0usize;
    let stats = walk_devices(context, &selector, |set, info, id| {
        if nodes.len() == limit {
            return Ok(Some("result_limit"));
        }
        let node = read_node(context, set, info, id, root)?;
        push_bounded(&mut nodes, &mut used_bytes, node)
    })?;
    context.check()?;
    Ok(json!({
        "nodes": nodes,
        "returned": nodes.len(),
        "limit": limit,
        "present_only": input.present_only,
        "truncated": !stats.complete,
        "enumeration": stats,
        "scan_limit": MAX_DEVICE_SCAN,
        "tree_complete": selector.instance_id.is_none()
            && selector.class_guid.is_none()
            && selector.class_name.is_none()
            && !input.present_only
            && stats.complete,
        "parent_references_may_be_outside_result": true,
        "snapshot_is_atomic": false
    }))
}

#[derive(Serialize)]
struct DriverAssociation {
    instance_id: String,
    class_guid: String,
    present: Reading<bool>,
    cm: Reading<CmState>,
    driver: DriverDetail,
}

pub fn drivers(context: &AdminContext, input: DriverListInput) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    if let Some(inf) = input.published_inf.as_deref() {
        validate_inf_name(inf)?;
    }
    let selector = Selector {
        instance_id: input.instance_id.as_deref(),
        class_guid: input.class_guid.as_deref(),
        class_name: input.class_name.as_deref(),
        present_only: input.present_only,
    };
    let mut rows = Vec::new();
    let mut used_bytes = 0usize;
    let mut without_inf = 0u32;
    let stats = walk_devices(context, &selector, |set, info, id| {
        let inf = string_property(context, set, info, &DEVPKEY_Device_DriverInfPath)?;
        let inf = match inf {
            Reading::Absent { .. } => {
                without_inf += 1;
                return Ok(None);
            }
            Reading::Unavailable { native_error } if input.published_inf.is_some() => {
                return Err(anyhow::Error::from(native_error)
                    .context(format!("Cannot filter the driver binding for {id}")));
            }
            value => value,
        };
        if let (Some(filter), Some(name)) = (input.published_inf.as_deref(), inf.value()) {
            if !filter.eq_ignore_ascii_case(name) {
                return Ok(None);
            }
        }
        if rows.len() == limit {
            return Ok(Some("result_limit"));
        }
        let cm = match cm_state(context, info.DevInst) {
            Ok(state) => Reading::available(state),
            Err(error) => unavailable(error)?,
        };
        let row = DriverAssociation {
            instance_id: id,
            class_guid: guid_string(info.ClassGuid),
            present: property(
                context,
                set,
                info,
                &DEVPKEY_Device_IsPresent,
                DEVPROP_TYPE_BOOLEAN,
                decode_bool,
            )?,
            cm,
            driver: driver_detail(context, set, info, inf)?,
        };
        push_bounded(&mut rows, &mut used_bytes, row)
    })?;
    context.check()?;
    Ok(json!({
        "scope": "installed_device_associations",
        "includes_unbound_staged_packages": false,
        "drivers": rows,
        "returned": rows.len(),
        "limit": limit,
        "present_only": input.present_only,
        "truncated": !stats.complete,
        "enumeration": stats,
        "enumerated_devices_without_published_inf": without_inf,
        "scan_limit": MAX_DEVICE_SCAN,
        "snapshot_is_atomic": false
    }))
}

#[derive(Clone, Copy)]
struct StateChange {
    state: SETUP_DI_STATE_CHANGE,
    scope: SETUP_DI_PROPERTY_CHANGE_SCOPE,
}

fn state_changes(action: DeviceStateAction) -> Vec<StateChange> {
    match action {
        DeviceStateAction::Enable => vec![
            StateChange {
                state: DICS_ENABLE,
                scope: DICS_FLAG_GLOBAL,
            },
            StateChange {
                state: DICS_ENABLE,
                scope: DICS_FLAG_CONFIGSPECIFIC,
            },
        ],
        DeviceStateAction::Disable => vec![StateChange {
            state: DICS_DISABLE,
            scope: DICS_FLAG_GLOBAL,
        }],
        DeviceStateAction::Restart => vec![StateChange {
            state: DICS_PROPCHANGE,
            scope: DICS_FLAG_CONFIGSPECIFIC,
        }],
    }
}

trait StateBackend {
    fn observe(&mut self, context: &AdminContext) -> Result<CmState>;
    fn prepare(&mut self, context: &AdminContext, change: StateChange) -> Result<()>;
    fn change(&mut self, context: &AdminContext) -> Result<()>;
    fn install_flags(&mut self, context: &AdminContext) -> Result<u32>;
}

struct NativeStateBackend {
    set: DeviceInfoSet,
    info: SP_DEVINFO_DATA,
    instance_id: String,
}

impl StateBackend for NativeStateBackend {
    fn observe(&mut self, context: &AdminContext) -> Result<CmState> {
        let devinst = locate_live(context, Some(&self.instance_id))?;
        cm_state(context, devinst)
    }

    fn prepare(&mut self, context: &AdminContext, change: StateChange) -> Result<()> {
        let parameters = SP_PROPCHANGE_PARAMS {
            ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                InstallFunction: DIF_PROPERTYCHANGE,
            },
            StateChange: change.state,
            Scope: change.scope,
            HwProfile: 0,
        };
        context.check()?;
        // These parameters belong to HDEVINFO; only the class-installer call changes the device.
        unsafe {
            SetupDiSetClassInstallParamsW(
                self.set.0,
                Some(&self.info),
                Some((&parameters as *const SP_PROPCHANGE_PARAMS).cast()),
                size_of::<SP_PROPCHANGE_PARAMS>() as u32,
            )
            .map_err(|error| setup_error("SetupDiSetClassInstallParamsW", error))?;
        }
        Ok(())
    }

    fn change(&mut self, context: &AdminContext) -> Result<()> {
        context.begin_mutation()?;
        unsafe {
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, self.set.0, Some(&self.info)).map_err(
                |error| setup_error("SetupDiCallClassInstaller(DIF_PROPERTYCHANGE)", error),
            )?;
        }
        Ok(())
    }

    fn install_flags(&mut self, context: &AdminContext) -> Result<u32> {
        let mut parameters = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        context.check()?;
        unsafe {
            SetupDiGetDeviceInstallParamsW(self.set.0, Some(&self.info), &mut parameters)
                .map_err(|error| setup_error("SetupDiGetDeviceInstallParamsW", error))?;
        }
        Ok(parameters.Flags.0)
    }
}

fn target_observed(action: DeviceStateAction, state: &CmState) -> bool {
    match action {
        DeviceStateAction::Disable => state.software_disabled && !state.started,
        DeviceStateAction::Enable | DeviceStateAction::Restart => {
            state.started && !state.has_problem && state.problem_code == 0
        }
    }
}

fn execute_state_change(
    context: &AdminContext,
    action: DeviceStateAction,
    backend: &mut impl StateBackend,
) -> Result<Value> {
    context.check()?;
    let before = backend.observe(context)?;
    if action == DeviceStateAction::Restart
        && (before.software_disabled || before.hardware_disabled)
    {
        bail!("Cannot restart a disabled device; restart does not implicitly enable it");
    }
    let mut flags = 0u32;
    let mut calls = Vec::new();
    for change in state_changes(action) {
        context.check()?;
        backend.prepare(context, change)?;
        backend.change(context)?;
        let current_flags = backend.install_flags(context)?;
        flags |= current_flags;
        calls.push(json!({
            "api": "SetupDiCallClassInstaller",
            "install_function": DIF_PROPERTYCHANGE.0,
            "state_change": change.state.0,
            "scope": change.scope.0,
            "hardware_profile": 0,
            "native_code": 0,
            "native_domain": "win32",
            "install_flags": current_flags
        }));
    }
    let mut after = None;
    let mut polls = 0usize;
    for attempt in 0..MAX_STATE_POLLS {
        context.check()?;
        polls += 1;
        after = Some(match backend.observe(context) {
            Ok(state) => Reading::available(state),
            Err(error) => unavailable(error)?,
        });
        let observed = after.as_ref().and_then(Reading::value);
        let terminal_observation_error = matches!(
            after.as_ref(),
            Some(Reading::Unavailable { native_error })
                if native_error.domain != "configret" || native_error.code != CR_NO_SUCH_DEVNODE.0
        );
        if flags & (DI_NEEDREBOOT.0 | DI_NEEDRESTART.0) != 0
            || observed.is_some_and(|state| state.needs_restart || target_observed(action, state))
            || terminal_observation_error
        {
            break;
        }
        if attempt + 1 == MAX_STATE_POLLS || context.remaining() <= STATE_POLL_INTERVAL {
            break;
        }
        std::thread::sleep(STATE_POLL_INTERVAL);
    }
    context.check()?;
    let observed = after.as_ref().and_then(Reading::value);
    let target_confirmed = observed.is_some_and(|state| target_observed(action, state));
    let known_restart_required =
        flags & DI_NEEDRESTART.0 != 0 || observed.is_some_and(|state| state.needs_restart);
    let known_reboot_required = flags & DI_NEEDREBOOT.0 != 0 || known_restart_required;
    let restart_required =
        (known_restart_required || observed.is_some()).then_some(known_restart_required);
    let reboot_required =
        (known_reboot_required || observed.is_some()).then_some(known_reboot_required);
    let outcome = if known_reboot_required {
        "reboot_required"
    } else if target_confirmed {
        "requested_state_observed"
    } else if observed.is_none() {
        "state_unavailable"
    } else {
        "state_not_confirmed"
    };
    Ok(json!({
        "action": action,
        "outcome": outcome,
        "native_calls": calls,
        "before": before,
        "after": after,
        "requested_state_observed": target_confirmed,
        "restart_cycle_independently_observed": false,
        "reboot_required": reboot_required,
        "restart_required": restart_required,
        "di_needreboot": flags & DI_NEEDREBOOT.0 != 0,
        "di_needrestart": flags & DI_NEEDRESTART.0 != 0,
        "reboot_reporting": "SetupAPI install flags and the observed Configuration Manager status",
        "install_flags": flags,
        "observation_attempts": polls,
        "automatically_retried": false,
        "reboot_initiated": false
    }))
}

pub fn set_state(context: &AdminContext, input: DeviceStateInput) -> Result<Value> {
    let (set, info, id) = open_exact(context, &input.instance_id)?;
    let mut backend = NativeStateBackend {
        set,
        info,
        instance_id: id,
    };
    let mut result = execute_state_change(context, input.action, &mut backend)?;
    result["instance_id"] = json!(backend.instance_id);
    Ok(result)
}

fn file_observation(context: &AdminContext, path: &Path) -> Result<Value> {
    context.check()?;
    Ok(match std::fs::metadata(path) {
        Ok(metadata) => json!({
            "state": "present",
            "is_file": metadata.is_file(),
            "size_bytes": metadata.len()
        }),
        Err(error) => {
            let native_error = error
                .raw_os_error()
                .map(|code| win32_error("std::fs::metadata", code as u32));
            json!({
                "state": if error.kind() == std::io::ErrorKind::NotFound { "absent" } else { "unavailable" },
                "error": error.to_string(),
                "native_error": native_error.as_ref().and_then(|error| error.downcast_ref::<NativeError>())
            })
        }
    })
}

#[derive(Serialize)]
struct StagedInf {
    published_inf: String,
    published_inf_path: String,
    driver_store_inf_path: String,
    published_file: Value,
}

fn decoded_inf_path(api: &str, buffer: &[u16], required: u32) -> Result<String> {
    if required == 0 || required as usize > buffer.len() {
        bail!("{api} returned an invalid INF path length");
    }
    let path = terminated_string(&buffer[..required as usize])
        .with_context(|| format!("{api} returned an invalid INF path"))?;
    validate_inf_path(&path).with_context(|| format!("{api} returned an invalid INF path"))?;
    Ok(path)
}

fn bounded_native_string(api: &str, buffer: &[u16]) -> Result<String> {
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .with_context(|| format!("{api} returned a string without a terminator"))?;
    terminated_string(&buffer[..=end]).with_context(|| format!("{api} returned invalid UTF-16"))
}

fn driver_store_location(context: &AdminContext, published_path: &str) -> Result<String> {
    validate_inf_path(published_path)?;
    let published_wide = wide(published_path, "published_inf_path", 32_000)?;
    let mut buffer = vec![0u16; MAX_PATH_UNITS];
    let mut required = 0u32;
    context.check()?;
    unsafe {
        SetupGetInfDriverStoreLocationW(
            PCWSTR(published_wide.as_ptr()),
            None,
            PCWSTR::null(),
            &mut buffer,
            Some(&mut required),
        )
        .map_err(|error| setup_error("SetupGetInfDriverStoreLocationW", error))?;
    }
    decoded_inf_path("SetupGetInfDriverStoreLocationW", &buffer, required)
}

fn published_name_from_store(context: &AdminContext, store_path: &str) -> Result<String> {
    validate_inf_path(store_path)?;
    let store_wide = wide(store_path, "driver_store_inf_path", 32_000)?;
    let mut buffer = vec![0u16; MAX_PATH_UNITS];
    context.check()?;
    unsafe {
        SetupGetInfPublishedNameW(PCWSTR(store_wide.as_ptr()), &mut buffer, None)
            .map_err(|error| setup_error("SetupGetInfPublishedNameW", error))?;
    }
    // Windows can return a basename and leave RequiredSize untouched even on success.
    let returned = bounded_native_string("SetupGetInfPublishedNameW", &buffer)?;
    let name = published_name_basename(&returned)?;
    let system_path = published_inf_path(context, name)?;
    let system_path = system_path
        .to_str()
        .context("The system INF path is not valid Unicode")?;
    normalize_published_name(&returned, system_path)
}

fn published_name_basename(value: &str) -> Result<&str> {
    let name = if Path::new(value).is_absolute() {
        validate_inf_path(value)?;
        Path::new(value)
            .file_name()
            .and_then(|name| name.to_str())
            .context("SetupGetInfPublishedNameW did not return an INF filename")?
    } else {
        value
    };
    validate_oem_inf(name)?;
    Ok(name)
}

fn normalize_published_name(returned: &str, system_path: &str) -> Result<String> {
    validate_inf_path(system_path)?;
    let name = published_name_basename(returned)?;
    let expected_name = published_name_basename(system_path)?;
    if !name.eq_ignore_ascii_case(expected_name)
        || (Path::new(returned).is_absolute() && !returned.eq_ignore_ascii_case(system_path))
    {
        bail!(
            "SetupGetInfPublishedNameW returned an identity outside the expected system INF path"
        );
    }
    Ok(system_path.to_owned())
}

fn validate_staged_mapping(
    published_path: &str,
    store_path: &str,
    mapped_path: &str,
) -> Result<()> {
    validate_inf_path(published_path)?;
    validate_inf_path(store_path)?;
    validate_inf_path(mapped_path)?;
    if !published_path.eq_ignore_ascii_case(mapped_path) {
        bail!(
            "Staged INF identity changed: expected {published_path}, but the driver-store INF \
             {store_path} maps to {mapped_path}; no device installation was attempted"
        );
    }
    if store_path.eq_ignore_ascii_case(published_path) {
        bail!("A published INF alias is not a driver-store INF path; no device installation was attempted");
    }
    Ok(())
}

fn staged_install_arguments(staged: &StagedInf) -> Result<(Vec<u16>, DIINSTALLDRIVER_FLAGS)> {
    validate_inf_path(&staged.driver_store_inf_path)?;
    if staged
        .driver_store_inf_path
        .eq_ignore_ascii_case(&staged.published_inf_path)
    {
        bail!("Installation requires the resolved driver-store INF, not its published alias");
    }
    Ok((
        wide(
            &staged.driver_store_inf_path,
            "driver_store_inf_path",
            32_000,
        )?,
        INSTALL_FLAGS,
    ))
}

fn stage_inf(context: &AdminContext, source: &str) -> Result<StagedInf> {
    let source_wide = wide(source, "inf_path", 32_000)?;
    let mut destination = vec![0u16; MAX_PATH_UNITS];
    let mut required = 0u32;
    // Reserve the maximum output up front: a sizing call would itself stage the package.
    context.begin_mutation()?;
    unsafe {
        SetupCopyOEMInfW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR::null(),
            SPOST_PATH,
            SP_COPY_STYLE(0),
            Some(&mut destination),
            Some(&mut required),
            None,
        )
        .map_err(|error| setup_error("SetupCopyOEMInfW", error))?;
    }
    if required == 0 || required as usize > destination.len() {
        bail!("SetupCopyOEMInfW succeeded but returned an invalid destination length; do not retry automatically");
    }
    let path = terminated_string(&destination[..required as usize])?;
    let inf = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("SetupCopyOEMInfW did not return an INF filename")?
        .to_owned();
    validate_oem_inf(&inf)
        .context("SetupCopyOEMInfW succeeded but did not return a published OEM INF identity")?;
    let driver_store_inf_path = (|| {
        // Resolve the published copy, never the caller's source, which can change after staging.
        let store_path = driver_store_location(context, &path)?;
        let mapped_path = published_name_from_store(context, &store_path)?;
        validate_staged_mapping(&path, &store_path, &mapped_path)?;
        Ok::<_, anyhow::Error>(store_path)
    })()
    .with_context(|| {
        format!(
            "Package was staged as {inf}, but resolving its driver-store identity failed; \
             no device installation was attempted"
        )
    })?;
    let published_file = file_observation(context, Path::new(&path))?;
    Ok(StagedInf {
        published_inf: inf,
        published_inf_path: path,
        driver_store_inf_path,
        published_file,
    })
}

fn bound_driver_snapshot(context: &AdminContext, published_inf: &str) -> Result<Value> {
    drivers(
        context,
        DriverListInput {
            instance_id: None,
            class_guid: None,
            class_name: None,
            published_inf: Some(published_inf.to_owned()),
            present_only: false,
            limit: Some(128),
            timeout_ms: None,
        },
    )
}

fn installed_package_snapshot(context: &AdminContext, store_path: &str) -> Result<Value> {
    // Reimporting a package can change its published alias; query it again from the resolved store path.
    let published_path = published_name_from_store(context, store_path)?;
    let inf = Path::new(&published_path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("SetupGetInfPublishedNameW did not return an INF filename")?;
    validate_oem_inf(inf)?;
    let mut snapshot = bound_driver_snapshot(context, inf)?;
    snapshot["published_inf"] = json!(inf);
    snapshot["published_inf_path"] = json!(published_path);
    snapshot["driver_store_inf_path"] = json!(store_path);
    Ok(snapshot)
}

fn ensure_unbound(context: &AdminContext, published_inf: &str) -> Result<WalkStats> {
    let selector = Selector {
        instance_id: None,
        class_guid: None,
        class_name: None,
        present_only: false,
    };
    let stats = walk_devices(context, &selector, |set, info, id| {
        match string_property(context, set, info, &DEVPKEY_Device_DriverInfPath)? {
            Reading::Available { value } if value.eq_ignore_ascii_case(published_inf) => {
                bail!(
                    "Refusing to remove {published_inf}: it is assigned to {id}. \
                     Present and non-present device bindings both block removal; no uninstall was attempted"
                );
            }
            Reading::Unavailable { native_error } => {
                return Err(anyhow::Error::from(native_error).context(format!(
                    "Cannot prove {published_inf} is unused because {id} is unreadable"
                )));
            }
            Reading::Available { .. } | Reading::Absent { .. } => {}
            Reading::NotApplicable { .. } => {
                bail!("Cannot determine the installed driver binding for {id}");
            }
        }
        Ok(None)
    })?;
    if !stats.complete {
        bail!("Device safety scan was truncated; refusing to remove a driver whose bindings are unknown");
    }
    Ok(stats)
}

fn published_inf_path(context: &AdminContext, inf: &str) -> Result<PathBuf> {
    let mut directory = vec![0u16; MAX_PATH_UNITS];
    context.check()?;
    let count = unsafe { GetWindowsDirectoryW(Some(&mut directory)) };
    if count == 0 {
        let error = unsafe { GetLastError() };
        return Err(win32_error("GetWindowsDirectoryW", error.0));
    }
    if count as usize >= directory.len() {
        bail!("GetWindowsDirectoryW returned an oversized path");
    }
    let directory = terminated_string(&directory[..count as usize + 1])?;
    Ok(Path::new(&directory).join("INF").join(inf))
}

fn remove_inf(context: &AdminContext, published_inf: &str) -> Result<Value> {
    validate_oem_inf(published_inf)?;
    let inf_wide = wide(published_inf, "published_inf", 255)?;
    let path = published_inf_path(context, published_inf)?;
    let safety_scan = ensure_unbound(context, published_inf)?;
    // The native no-force check also covers bindings created after the preflight snapshot.
    context.begin_mutation()?;
    let result = unsafe { SetupUninstallOEMInfW(PCWSTR(inf_wide.as_ptr()), REMOVE_FLAGS, None) };
    if !result.as_bool() {
        let error = unsafe { GetLastError() };
        return Err(win32_error("SetupUninstallOEMInfW", error.0));
    }
    let observed = file_observation(context, &path)?;
    let outcome = if observed["state"] == "absent" {
        "published_inf_removed"
    } else {
        "removal_not_confirmed"
    };
    Ok(json!({
        "action": "remove",
        "outcome": outcome,
        "published_inf": published_inf,
        "published_inf_path": path,
        "published_file": observed,
        "native_api": "SetupUninstallOEMInfW",
        "native_domain": "win32",
        "native_code": 0,
        "flags": REMOVE_FLAGS,
        "force": false,
        "device_uninstall_attempted": false,
        "safety_scan": safety_scan,
        "reboot_required": null,
        "reboot_reporting": "SetupUninstallOEMInfW does not expose a reboot flag",
        "reboot_initiated": false,
        "automatically_retried": false
    }))
}

pub fn manage_driver(context: &AdminContext, input: DriverPackageInput) -> Result<Value> {
    context.check()?;
    match input.action {
        DriverPackageAction::Remove => {
            if input.inf_path.is_some() {
                bail!("remove accepts published_inf only, not inf_path");
            }
            let inf = input
                .published_inf
                .as_deref()
                .context("remove requires the exact published_inf oemN.inf name")?;
            remove_inf(context, inf)
        }
        DriverPackageAction::Stage | DriverPackageAction::Install => {
            if input.published_inf.is_some() {
                bail!("stage and install accept inf_path only, not published_inf");
            }
            let source = input
                .inf_path
                .as_deref()
                .context("stage and install require a fully qualified inf_path")?;
            let path = validate_inf_path(source)?;
            context.check()?;
            if !std::fs::metadata(&path)
                .map_err(|error| match error.raw_os_error() {
                    Some(code) => win32_error("std::fs::metadata", code as u32),
                    None => anyhow::Error::from(error),
                })
                .with_context(|| format!("Cannot read INF file {}", path.display()))?
                .is_file()
            {
                bail!("inf_path must name an existing file");
            }
            let staged = stage_inf(context, source)?;
            if input.action == DriverPackageAction::Stage {
                let observed = staged.published_file["state"] == "present"
                    && staged.published_file["is_file"] == true;
                return Ok(json!({
                    "action": "stage",
                    "outcome": if observed { "staged" } else { "staging_not_confirmed" },
                    "package": staged,
                    "native_api": "SetupCopyOEMInfW",
                    "native_domain": "win32",
                    "native_code": 0,
                    "device_install_attempted": false,
                    "reboot_required": false,
                    "reboot_scope": "this staging operation only; no device installer was called",
                    "automatically_retried": false
                }));
            }
            let (install_inf_wide, install_flags) = staged_install_arguments(&staged)?;
            let mut reboot = BOOL::default();
            context.begin_mutation()?;
            unsafe {
                DiInstallDriverW(
                    None,
                    PCWSTR(install_inf_wide.as_ptr()),
                    install_flags,
                    Some(&mut reboot),
                )
                .map_err(|error| setup_error("DiInstallDriverW", error))
                .with_context(|| {
                    format!(
                        "Package was staged as {}, but installing driver-store INF {} failed",
                        staged.published_inf, staged.driver_store_inf_path
                    )
                })?;
            }
            let bindings = match installed_package_snapshot(context, &staged.driver_store_inf_path)
            {
                Ok(bindings) => bindings,
                Err(error) => {
                    context.check()?;
                    json!({
                        "state": "unavailable",
                        "error": format!("{error:#}"),
                        "native_error": error.downcast_ref::<NativeError>()
                    })
                }
            };
            context.check()?;
            Ok(json!({
                "action": "install",
                "outcome": if reboot.as_bool() { "reboot_required" } else { "installation_processed" },
                "package": staged,
                "native_calls": [
                    {"api": "SetupCopyOEMInfW", "domain": "win32", "code": 0},
                    {"api": "SetupGetInfDriverStoreLocationW", "domain": "win32", "code": 0},
                    {"api": "SetupGetInfPublishedNameW", "domain": "win32", "code": 0},
                    {
                        "api": "DiInstallDriverW", "domain": "win32", "code": 0,
                        "flags": install_flags.0, "inf_path": staged.driver_store_inf_path
                    }
                ],
                "device_install_attempted": true,
                "force": false,
                "selection_policy": "Windows selects compatible drivers by normal rank; no force-INF flag",
                "observed_current_bindings": bindings,
                "newly_installed_device_count": null,
                "binding_observation_note": "Bindings can predate this call; an unused staged package is not proof of device installation",
                "reboot_required": reboot.as_bool(),
                "reboot_source": "DiInstallDriverW.NeedReboot",
                "reboot_initiated": false,
                "automatically_retried": false
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn test_context() -> AdminContext {
        AdminContext::new(Duration::from_secs(10))
    }

    #[test]
    fn administration_devices_inputs_coerce_numbers_and_reject_unknown_fields() {
        let list: DeviceListInput =
            serde_json::from_value(json!({"limit": "2", "timeout_ms": "2500"})).unwrap();
        assert_eq!(list.limit, Some(2));
        assert_eq!(list.timeout_ms, Some(2500));
        assert!(list.present_only);
        let state: DeviceStateInput = serde_json::from_value(json!({
            "instance_id": r"ROOT\EXAMPLE\0000", "action": "restart", "timeout_ms": "3000"
        }))
        .unwrap();
        assert_eq!(state.action, DeviceStateAction::Restart);
        assert_eq!(state.timeout_ms, Some(3000));
        let drivers: DriverListInput =
            serde_json::from_value(json!({"limit": "4", "timeout_ms": "4000"})).unwrap();
        assert_eq!(drivers.limit, Some(4));
        assert_eq!(drivers.timeout_ms, Some(4000));
        assert!(!drivers.present_only);
        let package: DriverPackageInput = serde_json::from_value(json!({
            "action": "remove", "published_inf": "oem42.inf", "timeout_ms": "5000"
        }))
        .unwrap();
        assert_eq!(package.timeout_ms, Some(5000));
        assert!(serde_json::from_value::<DeviceListInput>(json!({"limit": -1})).is_err());
        assert!(serde_json::from_value::<DeviceListInput>(json!({"limit": 1.5})).is_err());
        assert!(
            serde_json::from_value::<DeviceListInput>(json!({"limit": "2", "extra": true}))
                .is_err()
        );
        assert!(serde_json::from_value::<DriverPackageInput>(
            json!({"action": "install", "force": true})
        )
        .is_err());
        assert!(serde_json::from_value::<DeviceStateInput>(
            json!({"instance_id": r"ROOT\EXAMPLE\0000", "action": "delete"})
        )
        .is_err());
    }

    #[test]
    fn administration_devices_schemas_expose_enums_and_numeric_inputs() {
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(DeviceListInput)).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"]["limit"]
            .to_string()
            .contains("integer"));
        assert!(schema["properties"]["timeout_ms"]
            .to_string()
            .contains("integer"));
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(DeviceStateInput)).unwrap();
        assert!(schema.to_string().contains("restart"));
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(DriverPackageInput)).unwrap();
        for action in ["stage", "install", "remove"] {
            assert!(schema.to_string().contains(action));
        }
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(DriverListInput)).unwrap();
        assert!(schema["properties"]["limit"]
            .to_string()
            .contains("integer"));
    }

    #[test]
    fn administration_devices_validate_exact_native_identities() {
        for id in [
            r"HTREE\ROOT\0",
            r"PCI\VEN_8086&DEV_1234\3&11583659&0&10",
            r"ROOT\*PNP0501\0000",
            r"SWD\MMDEVAPI\{0.0.0.00000000}.{00000000-0000-0000-0000-000000000001}",
        ] {
            assert!(validate_instance_id(id).is_ok(), "{id}");
        }
        for id in [
            "",
            r"PCI\*",
            r"ROOT\DEVICE\?",
            r"ROOT\*\0000",
            r"ROOT\DEV*\0000",
            r"ROOT\**PNP0501\0000",
            r"ROOT\DEVICE",
            r"ROOT\\0000",
            r"ROOT\DEVICE\0000\extra",
            r" ROOT\DEVICE\0000",
            "ROOT\\DEVICE\\0000\0suffix",
        ] {
            assert!(validate_instance_id(id).is_err(), "{id}");
        }
        for inf in ["oem0.inf", "OEM42.INF", "oem1234.inf"] {
            assert!(validate_oem_inf(inf).is_ok(), "{inf}");
        }
        for inf in [
            "driver.inf",
            "oem.inf",
            "oem*.inf",
            "oem-1.inf",
            "oem1.inf:stream",
            r"C:\Windows\INF\oem1.inf",
            r"..\oem1.inf",
            "oem4294967296.inf",
        ] {
            assert!(validate_oem_inf(inf).is_err(), "{inf}");
        }
        assert!(validate_inf_name("machine.inf").is_ok());
        assert!(validate_inf_path(r"C:\drivers\package.inf").is_ok());
        assert!(validate_inf_path(r"C:package.inf").is_err());
        assert!(validate_inf_path(r"C:\drivers\..\package.inf").is_err());
        assert!(validate_inf_path(r"C:\drivers\package.sys").is_err());
    }

    #[test]
    fn administration_devices_decode_bounded_unaligned_properties() {
        let mut unaligned = vec![0xaa];
        unaligned.extend_from_slice(&[b'A', 0, 0, 0]);
        assert_eq!(decode_string(&unaligned[1..]).unwrap(), "A");
        assert!(decode_string(&[b'A', 0]).is_err());
        assert!(decode_string(&[b'A', 0, 0]).is_err());
        assert!(decode_string(&[0, 0, b'A', 0]).is_err());
        assert_eq!(
            decode_string_list(&[b'A', 0, 0, 0, 0, 0]).unwrap(),
            vec!["A"]
        );
        assert!(decode_string_list(&[b'A', 0, 0, 0]).is_err());
        assert!(decode_string_list(&[0, 0, b'A', 0, 0, 0, 0, 0]).is_err());
        assert!(!decode_bool(&[0]).unwrap());
        assert!(decode_bool(&[0xff]).unwrap());
        assert!(decode_bool(&[1]).is_err());
        assert_eq!(
            decode_filetime(&u64::MAX.to_le_bytes()).unwrap(),
            u64::MAX.to_string()
        );
        assert!(decode_filetime(&[0; 7]).is_err());
    }

    #[test]
    fn administration_devices_staged_install_uses_store_identity_without_force() {
        let published = r"C:\Windows\INF\oem42.inf";
        let store =
            r"C:\Windows\System32\DriverStore\FileRepository\device.inf_amd64_01234567\device.inf";
        validate_staged_mapping(published, store, r"c:\windows\inf\OEM42.INF").unwrap();
        let staged = StagedInf {
            published_inf: "oem42.inf".into(),
            published_inf_path: published.into(),
            driver_store_inf_path: store.into(),
            published_file: json!({"state": "present", "is_file": true}),
        };
        let (path, flags) = staged_install_arguments(&staged).unwrap();
        assert_eq!(terminated_string(&path).unwrap(), store);
        assert_ne!(terminated_string(&path).unwrap(), published);
        assert_ne!(
            terminated_string(&path).unwrap(),
            r"C:\downloads\device.inf"
        );
        assert_eq!(flags.0, 0);
        assert_eq!(flags.0 & DIIRFLAG_FORCE_INF.0, 0);
        assert_eq!(
            serde_json::to_value(staged).unwrap()["driver_store_inf_path"],
            store
        );
    }

    #[test]
    fn administration_devices_staged_identity_rejects_alias_changes_and_invalid_native_paths() {
        let published = r"C:\Windows\INF\oem42.inf";
        let store =
            r"C:\Windows\System32\DriverStore\FileRepository\device.inf_amd64_01234567\device.inf";
        assert!(validate_staged_mapping(published, store, r"C:\Windows\INF\oem43.inf").is_err());
        assert!(validate_staged_mapping(published, published, published).is_err());
        assert!(validate_staged_mapping(published, r"device.inf", published).is_err());
        assert!(validate_staged_mapping(published, r"C:\store\..\device.inf", published).is_err());
        let buffer: Vec<u16> = store.encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(
            decoded_inf_path("Example", &buffer, buffer.len() as u32).unwrap(),
            store
        );
        assert!(decoded_inf_path("Example", &buffer, 0).is_err());
        assert!(decoded_inf_path("Example", &buffer, buffer.len() as u32 + 1).is_err());
        assert!(decoded_inf_path("Example", &buffer, buffer.len() as u32 - 1).is_err());
    }

    #[test]
    fn administration_devices_native_published_name_accepts_bounded_basename_output() {
        let system_path = r"C:\Windows\INF\oem42.inf";
        assert_eq!(
            normalize_published_name("OEM42.INF", system_path).unwrap(),
            system_path
        );
        assert_eq!(
            normalize_published_name(r"c:\windows\inf\OEM42.INF", system_path).unwrap(),
            system_path
        );
        for returned in [
            "",
            "oem43.inf",
            r".\oem42.inf",
            r"..\oem42.inf",
            r"C:\downloads\oem42.inf",
        ] {
            assert!(
                normalize_published_name(returned, system_path).is_err(),
                "{returned}"
            );
        }
        let mut buffer = vec![0u16; MAX_PATH_UNITS];
        let name: Vec<u16> = "oem42.inf".encode_utf16().collect();
        buffer[..name.len()].copy_from_slice(&name);
        buffer[MAX_PATH_UNITS - 1] = 0x1234;
        assert_eq!(
            bounded_native_string("SetupGetInfPublishedNameW", &buffer).unwrap(),
            "oem42.inf"
        );
        assert!(bounded_native_string("Example", &[1u16; 10]).is_err());
    }

    #[test]
    fn administration_devices_store_lookup_failure_preserves_staging_uncertainty() {
        let context = test_context();
        context.begin_mutation().unwrap();
        let error = win32_error("SetupGetInfDriverStoreLocationW", 2)
            .context("Package was staged as oem42.inf; resolving its driver-store identity failed");
        let value = super::super::admin_common::failure(&error, &context);
        assert_eq!(
            value["native_error"]["api"],
            "SetupGetInfDriverStoreLocationW"
        );
        assert_eq!(value["native_error"]["domain"], "win32");
        assert_eq!(value["native_error"]["code"], 2);
        assert_eq!(value["mutation_may_have_completed"], true);
        assert_eq!(value["automatically_retried"], false);
    }

    #[test]
    fn administration_devices_native_errors_preserve_original_domains_and_codes() {
        let error = cm_error("CM_Get_DevNode_Status", CR_ACCESS_DENIED);
        assert_eq!(error.domain, "configret");
        assert_eq!(error.code, CR_ACCESS_DENIED.0);
        let error = setup_error(
            "SetupDiCallClassInstaller",
            windows::core::Error::from_hresult(HRESULT::from_win32(5)),
        );
        assert_eq!(error.domain, "win32");
        assert_eq!(error.code, 5);
        let error = setup_error(
            "SetupDiOpenDeviceInfoW",
            windows::core::Error::from_hresult(HRESULT::from_win32(0xe000_020b)),
        );
        assert_eq!(error.code, 0xe000_020b);
        let context = test_context();
        context.begin_mutation().unwrap();
        let value = super::super::admin_common::failure(&error.into(), &context);
        assert_eq!(value["native_error"]["code"], 0xe000_020bu32);
        assert_eq!(value["mutation_may_have_completed"], true);
    }

    struct FakeStateBackend {
        states: VecDeque<std::result::Result<CmState, NativeError>>,
        flags: u32,
        changes: Vec<(u32, u32)>,
        mutations: usize,
        fail_mutation: Option<usize>,
    }

    impl StateBackend for FakeStateBackend {
        fn observe(&mut self, context: &AdminContext) -> Result<CmState> {
            context.check()?;
            self.states
                .pop_front()
                .expect("test must supply each observation")
                .map_err(anyhow::Error::from)
        }

        fn prepare(&mut self, context: &AdminContext, change: StateChange) -> Result<()> {
            context.check()?;
            self.changes.push((change.state.0, change.scope.0));
            Ok(())
        }

        fn change(&mut self, context: &AdminContext) -> Result<()> {
            context.begin_mutation()?;
            self.mutations += 1;
            if self.fail_mutation == Some(self.mutations) {
                return Err(win32_error("fake class installer", 5));
            }
            Ok(())
        }

        fn install_flags(&mut self, context: &AdminContext) -> Result<u32> {
            context.check()?;
            assert!(context.mutation_started());
            Ok(self.flags)
        }
    }

    fn fake_state(disabled: bool) -> CmState {
        if disabled {
            state_from_native(10, DN_HAS_PROBLEM, CM_PROB_DISABLED)
        } else {
            state_from_native(10, DN_STARTED | DN_DISABLEABLE, CM_PROB(0))
        }
    }

    fn fake_backend(before: CmState, after: CmState, flags: u32) -> FakeStateBackend {
        FakeStateBackend {
            states: VecDeque::from([Ok(before), Ok(after)]),
            flags,
            changes: Vec::new(),
            mutations: 0,
            fail_mutation: None,
        }
    }

    #[test]
    fn administration_devices_fake_enable_uses_global_then_current_profile() {
        let context = test_context();
        let mut backend = fake_backend(fake_state(true), fake_state(false), 0);
        let result =
            execute_state_change(&context, DeviceStateAction::Enable, &mut backend).unwrap();
        assert_eq!(
            backend.changes,
            vec![
                (DICS_ENABLE.0, DICS_FLAG_GLOBAL.0),
                (DICS_ENABLE.0, DICS_FLAG_CONFIGSPECIFIC.0)
            ]
        );
        assert_eq!(backend.mutations, 2);
        assert_eq!(result["requested_state_observed"], true);
        assert_eq!(result["reboot_required"], false);
        assert_eq!(result["after"]["value"]["started"], true);
    }

    #[test]
    fn administration_devices_fake_reboot_does_not_claim_requested_state() {
        let context = test_context();
        let mut backend = fake_backend(fake_state(false), fake_state(false), DI_NEEDREBOOT.0);
        let result =
            execute_state_change(&context, DeviceStateAction::Disable, &mut backend).unwrap();
        assert_eq!(backend.changes, vec![(DICS_DISABLE.0, DICS_FLAG_GLOBAL.0)]);
        assert_eq!(result["outcome"], "reboot_required");
        assert_eq!(result["requested_state_observed"], false);
        assert_eq!(result["reboot_required"], true);
        assert_eq!(result["reboot_initiated"], false);
    }

    #[test]
    fn administration_devices_fake_restart_and_cancellation_never_enable_implicitly() {
        let context = test_context();
        let mut backend = fake_backend(fake_state(true), fake_state(true), 0);
        assert!(execute_state_change(&context, DeviceStateAction::Restart, &mut backend).is_err());
        assert_eq!(backend.mutations, 0);
        assert!(!context.mutation_started());
        let context = test_context();
        let mut backend = fake_backend(fake_state(false), fake_state(false), DI_NEEDRESTART.0);
        let result =
            execute_state_change(&context, DeviceStateAction::Restart, &mut backend).unwrap();
        assert_eq!(
            backend.changes,
            vec![(DICS_PROPCHANGE.0, DICS_FLAG_CONFIGSPECIFIC.0)]
        );
        assert_eq!(result["restart_required"], true);
        let context = test_context();
        context.cancel();
        let mut backend = fake_backend(fake_state(false), fake_state(true), 0);
        assert!(execute_state_change(&context, DeviceStateAction::Disable, &mut backend).is_err());
        assert_eq!(backend.mutations, 0);
    }

    #[test]
    fn administration_devices_fake_partial_enable_is_not_retried() {
        let context = test_context();
        let mut backend = fake_backend(fake_state(true), fake_state(false), 0);
        backend.fail_mutation = Some(2);
        let error =
            execute_state_change(&context, DeviceStateAction::Enable, &mut backend).unwrap_err();
        assert_eq!(backend.mutations, 2);
        let result = super::super::admin_common::failure(&error, &context);
        assert_eq!(result["native_error"]["code"], 5);
        assert_eq!(result["mutation_may_have_completed"], true);
        assert_eq!(result["automatically_retried"], false);
    }

    #[test]
    fn administration_devices_fake_observation_failure_is_not_reported_as_running() {
        let context = test_context();
        let mut backend = fake_backend(fake_state(false), fake_state(false), 0);
        backend.states[1] = Err(cm_error("CM_Get_DevNode_Status", CR_ACCESS_DENIED));
        let result =
            execute_state_change(&context, DeviceStateAction::Restart, &mut backend).unwrap();
        assert_eq!(backend.mutations, 1);
        assert_eq!(result["outcome"], "state_unavailable");
        assert_eq!(result["requested_state_observed"], false);
        assert_eq!(result["reboot_required"], Value::Null);
        assert_eq!(result["after"]["native_error"]["domain"], "configret");
        assert_eq!(result["after"]["native_error"]["code"], CR_ACCESS_DENIED.0);
    }

    #[test]
    fn administration_devices_result_bounds_do_not_silently_overflow() {
        let mut rows = Vec::new();
        let mut bytes = MAX_NATIVE_BYTES;
        assert_eq!(
            push_bounded(&mut rows, &mut bytes, json!({"instance_id": "example"})).unwrap(),
            Some("byte_limit")
        );
        assert!(rows.is_empty());
        let context = test_context();
        let input = serde_json::from_value(json!({"limit": "0"})).unwrap();
        assert!(list(&context, input).is_err());
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_devices_driver_requests_do_not_expose_force_or_accept_ambiguous_paths() {
        assert_eq!(INSTALL_FLAGS.0 & DIIRFLAG_FORCE_INF.0, 0);
        assert_eq!(REMOVE_FLAGS & SUOI_FORCEDELETE, 0);
        for input in [
            json!({"action": "stage", "inf_path": "relative.inf"}),
            json!({"action": "install", "inf_path": r"C:\a.inf", "published_inf": "oem1.inf"}),
            json!({"action": "remove", "published_inf": "machine.inf"}),
            json!({"action": "remove", "published_inf": "oem1.inf", "inf_path": r"C:\a.inf"}),
            json!({"action": "remove"}),
        ] {
            let context = test_context();
            let input = serde_json::from_value(input).unwrap();
            assert!(manage_driver(&context, input).is_err());
            assert!(!context.mutation_started());
        }
    }

    #[test]
    fn administration_devices_native_inventory_is_read_only_and_bounded() {
        let context = test_context();
        let result = list(
            &context,
            DeviceListInput {
                instance_id: None,
                class_guid: None,
                class_name: None,
                present_only: true,
                limit: Some(2),
                timeout_ms: None,
            },
        )
        .unwrap();
        let nodes = result["nodes"].as_array().unwrap();
        assert!(!nodes.is_empty());
        assert!(nodes.len() <= 2);
        assert_eq!(result["returned"], nodes.len());
        for node in nodes {
            validate_instance_id(node["instance_id"].as_str().unwrap()).unwrap();
            assert!(node.get("parent").is_some());
            assert!(node.get("class_guid").is_some());
            assert!(node.get("cm").is_some());
            assert!(node["driver"].get("published_inf").is_some());
        }
        let exact = list(
            &context,
            DeviceListInput {
                instance_id: Some(nodes[0]["instance_id"].as_str().unwrap().to_owned()),
                class_guid: Some(nodes[0]["class_guid"].as_str().unwrap().to_owned()),
                class_name: None,
                present_only: true,
                limit: Some(1),
                timeout_ms: None,
            },
        )
        .unwrap();
        assert_eq!(exact["returned"], 1);
        assert_eq!(exact["nodes"][0]["instance_id"], nodes[0]["instance_id"]);
        assert_eq!(exact["truncated"], false);
        assert!(!context.mutation_started());
    }
}
