use super::admin_common::{
    absolute_path, check_win32, guid, guid_string, hresult_error, result_limit, text, wide,
    win32_error, AdminContext, NativeError, MAX_NATIVE_BYTES,
};
use anyhow::{bail, Context, Result};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::mem::size_of;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::Duration;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{self as foundation, HANDLE};
use windows::Win32::Storage::{FileSystem as fs, Vhd as vhd};

const MAX_PATH_UNITS: usize = 32_000;
const MAX_PATH_COMPONENTS: usize = 128;
const MAX_MOUNT_UNITS: usize = 65_536;
const BUFFER_ATTEMPTS: usize = 4;
const VOLUME_ROOT_LENGTH: usize = 49;
static MUTATIONS: Mutex<()> = Mutex::new(());

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolumeListInput {
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VolumeUpdateAction {
    SetLabel,
    AddMountPoint,
    RemoveMountPoint,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolumeUpdateInput {
    pub action: VolumeUpdateAction,
    /// Exact volume GUID root, including the final backslash.
    pub volume_guid_path: String,
    /// SetLabel only. An empty string explicitly clears the label.
    pub label: Option<String>,
    /// Mount actions only. A local drive root or existing directory, ending in a backslash.
    pub mount_path: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VirtualDiskAction {
    Inspect,
    Attach,
    Detach,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VirtualImageType {
    Vhd,
    Vhdx,
    Iso,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImageIdentity {
    pub canonical_path: String,
    /// Sixteen hexadecimal digits from FILE_ID_INFO.VolumeSerialNumber.
    pub volume_serial: String,
    /// Thirty-two hexadecimal digits from the backing file's 128-bit file ID.
    pub file_id: String,
    /// Sixteen hexadecimal digits containing the backing file's creation FILETIME.
    pub creation_time: String,
}

/// Image attachments always use PERMANENT_LIFETIME, survive handle closure, and require
/// explicit detach. Boot persistence and session-owned attachments are not requested.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VirtualDiskInput {
    pub action: VirtualDiskAction,
    /// Fully qualified local .vhd, .vhdx or .iso file. UNC, device aliases and reparse traversal are rejected.
    pub image_path: String,
    /// Optional explicit provider type; it must agree with the filename extension.
    pub image_type: Option<VirtualImageType>,
    /// Copy image_identity from Inspect. Required for Attach and Detach.
    pub expected_identity: Option<ImageIdentity>,
    /// Attach only; defaults to true. ISO images must be read-only.
    pub read_only: Option<bool>,
    /// Attach only; defaults to true. This suppresses automatic drive letters, not writes or volume access.
    pub no_drive_letter: Option<bool>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

fn native_result<T>(api: &str, result: windows::core::Result<T>) -> Result<T> {
    result.map_err(|error| {
        let code = error.code().0 as u32;
        if code & 0xffff_0000 == 0x8007_0000 {
            win32_error(api, code & 0xffff)
        } else {
            hresult_error(api, error)
        }
    })
}

fn error_value(error: &anyhow::Error) -> Value {
    json!({
        "message": format!("{error:#}"),
        "native_error": error.downcast_ref::<NativeError>(),
    })
}

fn has_code(error: &anyhow::Error, code: foundation::WIN32_ERROR) -> bool {
    error
        .downcast_ref::<NativeError>()
        .is_some_and(|native| native.domain == "win32" && native.code == code.0)
}

fn mutation_lock(context: &AdminContext) -> Result<MutexGuard<'static, ()>> {
    loop {
        context.check()?;
        match MUTATIONS.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => bail!("The storage mutation lock is poisoned"),
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(context.remaining().min(Duration::from_millis(10)));
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if let Err(error) = unsafe { foundation::CloseHandle(self.0) } {
            tracing::warn!(api = "CloseHandle", error = %error, "Storage handle cleanup failed");
        }
    }
}

struct VolumeSearch(HANDLE);

impl Drop for VolumeSearch {
    fn drop(&mut self) {
        if let Err(error) = unsafe { fs::FindVolumeClose(self.0) } {
            tracing::warn!(api = "FindVolumeClose", error = %error, "Volume enumeration cleanup failed");
        }
    }
}

struct FileSearch(HANDLE);

impl Drop for FileSearch {
    fn drop(&mut self) {
        if let Err(error) = unsafe { fs::FindClose(self.0) } {
            tracing::warn!(api = "FindClose", error = %error, "Directory enumeration cleanup failed");
        }
    }
}

fn terminated_string(buffer: &[u16], field: &str) -> Result<String> {
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .with_context(|| format!("{field} was not NUL-terminated"))?;
    String::from_utf16(&buffer[..end]).with_context(|| format!("{field} is not valid UTF-16"))
}

fn volume_guid_path(value: &str) -> Result<String> {
    text(value, "volume_guid_path", VOLUME_ROOT_LENGTH)?;
    if value.len() != VOLUME_ROOT_LENGTH
        || !value
            .get(..11)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\Volume{"))
        || !value.ends_with("}\\")
    {
        bail!("volume_guid_path must be exactly \\\\?\\Volume{{GUID}}\\");
    }
    let id = guid(&value[11..47], "volume GUID")?;
    Ok(format!(r"\\?\Volume{{{}}}\", guid_string(id)))
}

#[derive(Debug)]
struct LocalPath {
    root: String,
    components: Vec<String>,
}

fn path_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        bail!("Paths cannot contain empty, relative, wildcard, stream or ambiguous components");
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                (suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_digit())
                    || ["\u{b9}", "\u{b2}", "\u{b3}"].contains(&suffix)
            })
    {
        bail!("DOS device names are not storage file paths");
    }
    Ok(())
}

fn local_path(value: &str, field: &str, trailing_slash: bool) -> Result<LocalPath> {
    absolute_path(value, field)?;
    if value.contains('/') || value.ends_with('\\') != trailing_slash {
        bail!("{field} must use backslashes and have the required trailing-backslash form");
    }
    let (root, rest) = if value
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\Volume{"))
    {
        let root = value
            .get(..VOLUME_ROOT_LENGTH)
            .context("A volume GUID file path must contain its complete volume root")?;
        (volume_guid_path(root)?, &value[VOLUME_ROOT_LENGTH..])
    } else {
        let value = value.strip_prefix(r"\\?\").unwrap_or(value);
        let bytes = value.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            bail!("{field} must use a local drive or volume GUID root; UNC and device paths are unsupported");
        }
        (
            format!("{}:\\", (bytes[0] as char).to_ascii_uppercase()),
            &value[3..],
        )
    };
    let rest = if trailing_slash && !rest.is_empty() {
        rest.strip_suffix('\\').context("Missing final backslash")?
    } else {
        rest
    };
    let components: Vec<String> = if rest.is_empty() {
        Vec::new()
    } else {
        let mut components = Vec::new();
        for component in rest.split('\\') {
            if components.len() == MAX_PATH_COMPONENTS {
                bail!("{field} exceeds {MAX_PATH_COMPONENTS} path components");
            }
            path_component(component)?;
            components.push(component.to_owned());
        }
        components
    };
    if !trailing_slash && components.is_empty() {
        bail!("{field} must identify a file, not a root");
    }
    Ok(LocalPath { root, components })
}

fn mount_path(value: &str) -> Result<LocalPath> {
    let path = local_path(value, "mount_path", true)?;
    if path.root.len() != 3 && path.components.is_empty() {
        bail!("A volume GUID root itself is not a removable mount alias");
    }
    Ok(path)
}

fn image_type(value: &str) -> Result<VirtualImageType> {
    let path = local_path(value, "image_path", false)?;
    let extension = path
        .components
        .last()
        .and_then(|file| file.rsplit_once('.').map(|(_, extension)| extension))
        .context("image_path must end in .vhd, .vhdx or .iso")?;
    match extension.to_ascii_lowercase().as_str() {
        "vhd" => Ok(VirtualImageType::Vhd),
        "vhdx" => Ok(VirtualImageType::Vhdx),
        "iso" => Ok(VirtualImageType::Iso),
        _ => bail!("Only the installed Microsoft VHD, VHDX and ISO providers are supported"),
    }
}

fn parse_multisz(buffer: &[u16], context: &AdminContext) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut offset = 0;
    loop {
        context.check()?;
        let tail = buffer.get(offset..).context("Invalid MULTI_SZ offset")?;
        let length = tail
            .iter()
            .position(|&unit| unit == 0)
            .context("Native MULTI_SZ is missing its terminator")?;
        if length == 0 {
            return Ok(values);
        }
        if values.len() == 1024 || length > MAX_PATH_UNITS {
            bail!("Native mount-path results exceeded their count or path-length bound");
        }
        values.push(String::from_utf16(&tail[..length])?);
        offset += length + 1;
    }
}

fn volume_mount_paths(context: &AdminContext, volume: &str) -> Result<Vec<String>> {
    let volume = wide(volume, "volume_guid_path", VOLUME_ROOT_LENGTH)?;
    let mut buffer = vec![0u16; 256];
    for _ in 0..BUFFER_ATTEMPTS {
        context.check()?;
        let mut required = 0;
        let result = native_result("GetVolumePathNamesForVolumeNameW", unsafe {
            fs::GetVolumePathNamesForVolumeNameW(
                PCWSTR(volume.as_ptr()),
                Some(&mut buffer),
                &mut required,
            )
        });
        match result {
            Ok(()) => {
                if required == 0 || required as usize > buffer.len() {
                    bail!("GetVolumePathNamesForVolumeNameW returned an invalid UTF-16 length");
                }
                return parse_multisz(&buffer[..required as usize], context);
            }
            Err(error) if has_code(&error, foundation::ERROR_MORE_DATA) => {
                let required = required as usize;
                if required <= buffer.len()
                    || required > MAX_MOUNT_UNITS.min(MAX_NATIVE_BYTES / size_of::<u16>())
                {
                    bail!("GetVolumePathNamesForVolumeNameW exceeded its buffer bound");
                }
                buffer.resize(required, 0);
            }
            Err(error) => return Err(error),
        }
    }
    bail!("Volume mount paths changed too often to read within the retry bound")
}

fn observe_volume(context: &AdminContext, volume: &str) -> Result<Value> {
    let volume = volume_guid_path(volume)?;
    let wide_volume = wide(&volume, "volume_guid_path", VOLUME_ROOT_LENGTH)?;
    let mut errors = Vec::new();
    let mut label = [0u16; 261];
    let mut filesystem = [0u16; 261];
    let (mut serial, mut max_component, mut flags) = (0, 0, 0);
    context.check()?;
    let information = match native_result("GetVolumeInformationW", unsafe {
        fs::GetVolumeInformationW(
            PCWSTR(wide_volume.as_ptr()),
            Some(&mut label),
            Some(&mut serial),
            Some(&mut max_component),
            Some(&mut flags),
            Some(&mut filesystem),
        )
    }) {
        Ok(()) => match (
            terminated_string(&label, "volume label"),
            terminated_string(&filesystem, "filesystem name"),
        ) {
            (Ok(label), Ok(filesystem)) => json!({
                "label": label,
                "filesystem": filesystem,
                "volume_serial": format!("{serial:08x}"),
                "maximum_component_length": max_component,
                "filesystem_flags": flags,
            }),
            (Err(error), _) | (_, Err(error)) => {
                errors.push(error_value(&error));
                Value::Null
            }
        },
        Err(error) => {
            errors.push(error_value(&error));
            Value::Null
        }
    };
    context.check()?;
    let paths = match volume_mount_paths(context, &volume) {
        Ok(paths) => json!(paths),
        Err(error) => {
            context.check()?;
            errors.push(error_value(&error));
            Value::Null
        }
    };
    let (mut available, mut total, mut free) = (0u64, 0u64, 0u64);
    context.check()?;
    let capacity = match native_result("GetDiskFreeSpaceExW", unsafe {
        fs::GetDiskFreeSpaceExW(
            PCWSTR(wide_volume.as_ptr()),
            Some(&mut available),
            Some(&mut total),
            Some(&mut free),
        )
    }) {
        Ok(()) => json!({
            "total_bytes_available_to_caller": total,
            "free_bytes_available_to_caller": available,
            "total_free_bytes": free,
        }),
        Err(error) => {
            errors.push(error_value(&error));
            Value::Null
        }
    };
    Ok(json!({
        "volume_guid_path": volume,
        "information": information,
        "mount_paths": paths,
        "capacity": capacity,
        "errors": errors,
    }))
}

pub fn list_volumes(input: &VolumeListInput, context: &AdminContext) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    context.check()?;
    let mut buffer = [0u16; 1024];
    let search = match native_result("FindFirstVolumeW", unsafe {
        fs::FindFirstVolumeW(&mut buffer)
    }) {
        Ok(handle) => VolumeSearch(handle),
        Err(error) if has_code(&error, foundation::ERROR_NO_MORE_FILES) => {
            return Ok(json!({"volumes": [], "truncated": false, "enumeration_error": null}));
        }
        Err(error) => return Err(error),
    };
    let mut volumes = Vec::new();
    let mut truncated = false;
    let mut enumeration_error = Value::Null;
    loop {
        context.check()?;
        let volume = terminated_string(&buffer, "enumerated volume GUID")?;
        volumes.push(observe_volume(context, &volume)?);
        context.check()?;
        buffer.fill(0);
        match native_result("FindNextVolumeW", unsafe {
            fs::FindNextVolumeW(search.0, &mut buffer)
        }) {
            Ok(()) if volumes.len() == limit => {
                truncated = true;
                break;
            }
            Ok(()) => {}
            Err(error) if has_code(&error, foundation::ERROR_NO_MORE_FILES) => break,
            Err(error) => {
                enumeration_error = error_value(&error);
                break;
            }
        }
    }
    Ok(json!({
        "volumes": volumes,
        "truncated": truncated,
        "enumeration_error": enumeration_error,
    }))
}

fn dos_device(context: &AdminContext, drive: &str) -> Result<Option<String>> {
    let drive = wide(drive, "drive", 2)?;
    let mut buffer = vec![0u16; 512];
    for _ in 0..BUFFER_ATTEMPTS {
        context.check()?;
        let length =
            unsafe { fs::QueryDosDeviceW(PCWSTR(drive.as_ptr()), Some(buffer.as_mut_slice())) };
        if length != 0 {
            if length as usize > buffer.len() {
                bail!("QueryDosDeviceW returned an invalid UTF-16 length");
            }
            return Ok(Some(terminated_string(
                &buffer[..length as usize],
                "DOS device target",
            )?));
        }
        let code = unsafe { foundation::GetLastError() };
        if code == foundation::ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if code != foundation::ERROR_INSUFFICIENT_BUFFER {
            return Err(win32_error("QueryDosDeviceW", code.0));
        }
        if buffer.len() >= MAX_MOUNT_UNITS {
            bail!("QueryDosDeviceW exceeded its buffer bound");
        }
        buffer.resize((buffer.len() * 4).min(MAX_MOUNT_UNITS), 0);
    }
    bail!("QueryDosDeviceW exceeded its retry bound")
}

fn current_mount_target(context: &AdminContext, mount: &str) -> Result<Option<String>> {
    if mount.len() == 3 {
        match dos_device(context, &mount[..2])? {
            None => return Ok(None),
            Some(target) if target.starts_with(r"\??\") => {
                bail!("The drive is an existing DOS alias, not a direct volume mount: {target}");
            }
            Some(_) => {}
        }
    }
    let mount = wide(mount, "mount_path", MAX_PATH_UNITS)?;
    let mut volume = [0u16; 64];
    context.check()?;
    match native_result("GetVolumeNameForVolumeMountPointW", unsafe {
        fs::GetVolumeNameForVolumeMountPointW(PCWSTR(mount.as_ptr()), &mut volume)
    }) {
        Ok(()) => Ok(Some(volume_guid_path(&terminated_string(
            &volume,
            "mount target",
        )?)?)),
        Err(error) if has_code(&error, foundation::ERROR_NOT_A_REPARSE_POINT) => Ok(None),
        Err(error) => Err(error),
    }
}

fn canonical_local_path(
    context: &AdminContext,
    path: &LocalPath,
    directory: bool,
) -> Result<String> {
    let root = if path.root.len() == 3 {
        current_mount_target(context, &path.root)?
            .context("The requested drive has no direct volume mapping")?
    } else {
        path.root.clone()
    };
    let mut result = root;
    result.push_str(&path.components.join("\\"));
    if directory && !path.components.is_empty() {
        result.push('\\');
    }
    text(&result, "canonical storage path", MAX_PATH_UNITS)?;
    Ok(result)
}

fn open_attributes(context: &AdminContext, path: &str) -> Result<OwnedHandle> {
    let root_length = if path.starts_with(r"\\?\Volume{") {
        VOLUME_ROOT_LENGTH
    } else {
        3
    };
    let path = if path.len() > root_length {
        path.strip_suffix('\\').unwrap_or(path)
    } else {
        path
    };
    let path = wide(path, "storage path", MAX_PATH_UNITS)?;
    context.check()?;
    // Omitting FILE_SHARE_DELETE pins the selected file or directory against replacement.
    Ok(OwnedHandle(native_result("CreateFileW", unsafe {
        fs::CreateFileW(
            PCWSTR(path.as_ptr()),
            fs::FILE_READ_ATTRIBUTES.0,
            fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE,
            None,
            fs::OPEN_EXISTING,
            fs::FILE_FLAG_BACKUP_SEMANTICS | fs::FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    })?))
}

fn file_information(
    context: &AdminContext,
    handle: &OwnedHandle,
) -> Result<fs::BY_HANDLE_FILE_INFORMATION> {
    let mut information = fs::BY_HANDLE_FILE_INFORMATION::default();
    context.check()?;
    native_result("GetFileInformationByHandle", unsafe {
        fs::GetFileInformationByHandle(handle.0, &mut information)
    })?;
    Ok(information)
}

fn pin_directories(
    context: &AdminContext,
    canonical: &str,
    include_final: bool,
    allow_final_reparse: bool,
) -> Result<Vec<OwnedHandle>> {
    let path = local_path(canonical, "canonical storage path", true)?;
    let count = if include_final {
        path.components.len()
    } else {
        path.components.len().saturating_sub(1)
    };
    let mut handles = Vec::new();
    let mut current = path.root.clone();
    for index in 0..=count {
        context.check()?;
        if index > 0 {
            current.push_str(&path.components[index - 1]);
            current.push('\\');
        }
        let handle = open_attributes(context, &current)?;
        let information = file_information(context, &handle)?;
        if information.dwFileAttributes & fs::FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            bail!("Storage parent is not a directory: {current}");
        }
        if information.dwFileAttributes & fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            && !(allow_final_reparse && index == count && include_final && index != 0)
        {
            bail!("Storage operations do not traverse reparse points: {current}");
        }
        handles.push(handle);
    }
    Ok(handles)
}

fn require_empty_directory(context: &AdminContext, directory: &str) -> Result<()> {
    let pattern = wide(
        &format!("{directory}*"),
        "mount directory pattern",
        MAX_PATH_UNITS,
    )?;
    let mut data = fs::WIN32_FIND_DATAW::default();
    context.check()?;
    let search = match native_result("FindFirstFileW", unsafe {
        fs::FindFirstFileW(PCWSTR(pattern.as_ptr()), &mut data)
    }) {
        Ok(handle) => FileSearch(handle),
        Err(error) if has_code(&error, foundation::ERROR_FILE_NOT_FOUND) => return Ok(()),
        Err(error) => return Err(error),
    };
    for _ in 0..4 {
        context.check()?;
        let name = terminated_string(&data.cFileName, "mount directory entry")?;
        if name != "." && name != ".." {
            bail!("A directory mount point must be an existing empty directory");
        }
        match native_result("FindNextFileW", unsafe {
            fs::FindNextFileW(search.0, &mut data)
        }) {
            Ok(()) => {}
            Err(error) if has_code(&error, foundation::ERROR_NO_MORE_FILES) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    bail!("Mount-directory enumeration exceeded its bound")
}

struct PreparedMount<G> {
    path: String,
    _guard: G,
}

trait VolumeBackend {
    type Guard;
    fn prepare_mount(
        &self,
        context: &AdminContext,
        mount: &str,
        action: VolumeUpdateAction,
    ) -> Result<PreparedMount<Self::Guard>>;
    fn mount_target(&self, context: &AdminContext, mount: &str) -> Result<Option<String>>;
    fn set_label(&self, context: &AdminContext, volume: &str, label: &str) -> Result<()>;
    fn add_mount(&self, context: &AdminContext, volume: &str, mount: &str) -> Result<()>;
    fn remove_mount(&self, context: &AdminContext, volume: &str, mount: &str) -> Result<()>;
    fn observe(&self, context: &AdminContext, volume: &str) -> Result<Value>;
}

struct NativeStorage;

fn check_mount_ownership(
    action: VolumeUpdateAction,
    expected: &str,
    actual: Option<&str>,
) -> Result<()> {
    match action {
        VolumeUpdateAction::AddMountPoint if actual.is_some() => {
            bail!("The requested mount path is already assigned; existing aliases are never overwritten");
        }
        VolumeUpdateAction::RemoveMountPoint => {
            let actual = actual.context("The requested mount point is not assigned")?;
            if volume_guid_path(actual)? != volume_guid_path(expected)? {
                bail!("The mount point belongs to another volume; refusing to remove it");
            }
        }
        _ => {}
    }
    Ok(())
}

impl VolumeBackend for NativeStorage {
    type Guard = Vec<OwnedHandle>;

    fn prepare_mount(
        &self,
        context: &AdminContext,
        mount: &str,
        action: VolumeUpdateAction,
    ) -> Result<PreparedMount<Self::Guard>> {
        let parsed = mount_path(mount)?;
        if parsed.components.is_empty() {
            return Ok(PreparedMount {
                path: parsed.root,
                _guard: Vec::new(),
            });
        }
        let canonical = canonical_local_path(context, &parsed, true)?;
        let guards = pin_directories(
            context,
            &canonical,
            true,
            action == VolumeUpdateAction::RemoveMountPoint,
        )?;
        if action == VolumeUpdateAction::AddMountPoint {
            require_empty_directory(context, &canonical)?;
        }
        Ok(PreparedMount {
            path: canonical,
            _guard: guards,
        })
    }

    fn mount_target(&self, context: &AdminContext, mount: &str) -> Result<Option<String>> {
        current_mount_target(context, mount)
    }

    fn set_label(&self, context: &AdminContext, volume: &str, label: &str) -> Result<()> {
        let volume = wide(volume, "volume_guid_path", VOLUME_ROOT_LENGTH)?;
        let label = super::to_wide(label);
        context.begin_mutation()?;
        native_result("SetVolumeLabelW", unsafe {
            fs::SetVolumeLabelW(PCWSTR(volume.as_ptr()), PCWSTR(label.as_ptr()))
        })
        .context("Setting a volume label requires access to that volume; no privileges are enabled automatically")
    }

    fn add_mount(&self, context: &AdminContext, volume: &str, mount: &str) -> Result<()> {
        let wide_volume = wide(volume, "volume_guid_path", VOLUME_ROOT_LENGTH)?;
        let wide_mount = wide(mount, "mount_path", MAX_PATH_UNITS)?;
        let actual = current_mount_target(context, mount)?;
        check_mount_ownership(VolumeUpdateAction::AddMountPoint, volume, actual.as_deref())?;
        context.begin_mutation()?;
        native_result("SetVolumeMountPointW", unsafe {
            fs::SetVolumeMountPointW(PCWSTR(wide_mount.as_ptr()), PCWSTR(wide_volume.as_ptr()))
        })
        .context("Adding a mount point requires volume-management permissions and a supported empty host directory")
    }

    fn remove_mount(&self, context: &AdminContext, volume: &str, mount: &str) -> Result<()> {
        let wide_mount = wide(mount, "mount_path", MAX_PATH_UNITS)?;
        // Mount Manager has no compare-and-delete API; recheck immediately before the native call.
        let actual = current_mount_target(context, mount)?;
        check_mount_ownership(
            VolumeUpdateAction::RemoveMountPoint,
            volume,
            actual.as_deref(),
        )?;
        context.begin_mutation()?;
        native_result("DeleteVolumeMountPointW", unsafe {
            fs::DeleteVolumeMountPointW(PCWSTR(wide_mount.as_ptr()))
        })
        .context("Removing a mount alias requires volume-management permissions; no dismount or directory deletion is requested")
    }

    fn observe(&self, context: &AdminContext, volume: &str) -> Result<Value> {
        observe_volume(context, volume)
    }
}

fn validate_volume_update(input: &VolumeUpdateInput) -> Result<String> {
    let volume = volume_guid_path(&input.volume_guid_path)?;
    match input.action {
        VolumeUpdateAction::SetLabel => {
            let label = input.label.as_ref().context("set_label requires label")?;
            if input.mount_path.is_some()
                || label.encode_utf16().count() > 32
                || label.chars().any(char::is_control)
            {
                bail!("set_label accepts only a label of at most 32 UTF-16 units, without control characters; filesystem-specific rules also apply");
            }
        }
        VolumeUpdateAction::AddMountPoint | VolumeUpdateAction::RemoveMountPoint => {
            if input.label.is_some() {
                bail!("Mount operations do not accept label");
            }
            mount_path(
                input
                    .mount_path
                    .as_deref()
                    .context("A mount action requires mount_path")?,
            )?;
        }
    }
    Ok(volume)
}

fn update_volume_with<B: VolumeBackend>(
    backend: &B,
    input: &VolumeUpdateInput,
    context: &AdminContext,
) -> Result<Value> {
    let volume = validate_volume_update(input)?;
    let _lock = mutation_lock(context)?;
    let mut operation_mount = None;
    let mut prepared = None;
    match input.action {
        VolumeUpdateAction::SetLabel => {
            backend.set_label(context, &volume, input.label.as_deref().unwrap_or(""))?;
        }
        action => {
            let mount = input.mount_path.as_deref().context("Missing mount_path")?;
            prepared = Some(backend.prepare_mount(context, mount, action)?);
            let mount = &prepared.as_ref().context("Missing mount guard")?.path;
            let actual = backend.mount_target(context, mount)?;
            check_mount_ownership(action, &volume, actual.as_deref())?;
            context.check()?;
            match action {
                VolumeUpdateAction::AddMountPoint => backend.add_mount(context, &volume, mount)?,
                VolumeUpdateAction::RemoveMountPoint => {
                    backend.remove_mount(context, &volume, mount)?
                }
                VolumeUpdateAction::SetLabel => unreachable!(),
            }
            operation_mount = Some(mount.clone());
        }
    }
    let observation = backend.observe(context, &volume)?;
    let mut observation_error = Value::Null;
    let observed_target = match operation_mount.as_deref() {
        Some(mount) => match backend.mount_target(context, mount) {
            Ok(target) => json!(target),
            Err(error) => {
                context.check()?;
                observation_error = error_value(&error);
                Value::Null
            }
        },
        None => Value::Null,
    };
    let verified = match input.action {
        VolumeUpdateAction::SetLabel => {
            observation["information"]["label"].as_str() == input.label.as_deref()
        }
        VolumeUpdateAction::AddMountPoint => observed_target.as_str() == Some(volume.as_str()),
        VolumeUpdateAction::RemoveMountPoint => {
            observed_target.is_null() && observation_error.is_null()
        }
    };
    drop(prepared);
    Ok(json!({
        "action": input.action,
        "native_operation_succeeded": true,
        "state_verified": verified,
        "volume": observation,
        "requested_mount_path": input.mount_path,
        "operation_mount_path": operation_mount,
        "observed_mount_target": observed_target,
        "observation_error": observation_error,
        "pending": false,
        "reboot_required": null,
        "reboot_status_source": "These synchronous Win32 volume APIs do not report a reboot requirement",
        "forced_dismount": false,
    }))
}

pub fn update_volume(input: &VolumeUpdateInput, context: &AdminContext) -> Result<Value> {
    update_volume_with(&NativeStorage, input, context)
}

#[derive(Clone, Copy)]
struct ImagePlan {
    kind: VirtualImageType,
    read_only: bool,
    no_drive_letter: bool,
}

fn validate_image_input(input: &VirtualDiskInput) -> Result<ImagePlan> {
    let kind = image_type(&input.image_path)?;
    if input.image_type.is_some_and(|expected| expected != kind) {
        bail!("image_type must agree with the image_path extension");
    }
    if input.action != VirtualDiskAction::Attach
        && (input.read_only.is_some() || input.no_drive_letter.is_some())
    {
        bail!("read_only and no_drive_letter are accepted only for attach");
    }
    if input.action != VirtualDiskAction::Inspect && input.expected_identity.is_none() {
        bail!("Attach and detach require expected_identity copied from a prior inspect result");
    }
    if let Some(identity) = &input.expected_identity {
        validate_image_identity(identity)?;
        if image_type(&identity.canonical_path)? != kind {
            bail!("expected_identity refers to a different image type");
        }
    }
    let read_only = input.read_only.unwrap_or(true);
    if kind == VirtualImageType::Iso && !read_only {
        bail!("ISO images must be attached read-only");
    }
    Ok(ImagePlan {
        kind,
        read_only,
        no_drive_letter: input.no_drive_letter.unwrap_or(true),
    })
}

fn validate_image_identity(identity: &ImageIdentity) -> Result<()> {
    let path = local_path(
        &identity.canonical_path,
        "expected_identity.canonical_path",
        false,
    )?;
    if path.root.len() != VOLUME_ROOT_LENGTH {
        bail!("expected_identity.canonical_path must use the canonical volume GUID root returned by inspect");
    }
    for (name, value, length) in [
        ("volume_serial", &identity.volume_serial, 16),
        ("file_id", &identity.file_id, 32),
        ("creation_time", &identity.creation_time, 16),
    ] {
        if value.len() != length || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("expected_identity.{name} must contain exactly {length} hexadecimal digits");
        }
    }
    if identity.file_id.bytes().all(|byte| byte == b'0') {
        bail!("An all-zero file ID cannot identify a backing image");
    }
    Ok(())
}

fn check_image_identity(expected: &ImageIdentity, actual: &ImageIdentity) -> Result<()> {
    validate_image_identity(expected)?;
    if !expected
        .canonical_path
        .eq_ignore_ascii_case(&actual.canonical_path)
        || !expected
            .volume_serial
            .eq_ignore_ascii_case(&actual.volume_serial)
        || !expected.file_id.eq_ignore_ascii_case(&actual.file_id)
        || !expected
            .creation_time
            .eq_ignore_ascii_case(&actual.creation_time)
    {
        bail!("The image identity changed; refusing to act on a replaced file or a different canonical path");
    }
    Ok(())
}

fn attach_flags(plan: ImagePlan) -> vhd::ATTACH_VIRTUAL_DISK_FLAG {
    let mut flags = vhd::ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME;
    if plan.read_only {
        flags |= vhd::ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY;
    }
    if plan.no_drive_letter {
        flags |= vhd::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER;
    }
    flags
}

fn open_access(plan: ImagePlan) -> vhd::VIRTUAL_DISK_ACCESS_MASK {
    // DETACH is also required to reopen a permanently attached image for inspection.
    vhd::VIRTUAL_DISK_ACCESS_GET_INFO
        | vhd::VIRTUAL_DISK_ACCESS_DETACH
        | if plan.read_only {
            vhd::VIRTUAL_DISK_ACCESS_ATTACH_RO
        } else {
            vhd::VIRTUAL_DISK_ACCESS_ATTACH_RW
        }
}

fn final_file_path(context: &AdminContext, file: &OwnedHandle) -> Result<String> {
    let mut buffer = vec![0u16; 512];
    for _ in 0..BUFFER_ATTEMPTS {
        context.check()?;
        let length = unsafe {
            fs::GetFinalPathNameByHandleW(
                file.0,
                &mut buffer,
                fs::GETFINALPATHNAMEBYHANDLE_FLAGS(
                    fs::FILE_NAME_NORMALIZED.0 | fs::VOLUME_NAME_GUID.0,
                ),
            )
        };
        if length == 0 {
            return Err(win32_error("GetFinalPathNameByHandleW", unsafe {
                foundation::GetLastError().0
            }));
        }
        if (length as usize) < buffer.len() {
            if length as usize > MAX_PATH_UNITS {
                bail!("The image's canonical path exceeds its length bound");
            }
            return Ok(String::from_utf16(&buffer[..length as usize])?);
        }
        if length as usize > MAX_PATH_UNITS + 1 {
            bail!("The image's canonical path exceeds its buffer bound");
        }
        buffer.resize(length as usize + 1, 0);
    }
    bail!("GetFinalPathNameByHandleW exceeded its retry bound")
}

struct NativeImagePin {
    _file: OwnedHandle,
    _directories: Vec<OwnedHandle>,
}

struct PinnedImage<G> {
    identity: ImageIdentity,
    attributes: u32,
    _guard: G,
}

#[derive(Debug, Serialize)]
struct DiskObservation {
    attached: Option<bool>,
    physical_path: Option<String>,
    information: Value,
    errors: Vec<Value>,
}

trait VirtualDiskBackend {
    type Pin;
    type Disk;
    fn pin_image(
        &self,
        context: &AdminContext,
        path: &str,
        kind: VirtualImageType,
    ) -> Result<PinnedImage<Self::Pin>>;
    fn open_image(
        &self,
        context: &AdminContext,
        identity: &ImageIdentity,
        plan: ImagePlan,
    ) -> Result<Self::Disk>;
    fn observe_image(&self, context: &AdminContext, disk: &Self::Disk) -> Result<DiskObservation>;
    fn attach_image(
        &self,
        context: &AdminContext,
        disk: &Self::Disk,
        flags: vhd::ATTACH_VIRTUAL_DISK_FLAG,
    ) -> Result<u32>;
    fn detach_image(&self, context: &AdminContext, disk: &Self::Disk) -> Result<u32>;
}

fn virtual_information(
    context: &AdminContext,
    handle: &OwnedHandle,
    version: vhd::GET_VIRTUAL_DISK_INFO_VERSION,
) -> Result<vhd::GET_VIRTUAL_DISK_INFO> {
    // Only fixed-size union members are queried, using the SDK type's native alignment.
    let mut information = vhd::GET_VIRTUAL_DISK_INFO {
        Version: version,
        ..Default::default()
    };
    let mut bytes = size_of::<vhd::GET_VIRTUAL_DISK_INFO>() as u32;
    let mut used = 0;
    context.check()?;
    check_win32(
        "GetVirtualDiskInformation",
        unsafe {
            vhd::GetVirtualDiskInformation(handle.0, &mut bytes, &mut information, Some(&mut used))
        }
        .0,
    )
    .with_context(|| format!("Virtual disk information class {}", version.0))?;
    if bytes as usize > size_of::<vhd::GET_VIRTUAL_DISK_INFO>()
        || used as usize > size_of::<vhd::GET_VIRTUAL_DISK_INFO>()
        || information.Version != version
    {
        bail!("GetVirtualDiskInformation returned an invalid fixed-structure size or version");
    }
    Ok(information)
}

fn virtual_physical_path(context: &AdminContext, disk: &OwnedHandle) -> Result<String> {
    let mut buffer = vec![0u16; 256];
    for _ in 0..BUFFER_ATTEMPTS {
        context.check()?;
        // This API takes bytes, unlike the volume and final-path APIs.
        let mut bytes = (buffer.len() * size_of::<u16>()) as u32;
        let code = unsafe {
            vhd::GetVirtualDiskPhysicalPath(disk.0, &mut bytes, PWSTR(buffer.as_mut_ptr()))
        };
        if code.0 == 0 {
            if bytes as usize > buffer.len() * size_of::<u16>() || !bytes.is_multiple_of(2) {
                bail!("GetVirtualDiskPhysicalPath returned an invalid byte length");
            }
            let path = terminated_string(&buffer, "virtual disk physical path")?;
            text(&path, "virtual disk physical path", MAX_PATH_UNITS)?;
            return Ok(path);
        }
        if code != foundation::ERROR_INSUFFICIENT_BUFFER && code != foundation::ERROR_MORE_DATA {
            return Err(win32_error("GetVirtualDiskPhysicalPath", code.0));
        }
        let bytes = bytes as usize;
        if !bytes.is_multiple_of(2)
            || bytes <= buffer.len() * size_of::<u16>()
            || bytes > MAX_NATIVE_BYTES.min((MAX_PATH_UNITS + 1) * size_of::<u16>())
        {
            bail!("GetVirtualDiskPhysicalPath exceeded its buffer bound");
        }
        buffer.resize(bytes / size_of::<u16>(), 0);
    }
    bail!("GetVirtualDiskPhysicalPath exceeded its retry bound")
}

fn observe_image_native(context: &AdminContext, disk: &OwnedHandle) -> Result<DiskObservation> {
    let mut information = json!({});
    let mut errors = Vec::new();
    let mut loaded = None;
    for version in [
        vhd::GET_VIRTUAL_DISK_INFO_SIZE,
        vhd::GET_VIRTUAL_DISK_INFO_IDENTIFIER,
        vhd::GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE,
        vhd::GET_VIRTUAL_DISK_INFO_IS_LOADED,
        vhd::GET_VIRTUAL_DISK_INFO_PHYSICAL_DISK,
    ] {
        context.check()?;
        match virtual_information(context, disk, version) {
            Ok(value) => unsafe {
                if version == vhd::GET_VIRTUAL_DISK_INFO_SIZE {
                    let size = value.Anonymous.Size;
                    information["size"] = json!({
                        "virtual_bytes": size.VirtualSize,
                        "physical_bytes": size.PhysicalSize,
                        "block_bytes": size.BlockSize,
                        "sector_bytes": size.SectorSize,
                    });
                } else if version == vhd::GET_VIRTUAL_DISK_INFO_IDENTIFIER {
                    information["identifier"] = json!(guid_string(value.Anonymous.Identifier));
                } else if version == vhd::GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE {
                    let storage = value.Anonymous.VirtualStorageType;
                    information["storage_type"] = json!({
                        "device_id": storage.DeviceId,
                        "vendor_id": guid_string(storage.VendorId),
                    });
                } else if version == vhd::GET_VIRTUAL_DISK_INFO_IS_LOADED {
                    loaded = Some(value.Anonymous.IsLoaded.as_bool());
                    information["is_loaded"] = json!(loaded);
                } else if version == vhd::GET_VIRTUAL_DISK_INFO_PHYSICAL_DISK {
                    let physical = value.Anonymous.PhysicalDisk;
                    information["backing_storage"] = json!({
                        "logical_sector_bytes": physical.LogicalSectorSize,
                        "physical_sector_bytes": physical.PhysicalSectorSize,
                        "is_remote": physical.IsRemote.as_bool(),
                    });
                }
            },
            Err(error) => {
                context.check()?;
                errors.push(error_value(&error));
            }
        }
    }
    context.check()?;
    let mut not_attached = false;
    let physical_path = match virtual_physical_path(context, disk) {
        Ok(path) => Some(path),
        Err(error) => {
            context.check()?;
            not_attached = has_code(&error, foundation::ERROR_DEV_NOT_EXIST);
            errors.push(error_value(&error));
            None
        }
    };
    let attached = if physical_path.is_some() {
        Some(true)
    } else if loaded == Some(false) || (not_attached && loaded != Some(true)) {
        Some(false)
    } else {
        None
    };
    Ok(DiskObservation {
        attached,
        physical_path,
        information,
        errors,
    })
}

impl VirtualDiskBackend for NativeStorage {
    type Pin = NativeImagePin;
    type Disk = OwnedHandle;

    fn pin_image(
        &self,
        context: &AdminContext,
        path: &str,
        kind: VirtualImageType,
    ) -> Result<PinnedImage<Self::Pin>> {
        let parsed = local_path(path, "image_path", false)?;
        let canonical = canonical_local_path(context, &parsed, false)?;
        let directories = pin_directories(context, &format!("{canonical}\\"), false, false)?;
        let file = open_attributes(context, &canonical)?;
        let information = file_information(context, &file)?;
        if information.dwFileAttributes
            & (fs::FILE_ATTRIBUTE_DIRECTORY.0 | fs::FILE_ATTRIBUTE_REPARSE_POINT.0)
            != 0
        {
            bail!("image_path must be a regular file, not a directory or reparse point");
        }
        context.check()?;
        if unsafe { fs::GetFileType(file.0) } != fs::FILE_TYPE_DISK {
            bail!("image_path is not a disk-backed file");
        }
        let canonical_path = final_file_path(context, &file)?;
        if image_type(&canonical_path)? != kind {
            bail!("The canonical backing-file extension does not match the requested provider");
        }
        let mut file_id = fs::FILE_ID_INFO::default();
        context.check()?;
        native_result("GetFileInformationByHandleEx(FileIdInfo)", unsafe {
            fs::GetFileInformationByHandleEx(
                file.0,
                fs::FileIdInfo,
                (&mut file_id as *mut fs::FILE_ID_INFO).cast(),
                size_of::<fs::FILE_ID_INFO>() as u32,
            )
        })
        .context("Image operations require a filesystem exposing stable 128-bit file identities")?;
        let creation = (u64::from(information.ftCreationTime.dwHighDateTime) << 32)
            | u64::from(information.ftCreationTime.dwLowDateTime);
        let identity = ImageIdentity {
            canonical_path,
            volume_serial: format!("{:016x}", file_id.VolumeSerialNumber),
            file_id: file_id
                .FileId
                .Identifier
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            creation_time: format!("{creation:016x}"),
        };
        validate_image_identity(&identity)?;
        Ok(PinnedImage {
            identity,
            attributes: information.dwFileAttributes,
            _guard: NativeImagePin {
                _file: file,
                _directories: directories,
            },
        })
    }

    fn open_image(
        &self,
        context: &AdminContext,
        identity: &ImageIdentity,
        plan: ImagePlan,
    ) -> Result<Self::Disk> {
        let path = wide(
            &identity.canonical_path,
            "canonical image path",
            MAX_PATH_UNITS,
        )?;
        let storage_type = vhd::VIRTUAL_STORAGE_TYPE {
            DeviceId: match plan.kind {
                VirtualImageType::Vhd => vhd::VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
                VirtualImageType::Vhdx => vhd::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
                VirtualImageType::Iso => vhd::VIRTUAL_STORAGE_TYPE_DEVICE_ISO,
            },
            VendorId: vhd::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = vhd::OPEN_VIRTUAL_DISK_PARAMETERS {
            Version: vhd::OPEN_VIRTUAL_DISK_VERSION_1,
            Anonymous: vhd::OPEN_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: vhd::OPEN_VIRTUAL_DISK_PARAMETERS_0_0 {
                    RWDepth: u32::from(!plan.read_only),
                },
            },
        };
        let mut handle = HANDLE::default();
        context.check()?;
        check_win32(
            "OpenVirtualDisk",
            unsafe {
                vhd::OpenVirtualDisk(
                    &storage_type,
                    PCWSTR(path.as_ptr()),
                    open_access(plan),
                    vhd::OPEN_VIRTUAL_DISK_FLAG_NONE,
                    Some(&parameters),
                    &mut handle,
                )
            }
            .0,
        )
        .context("The installed Microsoft provider and backing-file permissions must permit this access; no feature installation or privilege enablement is attempted")?;
        if handle.is_invalid() {
            bail!("OpenVirtualDisk succeeded without returning a valid handle");
        }
        Ok(OwnedHandle(handle))
    }

    fn observe_image(&self, context: &AdminContext, disk: &Self::Disk) -> Result<DiskObservation> {
        observe_image_native(context, disk)
    }

    fn attach_image(
        &self,
        context: &AdminContext,
        disk: &Self::Disk,
        flags: vhd::ATTACH_VIRTUAL_DISK_FLAG,
    ) -> Result<u32> {
        let parameters = vhd::ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: vhd::ATTACH_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        context.begin_mutation()?;
        Ok(unsafe { vhd::AttachVirtualDisk(disk.0, None, flags, 0, Some(&parameters), None) }.0)
    }

    fn detach_image(&self, context: &AdminContext, disk: &Self::Disk) -> Result<u32> {
        context.begin_mutation()?;
        Ok(unsafe { vhd::DetachVirtualDisk(disk.0, vhd::DETACH_VIRTUAL_DISK_FLAG_NONE, 0) }.0)
    }
}

fn operation_status(api: &str, code: u32) -> Result<Value> {
    if code != 0
        && code != foundation::ERROR_IO_PENDING.0
        && code != foundation::ERROR_SUCCESS_REBOOT_REQUIRED.0
        && code != foundation::ERROR_SUCCESS_REBOOT_INITIATED.0
    {
        return Err(win32_error(api, code)).context(
            "Virtual disk attachment changes require appropriate backing-file access and volume-management rights (SeManageVolumePrivilege where required); busy devices are not forcibly dismounted",
        );
    }
    Ok(json!({
        "api": api,
        "code": code,
        "pending": code == foundation::ERROR_IO_PENDING.0,
        "reboot_required": if code == foundation::ERROR_SUCCESS_REBOOT_REQUIRED.0
            || code == foundation::ERROR_SUCCESS_REBOOT_INITIATED.0
        {
            Some(true)
        } else {
            None
        },
    }))
}

fn virtual_disk_with<B: VirtualDiskBackend>(
    backend: &B,
    input: &VirtualDiskInput,
    context: &AdminContext,
) -> Result<Value> {
    let plan = validate_image_input(input)?;
    context.check()?;
    let _lock = if input.action != VirtualDiskAction::Inspect {
        Some(mutation_lock(context)?)
    } else {
        None
    };
    let image = backend.pin_image(context, &input.image_path, plan.kind)?;
    if let Some(expected) = &input.expected_identity {
        check_image_identity(expected, &image.identity)?;
    }
    if !plan.read_only && image.attributes & fs::FILE_ATTRIBUTE_READONLY.0 != 0 {
        bail!("The backing image has the read-only file attribute; refusing a writable attachment");
    }
    let disk = backend.open_image(context, &image.identity, plan)?;
    let before = backend.observe_image(context, &disk)?;
    let mut status = Value::Null;
    let after = match input.action {
        VirtualDiskAction::Inspect => before,
        VirtualDiskAction::Attach => {
            if before.attached == Some(true) {
                bail!("The image is already attached; its access or lifetime policy will not be changed implicitly");
            }
            context.check()?;
            status = operation_status(
                "AttachVirtualDisk",
                backend.attach_image(context, &disk, attach_flags(plan))?,
            )?;
            backend.observe_image(context, &disk)?
        }
        VirtualDiskAction::Detach => {
            if before.attached == Some(false) {
                bail!("The selected image is not attached");
            }
            context.check()?;
            status = operation_status("DetachVirtualDisk", backend.detach_image(context, &disk)?)?;
            backend.observe_image(context, &disk)?
        }
    };
    let verified = match input.action {
        VirtualDiskAction::Inspect => Value::Null,
        VirtualDiskAction::Attach => json!(after.attached == Some(true)),
        VirtualDiskAction::Detach => json!(after.attached == Some(false)),
    };
    let attachment_request = if input.action == VirtualDiskAction::Attach {
        json!({
            "lifetime": "persistent",
            "survives_handle_close": true,
            "detaches_on_drop": false,
            "boot_attachment_requested": false,
            "read_only": plan.read_only,
            "no_drive_letter": plan.no_drive_letter,
            "native_flags": attach_flags(plan).0,
            "note": "PERMANENT_LIFETIME requires explicit detach; it is not AT_BOOT. NO_DRIVE_LETTER is not a write-protection or volume-access boundary.",
        })
    } else {
        Value::Null
    };
    Ok(json!({
        "action": input.action,
        "image_identity": image.identity,
        "image_type": plan.kind,
        "provider": "Microsoft",
        "backing_file_opened_read_only": plan.read_only,
        "attachment_request": attachment_request,
        "observation": after,
        "state_verified": verified,
        "native_status": status,
        "supported_attachment_lifetimes": ["persistent"],
        "observed_existing_attachment_read_only": null,
        "observed_existing_attachment_lifetime": null,
        "session_handle_retained": false,
        "forced_dismount": false,
        "completion_note": "Native calls are synchronous. A successful call is not proof of the observed attachment state; unsupported information classes and device-discovery errors are reported separately.",
    }))
}

pub fn virtual_disk(input: &VirtualDiskInput, context: &AdminContext) -> Result<Value> {
    virtual_disk_with(&NativeStorage, input, context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    const VOLUME: &str = r"\\?\Volume{00000000-0000-0000-0000-000000000001}\";
    const OTHER_VOLUME: &str = r"\\?\Volume{00000000-0000-0000-0000-000000000002}\";

    fn context() -> AdminContext {
        AdminContext::new(Duration::from_secs(15))
    }

    fn identity() -> ImageIdentity {
        ImageIdentity {
            canonical_path: format!("{VOLUME}images\\fixture.vhdx"),
            volume_serial: "0000000000000001".into(),
            file_id: "00000000000000000000000000000001".into(),
            creation_time: "0000000000000001".into(),
        }
    }

    fn image_input(action: VirtualDiskAction) -> VirtualDiskInput {
        VirtualDiskInput {
            action,
            image_path: r"C:\images\fixture.vhdx".into(),
            image_type: None,
            expected_identity: Some(identity()),
            read_only: None,
            no_drive_letter: None,
            timeout_ms: None,
        }
    }

    fn volume_input(action: VolumeUpdateAction) -> VolumeUpdateInput {
        VolumeUpdateInput {
            action,
            volume_guid_path: VOLUME.into(),
            label: if action == VolumeUpdateAction::SetLabel {
                Some("Fixture".into())
            } else {
                None
            },
            mount_path: if action != VolumeUpdateAction::SetLabel {
                Some("X:\\".into())
            } else {
                None
            },
            timeout_ms: None,
        }
    }

    #[derive(Default)]
    struct FakeVolumes {
        target: RefCell<Option<String>>,
        reassign_before_remove: RefCell<Option<String>>,
        label: RefCell<String>,
        mutations: Cell<usize>,
        native_error: Cell<u32>,
    }

    impl FakeVolumes {
        fn begin(&self, context: &AdminContext, api: &str) -> Result<()> {
            context.begin_mutation()?;
            self.mutations.set(self.mutations.get() + 1);
            check_win32(api, self.native_error.get())
        }
    }

    impl VolumeBackend for FakeVolumes {
        type Guard = ();

        fn prepare_mount(
            &self,
            context: &AdminContext,
            mount: &str,
            _action: VolumeUpdateAction,
        ) -> Result<PreparedMount<Self::Guard>> {
            context.check()?;
            Ok(PreparedMount {
                path: mount.into(),
                _guard: (),
            })
        }

        fn mount_target(&self, context: &AdminContext, _mount: &str) -> Result<Option<String>> {
            context.check()?;
            Ok(self.target.borrow().clone())
        }

        fn set_label(&self, context: &AdminContext, _volume: &str, label: &str) -> Result<()> {
            self.begin(context, "SetVolumeLabelW")?;
            self.label.replace(label.into());
            Ok(())
        }

        fn add_mount(&self, context: &AdminContext, volume: &str, _mount: &str) -> Result<()> {
            check_mount_ownership(
                VolumeUpdateAction::AddMountPoint,
                volume,
                self.target.borrow().as_deref(),
            )?;
            self.begin(context, "SetVolumeMountPointW")?;
            self.target.replace(Some(volume.into()));
            Ok(())
        }

        fn remove_mount(&self, context: &AdminContext, volume: &str, _mount: &str) -> Result<()> {
            if let Some(target) = self.reassign_before_remove.borrow_mut().take() {
                self.target.replace(Some(target));
            }
            check_mount_ownership(
                VolumeUpdateAction::RemoveMountPoint,
                volume,
                self.target.borrow().as_deref(),
            )?;
            self.begin(context, "DeleteVolumeMountPointW")?;
            self.target.replace(None);
            Ok(())
        }

        fn observe(&self, context: &AdminContext, volume: &str) -> Result<Value> {
            context.check()?;
            Ok(json!({
                "volume_guid_path": volume,
                "information": {"label": self.label.borrow().clone()},
                "errors": [],
            }))
        }
    }

    struct FakeDisk {
        attached: Rc<Cell<Option<bool>>>,
        owns_attachment: Cell<bool>,
        permanent: Cell<bool>,
        closed: Rc<Cell<usize>>,
    }

    impl Drop for FakeDisk {
        fn drop(&mut self) {
            if self.owns_attachment.get() && !self.permanent.get() {
                self.attached.set(Some(false));
            }
            self.closed.set(self.closed.get() + 1);
        }
    }

    struct FakeImages {
        identity: ImageIdentity,
        attributes: u32,
        attached: Rc<Cell<Option<bool>>>,
        closed: Rc<Cell<usize>>,
        opened: Cell<usize>,
        mutations: Cell<usize>,
        flags: Cell<i32>,
        access: Cell<i32>,
        native_code: Cell<u32>,
        keep_attached: Cell<bool>,
    }

    impl Default for FakeImages {
        fn default() -> Self {
            Self {
                identity: identity(),
                attributes: 0,
                attached: Rc::new(Cell::new(Some(false))),
                closed: Rc::new(Cell::new(0)),
                opened: Cell::new(0),
                mutations: Cell::new(0),
                flags: Cell::new(0),
                access: Cell::new(0),
                native_code: Cell::new(0),
                keep_attached: Cell::new(false),
            }
        }
    }

    impl VirtualDiskBackend for FakeImages {
        type Pin = ();
        type Disk = FakeDisk;

        fn pin_image(
            &self,
            context: &AdminContext,
            _path: &str,
            _kind: VirtualImageType,
        ) -> Result<PinnedImage<Self::Pin>> {
            context.check()?;
            Ok(PinnedImage {
                identity: self.identity.clone(),
                attributes: self.attributes,
                _guard: (),
            })
        }

        fn open_image(
            &self,
            context: &AdminContext,
            _identity: &ImageIdentity,
            plan: ImagePlan,
        ) -> Result<Self::Disk> {
            context.check()?;
            self.opened.set(self.opened.get() + 1);
            self.access.set(open_access(plan).0);
            Ok(FakeDisk {
                attached: self.attached.clone(),
                owns_attachment: Cell::new(false),
                permanent: Cell::new(false),
                closed: self.closed.clone(),
            })
        }

        fn observe_image(
            &self,
            context: &AdminContext,
            _disk: &Self::Disk,
        ) -> Result<DiskObservation> {
            context.check()?;
            Ok(DiskObservation {
                attached: self.attached.get(),
                physical_path: if self.attached.get() == Some(true) {
                    Some(r"\\.\PhysicalDrive42".into())
                } else {
                    None
                },
                information: json!({"is_loaded": self.attached.get()}),
                errors: Vec::new(),
            })
        }

        fn attach_image(
            &self,
            context: &AdminContext,
            disk: &Self::Disk,
            flags: vhd::ATTACH_VIRTUAL_DISK_FLAG,
        ) -> Result<u32> {
            context.begin_mutation()?;
            self.mutations.set(self.mutations.get() + 1);
            self.flags.set(flags.0);
            if self.native_code.get() == 0 {
                disk.owns_attachment.set(true);
                disk.permanent
                    .set(flags.0 & vhd::ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME.0 != 0);
                self.attached.set(Some(true));
            }
            Ok(self.native_code.get())
        }

        fn detach_image(&self, context: &AdminContext, _disk: &Self::Disk) -> Result<u32> {
            context.begin_mutation()?;
            self.mutations.set(self.mutations.get() + 1);
            if self.native_code.get() == 0 && !self.keep_attached.get() {
                self.attached.set(Some(false));
            }
            Ok(self.native_code.get())
        }
    }

    #[test]
    fn administration_storage_exact_volume_identity() {
        assert_eq!(volume_guid_path(VOLUME).unwrap(), VOLUME);
        assert_eq!(
            volume_guid_path(&VOLUME.to_ascii_uppercase()).unwrap(),
            VOLUME
        );
        for invalid in [
            "C:\\",
            "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}",
            "\\\\?\\Volume{00000000000000000000000000000001}\\",
            "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\child",
        ] {
            assert!(volume_guid_path(invalid).is_err(), "{invalid}");
        }
        assert!(check_mount_ownership(
            VolumeUpdateAction::RemoveMountPoint,
            VOLUME,
            Some(OTHER_VOLUME)
        )
        .is_err());
    }

    #[test]
    fn administration_storage_paths_are_local_exact_and_bounded() {
        assert_eq!(
            image_type(r"C:\images\one.VHDX").unwrap(),
            VirtualImageType::Vhdx
        );
        assert_eq!(
            image_type(r"\\?\C:\images\one.iso").unwrap(),
            VirtualImageType::Iso
        );
        assert!(image_type(&format!("{VOLUME}one.vhd")).is_ok());
        for invalid in [
            r"C:one.vhdx",
            r"\images\one.vhdx",
            r"C:\images\..\one.vhdx",
            r"\\?\C:\images\..\one.vhdx",
            r"C:\images\.\one.vhdx",
            r"C:\images\\one.vhdx",
            r"C:\images\one.vhdx:stream",
            r"C:\images\one*.vhdx",
            r"C:\images\one.vhdx ",
            r"C:\images\NUL.vhdx",
            "C:\\images\\COM\u{b9}.vhdx",
            r"\\server\share\one.vhdx",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\one.vhdx",
            r"C:\images\one.wim",
            "C:\\images\\one\0.vhdx",
        ] {
            assert!(image_type(invalid).is_err(), "{invalid:?}");
        }
        assert!(image_type(&format!("C:\\{}.vhd", "a".repeat(MAX_PATH_UNITS))).is_err());
        assert!(image_type(&format!("C:\\{}one.vhd", "a\\".repeat(MAX_PATH_COMPONENTS))).is_err());
        assert!(mount_path(r"C:\mounts\").is_ok());
        assert!(mount_path("X:\\").is_ok());
        assert!(mount_path(&format!("{VOLUME}mount\\")).is_ok());
        assert!(mount_path(VOLUME).is_err());
        assert!(mount_path(r"C:\mounts").is_err());
    }

    #[test]
    fn administration_storage_utf16_and_multisz_lengths() {
        let context = context();
        let buffer: Vec<u16> = "C:\\\0C:\\mount\\\0\0".encode_utf16().collect();
        assert_eq!(
            parse_multisz(&buffer, &context).unwrap(),
            ["C:\\", "C:\\mount\\"]
        );
        assert!(parse_multisz(&[0], &context).unwrap().is_empty());
        assert!(parse_multisz(&[0, 0], &context).unwrap().is_empty());
        assert!(parse_multisz(&[], &context).is_err());
        assert!(parse_multisz(&[65, 0], &context).is_err());
        assert!(parse_multisz(&[0xd800, 0, 0], &context).is_err());
        assert!(terminated_string(&[65], "fixture").is_err());
        let mut input = volume_input(VolumeUpdateAction::SetLabel);
        input.label = Some("\u{10000}".repeat(16));
        assert!(validate_volume_update(&input).is_ok());
        input.label = Some("\u{10000}".repeat(17));
        assert!(validate_volume_update(&input).is_err());
        input.label = Some(String::new());
        assert!(validate_volume_update(&input).is_ok());
        input.label = Some("name\0suffix".into());
        assert!(validate_volume_update(&input).is_err());
    }

    #[test]
    fn administration_storage_json_schema_and_numeric_coercion() {
        let list: VolumeListInput =
            serde_json::from_value(json!({"limit": "4", "timeout_ms": "15000"})).unwrap();
        assert_eq!(list.limit, Some(4));
        assert_eq!(list.timeout_ms, Some(15_000));
        let update: VolumeUpdateInput = serde_json::from_value(json!({
            "action": "set_label", "volume_guid_path": VOLUME,
            "label": "", "timeout_ms": "1000"
        }))
        .unwrap();
        assert_eq!(update.timeout_ms, Some(1000));
        let image: VirtualDiskInput = serde_json::from_value(json!({
            "action": "inspect", "image_path": "C:\\image.iso", "timeout_ms": "2000"
        }))
        .unwrap();
        assert_eq!(image.timeout_ms, Some(2000));
        assert!(serde_json::from_value::<VolumeListInput>(json!({"limit": -1})).is_err());
        assert!(serde_json::from_value::<VolumeListInput>(json!({"limit": "1.5"})).is_err());
        assert!(serde_json::from_value::<VirtualDiskInput>(json!({
            "action": "create", "image_path": "C:\\image.vhd"
        }))
        .is_err());
        assert!(serde_json::from_value::<VirtualDiskInput>(json!({
            "action": "inspect", "image_path": "C:\\image.iso", "force": true
        }))
        .is_err());
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(VirtualDiskInput)).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"]["timeout_ms"]
            .to_string()
            .contains("integer"));
        assert!(schema.to_string().contains("expected_identity"));
        assert!(schema.to_string().contains("no_drive_letter"));
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(VolumeUpdateInput)).unwrap();
        assert!(schema.to_string().contains("remove_mount_point"));
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(VolumeListInput)).unwrap();
        assert!(schema["properties"]["limit"]
            .to_string()
            .contains("integer"));
    }

    #[test]
    fn administration_storage_limits_and_action_specific_fields() {
        let context = context();
        for limit in [0, 1025] {
            assert!(list_volumes(
                &VolumeListInput {
                    limit: Some(limit),
                    timeout_ms: None,
                },
                &context
            )
            .is_err());
        }
        let mut label = volume_input(VolumeUpdateAction::SetLabel);
        label.mount_path = Some("X:\\".into());
        assert!(validate_volume_update(&label).is_err());
        let mut mount = volume_input(VolumeUpdateAction::RemoveMountPoint);
        mount.label = Some("unrelated".into());
        assert!(validate_volume_update(&mount).is_err());
        let mut image = image_input(VirtualDiskAction::Inspect);
        image.read_only = Some(false);
        assert!(validate_image_input(&image).is_err());
        image = image_input(VirtualDiskAction::Detach);
        image.no_drive_letter = Some(true);
        assert!(validate_image_input(&image).is_err());
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_storage_fixture_inspect_does_not_claim_attachment_policy() {
        let backend = FakeImages::default();
        backend.attached.set(Some(true));
        let mut input = image_input(VirtualDiskAction::Inspect);
        input.expected_identity = None;
        let context = context();
        let result = virtual_disk_with(&backend, &input, &context).unwrap();
        assert_eq!(result["observation"]["attached"], true);
        assert_eq!(result["attachment_request"], Value::Null);
        assert_eq!(result["observed_existing_attachment_lifetime"], Value::Null);
        assert_eq!(
            result["observed_existing_attachment_read_only"],
            Value::Null
        );
        assert_eq!(backend.mutations.get(), 0);
        assert_eq!(backend.attached.get(), Some(true));
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_storage_fixture_volume_changes_return_observed_state() {
        let backend = FakeVolumes::default();
        let label = update_volume_with(
            &backend,
            &volume_input(VolumeUpdateAction::SetLabel),
            &context(),
        )
        .unwrap();
        assert_eq!(label["volume"]["information"]["label"], "Fixture");
        assert_eq!(label["state_verified"], true);
        let added = update_volume_with(
            &backend,
            &volume_input(VolumeUpdateAction::AddMountPoint),
            &context(),
        )
        .unwrap();
        assert_eq!(added["observed_mount_target"], VOLUME);
        let removed = update_volume_with(
            &backend,
            &volume_input(VolumeUpdateAction::RemoveMountPoint),
            &context(),
        )
        .unwrap();
        assert_eq!(removed["state_verified"], true);
        assert_eq!(removed["observed_mount_target"], Value::Null);
        assert_eq!(removed["forced_dismount"], false);
        assert_eq!(backend.mutations.get(), 3);
    }

    #[test]
    fn administration_storage_fixture_refuses_alias_overwrite_and_wrong_removal() {
        let backend = FakeVolumes::default();
        backend.target.replace(Some(OTHER_VOLUME.into()));
        let context = context();
        for action in [
            VolumeUpdateAction::AddMountPoint,
            VolumeUpdateAction::RemoveMountPoint,
        ] {
            assert!(update_volume_with(&backend, &volume_input(action), &context).is_err());
        }
        backend.target.replace(Some(VOLUME.into()));
        assert!(update_volume_with(
            &backend,
            &volume_input(VolumeUpdateAction::AddMountPoint),
            &context
        )
        .is_err());
        backend
            .reassign_before_remove
            .replace(Some(OTHER_VOLUME.into()));
        assert!(update_volume_with(
            &backend,
            &volume_input(VolumeUpdateAction::RemoveMountPoint),
            &context
        )
        .is_err());
        assert_eq!(backend.mutations.get(), 0);
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_storage_fixture_native_errors_keep_codes_and_uncertainty() {
        let backend = FakeVolumes::default();
        backend.native_error.set(5);
        let context = context();
        let error = update_volume_with(
            &backend,
            &volume_input(VolumeUpdateAction::SetLabel),
            &context,
        )
        .unwrap_err();
        let native = error.downcast_ref::<NativeError>().unwrap();
        assert_eq!(native.api, "SetVolumeLabelW");
        assert_eq!(native.code, 5);
        assert_eq!(native.domain, "win32");
        assert!(context.mutation_started());
        assert_eq!(*backend.label.borrow(), "");
        let error = operation_status("AttachVirtualDisk", foundation::ERROR_VHD_INVALID_TYPE.0)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<NativeError>().unwrap().code,
            foundation::ERROR_VHD_INVALID_TYPE.0
        );
        let error = native_result::<()>(
            "SetVolumeMountPointW",
            Err(windows::core::Error::from_hresult(
                windows::core::HRESULT::from_win32(5),
            )),
        )
        .unwrap_err();
        assert_eq!(error.downcast_ref::<NativeError>().unwrap().code, 5);
    }

    #[test]
    fn administration_storage_fixture_requires_unchanged_image_identity() {
        let mut backend = FakeImages::default();
        backend.identity.file_id = "00000000000000000000000000000002".into();
        let context = context();
        assert!(
            virtual_disk_with(&backend, &image_input(VirtualDiskAction::Attach), &context).is_err()
        );
        assert_eq!(backend.opened.get(), 0);
        assert_eq!(backend.mutations.get(), 0);
        assert!(!context.mutation_started());
        let mut replaced = identity();
        replaced.canonical_path = format!("{OTHER_VOLUME}images\\fixture.vhdx");
        assert!(check_image_identity(&identity(), &replaced).is_err());
        replaced = identity();
        replaced.creation_time = "0000000000000002".into();
        assert!(check_image_identity(&identity(), &replaced).is_err());
        let mut input = image_input(VirtualDiskAction::Detach);
        input.expected_identity = None;
        assert!(validate_image_input(&input).is_err());
    }

    #[test]
    fn administration_storage_fixture_persistent_attach_survives_handle_close() {
        let backend = FakeImages::default();
        let attached = virtual_disk_with(
            &backend,
            &image_input(VirtualDiskAction::Attach),
            &context(),
        )
        .unwrap();
        assert_eq!(
            attached["observation"]["physical_path"],
            r"\\.\PhysicalDrive42"
        );
        assert_eq!(attached["state_verified"], true);
        assert_eq!(
            attached["attachment_request"]["survives_handle_close"],
            true
        );
        assert_eq!(attached["attachment_request"]["detaches_on_drop"], false);
        assert_eq!(backend.closed.get(), 1);
        assert_eq!(backend.attached.get(), Some(true));
        assert_ne!(
            backend.flags.get() & vhd::ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME.0,
            0
        );
        assert_ne!(
            backend.flags.get() & vhd::ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY.0,
            0
        );
        assert_ne!(
            backend.flags.get() & vhd::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER.0,
            0
        );
        assert_eq!(
            backend.access.get() & vhd::VIRTUAL_DISK_ACCESS_ATTACH_RW.0,
            0
        );
        assert_ne!(backend.access.get() & vhd::VIRTUAL_DISK_ACCESS_DETACH.0, 0);
        let detached = virtual_disk_with(
            &backend,
            &image_input(VirtualDiskAction::Detach),
            &context(),
        )
        .unwrap();
        assert_eq!(detached["state_verified"], true);
        assert_eq!(backend.attached.get(), Some(false));
        assert_eq!(backend.closed.get(), 2);
    }

    #[test]
    fn administration_storage_fixture_read_only_is_not_no_drive_letter() {
        let backend = FakeImages::default();
        let mut input = image_input(VirtualDiskAction::Attach);
        input.read_only = Some(false);
        let result = virtual_disk_with(&backend, &input, &context()).unwrap();
        assert_eq!(result["attachment_request"]["read_only"], false);
        assert_eq!(result["attachment_request"]["no_drive_letter"], true);
        assert_eq!(
            backend.flags.get() & vhd::ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY.0,
            0
        );
        assert_ne!(
            backend.flags.get() & vhd::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER.0,
            0
        );
        assert_ne!(
            backend.access.get() & vhd::VIRTUAL_DISK_ACCESS_ATTACH_RW.0,
            0
        );

        let readonly_backend = FakeImages {
            attributes: fs::FILE_ATTRIBUTE_READONLY.0,
            ..Default::default()
        };
        let context = context();
        assert!(virtual_disk_with(&readonly_backend, &input, &context).is_err());
        assert!(!context.mutation_started());
        input.image_path = r"C:\images\fixture.iso".into();
        input.expected_identity = Some(ImageIdentity {
            canonical_path: format!("{VOLUME}images\\fixture.iso"),
            ..identity()
        });
        assert!(validate_image_input(&input).is_err());
        input.read_only = Some(true);
        input.no_drive_letter = Some(false);
        let flags = attach_flags(validate_image_input(&input).unwrap());
        assert_ne!(flags.0 & vhd::ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY.0, 0);
        assert_eq!(flags.0 & vhd::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER.0, 0);
        input.image_type = Some(VirtualImageType::Vhd);
        assert!(validate_image_input(&input).is_err());
    }

    #[test]
    fn administration_storage_fixture_success_does_not_invent_detachment() {
        let backend = FakeImages::default();
        backend.attached.set(Some(true));
        backend.keep_attached.set(true);
        let result = virtual_disk_with(
            &backend,
            &image_input(VirtualDiskAction::Detach),
            &context(),
        )
        .unwrap();
        assert_eq!(result["native_status"]["code"], 0);
        assert_eq!(result["observation"]["attached"], true);
        assert_eq!(result["state_verified"], false);
        assert_eq!(result["forced_dismount"], false);
    }

    #[test]
    fn administration_storage_fixture_pending_reboot_and_failure_are_explicit() {
        let backend = FakeImages::default();
        backend.native_code.set(foundation::ERROR_IO_PENDING.0);
        let result = virtual_disk_with(
            &backend,
            &image_input(VirtualDiskAction::Attach),
            &context(),
        )
        .unwrap();
        assert_eq!(result["native_status"]["pending"], true);
        assert_eq!(result["state_verified"], false);
        let reboot = operation_status(
            "AttachVirtualDisk",
            foundation::ERROR_SUCCESS_REBOOT_REQUIRED.0,
        )
        .unwrap();
        assert_eq!(reboot["reboot_required"], true);
        backend.native_code.set(5);
        let context = context();
        let error = virtual_disk_with(&backend, &image_input(VirtualDiskAction::Attach), &context)
            .unwrap_err();
        assert_eq!(error.downcast_ref::<NativeError>().unwrap().code, 5);
        assert!(context.mutation_started());
        assert_eq!(backend.attached.get(), Some(false));
    }

    #[test]
    fn administration_storage_fixture_cancellation_never_mutates() {
        let context = context();
        context.cancel();
        let volumes = FakeVolumes::default();
        assert!(update_volume_with(
            &volumes,
            &volume_input(VolumeUpdateAction::SetLabel),
            &context
        )
        .is_err());
        let images = FakeImages::default();
        assert!(
            virtual_disk_with(&images, &image_input(VirtualDiskAction::Attach), &context).is_err()
        );
        assert_eq!(volumes.mutations.get(), 0);
        assert_eq!(images.mutations.get(), 0);
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_storage_private_unattached_images_inspect_natively() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                for extension in ["vhd", "vhdx"] {
                    let path = self.0.join(format!("fixture.{extension}"));
                    if let Err(error) = std::fs::remove_file(&path) {
                        if error.kind() != std::io::ErrorKind::NotFound {
                            eprintln!("Cannot remove image fixture {}: {error}", path.display());
                        }
                    }
                }
                if let Err(error) = std::fs::remove_dir(&self.0) {
                    eprintln!(
                        "Cannot remove image fixture directory {}: {error}",
                        self.0.display()
                    );
                }
            }
        }

        let directory =
            std::env::temp_dir().join(format!("mcp-administration-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let fixture = Fixture(directory);
        for (extension, device_id) in [
            ("vhd", vhd::VIRTUAL_STORAGE_TYPE_DEVICE_VHD),
            ("vhdx", vhd::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX),
        ] {
            let path = fixture.0.join(format!("fixture.{extension}"));
            let path = path.to_str().unwrap();
            let encoded = wide(path, "fixture image", MAX_PATH_UNITS).unwrap();
            let storage_type = vhd::VIRTUAL_STORAGE_TYPE {
                DeviceId: device_id,
                VendorId: vhd::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
            };
            let parameters = vhd::CREATE_VIRTUAL_DISK_PARAMETERS {
                Version: vhd::CREATE_VIRTUAL_DISK_VERSION_1,
                Anonymous: vhd::CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                    Version1: vhd::CREATE_VIRTUAL_DISK_PARAMETERS_0_0 {
                        MaximumSize: 16 * 1024 * 1024,
                        SectorSizeInBytes: 512,
                        ..Default::default()
                    },
                },
            };
            let mut handle = HANDLE::default();
            // Creating a private image file does not attach it or change host volumes.
            let code = unsafe {
                vhd::CreateVirtualDisk(
                    &storage_type,
                    PCWSTR(encoded.as_ptr()),
                    vhd::VIRTUAL_DISK_ACCESS_GET_INFO,
                    None,
                    vhd::CREATE_VIRTUAL_DISK_FLAG_NONE,
                    0,
                    &parameters,
                    None,
                    &mut handle,
                )
            };
            if [
                foundation::ERROR_ACCESS_DENIED,
                foundation::ERROR_PRIVILEGE_NOT_HELD,
                foundation::ERROR_VIRTDISK_PROVIDER_NOT_FOUND,
            ]
            .contains(&code)
            {
                eprintln!(
                    "Native {extension} fixture unavailable: {}",
                    win32_error("CreateVirtualDisk", code.0)
                );
                return;
            }
            check_win32("CreateVirtualDisk", code.0).unwrap();
            drop(OwnedHandle(handle));
            let context = context();
            let result = virtual_disk(
                &VirtualDiskInput {
                    image_path: path.into(),
                    expected_identity: None,
                    ..image_input(VirtualDiskAction::Inspect)
                },
                &context,
            )
            .unwrap();
            assert_eq!(result["image_type"], extension);
            assert_eq!(result["observation"]["attached"], false);
            assert_eq!(result["observation"]["physical_path"], Value::Null);
            assert_eq!(
                result["observation"]["information"]["size"]["virtual_bytes"],
                16 * 1024 * 1024
            );
            let identity: ImageIdentity =
                serde_json::from_value(result["image_identity"].clone()).unwrap();
            validate_image_identity(&identity).unwrap();
            assert_eq!(result["backing_file_opened_read_only"], true);
            assert!(!context.mutation_started());
        }
    }

    #[test]
    fn administration_storage_native_volume_enumeration_is_read_only() {
        let context = context();
        let result = list_volumes(
            &VolumeListInput {
                limit: Some(4),
                timeout_ms: None,
            },
            &context,
        )
        .unwrap();
        let volumes = result["volumes"].as_array().unwrap();
        assert!(volumes.len() <= 4);
        for volume in volumes {
            assert!(volume_guid_path(volume["volume_guid_path"].as_str().unwrap()).is_ok());
            assert!(volume["errors"].is_array());
            assert!(volume.get("mount_paths").is_some());
            assert!(volume.get("capacity").is_some());
        }
        assert!(!context.mutation_started());
    }
}
