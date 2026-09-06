use super::admin_common::*;
use anyhow::{ensure, Context, Result};
use base64::Engine;
use rmcp::schemars;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use windows::core::{s, w, PCWSTR, PSTR, PWSTR};
use windows::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, HMODULE,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Registry::*;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

const MAX_JOB_TIMEOUT_MS: u64 = 86_400_000;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VirtualizationQuery {
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WslTarget {
    /// Registration GUID from wsl_instances, scoped to expected_user_sid.
    pub registration_id: String,
    /// Expected exact name, checked again before invoking wsl.exe.
    pub expected_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WslAction {
    Status,
    Start {
        target: WslTarget,
        /// The owned job holds WSL open using /bin/sleep for this duration, 1..86400.
        #[serde(deserialize_with = "crate::coerce::num")]
        keep_alive_seconds: u32,
    },
    Stop {
        target: WslTarget,
    },
    Export {
        target: WslTarget,
        archive_path: String,
    },
    Import {
        name: String,
        install_directory: String,
        archive_path: String,
        #[serde(deserialize_with = "crate::coerce::num")]
        version: u32,
    },
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WslInput {
    /// Must match the actual server token, even when the server is elevated.
    pub expected_user_sid: String,
    #[serde(flatten)]
    pub operation: WslAction,
    /// Job deadline, 100..86400000 milliseconds, default 300000 except start's keepalive.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    /// Dispatch/validation deadline, 100..300000 milliseconds, default 15000.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub request_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum HyperVAction {
    Start {
        vm_id: String,
    },
    Stop {
        vm_id: String,
    },
    /// Immediate power removal, only when explicitly selected.
    PowerOff {
        vm_id: String,
    },
    Save {
        vm_id: String,
    },
    Export {
        vm_id: String,
        destination: String,
    },
    /// Register an existing .vmcx in place. Does not copy files or generate a new identity.
    Import {
        configuration_path: String,
    },
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HyperVInput {
    #[serde(flatten)]
    pub operation: HyperVAction,
    /// Owned provider job deadline, 100..86400000 milliseconds, default 300000.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
    /// Dispatch/validation deadline, 100..300000 milliseconds, default 15000.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub request_timeout_ms: Option<u64>,
}

pub struct VirtualizationJob {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub operation: &'static str,
    pub target: Value,
    pub caveat: &'static str,
}

fn job_timeout(timeout_ms: u64) -> Result<u64> {
    ensure!(
        (100..=MAX_JOB_TIMEOUT_MS).contains(&timeout_ms),
        "Job timeout_ms must be 100..={MAX_JOB_TIMEOUT_MS}"
    );
    Ok(timeout_ms)
}

struct RegistryKey(HKEY);

impl RegistryKey {
    fn open(parent: HKEY, path: &str) -> Result<Option<Self>> {
        let path = wide(path, "registry path", 1024)?;
        let mut handle = HKEY::default();
        let code = unsafe {
            RegOpenKeyExW(
                parent,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ | KEY_WOW64_64KEY,
                &mut handle,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check_win32("RegOpenKeyExW (WSL registrations)", code.0)?;
        Ok(Some(Self(handle)))
    }

    fn string(&self, name: &str) -> Result<Option<String>> {
        let name = wide(name, "value name", 256)?;
        let mut size = 0u32;
        let code = unsafe {
            RegGetValueW(
                self.0,
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut size),
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check_win32("RegGetValueW (WSL string size)", code.0)?;
        ensure!(
            size > 0 && size <= 65536 && size.is_multiple_of(2),
            "Invalid WSL registry string size"
        );
        let mut value = vec![0u16; size as usize / 2];
        let code = unsafe {
            RegGetValueW(
                self.0,
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(value.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        check_win32("RegGetValueW (WSL string)", code.0)?;
        Ok(Some(super::wchar_to_string(&value)))
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        let code = unsafe { RegCloseKey(self.0) };
        if code.0 != 0 {
            tracing::warn!(code = code.0, "Closing WSL registry key failed");
        }
    }
}

type WslRegistered = unsafe extern "system" fn(PCWSTR) -> windows::core::BOOL;
type WslConfiguration = unsafe extern "system" fn(
    PCWSTR,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut *mut PSTR,
    *mut u32,
) -> windows::core::HRESULT;

struct WslApi {
    module: HMODULE,
    registered: WslRegistered,
    configuration: WslConfiguration,
}

impl Drop for WslApi {
    fn drop(&mut self) {
        if let Err(error) = unsafe { FreeLibrary(self.module) } {
            tracing::warn!(%error, "Releasing WSL API library failed");
        }
    }
}

impl WslApi {
    fn load() -> Result<Self> {
        unsafe {
            let module = LoadLibraryExW(w!("wslapi.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .map_err(|error| {
                    hresult_error(
                        "LoadLibraryExW (WSL API unavailable; install/enable WSL explicitly)",
                        error,
                    )
                })?;
            let registered = GetProcAddress(module, s!("WslIsDistributionRegistered"));
            let configuration = GetProcAddress(module, s!("WslGetDistributionConfiguration"));
            match (registered, configuration) {
                (Some(registered), Some(configuration)) => Ok(Self {
                    module,
                    // The system DLL exports these documented WSL API signatures.
                    registered: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WslRegistered,
                    >(registered),
                    configuration: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WslConfiguration,
                    >(configuration),
                }),
                _ => {
                    let code = windows::Win32::Foundation::ERROR_PROC_NOT_FOUND.0;
                    if let Err(error) = FreeLibrary(module) {
                        tracing::warn!(%error, "Releasing incomplete WSL library failed");
                    }
                    Err(win32_error(
                        "GetProcAddress (required WSL API missing)",
                        code,
                    ))
                }
            }
        }
    }

    fn registered(&self, name: &str) -> Result<bool> {
        let name = wide(name, "distribution name", 256)?;
        Ok(unsafe { (self.registered)(PCWSTR(name.as_ptr())).as_bool() })
    }

    fn configuration(&self, name: &str) -> Result<Value> {
        let name = wide(name, "distribution name", 256)?;
        let mut version = 0;
        let mut uid = 0;
        let mut flags = 0;
        let mut environment = std::ptr::null_mut();
        let mut environment_count = 0;
        unsafe {
            let result = (self.configuration)(
                PCWSTR(name.as_ptr()),
                &mut version,
                &mut uid,
                &mut flags,
                &mut environment,
                &mut environment_count,
            );
            if result.is_err() {
                return Err(hresult_error(
                    "WslGetDistributionConfiguration",
                    windows::core::Error::from_hresult(result),
                ));
            }
            if !environment.is_null() {
                // Environment values can contain credentials. Free them without copying or exposing them.
                for index in 0..environment_count as usize {
                    CoTaskMemFree(Some((*environment.add(index)).0.cast()));
                }
                CoTaskMemFree(Some(environment.cast()));
            }
        }
        Ok(json!({
            "version": version, "default_uid": uid, "flags": flags,
            "running": null, "running_state_source": "not provided by WslGetDistributionConfiguration",
            "environment_included": false,
        }))
    }
}

pub fn system_directory() -> Result<PathBuf> {
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) };
    if length == 0 {
        return Err(win32_error("GetSystemDirectoryW", unsafe {
            GetLastError().0
        }));
    }
    ensure!(
        (length as usize) < buffer.len(),
        "System directory exceeds buffer"
    );
    Ok(PathBuf::from(String::from_utf16(
        &buffer[..length as usize],
    )?))
}

fn wsl_root() -> Result<Option<RegistryKey>> {
    RegistryKey::open(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Lxss",
    )
}

pub fn wsl_inventory(input: &VirtualizationQuery, context: &AdminContext) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    context.check()?;
    let user = current_user_sid()?;
    let utility = system_directory()?.join("wsl.exe");
    let api = WslApi::load();
    let root = wsl_root()?;
    let mut distributions = Vec::new();
    let mut truncated = false;
    if let Some(root) = root {
        for index in 0..=MAX_RESULTS {
            context.check()?;
            let mut name = [0u16; 256];
            let mut length = name.len() as u32;
            let code = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }
            if code == ERROR_MORE_DATA {
                return Err(win32_error(
                    "RegEnumKeyExW (WSL registration key too long)",
                    code.0,
                ));
            }
            check_win32("RegEnumKeyExW (WSL registrations)", code.0)?;
            if distributions.len() >= limit {
                truncated = true;
                break;
            }
            let key_name = String::from_utf16(&name[..length as usize])?;
            let id = guid(&key_name, "WSL registration key")?;
            let key = RegistryKey::open(root.0, &key_name)?
                .context("WSL registration disappeared during enumeration")?;
            let name = key
                .string("DistributionName")?
                .context("WSL registration has no DistributionName")?;
            let configuration = match &api {
                Ok(api) => match api.configuration(&name) {
                    Ok(configuration) => configuration,
                    Err(error) => failure(&error, context),
                },
                Err(error) => failure(error, context),
            };
            distributions.push(json!({
                "registration_id": guid_string(id),
                "name": name,
                "base_path": key.string("BasePath")?,
                "configuration": configuration,
            }));
        }
    }
    Ok(json!({
        "user_sid": user,
        "utility_present": utility.is_file(),
        "api_available": api.is_ok(),
        "api_error": api.as_ref().err().map(|error| failure(error, context)),
        "runtime_readiness": "Use the status action for an owned wsl.exe --status probe; DLL presence alone does not prove WSL is enabled.",
        "distributions": distributions, "truncated": truncated,
        "features_installed_or_enabled": false,
    }))
}

fn resolve_wsl(target: &WslTarget, api: &WslApi) -> Result<String> {
    let id = guid(&target.registration_id, "WSL registration GUID")?;
    validate_distribution_name(&target.expected_name)?;
    let root = wsl_root()?.context("This user has no WSL registrations")?;
    let key = RegistryKey::open(root.0, &format!("{{{}}}", guid_string(id)))?
        .context("WSL registration no longer exists for this user")?;
    let name = key
        .string("DistributionName")?
        .context("WSL registration has no name")?;
    ensure!(
        name == target.expected_name,
        "WSL registration name changed; no operation was started"
    );
    ensure!(
        api.registered(&name)?,
        "WSL API does not recognize this registration; no operation was started"
    );
    Ok(name)
}

fn validate_distribution_name(name: &str) -> Result<()> {
    text(name, "distribution name", 256)?;
    ensure!(
        !name.starts_with('-') && !name.contains(['\\', '/', '\r', '\n']),
        "Distribution name must not start with '-' or contain path separators or line breaks"
    );
    Ok(())
}

fn existing_file(value: &str, field: &str) -> Result<PathBuf> {
    let path = absolute_path(value, field)?;
    ensure!(path.is_file(), "{field} must identify an existing file");
    Ok(PathBuf::from(external_path(&path.canonicalize()?)?))
}

fn external_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .context("Path cannot be represented as UTF-8")?;
    if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        return Ok(format!(r"\\{unc}"));
    }
    Ok(value.strip_prefix(r"\\?\").unwrap_or(value).to_owned())
}

fn new_path(value: &str, field: &str) -> Result<PathBuf> {
    let path = absolute_path(value, field)?;
    ensure!(
        !path.try_exists()?,
        "{field} already exists; overwriting is not implicit"
    );
    ensure!(
        path.parent().is_some_and(Path::is_dir),
        "{field} requires an existing parent directory"
    );
    Ok(path)
}

pub fn wsl_job(input: &WslInput, context: &AdminContext) -> Result<VirtualizationJob> {
    context.check()?;
    let user = require_user(Some(&input.expected_user_sid))?;
    let program = system_directory()?.join("wsl.exe");
    ensure!(
        program.is_file(),
        "wsl.exe is unavailable; install WSL explicitly before managing distributions"
    );
    let mut timeout_ms = input.timeout_ms.unwrap_or(300_000);
    let (operation, args, target, caveat) = match &input.operation {
        WslAction::Status => (
            "wsl_status",
            vec!["--status".into()],
            json!({"user_sid": user}),
            "Status is the native utility result; no feature is installed or enabled.",
        ),
        WslAction::Start {
            target,
            keep_alive_seconds,
        } => {
            ensure!(
                (1..=86400).contains(keep_alive_seconds),
                "keep_alive_seconds must be 1..=86400"
            );
            let api = WslApi::load()?;
            let name = resolve_wsl(target, &api)?;
            if input.timeout_ms.is_none() {
                timeout_ms = ((*keep_alive_seconds as u64) * 1000 + 30_000).min(MAX_JOB_TIMEOUT_MS);
            }
            (
                "wsl_start",
                vec!["--distribution".into(), name.clone(), "--exec".into(), "/bin/sleep".into(), keep_alive_seconds.to_string()],
                json!({"registration_id": target.registration_id, "name": name, "user_sid": user}),
                "The job runs /bin/sleep to keep the distribution alive until the specified duration or job deadline. The distribution must provide /bin/sleep. Job cancellation is not distribution termination; use stop explicitly.",
            )
        }
        WslAction::Stop { target } => {
            let api = WslApi::load()?;
            let name = resolve_wsl(target, &api)?;
            (
                "wsl_stop", vec!["--terminate".into(), name.clone()],
                json!({"registration_id": target.registration_id, "name": name, "user_sid": user}),
                "Termination stops every process in the explicitly selected distribution, including processes not started by this server.",
            )
        }
        WslAction::Export {
            target,
            archive_path,
        } => {
            let api = WslApi::load()?;
            let name = resolve_wsl(target, &api)?;
            let path = new_path(archive_path, "archive_path")?;
            (
                "wsl_export", vec!["--export".into(), name.clone(), path.display().to_string()],
                json!({"registration_id": target.registration_id, "name": name, "archive_path": path, "user_sid": user}),
                "Exports a TAR archive. Deadline/cancellation can leave a partial archive; inspect it before retrying.",
            )
        }
        WslAction::Import {
            name,
            install_directory,
            archive_path,
            version,
        } => {
            validate_distribution_name(name)?;
            ensure!(*version == 1 || *version == 2, "WSL version must be 1 or 2");
            let api = WslApi::load()?;
            ensure!(
                !api.registered(name)?,
                "A WSL distribution with this name is already registered"
            );
            let destination = new_path(install_directory, "install_directory")?;
            let archive = existing_file(archive_path, "archive_path")?;
            (
                "wsl_import",
                vec!["--import".into(), name.clone(), destination.display().to_string(), archive.display().to_string(), "--version".into(), version.to_string()],
                json!({"name": name, "install_directory": destination, "archive_path": archive, "version": version, "user_sid": user}),
                "Imports a TAR archive into a new directory. Existing distributions are not replaced. Cancellation can leave partial files or registration; inspect before retrying.",
            )
        }
    };
    let timeout_ms = job_timeout(timeout_ms)?;
    Ok(VirtualizationJob {
        program: program.display().to_string(),
        args,
        timeout_ms,
        operation,
        target,
        caveat,
    })
}

const VM_FIELDS: &str =
    "Id,Name,State,Status,Generation,Version,ProcessorCount,MemoryAssigned,Uptime";

pub fn hyperv_inventory_script(input: &VirtualizationQuery) -> Result<String> {
    let limit = result_limit(input.limit)?;
    Ok(format!(
        "$ErrorActionPreference='Stop'; \
         $m=Get-Module -ListAvailable -Name Hyper-V | Select-Object -First 1; \
         if($null -eq $m) {{ [pscustomobject]@{{available=$false; prerequisite='Installed Hyper-V management PowerShell module'; features_installed_or_enabled=$false}}; return }}; \
         Import-Module Hyper-V -ErrorAction Stop; \
         $items=@(Get-VM -ErrorAction Stop | Select-Object -First {probe} | Select-Object {VM_FIELDS}); \
         [pscustomobject]@{{available=$true; scope='local_machine'; machines=@($items | Select-Object -First {limit}); truncated=($items.Count -gt {limit}); features_installed_or_enabled=$false}}",
        probe = limit + 1,
    ))
}

fn provider_path(path: &str, field: &str, must_exist: bool) -> Result<String> {
    ensure!(
        !path.contains(['*', '?', '[', ']']),
        "{field} must be an exact path without PowerShell wildcard syntax"
    );
    let path = if must_exist {
        existing_file(path, field)?
    } else {
        new_path(path, field)?
    };
    Ok(path.display().to_string())
}

fn vm_selection(id: &str) -> Result<String> {
    let id = guid_string(guid(id, "vm_id")?);
    Ok(format!(
        "$vm=Get-VM -Id ([Guid]{}) -ErrorAction Stop; ",
        ps_quote(&id)?
    ))
}

fn hyperv_action_script(input: &HyperVInput) -> Result<(String, &'static str, Value)> {
    let (action, operation, target) = match &input.operation {
        HyperVAction::Start { vm_id } => (
            format!(
                "{}$attempted=$true; Start-VM -VM $vm -ErrorAction Stop | Out-Null; ",
                vm_selection(vm_id)?
            ),
            "hyperv_start",
            json!({"vm_id": vm_id}),
        ),
        HyperVAction::Stop { vm_id } => (
            format!(
                "{}$attempted=$true; Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop; ",
                vm_selection(vm_id)?
            ),
            "hyperv_stop",
            json!({"vm_id": vm_id}),
        ),
        HyperVAction::PowerOff { vm_id } => (
            format!(
                "{}$attempted=$true; Stop-VM -VM $vm -TurnOff -Confirm:$false -ErrorAction Stop; ",
                vm_selection(vm_id)?
            ),
            "hyperv_power_off",
            json!({"vm_id": vm_id}),
        ),
        HyperVAction::Save { vm_id } => (
            format!(
                "{}$attempted=$true; Save-VM -VM $vm -ErrorAction Stop; ",
                vm_selection(vm_id)?
            ),
            "hyperv_save",
            json!({"vm_id": vm_id}),
        ),
        HyperVAction::Export { vm_id, destination } => {
            let path = provider_path(destination, "destination", false)?;
            let quoted = ps_quote(&path)?;
            (
                format!("{}if(Test-Path -LiteralPath {quoted}) {{ throw 'Export destination now exists; no export was attempted' }}; $attempted=$true; Export-VM -VM $vm -Path {quoted} -ErrorAction Stop; ", vm_selection(vm_id)?),
                "hyperv_export", json!({"vm_id": vm_id, "destination": path}),
            )
        }
        HyperVAction::Import { configuration_path } => {
            let path = provider_path(configuration_path, "configuration_path", true)?;
            ensure!(
                Path::new(&path)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("vmcx")),
                "configuration_path must be a .vmcx file"
            );
            (
                format!(
                    "$attempted=$true; $vm=Import-VM -Path {} -ErrorAction Stop; ",
                    ps_quote(&path)?
                ),
                "hyperv_import",
                json!({"configuration_path": path, "mode": "register_in_place"}),
            )
        }
    };
    Ok((
        format!(
            "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; \
             [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); \
             $attempted=$false; try {{ \
             if($null -eq (Get-Module -ListAvailable -Name Hyper-V | Select-Object -First 1)) {{ throw 'Hyper-V management module is not installed; install/enable it explicitly' }}; \
             Import-Module Hyper-V -ErrorAction Stop; {action} \
             $after=Get-VM -Id $vm.Id -ErrorAction Stop | Select-Object {VM_FIELDS}; \
             [pscustomobject]@{{accepted=$true; operation='{operation}'; observed_vm=$after; features_installed_or_enabled=$false}} | ConvertTo-Json -Depth 6 -Compress; \
             }} catch {{ \
             [pscustomobject]@{{accepted=$null; completed=$false; error=$_.Exception.Message; hresult=$_.Exception.HResult; error_id=$_.FullyQualifiedErrorId; outcome_may_have_changed=$attempted; automatically_retried=$false}} | ConvertTo-Json -Compress; exit 1 \
             }}"
        ),
        operation,
        target,
    ))
}

pub fn hyperv_job(input: &HyperVInput, context: &AdminContext) -> Result<VirtualizationJob> {
    context.check()?;
    let timeout_ms = job_timeout(input.timeout_ms.unwrap_or(300_000))?;
    let (script, operation, target) = hyperv_action_script(input)?;
    let program = system_directory()?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    ensure!(
        program.is_file(),
        "Windows PowerShell required by the installed Hyper-V module is unavailable"
    );
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    Ok(VirtualizationJob {
        program: program.display().to_string(),
        args: vec!["-NoProfile".into(), "-NoLogo".into(), "-NonInteractive".into(), "-EncodedCommand".into(), encoded],
        timeout_ms, operation, target,
        caveat: "Read the job exit status and its JSON stdout for the provider result. A deadline or cancellation may not cancel a Hyper-V operation already accepted by VMMS; query the VM before retrying.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn administration_virtualization_typed_args_and_coercion() {
        let input: WslInput = serde_json::from_value(json!({
            "expected_user_sid": "S-1-5-21-1", "action": "start",
            "target": {"registration_id": "00000000-0000-0000-0000-000000000001", "expected_name": "Ubuntu"},
            "keep_alive_seconds": "30", "timeout_ms": "31000"
        })).unwrap();
        assert_eq!(input.timeout_ms, Some(31000));
        assert!(validate_distribution_name("--install").is_err());
        assert!(validate_distribution_name("Ubuntu").is_ok());
        assert!(vm_selection("name*").is_err());
        let schema = serde_json::to_value(schemars::schema_for!(WslInput)).unwrap();
        assert!(schema.is_object());
    }

    #[test]
    fn administration_virtualization_job_deadlines_are_separate_from_dispatch() {
        assert_eq!(job_timeout(100).unwrap(), 100);
        assert_eq!(job_timeout(1_800_000).unwrap(), 1_800_000);
        assert_eq!(job_timeout(MAX_JOB_TIMEOUT_MS).unwrap(), MAX_JOB_TIMEOUT_MS);
        assert!(job_timeout(99).is_err());
        assert!(job_timeout(MAX_JOB_TIMEOUT_MS + 1).is_err());
        assert!(timeout_duration(Some(1_800_000)).is_err());
        let input: HyperVInput = serde_json::from_value(json!({
            "action": "export",
            "vm_id": "00000000-0000-0000-0000-000000000001",
            "destination": "C:\\exports\\new-vm",
            "timeout_ms": "1800000",
            "request_timeout_ms": "15000"
        }))
        .unwrap();
        assert_eq!(input.timeout_ms, Some(1_800_000));
        assert_eq!(input.request_timeout_ms, Some(15_000));
    }

    #[test]
    fn administration_hyperv_scripts_target_exact_ids_and_no_feature_install() {
        let input = HyperVInput {
            operation: HyperVAction::Stop {
                vm_id: "00000000-0000-0000-0000-000000000001".into(),
            },
            timeout_ms: None,
            request_timeout_ms: None,
        };
        let (script, _, _) = hyperv_action_script(&input).unwrap();
        assert!(script.contains("Get-VM -Id"));
        assert!(!script.contains("-TurnOff"));
        assert!(script.contains("exit 1"));
        assert!(!script.contains("Enable-WindowsOptionalFeature"));
        assert!(!script.contains("Add-Type"));
        assert!(hyperv_inventory_script(&VirtualizationQuery {
            limit: Some(0),
            timeout_ms: None
        })
        .is_err());
    }

    #[test]
    fn administration_provider_paths_do_not_introduce_wildcards() {
        assert_eq!(
            external_path(Path::new(r"\\?\C:\images\vm.vmcx")).unwrap(),
            r"C:\images\vm.vmcx"
        );
        assert_eq!(
            external_path(Path::new(r"\\?\UNC\server\share\vm.vmcx")).unwrap(),
            r"\\server\share\vm.vmcx"
        );
        assert!(provider_path(r"C:\images\[vm].vmcx", "path", true).is_err());
    }

    #[test]
    fn administration_wsl_read_only_inventory_and_missing_features() {
        let context = AdminContext::new(Duration::from_secs(10));
        let output = wsl_inventory(
            &VirtualizationQuery {
                limit: Some(1),
                timeout_ms: None,
            },
            &context,
        )
        .unwrap();
        assert!(output["distributions"].as_array().unwrap().len() <= 1);
        assert_eq!(output["features_installed_or_enabled"], false);
        if output["api_available"] == false {
            assert!(output["api_error"]["native_error"]["code"].is_number());
        }
        assert!(!context.mutation_started());
    }
}
