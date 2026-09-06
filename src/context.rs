mod storage;

use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{LocalFree, FILETIME, HANDLE, HLOCAL},
        Security::{
            Authorization::ConvertSidToStringSidW, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, LookupAccountSidW, TokenAppContainerSid, TokenCapabilities,
            TokenElevation, TokenElevationType, TokenGroups, TokenHasRestrictions,
            TokenIntegrityLevel, TokenIsAppContainer, TokenPrivileges, TokenRestrictedSids,
            TokenSessionId, TokenStatistics, TokenUIAccess, TokenUser, PSID, SID_NAME_USE,
            TOKEN_APPCONTAINER_INFORMATION, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
            TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
        },
        System::{
            RemoteDesktop::WTSGetActiveConsoleSessionId,
            StationsAndDesktops::{
                CloseDesktop, GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW,
                OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, UOI_NAME,
            },
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessTimes,
                OpenProcessToken,
            },
        },
    },
};

pub(crate) use storage::{validate_name, verify_owner_only, SecurityDescriptor};

pub(crate) fn raw(handle: &impl AsRawHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

/// The caller transfers a valid, uniquely owned CloseHandle-compatible handle.
pub(crate) unsafe fn own(handle: HANDLE) -> OwnedHandle {
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Windows clock predates the Unix epoch")
        .as_millis() as u64
}

pub(crate) fn process_creation_time(process: HANDLE) -> anyhow::Result<u64> {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user)? };
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

pub(crate) fn process_token(process: HANDLE) -> anyhow::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token)?;
        Ok(own(token))
    }
}

fn token_value<T: Default>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<T> {
    let mut value = T::default();
    let mut returned = 0;
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some((&mut value as *mut T).cast()),
            std::mem::size_of::<T>() as u32,
            &mut returned,
        )?;
    }
    Ok(value)
}

// Token structures contain pointers, so byte-aligned Vec<u8> storage is insufficient.
fn token_buffer(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<Vec<usize>> {
    let mut size = 0;
    let probe = unsafe { GetTokenInformation(token, class, None, 0, &mut size) };
    if size == 0 || size > 1_048_576 {
        probe?;
        bail!("invalid Windows token information size: {size}");
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        )?;
    }
    Ok(buffer)
}

pub(crate) fn sid_string(sid: PSID) -> anyhow::Result<String> {
    let mut value = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut value)?;
        let result = value.to_string().context("invalid SID string");
        LocalFree(Some(HLOCAL(value.0.cast())));
        result
    }
}

fn account_name(sid: PSID) -> anyhow::Result<String> {
    let (mut name_len, mut domain_len) = (0, 0);
    let mut kind = SID_NAME_USE::default();
    let probe = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    if name_len == 0 || name_len > 32768 || domain_len > 32768 {
        probe?;
        bail!("Windows returned an invalid account name length");
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )?;
    }
    let name = String::from_utf16(&name[..name_len as usize])?;
    let domain = String::from_utf16(&domain[..domain_len as usize])?;
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

fn token_groups(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
) -> anyhow::Result<Vec<(String, u32)>> {
    let data = token_buffer(token, class)?;
    let groups = unsafe { &*data.as_ptr().cast::<TOKEN_GROUPS>() };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    let mut result = Vec::with_capacity(entries.len());
    for group in entries {
        result.push((sid_string(group.Sid)?, group.Attributes));
    }
    result.sort_unstable();
    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenContext {
    pub user_sid: String,
    pub account: Option<String>,
    pub account_lookup_error: Option<String>,
    pub session_id: u32,
    pub logon_id: String,
    pub integrity_rid: u32,
    pub integrity: String,
    pub elevated: bool,
    pub elevation_type: u32,
    pub ui_access: bool,
    pub restricted: bool,
    pub app_container: bool,
    pub app_container_sid: Option<String>,
    pub capabilities: Vec<(String, u32)>,
    pub groups: Vec<(String, u32)>,
    pub restricted_sids: Vec<(String, u32)>,
    pub privileges: Vec<(u64, u32)>,
}

impl TokenContext {
    pub(crate) fn read(token: HANDLE) -> anyhow::Result<Self> {
        let user_data = token_buffer(token, TokenUser)?;
        let user = unsafe { &*user_data.as_ptr().cast::<TOKEN_USER>() };
        let user_sid = sid_string(user.User.Sid)?;
        let (account, account_lookup_error) = match account_name(user.User.Sid) {
            Ok(name) => (Some(name), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        let integrity_data = token_buffer(token, TokenIntegrityLevel)?;
        let label = unsafe { &*integrity_data.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        let integrity_rid = unsafe {
            let count = *GetSidSubAuthorityCount(label.Label.Sid);
            anyhow::ensure!(count != 0, "Windows returned an empty integrity SID");
            *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1))
        };
        let stats: TOKEN_STATISTICS = token_value(token, TokenStatistics)?;
        let app_container = token_value::<u32>(token, TokenIsAppContainer)? != 0;
        let app_container_sid = if app_container {
            let data = token_buffer(token, TokenAppContainerSid)?;
            let app = unsafe { &*data.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>() };
            Some(sid_string(app.TokenAppContainer)?)
        } else {
            None
        };
        let privilege_data = token_buffer(token, TokenPrivileges)?;
        let privileges = unsafe { &*privilege_data.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        let entries = unsafe {
            std::slice::from_raw_parts(
                privileges.Privileges.as_ptr(),
                privileges.PrivilegeCount as usize,
            )
        };
        let mut privileges: Vec<_> = entries
            .iter()
            .map(|entry| {
                (
                    ((entry.Luid.HighPart as u64) << 32) | u64::from(entry.Luid.LowPart),
                    entry.Attributes.0,
                )
            })
            .collect();
        privileges.sort_unstable();
        Ok(Self {
            user_sid,
            account,
            account_lookup_error,
            session_id: token_value(token, TokenSessionId)?,
            logon_id: format!(
                "{:08x}{:08x}",
                stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart
            ),
            integrity_rid,
            integrity: match integrity_rid {
                0..4096 => "untrusted",
                4096..8192 => "low",
                8192..8448 => "medium",
                8448..12288 => "medium_plus",
                12288..16384 => "high",
                16384..20480 => "system",
                _ => "protected_or_higher",
            }
            .into(),
            elevated: token_value::<TOKEN_ELEVATION>(token, TokenElevation)?.TokenIsElevated != 0,
            elevation_type: token_value(token, TokenElevationType)?,
            ui_access: token_value::<u32>(token, TokenUIAccess)? != 0,
            restricted: token_value::<u32>(token, TokenHasRestrictions)? != 0,
            app_container,
            app_container_sid,
            capabilities: token_groups(token, TokenCapabilities)?,
            groups: token_groups(token, TokenGroups)?,
            restricted_sids: token_groups(token, TokenRestrictedSids)?,
            privileges,
        })
    }

    pub fn current() -> anyhow::Result<Self> {
        let token = process_token(unsafe { GetCurrentProcess() })?;
        Self::read(raw(&token))
    }

    pub(crate) fn require_same_access(&self, peer: &Self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.user_sid == peer.user_sid
                && self.session_id == peer.session_id
                && self.logon_id == peer.logon_id
                && self.integrity_rid == peer.integrity_rid
                && self.elevated == peer.elevated
                && self.elevation_type == peer.elevation_type
                && self.ui_access == peer.ui_access
                && self.restricted == peer.restricted
                && self.app_container == peer.app_container
                && self.app_container_sid == peer.app_container_sid
                && self.capabilities == peer.capabilities
                && self.groups == peer.groups
                && self.restricted_sids == peer.restricted_sids
                && self.privileges == peer.privileges,
            "local host access context mismatch: SID, logon, session, integrity, elevation, groups and privileges must match; the bridge never elevates"
        );
        Ok(())
    }

    pub(crate) fn endpoint_key(&self, name: &str) -> anyhow::Result<String> {
        validate_name(name)?;
        Ok(format!(
            "{}-{}-{}-{}-{name}",
            self.user_sid, self.session_id, self.logon_id, self.integrity_rid
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopContext {
    pub selected_session_id: u32,
    pub active_console_session_id: Option<u32>,
    pub window_station: Option<String>,
    pub thread_desktop: Option<String>,
    pub input_desktop: Option<String>,
    pub matches_input_desktop: bool,
    pub errors: Vec<String>,
    pub selection: String,
    pub limitations: Vec<String>,
}

fn object_name(handle: HANDLE) -> anyhow::Result<String> {
    let mut name = [0u16; 512];
    let mut returned = 0;
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            std::mem::size_of_val(&name) as u32,
            Some(&mut returned),
        )?;
    }
    let length = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Ok(String::from_utf16(&name[..length])?)
}

impl DesktopContext {
    fn current(session_id: u32) -> Self {
        let mut errors = Vec::new();
        let mut describe = |label: &str, result: anyhow::Result<String>| match result {
            Ok(name) => Some(name),
            Err(error) => {
                errors.push(format!("{label}: {error:#}"));
                None
            }
        };
        let station = unsafe { GetProcessWindowStation() }
            .map_err(anyhow::Error::from)
            .and_then(|station| object_name(HANDLE(station.0)));
        let window_station = describe("window_station", station);
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
            .map_err(anyhow::Error::from)
            .and_then(|desktop| object_name(HANDLE(desktop.0)));
        let thread_desktop = describe("thread_desktop", desktop);
        let input =
            unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
                .map_err(anyhow::Error::from)
                .and_then(|desktop| {
                    let name = object_name(HANDLE(desktop.0));
                    unsafe { CloseDesktop(desktop)? };
                    name
                });
        let input_desktop = describe("input_desktop", input);
        let active = unsafe { WTSGetActiveConsoleSessionId() };
        Self {
            selected_session_id: session_id,
            active_console_session_id: (active != u32::MAX).then_some(active),
            matches_input_desktop: session_id != 0
                && window_station.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("WinSta0"))
                && thread_desktop.is_some()
                && thread_desktop == input_desktop,
            window_station,
            thread_desktop,
            input_desktop,
            errors,
            selection: "current process token, session and thread desktop; no implicit session switching".into(),
            limitations: vec![
                "Session 0 cannot directly control another user's interactive desktop".into(),
                "Administrator and SYSTEM do not imply access to secure desktops or protected processes".into(),
                "Per-user paths and settings belong to the reported token account, not an inferred pre-elevation user".into(),
                "Matching the input desktop does not establish that an application accepted an action".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub pid: u32,
    pub process_creation_time: u64,
    pub architecture: String,
    pub token: TokenContext,
    pub desktop: DesktopContext,
}

impl ExecutionContext {
    pub fn current() -> anyhow::Result<Self> {
        let token = TokenContext::current()?;
        Ok(Self {
            pid: unsafe { GetCurrentProcessId() },
            process_creation_time: process_creation_time(unsafe { GetCurrentProcess() })?,
            architecture: std::env::consts::ARCH.into(),
            desktop: DesktopContext::current(token.session_id),
            token,
        })
    }
}

#[derive(Clone)]
pub struct RecoveryStore {
    directory: Arc<storage::StateDirectory>,
}

impl RecoveryStore {
    pub fn open(scope: &str) -> anyhow::Result<Self> {
        let token = TokenContext::current()?;
        Ok(Self {
            directory: Arc::new(storage::StateDirectory::recovery(&token, scope)?),
        })
    }

    #[cfg(test)]
    pub fn at(path: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(path.is_absolute(), "recovery directory must be absolute");
        Ok(Self {
            directory: Arc::new(storage::StateDirectory::at(
                &TokenContext::current()?,
                path,
            )?),
        })
    }

    #[cfg(test)]
    pub fn state_directory(&self) -> &Path {
        self.directory.path()
    }
    pub fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.directory.list(prefix)
    }
    pub fn read_checkpoint(&self, name: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        self.directory.read(name, max_bytes)
    }
    pub fn write_checkpoint(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        self.directory.write(name, data)
    }
    pub fn remove_checkpoint(&self, name: &str) -> anyhow::Result<bool> {
        self.directory.remove(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceMode {
    ConnectionOwned,
    PersistentHost,
}

#[derive(Clone, Serialize)]
pub struct PersistenceContext {
    pub mode: PersistenceMode,
    pub epoch: String,
    pub started_at_ms: u64,
    pub execution: ExecutionContext,
    #[serde(skip)]
    directory: Option<Arc<storage::StateDirectory>>,
}

impl PersistenceContext {
    pub fn connection_owned() -> anyhow::Result<Self> {
        Ok(Self {
            mode: PersistenceMode::ConnectionOwned,
            epoch: uuid::Uuid::new_v4().to_string(),
            started_at_ms: now_ms(),
            execution: ExecutionContext::current()?,
            directory: None,
        })
    }

    pub(crate) fn persistent_host(
        name: &str,
        state_directory: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let mut context = Self::connection_owned()?;
        let directory = match state_directory {
            Some(path) => {
                anyhow::ensure!(
                    path.is_absolute(),
                    "--host-state-dir must be an absolute local directory path"
                );
                storage::StateDirectory::at(&context.execution.token, path)?
            }
            None => storage::StateDirectory::host(&context.execution.token, name)?,
        };
        context.mode = PersistenceMode::PersistentHost;
        context.directory = Some(Arc::new(directory.lock_for_host()?));
        Ok(context)
    }

    pub fn is_persistent(&self) -> bool {
        self.mode == PersistenceMode::PersistentHost
    }

    pub fn state_directory(&self) -> Option<&Path> {
        self.directory.as_ref().map(|directory| directory.path())
    }

    pub fn read_checkpoint(&self, name: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        self.directory
            .as_ref()
            .context("checkpoints require an explicitly started local host")?
            .read(name, max_bytes)
    }

    pub fn write_checkpoint(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        self.directory
            .as_ref()
            .context("checkpoints require an explicitly started local host")?
            .write(name, data)
    }

    #[cfg(test)]
    pub(crate) fn test_host(path: &Path) -> anyhow::Result<Self> {
        Self::persistent_host("fixture", Some(path))
    }
}
