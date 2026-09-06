use std::mem::size_of;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use windows::core::{w, BOOL, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::SystemInformation::*;
use windows::Win32::System::Threading::*;

pub(super) struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            if let Err(error) = unsafe { CloseHandle(self.0) } {
                tracing::error!(%error, "diagnostics CloseHandle failed");
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Deadline {
    end: Instant,
    canceled: Arc<AtomicBool>,
}

impl Deadline {
    pub fn new(timeout_ms: u64) -> Result<Self> {
        if !(1..=120_000).contains(&timeout_ms) {
            bail!("timeout_ms must be between 1 and 120000");
        }
        Ok(Self {
            end: Instant::now() + Duration::from_millis(timeout_ms),
            canceled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    pub fn check(&self) -> Result<()> {
        if self.canceled.load(Ordering::Acquire) {
            bail!("diagnostic operation canceled");
        }
        if Instant::now() >= self.end {
            bail!("diagnostic operation timed out");
        }
        Ok(())
    }

    pub fn remaining(&self) -> Duration {
        self.end.saturating_duration_since(Instant::now())
    }
}

pub(super) struct CancelOnDrop(pub Deadline);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Privileges {
    pub elevated: Option<bool>,
    pub debug_privilege_enabled: Option<bool>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    // FILETIME is emitted as a string so JavaScript clients do not round it.
    pub creation_time: String,
    pub session_id: u32,
    pub architecture: String,
    pub native_architecture: String,
    pub executable: Option<String>,
    pub protection_level: Option<u32>,
    pub target_privileges: Privileges,
    pub caller_privileges: Privileges,
    pub limitations: Vec<String>,
}

pub(super) struct Process {
    pub handle: Handle,
    pub identity: ProcessIdentity,
    pub created: u64,
    pub machine: IMAGE_FILE_MACHINE,
}

pub(super) fn filetime(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

pub(super) fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(super) fn native_error(operation: &str, error: windows::core::Error) -> anyhow::Error {
    anyhow!(
        "{operation}: {error}. Windows access rights, token privileges, architecture, \
         and protected-process restrictions apply; elevation does not bypass PPL or secure desktops."
    )
}

pub(super) fn win32_result(operation: &str, status: u32) -> Result<()> {
    if status == ERROR_SUCCESS.0 {
        Ok(())
    } else {
        Err(native_error(
            operation,
            windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(status)),
        ))
    }
}

pub(super) fn validate_creation(actual: u64, expected: Option<u64>) -> Result<()> {
    if let Some(expected) = expected {
        if actual != expected {
            bail!("stale process identity: expected creation_time {expected}, observed {actual}; PID may have been reused");
        }
    }
    Ok(())
}

pub(super) fn machine_name(machine: IMAGE_FILE_MACHINE) -> String {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => "x64".into(),
        IMAGE_FILE_MACHINE_I386 => "x86".into(),
        IMAGE_FILE_MACHINE_ARM64 => "arm64".into(),
        other => format!("machine_0x{:04x}", other.0),
    }
}

pub(super) fn context_compatible(host: &str, target: &str) -> bool {
    matches!(
        (host, target),
        ("x86_64", "x64" | "x86") | ("x86", "x86") | ("aarch64", "arm64")
    )
}

fn query_privileges(process: HANDLE) -> Result<Privileges> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token)?;
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )?;
        let mut luid = LUID::default();
        LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid)?;
        let mut privileges = PRIVILEGE_SET {
            PrivilegeCount: 1,
            Control: 1,
            Privilege: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut enabled = BOOL::default();
        PrivilegeCheck(token.0, &mut privileges, &mut enabled)?;
        Ok(Privileges {
            elevated: Some(elevation.TokenIsElevated != 0),
            debug_privilege_enabled: Some(enabled.as_bool()),
            error: None,
        })
    }
}

fn privileges(process: HANDLE) -> Privileges {
    query_privileges(process).unwrap_or_else(|error| Privileges {
        elevated: None,
        debug_privilege_enabled: None,
        error: Some(format!("token information unavailable: {error}")),
    })
}

impl Process {
    pub fn open(pid: u32, expected: Option<u64>, access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        if pid == 0 {
            bail!("PID 0 is not an inspectable user-mode process");
        }
        let handle = unsafe {
            OpenProcess(
                access | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map_err(|error| native_error(&format!("OpenProcess({pid})"), error))?;
        Self::from_handle(Handle(handle), expected)
    }

    pub fn from_handle(handle: Handle, expected: Option<u64>) -> Result<Self> {
        unsafe {
            let pid = GetProcessId(handle.0);
            if pid == 0 {
                return Err(native_error(
                    "GetProcessId",
                    windows::core::Error::from_thread(),
                ));
            }
            let (mut created, mut exited, mut kernel, mut user) = Default::default();
            GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user)?;
            let created = filetime(created);
            validate_creation(created, expected)?;
            let mut session_id = 0;
            ProcessIdToSessionId(pid, &mut session_id)?;
            let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            IsWow64Process2(handle.0, &mut process_machine, Some(&mut native_machine))
                .map_err(|error| native_error("IsWow64Process2", error))?;
            let machine = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
                native_machine
            } else {
                process_machine
            };
            let mut limitations = vec![
                "User-mode diagnostics do not grant access to protected processes, kernel memory, or secure desktops.".into(),
            ];
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            let executable = match QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_FORMAT(0),
                PWSTR(path.as_mut_ptr()),
                &mut length,
            ) {
                Ok(()) => Some(String::from_utf16_lossy(&path[..length as usize])),
                Err(error) => {
                    limitations.push(format!("executable path unavailable: {error}"));
                    None
                }
            };
            let mut protection = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
            let protection_level = match GetProcessInformation(
                handle.0,
                ProcessProtectionLevelInfo,
                (&mut protection as *mut PROCESS_PROTECTION_LEVEL_INFORMATION).cast(),
                size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
            ) {
                Ok(()) => Some(protection.ProtectionLevel.0),
                Err(error) => {
                    limitations.push(format!("protection level unavailable: {error}"));
                    None
                }
            };
            let identity = ProcessIdentity {
                pid,
                creation_time: created.to_string(),
                session_id,
                architecture: machine_name(machine),
                native_architecture: machine_name(native_machine),
                executable,
                protection_level,
                target_privileges: privileges(handle.0),
                caller_privileges: privileges(GetCurrentProcess()),
                limitations,
            };
            Ok(Self {
                handle,
                identity,
                created,
                machine,
            })
        }
    }

    pub fn ensure_alive(&self) -> Result<()> {
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => bail!("target process {} has exited", self.identity.pid),
            _ => Err(native_error(
                "WaitForSingleObject",
                windows::core::Error::from_thread(),
            )),
        }
    }

    pub fn ensure_external(&self) -> Result<()> {
        if self.identity.pid == unsafe { GetCurrentProcessId() } {
            bail!("suspending or debugging the MCP server itself is unavailable; use an external process to avoid deadlock");
        }
        self.ensure_alive()
    }

    pub fn ensure_context_supported(&self) -> Result<()> {
        if !context_compatible(std::env::consts::ARCH, &self.identity.architecture) {
            bail!("register/stack architecture unavailable: {} server cannot capture {} contexts; use a matching native build",
                std::env::consts::ARCH, self.identity.architecture);
        }
        Ok(())
    }
}

pub(super) fn thread_ids(
    process: &Process,
    limit: usize,
    deadline: &Deadline,
) -> Result<(Vec<u32>, bool)> {
    process.ensure_alive()?;
    let snapshot = Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?);
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut threads = Vec::new();
    let mut next = unsafe { Thread32First(snapshot.0, &mut entry) };
    loop {
        match next {
            Ok(()) => {}
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0) =>
            {
                break
            }
            Err(error) => return Err(native_error("ToolHelp thread enumeration", error)),
        }
        deadline.check()?;
        if entry.th32OwnerProcessID == process.identity.pid {
            if threads.len() == limit {
                return Ok((threads, true));
            }
            threads.push(entry.th32ThreadID);
        }
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        next = unsafe { Thread32Next(snapshot.0, &mut entry) };
    }
    Ok((threads, false))
}

pub(super) fn open_thread(
    process: &Process,
    tid: u32,
    access: THREAD_ACCESS_RIGHTS,
) -> Result<(Handle, u64)> {
    process.ensure_alive()?;
    let handle = Handle(
        unsafe { OpenThread(access | THREAD_QUERY_INFORMATION, false, tid) }
            .map_err(|error| native_error("OpenThread", error))?,
    );
    unsafe {
        if GetProcessIdOfThread(handle.0) != process.identity.pid {
            bail!(
                "thread {tid} no longer belongs to target process; thread ID may have been reused"
            );
        }
        let (mut created, mut exited, mut kernel, mut user) = Default::default();
        GetThreadTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user)
            .context("GetThreadTimes")?;
        let created = filetime(created);
        if created < process.created {
            bail!("thread identity predates target process");
        }
        Ok((handle, created))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_pid_reuse() {
        assert!(validate_creation(123, Some(122)).is_err());
        assert!(validate_creation(123, Some(123)).is_ok());
    }

    #[test]
    fn architecture_matrix_is_explicit() {
        assert!(context_compatible("x86_64", "x86"));
        assert!(context_compatible("x86_64", "x64"));
        assert!(!context_compatible("x86", "x64"));
        assert!(!context_compatible("x86_64", "arm64"));
        assert!(context_compatible("aarch64", "arm64"));
    }

    #[test]
    fn cancellation_is_shared_and_deadlines_are_bounded() {
        let deadline = Deadline::new(100).unwrap();
        let copy = deadline.clone();
        deadline.cancel();
        assert!(copy.check().unwrap_err().to_string().contains("canceled"));
        assert!(Deadline::new(0).is_err());
        assert!(Deadline::new(120001).is_err());
    }

    #[test]
    fn unavailable_access_reports_real_windows_limits() {
        let error = native_error(
            "OpenProcess",
            windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
                ERROR_ACCESS_DENIED.0,
            )),
        )
        .to_string();
        assert!(error.contains("protected-process"));
        assert!(error.contains("PPL"));
        assert!(error.contains("secure desktops"));
    }
}
