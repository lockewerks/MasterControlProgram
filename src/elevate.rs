//! # Self-Elevation via sudo for Windows
//!
//! We need admin. Half the tool surface is worthless without it: HKLM writes,
//! service control, opening handles to processes we do not own, and SendInput
//! into windows owned by elevated processes (UIPI blocks that from medium
//! integrity, which is why input tools silently no-op against Task Manager).
//!
//! ## Why we do not just ask Windows for it
//!
//! The obvious answers both break an stdio MCP server:
//!
//! - A manifest with `requestedExecutionLevel = requireAdministrator` does not
//!   self-elevate. `CreateProcess` never triggers UAC, it fails outright with
//!   ERROR_ELEVATION_REQUIRED (740). Every MCP host spawns stdio servers with
//!   CreateProcess, so a manifested build simply refuses to launch.
//! - `ShellExecuteEx` with the `runas` verb does elevate, but it creates a new
//!   process through the AppInfo broker, and that process cannot inherit the
//!   stdin/stdout pipe handles the MCP client handed us. The elevated child
//!   comes up with nothing attached and the client sees a dead server.
//!
//! ## What we do instead
//!
//! sudo for Windows (24H2+) in Inline mode solves exactly this: it duplicates
//! our stdio handles across the elevation boundary into the elevated child.
//! Verified with anonymous pipes, no console, UseShellExecute=false, which is
//! precisely how a host spawns us.
//!
//! So: if we are already elevated, serve normally. If not, re-exec ourselves
//! through sudo with inherited stdio and sit there waiting. The elevated child
//! talks to the client over our pipes directly, so there is no relay to write.
//!
//! The other two sudo modes are useless to us and fail confusingly:
//! ForceNewWindow detaches stdio into a fresh console, and DisableInput closes
//! stdin so the server takes an immediate EOF and shuts down. We check the mode
//! up front and refuse to start rather than fail in those shapes.

use std::process::Stdio;

use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey,
    RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::win32::to_wide;

/// Sentinel we append when re-execing. The child gates on this flag, not on its
/// own token, so a sudo that returns without actually elevating produces one
/// unelevated server instead of an infinite fork bomb.
pub const ELEVATED_FLAG: &str = "--elevated";

/// Escape hatch for debugging. Set MCP_ALLOW_UNELEVATED=1 to run degraded
/// instead of refusing to start when elevation is unavailable.
const ALLOW_UNELEVATED: &str = "MCP_ALLOW_UNELEVATED";

const SUDO_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Sudo";

/// The only mode that keeps our stdio pipes intact across the boundary.
const SUDO_INLINE: u32 = 3;

/// Read our own token and ask whether it is elevated.
pub fn is_elevated() -> anyhow::Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned: u32 = 0;
        let query = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        query?;

        Ok(elevation.TokenIsElevated != 0)
    }
}

/// Read HKLM\...\Sudo\Enabled. None means sudo has never been configured on
/// this machine, which is the out-of-box state.
pub fn sudo_mode() -> Option<u32> {
    let subpath = to_wide(SUDO_KEY);
    let name = to_wide("Enabled");
    let mut key = HKEY::default();

    unsafe {
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(subpath.as_ptr()),
            None,
            REG_SAM_FLAGS(KEY_READ.0),
            &mut key,
        ) != ERROR_SUCCESS
        {
            return None;
        }

        let mut data: u32 = 0;
        let mut len: u32 = std::mem::size_of::<u32>() as u32;
        let mut vtype = REG_VALUE_TYPE::default();
        let err = RegQueryValueExW(
            key,
            windows::core::PCWSTR(name.as_ptr()),
            None,
            Some(&mut vtype),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut len),
        );
        let _ = RegCloseKey(key);

        if err == ERROR_SUCCESS { Some(data) } else { None }
    }
}

pub fn describe_sudo_mode(mode: Option<u32>) -> &'static str {
    match mode {
        None => "not configured",
        Some(0) => "disabled",
        Some(1) => "ForceNewWindow (detaches stdio, unusable here)",
        Some(2) => "DisableInput (closes stdin, unusable here)",
        Some(SUDO_INLINE) => "Inline (good)",
        Some(_) => "unknown",
    }
}

/// Re-exec ourselves elevated, wiring the child straight to the pipes our
/// client gave us. Returns the child's exit code; we then exit with it so the
/// client sees a faithful result.
fn relaunch_via_sudo() -> anyhow::Result<i32> {
    let exe = std::env::current_exe()?;

    // Forward whatever we were launched with, then the sentinel. Command does
    // Windows argument quoting for us, which matters because the install path
    // lives under Program Files and has a space in it.
    let forwarded: Vec<String> = std::env::args().skip(1).collect();

    tracing::info!(
        exe = %exe.display(),
        args = ?forwarded,
        "not elevated, re-execing through sudo"
    );

    let status = std::process::Command::new("sudo")
        .arg(&exe)
        .args(&forwarded)
        .arg(ELEVATED_FLAG)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "sudo.exe not found. Self-elevation needs sudo for Windows (24H2+). \
                     Set {ALLOW_UNELEVATED}=1 to run without admin."
                )
            } else {
                anyhow::anyhow!("failed to run sudo: {e}")
            }
        })?;

    Ok(status.code().unwrap_or(1))
}

/// What main should do next.
pub enum Gate {
    /// We are elevated (or explicitly allowed not to be). Carry on and serve.
    Serve,
    /// A child served in our place. Exit with this code and touch nothing else.
    Exit(i32),
}

/// The elevation gate. Call this before spawning the PowerShell pool, otherwise
/// the wrapper process spawns three pwsh workers it immediately orphans.
pub fn gate() -> anyhow::Result<Gate> {
    // Gate on the sentinel first. If we are the child, we do not get a second
    // opinion about elevating, no matter what the token says.
    if std::env::args().any(|a| a == ELEVATED_FLAG) {
        match is_elevated() {
            Ok(true) => tracing::info!("running elevated"),
            Ok(false) => tracing::error!(
                "re-exec completed but token is still not elevated; admin-only tools will fail"
            ),
            Err(e) => tracing::warn!(err = %e, "could not read elevation state"),
        }
        return Ok(Gate::Serve);
    }

    if is_elevated()? {
        tracing::info!("already elevated, serving directly");
        return Ok(Gate::Serve);
    }

    let permissive = std::env::var(ALLOW_UNELEVATED).is_ok_and(|v| v == "1");
    let mode = sudo_mode();

    if mode != Some(SUDO_INLINE) {
        let detail = describe_sudo_mode(mode);
        if permissive {
            tracing::warn!(
                mode = detail,
                "sudo unusable and {ALLOW_UNELEVATED}=1, serving unelevated"
            );
            return Ok(Gate::Serve);
        }
        anyhow::bail!(
            "refusing to start unelevated: sudo mode is {detail}, needs Inline. \
             Fix with `sudo config --enable normal` (admin), or set {ALLOW_UNELEVATED}=1 \
             to run degraded."
        );
    }

    match relaunch_via_sudo() {
        Ok(code) => Ok(Gate::Exit(code)),
        Err(e) if permissive => {
            tracing::warn!(err = %e, "elevation failed and {ALLOW_UNELEVATED}=1, serving unelevated");
            Ok(Gate::Serve)
        }
        Err(e) => Err(e),
    }
}
