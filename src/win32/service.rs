//! # Windows Service Control Manager: Digital Bureaucracy Simulator
//!
//! If you've ever fantasized about interacting with a government agency via
//! raw memory manipulation, congratulations — the SCM is for you. Want to
//! enumerate services? First, open the SCM with the right access rights
//! (hope you picked correctly!), then call EnumServicesStatusExW TWICE — once
//! with a null buffer to ask "how big should the buffer be?" and again with
//! the actual buffer, because apparently allocating memory is YOUR job here.
//!
//! And ChangeServiceConfigW? Eleven parameters. ELEVEN. Most of which you pass
//! as SERVICE_NO_CHANGE because you only want to modify one fucking thing.
//! Microsoft could have made separate functions. They chose violence instead.

use super::{pretty, from_wide};
use serde_json::json;
use windows::Win32::Foundation::*;
use windows::Win32::System::Services::*;

/// RAII wrapper for SC_HANDLE because the Service Control Manager predates the
/// concept of resource management. You open it, you close it, and if you forget,
/// you leak. Just like the good old days.
struct ScmHandle(SC_HANDLE);
impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseServiceHandle(self.0); }
        }
    }
}

/// Opens a connection to the almighty Service Control Manager.
/// You need specific access rights or it tells you to go fuck yourself.
/// SC_MANAGER_ENUMERATE_SERVICE to list, SC_MANAGER_CONNECT to open
/// individual services... it's like a bouncer checking your ID at every door.
fn open_scm(access: u32) -> anyhow::Result<ScmHandle> {
    unsafe {
        let h = OpenSCManagerW(None, None, access)?;
        Ok(ScmHandle(h))
    }
}

/// Opens a specific service by name. Requires the SCM handle you already
/// fought to obtain, plus ANOTHER set of access flags because apparently
/// the SCM's permission wasn't enough. It's access rights all the way down.
fn open_service(scm: &ScmHandle, name: &str, access: u32) -> anyhow::Result<ScmHandle> {
    let wide = super::to_wide(name);
    unsafe {
        let h = OpenServiceW(scm.0, windows::core::PCWSTR(wide.as_ptr()), access)?;
        Ok(ScmHandle(h))
    }
}

/// Translates a service state enum to a human-readable string because
/// Microsoft gives you an integer and expects YOU to know what it means.
/// Seven possible states for something that's either running or not.
/// They really needed "PausePending" and "ContinuePending" as distinct states.
/// Enterprise software, baby.
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

/// Converts start type magic numbers to strings. These are just 0-4 but
/// Microsoft didn't give them proper enum names in the original API, so here
/// we are manually mapping integers to words like animals.
fn start_type_str(st: u32) -> &'static str {
    match st {
        0 => "Boot",       // Loaded by the boot loader. Kernel-level stuff.
        1 => "System",     // Started during kernel init. Still terrifying.
        2 => "Automatic",  // Starts at login. The "please slow down my boot" option.
        3 => "Manual",     // You start it yourself. Like a responsible adult.
        4 => "Disabled",   // Dead to the system. The way most services should be.
        _ => "Unknown",
    }
}

/// Lists all Win32 services. This is the legendary "call it twice" pattern:
/// first call with no buffer to get the required size (which "fails" with
/// ERROR_MORE_DATA like that's a normal thing), then allocate and call again.
/// Microsoft invented this pattern and uses it EVERYWHERE. It's their love
/// language. The return is a raw byte buffer that we cast to an array of
/// ENUM_SERVICE_STATUS_PROCESSW. Totally safe and normal.
pub fn list() -> anyhow::Result<String> {
    unsafe {
        let scm = open_scm(SC_MANAGER_ENUMERATE_SERVICE)?;

        // First call: "Hey Windows, how much memory do I need?"
        // Windows: *fails with an error code that means success*
        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let mut resume: u32 = 0;
        let _ = EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        );

        // Second call: "Okay HERE'S the buffer, now actually give me the data."
        // Pray the required size didn't change between calls.
        let mut buf = vec![0u8; needed as usize];
        EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        )?;

        // Reinterpret raw bytes as service structs. Nothing can go wrong here.
        let services = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        );

        let mut entries: Vec<serde_json::Value> = services
            .iter()
            .map(|s| {
                let name = from_wide(s.lpServiceName.0);
                let display = from_wide(s.lpDisplayName.0);
                let state = status_str(s.ServiceStatusProcess.dwCurrentState);
                json!({
                    "Name": name,
                    "DisplayName": display,
                    "Status": state,
                    "PID": s.ServiceStatusProcess.dwProcessId,
                })
            })
            .collect();

        entries.sort_by(|a, b| a["Name"].as_str().unwrap_or("").cmp(b["Name"].as_str().unwrap_or("")));
        Ok(pretty(&json!(entries)))
    }
}

/// Gets detailed info for a single service. Requires opening the SCM, then
/// opening the service, then querying status AND config separately because
/// why would one API call give you all the information about one thing?
/// QueryServiceConfigW also uses the "call twice" pattern. Surprise!
pub fn detail(name: &str) -> anyhow::Result<String> {
    unsafe {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let svc = open_service(&scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;

        // Query status — because knowing if it's running requires a whole
        // separate struct and API call from getting its configuration
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed: u32 = 0;
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut needed,
        )?;

        // Query config — call twice pattern, our old nemesis returns
        let mut needed2: u32 = 0;
        let _ = QueryServiceConfigW(svc.0, None, 0, &mut needed2);
        let mut config_buf = vec![0u8; needed2 as usize];
        QueryServiceConfigW(
            svc.0,
            Some(config_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            needed2,
            &mut needed2,
        )?;
        let config = &*(config_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);

        Ok(pretty(&json!({
            "Name": name,
            "DisplayName": from_wide(config.lpDisplayName.0),
            "State": status_str(status.dwCurrentState),
            "StartType": start_type_str(config.dwStartType.0),
            "BinaryPath": from_wide(config.lpBinaryPathName.0),
            "ServiceAccount": from_wide(config.lpServiceStartName.0),
            "PID": status.dwProcessId,
        })))
    }
}

/// Starts a service. Deceptively simple compared to everything else in this
/// module. Don't get used to it.
pub fn start(name: &str) -> anyhow::Result<String> {
    unsafe {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let svc = open_service(&scm, name, SERVICE_START | SERVICE_QUERY_STATUS)?;
        StartServiceW(svc.0, None)?;
        Ok(pretty(&json!({ "Name": name, "Status": "StartPending" })))
    }
}

/// Stops a service by sending SERVICE_CONTROL_STOP. This is the polite way —
/// the service gets a chance to clean up. Unlike TerminateProcess, which is
/// more of a "surprise, you're dead" situation. Returns "StopPending" because
/// services don't stop immediately; they enter a bureaucratic limbo state
/// while they file their shutdown paperwork.
pub fn stop(name: &str) -> anyhow::Result<String> {
    unsafe {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let svc = open_service(&scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        let mut status = SERVICE_STATUS::default();
        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status)?;
        Ok(pretty(&json!({ "Name": name, "Status": "StopPending" })))
    }
}

/// "Restarts" a service by stopping then starting it with a 500ms nap in between.
/// This is not a real atomic restart — it's the "turn it off, count to one,
/// turn it back on" approach. If the service takes longer than 500ms to stop,
/// well, the start call will probably just fail. Professional-grade engineering.
pub fn restart(name: &str) -> anyhow::Result<String> {
    // Stop, then start
    let _ = stop(name); // ignore stop errors (might already be stopped)
    // Brief wait for stop — a.k.a. "hope and prayer driven development"
    std::thread::sleep(std::time::Duration::from_millis(500));
    start(name)
}

/// Changes a service's startup type. This calls ChangeServiceConfigW, which
/// takes ELEVEN parameters. We only care about ONE of them (the start type).
/// The other ten? SERVICE_NO_CHANGE / None. Microsoft could have made a
/// ChangeServiceStartType function. They could have used a builder pattern.
/// They could have done literally anything else. But no, here we are, passing
/// eleven goddamn arguments to change one setting. This is what peak API
/// design looks like, and it looks like shit.
pub fn set_startup(name: &str, startup_type: &str) -> anyhow::Result<String> {
    let st = match startup_type.to_lowercase().as_str() {
        "automatic" | "auto" => SERVICE_AUTO_START,
        "manual" => SERVICE_DEMAND_START,
        "disabled" => SERVICE_DISABLED,
        other => anyhow::bail!("Unknown startup type: {other}. Use Automatic, Manual, or Disabled"),
    };

    unsafe {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let svc = open_service(&scm, name, SERVICE_CHANGE_CONFIG)?;
        // Behold: eleven arguments, ten of which mean "don't change this."
        // This is the function signature equivalent of a Terms & Conditions page.
        ChangeServiceConfigW(
            svc.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),   // Don't change the type
            st,                                      // THE ONE THING WE ACTUALLY WANT
            SERVICE_ERROR(SERVICE_NO_CHANGE),         // Don't change error control
            None,                                     // Don't change binary path
            None,                                     // Don't change load order group
            None,                                     // Don't change tag ID
            None,                                     // Don't change dependencies
            None,                                     // Don't change service account
            None,                                     // Don't change password
            None,                                     // Don't change display name
        )?;
        Ok(pretty(&json!({ "Name": name, "StartupType": startup_type })))
    }
}
