//! # Process Management: A Love Letter to ToolHelp32
//!
//! This module wraps the Windows ToolHelp32 API, which Microsoft shipped with
//! Windows 95 and apparently decided was perfect on the first try because they
//! never fucking improved it. You want to enumerate processes? Cool, here's a
//! "snapshot" API that makes you iterate with Process32FirstW/Process32NextW
//! like you're walking a linked list in a goddamn CS101 class.
//!
//! The crown jewel is PROCESSENTRY32W, a struct that SILENTLY FAILS if you
//! forget to set dwSize before calling. Not an error code. Not a panic.
//! Just... nothing. Enjoy debugging that at 2 AM.

use super::{pretty, wchar_to_string};
use serde_json::json;
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;

/// RAII wrapper because Windows HANDLE doesn't implement Drop, because of course
/// Microsoft expects you to manually close every handle like it's 1993 and we're
/// all writing C in Borland.
struct SafeHandle(HANDLE);
impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}

/// Takes a "snapshot" of all running processes using the ToolHelp32 API.
/// Note the ritual sacrifice on line with `dwSize` — you MUST set this field
/// to the struct size or the API silently returns garbage. Not documented
/// anywhere useful. Thanks, Raymond Chen, for writing that one blog post
/// in 2004 that saved us all. Also we have to re-set dwSize in the loop
/// because Process32NextW helpfully clobbers it. Classic Windows.
fn snapshot_processes() -> anyhow::Result<Vec<PROCESSENTRY32W>> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let _guard = SafeHandle(snap);
        // Here it is. The magic line. Forget this and everything returns zeroes.
        // No error. No warning. Just vibes.
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut procs = Vec::new();
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                procs.push(entry);
                // Reset dwSize AGAIN because Microsoft treats struct fields like
                // scratch paper. Who designed this? Were they okay?
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        Ok(procs)
    }
}

/// Gets working set memory for a process. Requires PROCESS_QUERY_LIMITED_INFORMATION
/// *and* PROCESS_VM_READ because apparently querying memory info counts as "reading
/// virtual memory." You also have to set `cb` on the struct first or — say it with
/// me — it silently fails. Microsoft really has ONE design pattern and it's
/// "pre-initialize this field or get fucked."
fn get_process_memory(pid: u32) -> Option<usize> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;
        let _guard = SafeHandle(handle);
        let mut counters = PROCESS_MEMORY_COUNTERS::default();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        GetProcessMemoryInfo(handle, &mut counters, counters.cb).ok()?;
        Some(counters.WorkingSetSize)
    }
}

/// Gets kernel and user CPU time for a process. Times are returned as FILETIME
/// structs — 100-nanosecond intervals since January 1, 1601 — because nothing
/// says "ergonomic API" like counting time from the year the Dutch East India
/// Company was founded. We get to manually stitch two u32s into a u64 because
/// this API predates 64-bit integers in Windows. Living the dream.
fn get_process_times(pid: u32) -> Option<(u64, u64)> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let _guard = SafeHandle(handle);
        let (mut creation, mut exit, mut kernel, mut user) =
            (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).ok()?;
        // Manually reassemble 64-bit integers from two 32-bit halves.
        // Because when this API was designed, 64-bit was science fiction.
        let k = ((kernel.dwHighDateTime as u64) << 32) | kernel.dwLowDateTime as u64;
        let u = ((user.dwHighDateTime as u64) << 32) | user.dwLowDateTime as u64;
        Some((k, u))
    }
}

/// Build a PID → process name HashMap for fast lookups.
/// Used by the network module to figure out which process owns a connection,
/// because apparently GetTcpTable2 only gives you PIDs and figuring out
/// the actual name is YOUR problem.
pub fn snapshot_name_cache() -> std::collections::HashMap<u32, String> {
    snapshot_processes()
        .unwrap_or_default()
        .iter()
        .map(|p| (p.th32ProcessID, wchar_to_string(&p.szExeFile)))
        .collect()
}

/// Lists processes with sorting and filtering. We snapshot the entire process
/// table, query memory and CPU for every single one individually (because
/// there's no batch API, naturally), then sort and truncate. It's O(n * syscalls)
/// and it's the best Windows can offer. Welcome to high-performance computing.
pub fn list(sort_by: Option<&str>, limit: u32, filter: Option<&str>) -> anyhow::Result<String> {
    let procs = snapshot_processes()?;
    let mut entries: Vec<serde_json::Value> = procs
        .iter()
        .filter(|p| {
            if let Some(f) = filter {
                let name = wchar_to_string(&p.szExeFile);
                name.to_lowercase().contains(&f.to_lowercase())
            } else {
                true
            }
        })
        .map(|p| {
            let pid = p.th32ProcessID;
            let name = wchar_to_string(&p.szExeFile);
            let mem_bytes = get_process_memory(pid).unwrap_or(0);
            let cpu_time = get_process_times(pid)
                .map(|(k, u)| (k + u) as f64 / 10_000_000.0) // 100ns units → seconds
                .unwrap_or(0.0);
            json!({
                "Id": pid,
                "ProcessName": name,
                "CPU_Seconds": (cpu_time * 100.0).round() / 100.0,
                "MemoryMB": (mem_bytes as f64 / 1_048_576.0 * 10.0).round() / 10.0,
                "Threads": p.cntThreads,
            })
        })
        .collect();

    match sort_by.unwrap_or("cpu") {
        "memory" => entries.sort_by(|a, b| {
            b["MemoryMB"].as_f64().unwrap_or(0.0)
                .partial_cmp(&a["MemoryMB"].as_f64().unwrap_or(0.0))
                .unwrap()
        }),
        "name" => entries.sort_by(|a, b| {
            a["ProcessName"].as_str().unwrap_or("")
                .cmp(b["ProcessName"].as_str().unwrap_or(""))
        }),
        "pid" => entries.sort_by(|a, b| {
            a["Id"].as_u64().unwrap_or(0).cmp(&b["Id"].as_u64().unwrap_or(0))
        }),
        _ => entries.sort_by(|a, b| {
            b["CPU_Seconds"].as_f64().unwrap_or(0.0)
                .partial_cmp(&a["CPU_Seconds"].as_f64().unwrap_or(0.0))
                .unwrap()
        }),
    }

    entries.truncate(limit as usize);
    Ok(pretty(&json!(entries)))
}

/// Gets detailed info for a single process. We snapshot ALL processes just to
/// find one, because ToolHelp32 has no "get process by PID" function. That
/// would be too convenient. We then open the process AGAIN separately to get
/// the full executable path, because PROCESSENTRY32W.szExeFile only gives
/// you the filename, not the path. Two syscalls for what should be one field.
pub fn detail(pid: u32) -> anyhow::Result<String> {
    let procs = snapshot_processes()?;
    let proc = procs
        .iter()
        .find(|p| p.th32ProcessID == pid)
        .ok_or_else(|| anyhow::anyhow!("Process {pid} not found"))?;

    let name = wchar_to_string(&proc.szExeFile);
    let mem = get_process_memory(pid).unwrap_or(0);
    let (kernel, user) = get_process_times(pid).unwrap_or((0, 0));
    let cpu_sec = (kernel + user) as f64 / 10_000_000.0;

    // Get executable path via QueryFullProcessImageNameW
    // Because szExeFile is just the filename. Why would a PROCESS ENTRY
    // contain the full path to the process? That's crazy talk.
    let exe_path = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .ok()
            .and_then(|handle| {
                let _guard = SafeHandle(handle);
                let mut buf = vec![0u16; 1024];
                let mut size = buf.len() as u32;
                QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut size).ok()?;
                Some(String::from_utf16_lossy(&buf[..size as usize]))
            })
            .unwrap_or_default()
    };

    Ok(pretty(&json!({
        "ProcessId": pid,
        "Name": name,
        "ExecutablePath": exe_path,
        "ParentProcessId": proc.th32ParentProcessID,
        "ThreadCount": proc.cntThreads,
        "WorkingSetMB": (mem as f64 / 1_048_576.0 * 10.0).round() / 10.0,
        "CPU_Seconds": (cpu_sec * 100.0).round() / 100.0,
    })))
}

/// Kills a process. TerminateProcess is the "I don't give a shit about your
/// cleanup handlers" option. No graceful shutdown. No WM_CLOSE. No asking nicely.
/// Just straight-up murder. The exit code is hardcoded to 1 because at this point,
/// does the exit code really matter? You're dead, process. You're dead.
pub fn kill(pid: u32) -> anyhow::Result<String> {
    unsafe {
        // Need PROCESS_TERMINATE (to kill it) AND PROCESS_QUERY_LIMITED_INFORMATION
        // (to ask its name before we execute it). Very polite of us, really.
        let handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        let _guard = SafeHandle(handle);

        // Get name before killing — like reading a prisoner their charges
        let mut buf = vec![0u16; 260];
        let mut size = buf.len() as u32;
        let name = if QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut size).is_ok() {
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            path.rsplit('\\').next().unwrap_or(&path).to_string()
        } else {
            "unknown".to_string()
        };

        TerminateProcess(handle, 1)?;
        Ok(pretty(&json!({
            "Id": pid,
            "ProcessName": name,
            "Status": "Terminated"
        })))
    }
}

/// Starts a new process. CreateProcessW is one of the more "reasonable" Win32 APIs,
/// which is to say it only takes 10 parameters instead of 15. STARTUPINFOW also
/// requires you to set `cb` to the struct size because Microsoft literally cannot
/// stop themselves from adding this footgun to every single struct they design.
/// It's pathological at this point.
pub fn start(path: &str, args: Option<&str>, working_dir: Option<&str>) -> anyhow::Result<String> {
    unsafe {
        let mut cmd_line = if let Some(a) = args {
            format!("\"{}\" {}", path, a)
        } else {
            format!("\"{}\"", path)
        };
        let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

        let wd_wide = working_dir.map(super::to_wide);
        let wd_ptr = wd_wide.as_ref().map(|w| windows::core::PCWSTR(w.as_ptr()));

        // Ah yes, STARTUPINFOW. cb = struct size. Say it with me now.
        let mut si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        CreateProcessW(
            None,
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            wd_ptr.unwrap_or(windows::core::PCWSTR::null()),
            &mut si,
            &mut pi,
        )?;

        // CreateProcessW gives you TWO handles to close. Because one wasn't enough.
        let _hproc = SafeHandle(pi.hProcess);
        let _hthr = SafeHandle(pi.hThread);

        Ok(pretty(&json!({
            "Id": pi.dwProcessId,
            "ThreadId": pi.dwThreadId,
            "Status": "Started"
        })))
    }
}

/// Returns all processes with their parent PIDs so you can reconstruct the tree
/// on the client side. We don't build the actual tree here because honestly,
/// dealing with Windows' orphaned process problem (where parent PIDs point to
/// long-dead processes whose PIDs got recycled) is a nightmare I'm not signing
/// up for at the API layer.
pub fn tree() -> anyhow::Result<String> {
    let procs = snapshot_processes()?;
    let entries: Vec<serde_json::Value> = procs
        .iter()
        .map(|p| {
            let mem = get_process_memory(p.th32ProcessID).unwrap_or(0);
            json!({
                "ProcessId": p.th32ProcessID,
                "ParentProcessId": p.th32ParentProcessID,
                "Name": wchar_to_string(&p.szExeFile),
                "MemoryMB": (mem as f64 / 1_048_576.0 * 10.0).round() / 10.0,
            })
        })
        .collect();
    Ok(pretty(&json!(entries)))
}
