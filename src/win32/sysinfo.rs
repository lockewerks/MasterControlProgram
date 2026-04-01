//! # System Information: Where Simple Questions Get Complicated Answers
//!
//! You'd think "what version of Windows am I running?" would be a simple question.
//! You'd be wrong. GetVersionExW was deprecated because apps were using it to
//! lie about compatibility, so now it LIES TO YOU and returns Windows 8 for
//! everything. The official workaround? Read the version from the fucking
//! REGISTRY. That's right — Microsoft deprecated the version API and told
//! everyone to go scrape it from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
//! like we're parsing config files in 1998.
//!
//! GlobalMemoryStatusEx requires you to set dwLength before calling — because
//! OBVIOUSLY. GetLogicalDriveStringsW returns drives as a double-null-terminated
//! string, because apparently a simple array was too mainstream.

use super::{pretty, to_wide};
use serde_json::json;
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::SystemInformation::*;

/// Gathers system info: hostname, OS version, CPU count, memory, and uptime.
/// This calls about five different APIs because Windows doesn't have a single
/// "tell me about yourself" function. Each piece of information comes from a
/// different subsystem with a different calling convention and a different
/// way of making you set struct sizes before calling.
pub fn system_info() -> anyhow::Result<String> {
    unsafe {
        // Computer name — at least this one is relatively straightforward.
        // GetComputerNameExW only has three variants of computer name to
        // choose from. We use DnsHostname because it's 2026 and NetBIOS
        // can rot in peace.
        let mut name_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        GetComputerNameExW(
            ComputerNameDnsHostname,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
        )?;
        let hostname = String::from_utf16_lossy(&name_buf[..name_len as usize]);

        // Memory info — set dwLength or it silently fails. I'll say it until
        // I die: this is the worst API pattern Microsoft ever invented and they
        // put it in EVERY. SINGLE. STRUCT.
        let mut mem = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        GlobalMemoryStatusEx(&mut mem)?;

        // System info — one of the rare Win32 functions that just... works.
        // No pre-initialization, no double-call, just fills in the struct.
        // I'm suspicious.
        let mut sysinfo = SYSTEM_INFO::default();
        GetSystemInfo(&mut sysinfo);

        // Uptime via GetTickCount64. Returns milliseconds since boot.
        // Finally, a number that doesn't need to be converted from
        // 100-nanosecond intervals since the fall of Constantinople or whatever.
        let uptime_ms = GetTickCount64();
        let uptime_hours = uptime_ms / 3_600_000;
        let uptime_mins = (uptime_ms % 3_600_000) / 60_000;

        // OS version: we read this from the registry because GetVersionExW
        // is a deprecated liar. Let that sink in. Microsoft deprecated their
        // own version API because THEY couldn't stop apps from misusing it,
        // so now EVERYONE has to read the registry like barbarians.
        let version = get_os_version_from_registry().unwrap_or_default();

        Ok(pretty(&json!({
            "Hostname": hostname,
            "OS": version.get("ProductName").unwrap_or(&json!("Windows")),
            "Version": version.get("DisplayVersion").unwrap_or(&json!("Unknown")),
            "Build": version.get("CurrentBuildNumber").unwrap_or(&json!("Unknown")),
            // wProcessorArchitecture == 9 means AMD64. Because 9 obviously means 64-bit.
            // What else would it mean? (PROCESSOR_ARCHITECTURE_AMD64 = 9, the constant
            // that makes you go "...why 9?")
            "Architecture": if sysinfo.Anonymous.Anonymous.wProcessorArchitecture.0 == 9 { "64-bit" } else { "32-bit" },
            "Processors": sysinfo.dwNumberOfProcessors,
            "TotalMemoryMB": mem.ullTotalPhys / 1_048_576,
            "FreeMemoryMB": mem.ullAvailPhys / 1_048_576,
            "MemoryLoad": mem.dwMemoryLoad,
            "Uptime": format!("{}h {}m", uptime_hours, uptime_mins),
        })))
    }
}

/// Reads the OS version from the registry because the actual version API
/// (GetVersionExW) was deprecated and now lies about the Windows version.
/// This is not a joke. This is official Microsoft guidance: "just read it
/// from the registry." We're literally scraping our own OS for version info
/// like it's a web page we're screen-scraping. I want to die.
fn get_os_version_from_registry() -> Option<serde_json::Map<String, serde_json::Value>> {
    use windows::Win32::System::Registry::*;
    let subpath = to_wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let mut key = HKEY::default();
    unsafe {
        let err = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(subpath.as_ptr()),
            None,
            REG_SAM_FLAGS(KEY_READ.0),
            &mut key,
        );
        if err != ERROR_SUCCESS {
            return None;
        }
    }

    let mut map = serde_json::Map::new();
    for name in ["ProductName", "DisplayVersion", "CurrentBuildNumber"] {
        let name_wide = to_wide(name);
        let mut data_len: u32 = 0;
        let mut vtype = REG_VALUE_TYPE::default();
        unsafe {
            // Two-call pattern AGAIN. Get size, then get data. For three values,
            // that's six syscalls. For something that should be one function call.
            let _ = RegQueryValueExW(
                key,
                windows::core::PCWSTR(name_wide.as_ptr()),
                None,
                Some(&mut vtype),
                None,
                Some(&mut data_len),
            );
            let mut data = vec![0u8; data_len as usize];
            if RegQueryValueExW(
                key,
                windows::core::PCWSTR(name_wide.as_ptr()),
                None,
                Some(&mut vtype),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            ) == ERROR_SUCCESS {
                let wide: &[u16] = std::slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / 2);
                let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                map.insert(name.to_string(), json!(String::from_utf16_lossy(&wide[..len])));
            }
        }
    }
    unsafe { let _ = RegCloseKey(key); }
    Some(map)
}

/// Returns detailed memory statistics. Calls GlobalMemoryStatusEx which,
/// despite having "Global" in the name, gives you physical memory info.
/// Also includes page file and virtual memory stats because why not —
/// it's not like anyone can keep track of which "memory" number means what.
/// Don't forget to set dwLength first! (He said, for the thousandth time.)
pub fn memory_info() -> anyhow::Result<String> {
    unsafe {
        let mut mem = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        GlobalMemoryStatusEx(&mut mem)?;

        let total_mb = mem.ullTotalPhys / 1_048_576;
        let free_mb = mem.ullAvailPhys / 1_048_576;
        let used_mb = total_mb - free_mb;

        Ok(pretty(&json!({
            "TotalMB": total_mb,
            "FreeMB": free_mb,
            "UsedMB": used_mb,
            "UsedPercent": mem.dwMemoryLoad,
            "TotalPageFileMB": mem.ullTotalPageFile / 1_048_576,
            "FreePageFileMB": mem.ullAvailPageFile / 1_048_576,
            "TotalVirtualMB": mem.ullTotalVirtual / 1_048_576,
        })))
    }
}

/// Enumerates logical drives and returns their info. GetLogicalDriveStringsW
/// returns ALL drive letters as one big string: "C:\\\0D:\\\0E:\\\0\0" — a
/// double-null-terminated sequence of null-terminated strings. Because arrays
/// are for other operating systems. For each drive we then call
/// GetVolumeInformationW (volume name, filesystem type) and
/// GetDiskFreeSpaceExW (free/total space) — three API calls per drive letter.
/// If you have 5 drives, that's 16 syscalls for what should be one list.
pub fn disk_info() -> anyhow::Result<String> {
    unsafe {
        // Get the double-null-terminated list of drive strings. Each drive is
        // like "C:\\\0" and the whole thing ends with an extra "\0". It's like
        // someone designed this in a fever dream about null terminators.
        let mut buf = vec![0u16; 1024];
        let len = GetLogicalDriveStringsW(Some(&mut buf));
        if len == 0 {
            anyhow::bail!("Failed to get drive strings");
        }

        let mut drives = Vec::new();
        let mut start = 0;
        for i in 0..len as usize {
            if buf[i] == 0 {
                if i > start {
                    let drive_str = String::from_utf16_lossy(&buf[start..i]);
                    let drive_wide = to_wide(&drive_str);
                    let pcwstr = windows::core::PCWSTR(drive_wide.as_ptr());

                    // Volume info — name, serial number, max component length, flags,
                    // and filesystem name. Five out-params. Just vibing.
                    let mut vol_name = vec![0u16; 256];
                    let mut fs_name = vec![0u16; 256];
                    let mut serial: u32 = 0;
                    let mut max_comp: u32 = 0;
                    let mut flags: u32 = 0;
                    let has_vol = GetVolumeInformationW(
                        pcwstr,
                        Some(&mut vol_name),
                        Some(&mut serial),
                        Some(&mut max_comp),
                        Some(&mut flags),
                        Some(&mut fs_name),
                    ).is_ok();

                    // Free space — because this is a separate API call from volume info.
                    // Obviously.
                    let mut free_caller: u64 = 0;
                    let mut total: u64 = 0;
                    let mut free_total: u64 = 0;
                    let has_space = GetDiskFreeSpaceExW(
                        pcwstr,
                        Some(&mut free_caller),
                        Some(&mut total),
                        Some(&mut free_total),
                    ).is_ok();

                    let drive_type = GetDriveTypeW(pcwstr);
                    let drive_letter = drive_str.chars().next().unwrap_or('?');
                    drives.push(json!({
                        "DriveLetter": drive_letter.to_string(),
                        "Label": if has_vol { super::wchar_to_string(&vol_name) } else { String::new() },
                        "FileSystem": if has_vol { super::wchar_to_string(&fs_name) } else { String::new() },
                        "SizeGB": if has_space { format!("{:.2}", total as f64 / 1_073_741_824.0) } else { "N/A".into() },
                        "FreeGB": if has_space { format!("{:.2}", free_total as f64 / 1_073_741_824.0) } else { "N/A".into() },
                        "DriveType": match drive_type {
                            2 => "Removable",    // DRIVE_REMOVABLE
                            3 => "Fixed",         // DRIVE_FIXED
                            4 => "Network",       // DRIVE_REMOTE
                            5 => "CD-ROM",        // DRIVE_CDROM — what year is it?
                            6 => "RAMDisk",       // DRIVE_RAMDISK — for the three people who use these
                            _ => "Unknown",
                        },
                    }));
                }
                start = i + 1;
            }
        }

        Ok(pretty(&json!(drives)))
    }
}
