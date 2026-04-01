//! # Filesystem Operations: FindFirstFileW and the Audacity of 1995
//!
//! Welcome to the Windows filesystem API, where we enumerate files using
//! FindFirstFileW/FindNextFileW — an iterator pattern from Windows 95 that
//! Microsoft never replaced because "if it ain't broke, don't fix it" is
//! their entire philosophy (even when it IS broke).
//!
//! Timestamps are FILETIME structs: 64-bit values counting 100-nanosecond
//! intervals since January 1, 1601. Why 1601? Because that's the start of a
//! 400-year Gregorian calendar cycle. Someone at Microsoft in 1989 thought this
//! was a reasonable epoch and NOBODY STOPPED THEM.
//!
//! File attributes are a bitmask because of course they are. Want to know if
//! something is a directory? Bitwise AND with FILE_ATTRIBUTE_DIRECTORY. Hidden?
//! Another bitmask. Read-only? You guessed it. It's like a punch card but worse.
//!
//! And to get the owner of a file you need GetNamedSecurityInfoW (returns a SID)
//! then LookupAccountSidW (turns the SID into a name). TWO API calls to answer
//! "who owns this file?" Other operating systems call this `stat()`.

use super::{pretty, to_wide, wchar_to_string};
use serde_json::json;
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;

/// Converts a FILETIME to an ISO 8601 string. FILETIME is 100-nanosecond
/// intervals since January 1, 1601 — a date chosen because it's the beginning
/// of a 400-year Gregorian calendar cycle. You know, the thing everyone thinks
/// about when designing a timestamp format. We subtract 116,444,736,000,000,000
/// to get to the Unix epoch because that's how many 100ns intervals there are
/// between 1601 and 1970. I wish I was making this up.
fn filetime_to_iso(ft: &FILETIME) -> String {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    if ticks == 0 { return String::new(); }
    // Convert Windows FILETIME (100ns since 1601) to Unix epoch
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000; // 369 years of bullshit
    if ticks < EPOCH_DIFF { return String::new(); }
    let unix_100ns = ticks - EPOCH_DIFF;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    let dt = chrono_format(secs as i64, nanos);
    dt
}

/// Formats a Unix timestamp to ISO 8601 WITHOUT the chrono crate because we're
/// not dragging in a dependency just to print a date. Instead we do calendar math
/// by hand like some kind of medieval astronomer. Leap years included. You're welcome.
fn chrono_format(secs: i64, _nanos: u32) -> String {
    // Simple UTC format without chrono dependency
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Days since unix epoch to Y/M/D — implementing the Gregorian calendar
    // from scratch in a filesystem module. This is fine. Everything is fine.
    let mut y = 1970i64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining_days < days_in_year { break; }
        remaining_days -= days_in_year;
        y += 1;
    }
    let months_days: [i64; 12] = if is_leap(y) {
        [31,29,31,30,31,30,31,31,30,31,30,31]
    } else {
        [31,28,31,30,31,30,31,31,30,31,30,31]
    };
    let mut month = 1;
    for &md in &months_days {
        if remaining_days < md { break; }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;
    format!("{y:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Returns whether a year is a leap year. The one function in this entire
/// codebase that actually makes sense.
fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Converts file attribute bitmask to a compact string representation.
/// 'd' for directory, 'r' for read-only, 'h' for hidden, 's' for system,
/// 'a' for archive. It's like Unix file modes except less useful and stored
/// in a DWORD because Windows measures everything in 32-bit chunks of regret.
fn attrs_string(attrs: u32) -> String {
    let mut s = String::new();
    if attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0 { s.push('d'); } else { s.push('-'); }
    if attrs & FILE_ATTRIBUTE_READONLY.0 != 0 { s.push('r'); }
    if attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0 { s.push('h'); }
    if attrs & FILE_ATTRIBUTE_SYSTEM.0 != 0 { s.push('s'); }
    if attrs & FILE_ATTRIBUTE_ARCHIVE.0 != 0 { s.push('a'); }
    s
}

/// Lists directory contents using FindFirstFileW/FindNextFileW. This API is
/// literally the same one Windows 95 used. You append "\\*" to the path,
/// call FindFirstFileW, then loop with FindNextFileW until it returns an error.
/// "." and ".." are included in the results because apparently knowing you're
/// in a directory that has a parent is vital information. We filter those out
/// because we're not savages.
pub fn list(path: &str, hidden: bool, recurse: bool) -> anyhow::Result<String> {
    let mut entries = Vec::new();
    list_dir(path, hidden, recurse, &mut entries, 500)?;
    Ok(pretty(&json!(entries)))
}

/// The actual directory listing implementation. Capped at 500 entries because
/// without a limit, listing C:\ recursively would eat all available memory
/// and crash harder than Windows ME on a good day.
fn list_dir(path: &str, hidden: bool, recurse: bool, entries: &mut Vec<serde_json::Value>, limit: usize) -> anyhow::Result<()> {
    if entries.len() >= limit { return Ok(()); }

    // The magic "\\*" suffix tells FindFirstFileW "give me everything."
    // This is how Windows does glob patterns. In 2026. In a systems language.
    let search = format!("{}\\*", path.trim_end_matches('\\'));
    let wide = to_wide(&search);
    let mut fd = WIN32_FIND_DATAW::default();

    unsafe {
        let handle = FindFirstFileW(windows::core::PCWSTR(wide.as_ptr()), &mut fd)?;
        loop {
            let name = wchar_to_string(&fd.cFileName);
            if name != "." && name != ".." {
                let is_hidden = fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN.0 != 0;
                if hidden || !is_hidden {
                    let is_dir = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
                    // File size is split across two u32 fields because this API
                    // was designed when 4GB was an unfathomable amount of storage.
                    let size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
                    let full = format!("{}\\{}", path.trim_end_matches('\\'), name);

                    entries.push(json!({
                        "Name": name,
                        "FullName": full,
                        "Mode": attrs_string(fd.dwFileAttributes),
                        "SizeKB": if is_dir { json!(null) } else { json!((size as f64 / 1024.0 * 10.0).round() / 10.0) },
                        "LastWriteTime": filetime_to_iso(&fd.ftLastWriteTime),
                    }));

                    if recurse && is_dir && entries.len() < limit {
                        let _ = list_dir(&full, hidden, recurse, entries, limit);
                    }
                }
            }
            if FindNextFileW(handle, &mut fd).is_err() { break; }
        }
        // FindClose: because even the search handle needs manual cleanup.
        // Every. Single. Handle. In. Win32.
        let _ = FindClose(handle);
    }
    Ok(())
}

/// Searches for files matching a glob pattern, recursively. Uses the same
/// FindFirstFileW/FindNextFileW pattern twice — once for matching files in
/// the current directory, and once for enumerating subdirectories to recurse
/// into. It's like doing the same terrible dance twice per directory level.
pub fn search(path: &str, pattern: &str, limit: u32) -> anyhow::Result<String> {
    let mut results = Vec::new();
    search_dir(path, pattern, &mut results, limit as usize)?;
    Ok(pretty(&json!(results)))
}

/// Recursive file search implementation. Two FindFirstFileW loops per directory:
/// one with the pattern to find matches, one with "*" to find subdirectories.
/// If you're thinking "couldn't this be one loop?" — yes, absolutely, but then
/// we'd lose the authentic "Win32 API" flavor of doing everything the hard way.
fn search_dir(path: &str, pattern: &str, results: &mut Vec<serde_json::Value>, limit: usize) -> anyhow::Result<()> {
    if results.len() >= limit { return Ok(()); }

    // Search for matching files in this directory
    let search_pattern = format!("{}\\{}", path.trim_end_matches('\\'), pattern);
    let wide = to_wide(&search_pattern);
    let mut fd = WIN32_FIND_DATAW::default();

    unsafe {
        if let Ok(handle) = FindFirstFileW(windows::core::PCWSTR(wide.as_ptr()), &mut fd) {
            loop {
                let name = wchar_to_string(&fd.cFileName);
                if name != "." && name != ".." {
                    let full = format!("{}\\{}", path.trim_end_matches('\\'), name);
                    let size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
                    results.push(json!({
                        "FullName": full,
                        "SizeKB": (size as f64 / 1024.0 * 10.0).round() / 10.0,
                        "LastWriteTime": filetime_to_iso(&fd.ftLastWriteTime),
                        "Mode": attrs_string(fd.dwFileAttributes),
                    }));
                    if results.len() >= limit { let _ = FindClose(handle); return Ok(()); }
                }
                if FindNextFileW(handle, &mut fd).is_err() { break; }
            }
            let _ = FindClose(handle);
        }
    }

    // Recurse into subdirectories — second FindFirstFileW loop because
    // we need "\\*" to get all entries, not just pattern matches.
    let dir_search = format!("{}\\*", path.trim_end_matches('\\'));
    let wide = to_wide(&dir_search);
    let mut fd = WIN32_FIND_DATAW::default();

    unsafe {
        if let Ok(handle) = FindFirstFileW(windows::core::PCWSTR(wide.as_ptr()), &mut fd) {
            loop {
                let name = wchar_to_string(&fd.cFileName);
                if name != "." && name != ".."
                    && fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
                {
                    let subdir = format!("{}\\{}", path.trim_end_matches('\\'), name);
                    let _ = search_dir(&subdir, pattern, results, limit);
                    if results.len() >= limit { let _ = FindClose(handle); return Ok(()); }
                }
                if FindNextFileW(handle, &mut fd).is_err() { break; }
            }
            let _ = FindClose(handle);
        }
    }

    Ok(())
}

/// Gets detailed info about a single file/directory. Calls FindFirstFileW
/// (yes, FIND, even though we know the exact path — there's no GetFileInfoW
/// that returns a WIN32_FIND_DATAW because that would be convenient). Then
/// calls get_file_owner() which is its own two-API-call adventure to translate
/// a security descriptor into a human-readable "DOMAIN\username" string.
pub fn info(path: &str) -> anyhow::Result<String> {
    let wide = to_wide(path);

    unsafe {
        let mut fd = WIN32_FIND_DATAW::default();
        let handle = FindFirstFileW(windows::core::PCWSTR(wide.as_ptr()), &mut fd)?;
        let _ = FindClose(handle);

        let name = wchar_to_string(&fd.cFileName);
        let size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
        let is_dir = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;

        // Get owner via GetNamedSecurityInfoW — buckle up for two more API calls
        let owner = get_file_owner(path).unwrap_or_default();

        Ok(pretty(&json!({
            "Name": name,
            "FullName": path,
            "Length": if is_dir { json!(null) } else { json!(size) },
            "Attributes": attrs_string(fd.dwFileAttributes),
            "CreationTime": filetime_to_iso(&fd.ftCreationTime),
            "LastWriteTime": filetime_to_iso(&fd.ftLastWriteTime),
            "LastAccessTime": filetime_to_iso(&fd.ftLastAccessTime),
            "IsDirectory": is_dir,
            "IsReadOnly": fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY.0 != 0,
            "Owner": owner,
        })))
    }
}

/// Gets the owner of a file. This is a two-step process because Windows stores
/// ownership as a binary Security Identifier (SID) — a variable-length blob of
/// bytes that identifies a user, group, or service. To turn this into something
/// a human can read, you have to:
///   1. Call GetNamedSecurityInfoW to get the SID (also allocates a security
///      descriptor that you have to LocalFree yourself)
///   2. Call LookupAccountSidW to translate the SID into "DOMAIN\username"
///
/// On Linux this is literally just `stat(path).st_uid`. One number. One call.
/// But sure, Microsoft, let's involve security descriptors and SID lookups
/// for "who created this text file."
fn get_file_owner(path: &str) -> Option<String> {
    use windows::Win32::Security::*;
    use windows::Win32::Security::Authorization::*;

    let wide = to_wide(path);
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut owner_sid = PSID::default();

        let result = GetNamedSecurityInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0),
            Some(&mut owner_sid),
            None,
            None,
            None,
            &mut sd,
        );

        if result != ERROR_SUCCESS {
            return None;
        }

        // Now translate the SID blob into a name. Allocate buffers for both
        // the username AND the domain because EVERYTHING in Win32 is
        // "DOMAIN\username" even on machines that aren't joined to a domain.
        let mut name_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut domain_buf = vec![0u16; 256];
        let mut domain_len = domain_buf.len() as u32;
        let mut sid_use = SID_NAME_USE::default();

        if LookupAccountSidW(
            None,
            owner_sid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_use,
        ).is_ok() {
            let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            // Don't forget to LocalFree the security descriptor!
            // Because Win32 allocated it FOR you but cleaning it up is YOUR job.
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            Some(format!("{domain}\\{name}"))
        } else {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            None
        }
    }
}
