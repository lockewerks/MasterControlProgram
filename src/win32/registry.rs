//! # The Windows Registry: God's Mistake
//!
//! The Windows Registry is a hierarchical database that stores configuration for
//! the entire operating system in one monolithic, fragile, corruptible blob.
//! It was invented because INI files were "too simple" and someone at Microsoft
//! thought "what if we put everything in one place and made it impossible to
//! back up properly?"
//!
//! There are FIVE root hives (HKLM, HKCU, HKCR, HKU, HKCC) because having one
//! giant tree of sadness wasn't enough — we needed five overlapping trees of sadness.
//! HKCR is literally just a merged view of HKLM\Software\Classes and HKCU\Software\Classes.
//! Why? Don't ask questions you don't want the answer to.
//!
//! Also, REG_MULTI_SZ: a null-separated list of strings, inside a null-terminated
//! buffer, inside a byte array. It's like Russian dolls but each one is more
//! disappointing than the last.

use super::{pretty, to_wide};
use serde_json::json;
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Registry::*;

/// Parses a registry path into a hive handle and subpath. Supports both the
/// "HKLM:\Software\..." PowerShell format and the "HKLM\Software\..." sane
/// format, because even the path syntax couldn't be consistent across tools.
/// Also strips "Computer\" from the beginning because regedit.exe prepends
/// that for no goddamn reason.
fn parse_hive(path: &str) -> anyhow::Result<(HKEY, &str)> {
    // Accept both "HKLM:\Software\..." and "HKLM\Software\..." formats
    let path = path.trim_start_matches("Computer\\");
    let (hive_str, subpath) = path.split_once('\\').unwrap_or((path, ""));
    let hive_str = hive_str.trim_end_matches(':');
    let hive = match hive_str.to_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,     // The Frankenstein merge-hive
        "HKU" | "HKEY_USERS" => HKEY_USERS,                    // Every user's sins in one place
        "HKCC" | "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG, // Does anyone even use this one?
        other => anyhow::bail!("Unknown registry hive: {other}"),
    };
    Ok((hive, subpath))
}

/// Turns a WIN32_ERROR into a Result because the registry APIs don't return
/// HRESULT like civilized Win32 APIs. They return WIN32_ERROR, which is just
/// a u32 that you compare against ERROR_SUCCESS (which is 0, because success
/// is nothing and nothing is success — very Zen of Microsoft).
fn win32_ok(err: WIN32_ERROR) -> anyhow::Result<()> {
    if err == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Win32 error: {}", err.0))
    }
}

/// Opens a registry key with the specified access rights. Yet another API
/// where you need to get the access flags exactly right or it fails, and
/// the flags are a bitfield you have to OR together yourself.
fn open_key(hive: HKEY, subpath: &str, access: u32) -> anyhow::Result<HKEY> {
    let wide = to_wide(subpath);
    let mut key = HKEY::default();
    unsafe {
        let err = RegOpenKeyExW(
            hive,
            windows::core::PCWSTR(wide.as_ptr()),
            None,
            REG_SAM_FLAGS(access),
            &mut key,
        );
        win32_ok(err)?;
    }
    Ok(key)
}

/// Closes a registry key. Manual resource management in 2026. Rust weeps.
fn close_key(key: HKEY) {
    unsafe { let _ = RegCloseKey(key); }
}

/// Converts registry type constants to human-readable strings. There are
/// at least seven types because Microsoft looked at a config store and
/// thought "this needs DWORD, QWORD, string, expandable string, multi-string,
/// binary, AND a none type."
fn reg_type_name(t: REG_VALUE_TYPE) -> &'static str {
    match t {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_DWORD => "REG_DWORD",
        REG_QWORD => "REG_QWORD",
        REG_BINARY => "REG_BINARY",
        REG_NONE => "REG_NONE",
        _ => "Unknown",
    }
}

/// Interprets raw registry value bytes based on the type. This is where the
/// real fun begins. REG_SZ? Wide string with a null terminator. REG_MULTI_SZ?
/// Multiple wide strings separated by nulls with a double-null terminator —
/// a.k.a. "we heard you like null terminators so we put null terminators in
/// your null-terminated strings." REG_DWORD? Four bytes, little-endian,
/// because endianness is something we should all still worry about in a
/// fucking configuration store.
fn read_value_data(data: &[u8], vtype: REG_VALUE_TYPE) -> serde_json::Value {
    match vtype {
        REG_SZ | REG_EXPAND_SZ => {
            let wide: &[u16] = unsafe {
                std::slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / 2)
            };
            let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
            json!(String::from_utf16_lossy(&wide[..len]))
        }
        REG_MULTI_SZ => {
            // Ah yes, REG_MULTI_SZ. A list of strings where each string is
            // null-terminated AND the whole thing is double-null-terminated.
            // It's the turducken of string encoding.
            let wide: &[u16] = unsafe {
                std::slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / 2)
            };
            let mut strings = Vec::new();
            let mut start = 0;
            for (i, &c) in wide.iter().enumerate() {
                if c == 0 {
                    if i > start {
                        strings.push(String::from_utf16_lossy(&wide[start..i]));
                    }
                    start = i + 1;
                }
            }
            json!(strings)
        }
        REG_DWORD => {
            if data.len() >= 4 {
                json!(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
            } else {
                json!(null)
            }
        }
        REG_QWORD => {
            if data.len() >= 8 {
                json!(u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ]))
            } else {
                json!(null)
            }
        }
        REG_BINARY => {
            // Just hex-dump it. What else are you going to do with mystery bytes?
            json!(data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "))
        }
        _ => json!(null),
    }
}

/// Reads all values from a registry key. Uses RegEnumValueW, which — you guessed
/// it — requires TWO calls per value: one to get the data size, one to get the
/// actual data. The "call it twice" pattern strikes again. Microsoft loves this
/// pattern like I love strong coffee: desperately and too frequently.
pub fn read(path: &str) -> anyhow::Result<String> {
    let (hive, subpath) = parse_hive(path)?;
    let key = open_key(hive, subpath, KEY_READ.0)?;
    let _guard = scopeguard(key);

    let mut values = serde_json::Map::new();
    let mut idx: u32 = 0;
    loop {
        let mut name_buf = vec![0u16; 16384];
        let mut name_len = name_buf.len() as u32;
        let mut vtype: u32 = 0;
        let mut data_len: u32 = 0;

        // First call: just tell me how big the data is
        let res = unsafe {
            RegEnumValueW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, Some(&mut vtype), None, Some(&mut data_len))
        };
        if res != ERROR_SUCCESS { break; }

        // Second call: okay NOW give me the actual data
        let mut data = vec![0u8; data_len as usize];
        name_len = name_buf.len() as u32;
        let res = unsafe {
            RegEnumValueW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, Some(&mut vtype), Some(data.as_mut_ptr()), Some(&mut data_len))
        };
        if res != ERROR_SUCCESS { break; }

        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let val = read_value_data(&data[..data_len as usize], REG_VALUE_TYPE(vtype));
        values.insert(name, val);
        idx += 1;
    }

    close_key(key);
    Ok(pretty(&json!(values)))
}

/// Writes a value to the registry. Uses RegCreateKeyExW which creates the key
/// if it doesn't exist (convenient!) and gives you a disposition telling you
/// whether it was created or opened (which we promptly ignore, because who cares).
/// The actual write via RegSetValueExW requires you to manually serialize your
/// value to bytes and tell it the type. There's no type safety. You can write
/// garbage bytes and call them REG_SZ. The registry does not judge. The registry
/// has seen things.
pub fn write(path: &str, name: &str, value: &str, value_type: &str) -> anyhow::Result<String> {
    let (hive, subpath) = parse_hive(path)?;

    // Create key if it doesn't exist
    let wide_path = to_wide(subpath);
    let mut key = HKEY::default();
    let mut _disp = REG_CREATE_KEY_DISPOSITION::default();
    unsafe {
        let err = RegCreateKeyExW(
            hive,
            windows::core::PCWSTR(wide_path.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            Some(&mut _disp),
        );
        win32_ok(err)?;
    }
    let _guard = scopeguard(key);

    let name_wide = to_wide(name);
    let name_pcwstr = windows::core::PCWSTR(name_wide.as_ptr());

    match value_type.to_uppercase().as_str() {
        "STRING" | "REG_SZ" => {
            let val_wide = to_wide(value);
            let bytes = unsafe { std::slice::from_raw_parts(val_wide.as_ptr() as *const u8, val_wide.len() * 2) };
            unsafe { win32_ok(RegSetValueExW(key, name_pcwstr, None, REG_SZ, Some(bytes)))?; }
        }
        "DWORD" | "REG_DWORD" => {
            let dw: u32 = value.parse().map_err(|_| anyhow::anyhow!("Invalid DWORD value: {value}"))?;
            let bytes = dw.to_le_bytes();
            unsafe { win32_ok(RegSetValueExW(key, name_pcwstr, None, REG_DWORD, Some(&bytes)))?; }
        }
        "QWORD" | "REG_QWORD" => {
            let qw: u64 = value.parse().map_err(|_| anyhow::anyhow!("Invalid QWORD value: {value}"))?;
            let bytes = qw.to_le_bytes();
            unsafe { win32_ok(RegSetValueExW(key, name_pcwstr, None, REG_QWORD, Some(&bytes)))?; }
        }
        "EXPANDSTRING" | "REG_EXPAND_SZ" => {
            let val_wide = to_wide(value);
            let bytes = unsafe { std::slice::from_raw_parts(val_wide.as_ptr() as *const u8, val_wide.len() * 2) };
            unsafe { win32_ok(RegSetValueExW(key, name_pcwstr, None, REG_EXPAND_SZ, Some(bytes)))?; }
        }
        other => anyhow::bail!("Unsupported type: {other}. Use String, DWord, QWord, or ExpandString"),
    }

    close_key(key);
    Ok(pretty(&json!({ "Path": path, "Name": name, "Value": value, "Type": value_type, "Status": "Written" })))
}

/// Deletes a registry value, or an entire key if name is "*". RegDeleteKeyExW
/// for keys, RegDeleteValueW for values. The "*" convention is our own because
/// the Win32 API has no concept of "delete everything" — you'd normally have to
/// recursively enumerate and delete, because the registry is a tree and trees
/// don't delete themselves. Unless you're on fire. Like this codebase.
pub fn delete(path: &str, name: &str) -> anyhow::Result<String> {
    let (hive, subpath) = parse_hive(path)?;

    if name == "*" {
        // Delete entire key
        let wide = to_wide(subpath);
        unsafe { win32_ok(RegDeleteKeyExW(hive, windows::core::PCWSTR(wide.as_ptr()), KEY_WOW64_64KEY.0, Some(0)))?; }
        Ok(pretty(&json!({ "Deleted": path, "Type": "Key" })))
    } else {
        // Delete single value
        let key = open_key(hive, subpath, KEY_SET_VALUE.0)?;
        let name_wide = to_wide(name);
        unsafe { win32_ok(RegDeleteValueW(key, windows::core::PCWSTR(name_wide.as_ptr())))?; }
        close_key(key);
        Ok(pretty(&json!({ "Deleted": name, "Path": path, "Type": "Value" })))
    }
}

/// Lists subkeys and values under a registry path. Enumerates both subkeys
/// (via RegEnumKeyExW) and values (via the double-call RegEnumValueW dance).
/// Each value read requires two API calls. If a key has 100 values, that's
/// 200 syscalls. Efficiency!
pub fn list_key(path: &str) -> anyhow::Result<String> {
    let (hive, subpath) = parse_hive(path)?;
    let key = open_key(hive, subpath, KEY_READ.0)?;
    let _guard = scopeguard(key);

    // Enumerate subkeys
    let mut subkeys = Vec::new();
    let mut idx: u32 = 0;
    loop {
        let mut name_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let res = unsafe { RegEnumKeyExW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None) };
        if res != ERROR_SUCCESS { break; }
        subkeys.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
        idx += 1;
    }

    // Enumerate values — here we go again with the two-call tango
    let mut value_entries = Vec::new();
    idx = 0;
    loop {
        let mut name_buf = vec![0u16; 16384];
        let mut name_len = name_buf.len() as u32;
        let mut vtype: u32 = 0;
        let mut data_len: u32 = 0;
        let res = unsafe {
            RegEnumValueW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, Some(&mut vtype), None, Some(&mut data_len))
        };
        if res != ERROR_SUCCESS { break; }

        let mut data = vec![0u8; data_len as usize];
        name_len = name_buf.len() as u32;
        let res = unsafe {
            RegEnumValueW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, Some(&mut vtype), Some(data.as_mut_ptr()), Some(&mut data_len))
        };
        if res != ERROR_SUCCESS { break; }

        let vtype_enum = REG_VALUE_TYPE(vtype);
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let val = read_value_data(&data[..data_len as usize], vtype_enum);
        value_entries.push(json!({ "Name": name, "Type": reg_type_name(vtype_enum), "Data": val }));
        idx += 1;
    }

    close_key(key);
    Ok(pretty(&json!({ "SubKeys": subkeys, "Values": value_entries })))
}

/// Recursively searches the registry for keys or values matching a pattern.
/// This is depth-first traversal of an arbitrarily deep tree where any node
/// might be access-denied, any key might have thousands of values, and the
/// whole thing could take minutes on HKLM. We cap results with a limit
/// because without one, searching HKCR (which has roughly ten billion file
/// extension mappings) would run until the heat death of the universe.
pub fn search(path: &str, pattern: &str, limit: u32) -> anyhow::Result<String> {
    let (hive, subpath) = parse_hive(path)?;
    let mut results = Vec::new();
    let pattern_lower = pattern.to_lowercase();
    search_recursive(hive, subpath, &pattern_lower, limit, &mut results);
    Ok(pretty(&json!(results)))
}

/// The recursive search workhorse. Opens each key, checks value names, checks
/// subkey names, then recurses into child keys. If a key can't be opened (ACCESS
/// DENIED, usually because it's some protected system key), we just skip it and
/// move on. No error, no warning, just silent acceptance that the registry has
/// places we're not welcome. Like most of Windows, really.
fn search_recursive(hive: HKEY, subpath: &str, pattern: &str, limit: u32, results: &mut Vec<serde_json::Value>) {
    if results.len() >= limit as usize { return; }

    let key = match open_key(hive, subpath, KEY_READ.0) {
        Ok(k) => k,
        Err(_) => return, // ACCESS DENIED? Cool, cool, cool. Moving on.
    };

    // Check value names
    let mut idx: u32 = 0;
    loop {
        if results.len() >= limit as usize { break; }
        let mut name_buf = vec![0u16; 16384];
        let mut name_len = name_buf.len() as u32;
        let res = unsafe { RegEnumValueW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None) };
        if res != ERROR_SUCCESS { break; }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if name.to_lowercase().contains(pattern) {
            results.push(json!({ "Path": format!("{subpath}"), "ValueName": name }));
        }
        idx += 1;
    }

    // Recurse into subkeys — abandon all hope ye who enter here
    idx = 0;
    let mut child_names = Vec::new();
    loop {
        let mut name_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let res = unsafe { RegEnumKeyExW(key, idx, Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None) };
        if res != ERROR_SUCCESS { break; }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if name.to_lowercase().contains(pattern) && results.len() < limit as usize {
            results.push(json!({ "Path": format!("{subpath}\\{name}"), "Type": "Key" }));
        }
        child_names.push(name);
        idx += 1;
    }

    close_key(key);

    for child in child_names {
        if results.len() >= limit as usize { break; }
        let child_path = if subpath.is_empty() { child.clone() } else { format!("{subpath}\\{child}") };
        search_recursive(hive, &child_path, pattern, limit, results);
    }
}

/// A poor man's scope guard for HKEY cleanup. We can't use the `scopeguard`
/// crate because that would mean adding a dependency for something that should
/// be a language feature. Oh wait, Rust DOES have RAII, but HKEY isn't a Rust
/// type so we get to build our own Drop impl. Again. For the fifth time today.
fn scopeguard(key: HKEY) -> impl Drop {
    struct Guard(HKEY);
    impl Drop for Guard {
        fn drop(&mut self) { close_key(self.0); }
    }
    Guard(key)
}
