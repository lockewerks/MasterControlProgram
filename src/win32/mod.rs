//! # Direct Win32 Syscall Layer
//!
//! This is where we bypass PowerShell's bloated ass and talk directly to the
//! Windows kernel like adults. Sub-millisecond responses instead of waiting
//! 1.5 seconds for PowerShell to load half of .NET just to count processes.
//!
//! 41 of our 98 tools run through here. The other 57 are stuck in PowerShell
//! purgatory because Microsoft decided that firewall rules, scheduled tasks,
//! and user management should only be accessible through COM objects.
//! Thanks, Microsoft. Real cool.

pub mod process;
pub mod service;
pub mod registry;
pub mod sysinfo;
pub mod network;
pub mod filesystem;
pub mod clipboard;
pub mod screen;
pub mod input;

use windows::core::PWSTR;

/// Convert a &str to a null-terminated UTF-16 wide string.
/// Because Windows decided in 1993 that UTF-16 was the future,
/// and now we all have to live with that decision forever.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert a raw UTF-16 pointer to a Rust String.
/// Walks the pointer until it hits a null terminator, like a dog
/// looking for the end of a fence. Lossy because sometimes Windows
/// gives us garbage and we just have to deal with it.
///
/// # Safety
/// The pointer must point to a valid null-terminated wide string,
/// or you get to enjoy undefined behavior as a treat.
pub unsafe fn from_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Convert a PWSTR to a Rust String. A thin wrapper because we're
/// too lazy to write `unsafe { from_wide(p.0) }` every damn time.
#[allow(dead_code)]
pub fn pwstr_to_string(p: &PWSTR) -> String {
    unsafe { from_wide(p.0) }
}

/// Convert a fixed-size wide char buffer (like the ones Win32 loves to hand you)
/// into a proper String. Trims at the first null terminator because Windows
/// pads these buffers with more zeros than a politician's promises.
pub fn wchar_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Pretty-print JSON because raw JSON is for machines and we have *some* dignity.
pub fn pretty(val: &serde_json::Value) -> String {
    serde_json::to_string_pretty(val).unwrap_or_else(|_| val.to_string())
}
