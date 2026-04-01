//! # Clipboard API: The Most Overcomplicated Copy-Paste in Computing History
//!
//! You want to put text on the clipboard? Cool. Here's what you have to do:
//!
//!   1. `GlobalAlloc` — Allocate global memory with GMEM_MOVEABLE (because the
//!      memory might MOVE, like a Windows-managed nomad)
//!   2. `GlobalLock` — Lock the memory so it stops moving and gives you a pointer
//!   3. Copy your bytes into the pointer
//!   4. `GlobalUnlock` — Let the memory roam free again
//!   5. `OpenClipboard` — Open the clipboard (takes an optional window handle;
//!      pass None for "I don't have a window and I don't care")
//!   6. `EmptyClipboard` — Clear whatever was there before
//!   7. `SetClipboardData` — Hand ownership of the memory to the clipboard
//!   8. `CloseClipboard` — Close the clipboard
//!
//! That's EIGHT steps to do what Ctrl+C does in one keystroke. And if you get
//! the order wrong, or forget to close the clipboard, you've just locked it
//! for the entire system. Every other app's paste will fail. Because of you.
//!
//! The GlobalAlloc/GlobalLock pattern is from Windows 3.1's cooperative
//! multitasking era when memory could be relocated by the OS. We still use it
//! in 2026 because backward compatibility is Windows' only religion.

use super::{pretty, to_wide};
use serde_json::json;
use windows::Win32::Foundation::*;
use windows::Win32::System::DataExchange::*;
use windows::Win32::System::Memory::*;

/// CF_UNICODETEXT = 13. The clipboard format for Unicode text. There are dozens
/// of clipboard formats (CF_TEXT, CF_BITMAP, CF_HDROP, CF_HTML...) but we only
/// care about this one because we're not monsters.
const CF_UNICODETEXT: u32 = 13;

/// Gets the current clipboard text. Opens the clipboard with None as the window
/// handle (because we don't have a window — we're a fucking MCP server), grabs
/// the data handle, GlobalLock's it to get a pointer, reads the wide string,
/// then GlobalUnlock's and CloseClipboard's. If this sounds like a lot of
/// ceremony for "read a string" — it is. It absolutely is.
pub fn get() -> anyhow::Result<String> {
    unsafe {
        // Open clipboard with no window handle. None means "any window on this
        // thread can claim it." We have no windows. We are windowless. Ironic,
        // for a Windows application.
        OpenClipboard(None)?;

        let text = match GetClipboardData(CF_UNICODETEXT) {
            Err(_) => String::from("(clipboard empty or not text)"),
            Ok(handle) => {
                // GlobalLock: "please stop moving this memory around and let me
                // read it." Returns a raw pointer because safety is for other APIs.
                let ptr = GlobalLock(HGLOBAL(handle.0)) as *const u16;
                if ptr.is_null() {
                    let _ = CloseClipboard();
                    anyhow::bail!("Failed to lock clipboard data");
                }
                let text = super::from_wide(ptr);
                // GlobalUnlock: "okay you can move it again, I'm done."
                // This entire lock/unlock dance exists because Windows 3.1
                // needed to defragment memory. In 2026. We still do this.
                let _ = GlobalUnlock(HGLOBAL(handle.0));
                text
            }
        };

        let _ = CloseClipboard();
        Ok(text)
    }
}

/// Sets the clipboard text. This is the full eight-step ritual described above.
/// GlobalAlloc with GMEM_MOVEABLE, GlobalLock, memcpy, GlobalUnlock,
/// OpenClipboard, EmptyClipboard, SetClipboardData, CloseClipboard.
/// If any step fails, we have to clean up everything we've done so far
/// because there's no transaction rollback. It's manual state management
/// at its absolute finest.
///
/// Note: after SetClipboardData succeeds, the clipboard OWNS the memory.
/// Do NOT free it. The clipboard will free it when it's good and ready.
/// If SetClipboardData fails though? Then YOU still own it and must free it.
/// Ownership semantics that would make even C++ move semantics blush.
pub fn set(text: &str) -> anyhow::Result<String> {
    let wide = to_wide(text);
    let byte_len = wide.len() * 2;

    unsafe {
        // Step 1: Allocate moveable global memory. GMEM_MOVEABLE because the
        // clipboard API demands it. In 2026. For text. On a machine with 32GB of RAM.
        let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len)?;
        // Step 2: Lock it down so we can write to it
        let ptr = GlobalLock(hmem) as *mut u16;
        if ptr.is_null() {
            let _ = GlobalFree(Some(hmem));
            anyhow::bail!("Failed to lock allocated memory");
        }
        // Step 3: Copy the bytes. Raw pointer memcpy. In a "safe" language. Sure.
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        // Step 4: Unlock. The memory is now a free-range pointer again.
        let _ = GlobalUnlock(hmem);

        // Step 5: Open the clipboard. If this fails, we still own the memory
        // and have to free it ourselves. Fun error handling!
        if let Err(e) = OpenClipboard(None) {
            let _ = GlobalFree(Some(hmem));
            anyhow::bail!("Failed to open clipboard: {e}");
        }

        // Step 6: Empty the clipboard. Out with the old.
        let _ = EmptyClipboard();
        // Step 7: Hand the memory to the clipboard. It's the clipboard's problem now.
        // DO NOT free hmem after this — the clipboard owns it. Double-free = crash.
        let result = SetClipboardData(CF_UNICODETEXT, Some(HANDLE(hmem.0)));
        // Step 8: Close the clipboard. Finally. Jesus Christ. We're done.
        let _ = CloseClipboard();

        if result.is_err() {
            anyhow::bail!("Failed to set clipboard data");
        }

        Ok(pretty(&json!({
            "Status": "Copied",
            "Length": text.len(),
        })))
    }
}
