//! # Screen Capture via GDI
//!
//! You'd think Windows would have a simple "take screenshot" function.
//! You'd be wrong. Instead, we get to play with Device Contexts,
//! compatible bitmaps, and bit-blitting like it's 1995.
//!
//! The pipeline:
//!   1. GetDC(NULL) — get the screen's device context
//!   2. CreateCompatibleDC — make a memory DC to draw into
//!   3. CreateCompatibleBitmap — make a bitmap the size of the capture
//!   4. SelectObject — attach the bitmap to the memory DC
//!   5. BitBlt — blast screen pixels into our bitmap
//!   6. GetDIBits — extract raw BGRA pixels from the bitmap
//!   7. Convert BGRA → RGB (because nobody wants Windows' weirdo byte order)
//!   8. Encode to JPEG, then base64 for MCP transport
//!
//! That's EIGHT steps to take a screenshot. Windows: making the simple complex
//! since 1985.

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::*;

/// Capture a region of the screen and return (base64_jpeg, width, height).
///
/// If x/y/width/height are None, captures the full **virtual screen** —
/// every monitor, at real physical resolution. Virtual screen coordinates
/// can be negative: the primary monitor's top-left is (0,0), monitors to
/// the left have negative X, monitors above have negative Y.
///
/// This matches the coordinate space SetCursorPos uses (once the process
/// is DPI-aware), so a coordinate you see in a screenshot is the same
/// coordinate you pass to the mouse tools.
pub fn capture(
    x: Option<i32>,
    y: Option<i32>,
    width: Option<u32>,
    height: Option<u32>,
) -> Result<(String, u32, u32)> {
    unsafe {
        // Defaults span the entire virtual desktop, not just the primary monitor.
        // SM_XVIRTUALSCREEN / SM_YVIRTUALSCREEN can be negative when monitors
        // sit to the left or above the primary — that's fine, BitBlt accepts it.
        let cap_x = x.unwrap_or_else(|| GetSystemMetrics(SM_XVIRTUALSCREEN));
        let cap_y = y.unwrap_or_else(|| GetSystemMetrics(SM_YVIRTUALSCREEN));
        let cap_w = width.unwrap_or_else(|| GetSystemMetrics(SM_CXVIRTUALSCREEN) as u32);
        let cap_h = height.unwrap_or_else(|| GetSystemMetrics(SM_CYVIRTUALSCREEN) as u32);

        if cap_w == 0 || cap_h == 0 {
            anyhow::bail!("Invalid capture dimensions: {cap_w}x{cap_h}");
        }

        // Step 1: Get the screen device context. None = entire desktop surface.
        let hdc_screen = GetDC(None);

        // Step 2-4: Create a memory DC with a compatible bitmap attached
        let hdc_mem = CreateCompatibleDC(Some(hdc_screen));
        let hbm = CreateCompatibleBitmap(hdc_screen, cap_w as i32, cap_h as i32);
        let old_obj = SelectObject(hdc_mem, hbm.into());

        // Step 5: BitBlt — copy screen pixels into our bitmap
        BitBlt(
            hdc_mem,
            0,
            0,
            cap_w as i32,
            cap_h as i32,
            Some(hdc_screen),
            cap_x,
            cap_y,
            SRCCOPY,
        )?;

        // Step 6: Extract raw BGRA pixel data
        // Negative biHeight = top-down row order (what PNG expects)
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = cap_w as i32;
        bmi.bmiHeader.biHeight = -(cap_h as i32);
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        // biCompression = BI_RGB = 0, already zeroed

        let pixel_count = (cap_w * cap_h) as usize;
        let mut bgra = vec![0u8; pixel_count * 4];
        let lines = GetDIBits(
            hdc_mem,
            hbm,
            0,
            cap_h,
            Some(bgra.as_mut_ptr() as *mut _),
            &mut bmi,
            DIB_RGB_COLORS,
        );

        // Cleanup GDI resources — order matters, reverse of creation
        SelectObject(hdc_mem, old_obj);
        let _ = DeleteObject(hbm.into());
        let _ = DeleteDC(hdc_mem);
        ReleaseDC(None, hdc_screen);

        if lines == 0 {
            anyhow::bail!("GetDIBits failed — captured 0 scan lines");
        }

        // Step 7: Convert BGRA → RGB for PNG
        // Windows gives us Blue-Green-Red-Alpha, PNG wants Red-Green-Blue.
        // Thanks, Windows, for being backwards. Literally.
        let mut rgb = vec![0u8; pixel_count * 3];
        for i in 0..pixel_count {
            rgb[i * 3] = bgra[i * 4 + 2]; // R ← B position
            rgb[i * 3 + 1] = bgra[i * 4 + 1]; // G stays
            rgb[i * 3 + 2] = bgra[i * 4]; // B ← R position
        }

        // Step 8: Encode to JPEG, then base64
        // JPEG is way smaller than PNG for screenshots — less data to shove
        // through MCP transport, faster round-trips, everybody wins.
        let mut jpeg_buf = Vec::new();
        let encoder = jpeg_encoder::Encoder::new(&mut jpeg_buf, 80);
        encoder.encode(
            &rgb,
            cap_w as u16,
            cap_h as u16,
            jpeg_encoder::ColorType::Rgb,
        ).map_err(|e| anyhow::anyhow!("JPEG encode failed: {e}"))?;

        let b64 = STANDARD.encode(&jpeg_buf);
        Ok((b64, cap_w, cap_h))
    }
}
