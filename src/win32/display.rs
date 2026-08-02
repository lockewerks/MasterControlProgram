//! # Monitor Info via EnumDisplayMonitors
//!
//! Returns one record per physical monitor with its virtual-screen rect,
//! work area, and orientation pulled from DEVMODE. This replaces the old
//! PowerShell `Win32_VideoController` path which returned GPU info, not
//! monitor geometry, and never mentioned rotation at all, it just silently
//! swapped width and height on portrait monitors which made coordinate math
//! a guessing game.
//!
//! Pipeline:
//!   1. EnumDisplayMonitors with a callback that collects HMONITOR handles
//!   2. GetMonitorInfoW for each HMONITOR → device name + rects + primary flag
//!   3. EnumDisplaySettingsW with device name → DEVMODE with dmDisplayOrientation,
//!      dmPelsWidth/Height, dmDisplayFrequency, dmBitsPerPel
//!
//! Also reports the full virtual screen envelope so callers can cross-reference
//! with mouse and screen_capture coordinates.

use super::{pretty, wchar_to_string};
use anyhow::Result;
use serde_json::json;
use windows::Win32::Foundation::{LPARAM, RECT, TRUE};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{BOOL, PCWSTR};

/// Callback for EnumDisplayMonitors. Appends each HMONITOR to the Vec
/// passed via LPARAM. Always returns TRUE to keep the enumeration going.
unsafe extern "system" fn enum_proc(
    hmon: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    let monitors = unsafe { &mut *(lparam.0 as *mut Vec<HMONITOR>) };
    monitors.push(hmon);
    TRUE
}

pub fn info() -> Result<String> {
    unsafe {
        let mut handles: Vec<HMONITOR> = Vec::new();
        let ok = EnumDisplayMonitors(
            None,
            None,
            Some(enum_proc),
            LPARAM(&mut handles as *mut _ as isize),
        );
        if !ok.as_bool() {
            anyhow::bail!("EnumDisplayMonitors failed");
        }

        let mut monitors = Vec::with_capacity(handles.len());
        for (i, hmon) in handles.iter().enumerate() {
            let mut info_ex: MONITORINFOEXW = std::mem::zeroed();
            info_ex.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;

            let got = GetMonitorInfoW(*hmon, &mut info_ex.monitorInfo as *mut MONITORINFO);
            if !got.as_bool() {
                continue;
            }

            let rc = info_ex.monitorInfo.rcMonitor;
            let work = info_ex.monitorInfo.rcWork;
            let is_primary = info_ex.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0;
            let device_name = wchar_to_string(&info_ex.szDevice);

            // DEVMODE pulls refresh rate, bit depth, and most importantly
            // dmDisplayOrientation so we can distinguish landscape vs portrait
            // vs flipped instead of pretending rotated monitors don't exist.
            let mut devmode: DEVMODEW = std::mem::zeroed();
            devmode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
            let device_ptr = PCWSTR(info_ex.szDevice.as_ptr());
            let have_devmode =
                EnumDisplaySettingsW(device_ptr, ENUM_CURRENT_SETTINGS, &mut devmode).as_bool();

            let (orientation, orientation_degrees) = if have_devmode {
                // The orientation field lives inside a nested anonymous union.
                // Windows-RS exposes it as Anonymous1.Anonymous2.dmDisplayOrientation.
                // Values: 0=DMDO_DEFAULT, 1=DMDO_90, 2=DMDO_180, 3=DMDO_270.
                let orient = devmode.Anonymous1.Anonymous2.dmDisplayOrientation;
                match orient {
                    DMDO_DEFAULT => ("Landscape", 0u32),
                    DMDO_90 => ("Portrait (rotated 90° CCW)", 90),
                    DMDO_180 => ("Landscape (flipped 180°)", 180),
                    DMDO_270 => ("Portrait (rotated 270° CCW)", 270),
                    _ => ("Unknown", 0),
                }
            } else {
                ("Unknown (DEVMODE unavailable)", 0)
            };

            monitors.push(json!({
                "Index": i,
                "Device": device_name,
                "Primary": is_primary,
                "Bounds": {
                    "Left": rc.left,
                    "Top": rc.top,
                    "Right": rc.right,
                    "Bottom": rc.bottom,
                    "Width": rc.right - rc.left,
                    "Height": rc.bottom - rc.top,
                },
                "WorkArea": {
                    "Left": work.left,
                    "Top": work.top,
                    "Right": work.right,
                    "Bottom": work.bottom,
                    "Width": work.right - work.left,
                    "Height": work.bottom - work.top,
                },
                "Orientation": orientation,
                "OrientationDegrees": orientation_degrees,
                "RefreshHz": if have_devmode { devmode.dmDisplayFrequency } else { 0 },
                "BitsPerPixel": if have_devmode { devmode.dmBitsPerPel } else { 0 },
                "PelsWidth": if have_devmode { devmode.dmPelsWidth } else { 0 },
                "PelsHeight": if have_devmode { devmode.dmPelsHeight } else { 0 },
            }));
        }

        let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        Ok(pretty(&json!({
            "MonitorCount": monitors.len(),
            "Monitors": monitors,
            "VirtualScreen": {
                "OriginX": vx,
                "OriginY": vy,
                "Width": vw,
                "Height": vh,
                "Note": "Mouse and screen_capture coordinates live in this space. A monitor with negative Left/Top is left of / above the primary.",
            },
        })))
    }
}
