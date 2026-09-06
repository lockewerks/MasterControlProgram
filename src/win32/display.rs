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
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{LPARAM, RECT, TRUE};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::HiDpi::{
    GetDpiForMonitor, SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, MDT_EFFECTIVE_DPI,
};
use windows::Win32::UI::WindowsAndMessaging::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub(crate) struct Rect {
    #[serde(deserialize_with = "crate::coerce::num")]
    pub x: i32,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub y: i32,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub width: u32,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub height: u32,
}

impl Rect {
    pub fn right(&self) -> i64 {
        i64::from(self.x) + i64::from(self.width)
    }

    pub fn bottom(&self) -> i64 {
        i64::from(self.y) + i64::from(self.height)
    }

    pub fn validate(&self) -> Result<()> {
        if self.width == 0 || self.height == 0 {
            bail!("A rectangle must have nonzero width and height");
        }
        if self.width > i32::MAX as u32
            || self.height > i32::MAX as u32
            || self.right() > i64::from(i32::MAX)
            || self.bottom() > i64::from(i32::MAX)
        {
            bail!("Rectangle coordinates exceed the Win32 coordinate range");
        }
        Ok(())
    }

    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let x = i64::from(self.x.max(other.x));
        let y = i64::from(self.y.max(other.y));
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());
        (right > x && bottom > y).then_some(Self {
            x: x as i32,
            y: y as i32,
            width: (right - x).max(0) as u32,
            height: (bottom - y).max(0) as u32,
        })
    }

    pub fn from_native(rect: RECT) -> Result<Self> {
        let width = i64::from(rect.right) - i64::from(rect.left);
        let height = i64::from(rect.bottom) - i64::from(rect.top);
        let rect = Self {
            x: rect.left,
            y: rect.top,
            width: u32::try_from(width).context("Invalid native rectangle width")?,
            height: u32::try_from(height).context("Invalid native rectangle height")?,
        };
        rect.validate()?;
        Ok(rect)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Monitor {
    pub index: u32,
    pub device: String,
    pub primary: bool,
    pub bounds: Rect,
    pub work_area: Rect,
    pub orientation: String,
    pub orientation_degrees: u32,
    pub refresh_hz: u32,
    pub bits_per_pixel: u32,
    pub pels_width: u32,
    pub pels_height: u32,
    pub dpi_x: Option<u32>,
    pub dpi_y: Option<u32>,
    pub scale_x: Option<f64>,
    pub scale_y: Option<f64>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Geometry {
    pub virtual_screen: Rect,
    pub monitors: Vec<Monitor>,
}

// Blocking-pool threads can inherit a caller's DPI context. Restore that
// context when the native operation ends rather than changing the whole pool.
pub(crate) struct DpiScope(DPI_AWARENESS_CONTEXT);

impl DpiScope {
    pub fn enter() -> Result<Self> {
        let old =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if old.0.is_null() {
            bail!(
                "SetThreadDpiAwarenessContext failed: {}",
                windows::core::Error::from_thread()
            );
        }
        Ok(Self(old))
    }
}

impl Drop for DpiScope {
    fn drop(&mut self) {
        unsafe {
            if SetThreadDpiAwarenessContext(self.0).0.is_null() {
                tracing::warn!("Could not restore the thread DPI context");
            }
        }
    }
}

#[derive(Default)]
struct MonitorHandles {
    handles: Vec<HMONITOR>,
    overflow: bool,
}

unsafe extern "system" fn enum_proc(
    hmon: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    let monitors = unsafe { &mut *(lparam.0 as *mut MonitorHandles) };
    if monitors.handles.len() >= 256 {
        monitors.overflow = true;
        return BOOL(0);
    }
    monitors.handles.push(hmon);
    TRUE
}

pub(crate) fn geometry() -> Result<Geometry> {
    let _dpi = DpiScope::enter()?;
    unsafe {
        let mut handles = MonitorHandles::default();
        let ok = EnumDisplayMonitors(
            None,
            None,
            Some(enum_proc),
            LPARAM(&mut handles as *mut _ as isize),
        );
        if handles.overflow {
            bail!("Monitor enumeration exceeded the 256-monitor limit");
        }
        if !ok.as_bool() {
            bail!(
                "EnumDisplayMonitors failed: {}",
                windows::core::Error::from_thread()
            );
        }

        let mut monitors = Vec::with_capacity(handles.handles.len());
        for (i, hmon) in handles.handles.iter().enumerate() {
            let mut info_ex: MONITORINFOEXW = std::mem::zeroed();
            info_ex.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;

            let got = GetMonitorInfoW(*hmon, &mut info_ex.monitorInfo as *mut MONITORINFO);
            if !got.as_bool() {
                bail!(
                    "GetMonitorInfoW failed for monitor {i}: {}",
                    windows::core::Error::from_thread()
                );
            }

            let rc = info_ex.monitorInfo.rcMonitor;
            let work = info_ex.monitorInfo.rcWork;
            let is_primary = info_ex.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0;
            let device_name = wchar_to_string(&info_ex.szDevice);

            let mut devmode: DEVMODEW = std::mem::zeroed();
            devmode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
            let device_ptr = PCWSTR(info_ex.szDevice.as_ptr());
            let have_devmode =
                EnumDisplaySettingsW(device_ptr, ENUM_CURRENT_SETTINGS, &mut devmode).as_bool();

            let (orientation, orientation_degrees) = if have_devmode {
                let orient = devmode.Anonymous1.Anonymous2.dmDisplayOrientation;
                match orient {
                    DMDO_DEFAULT => ("Landscape", 0u32),
                    DMDO_90 => ("Portrait (rotated 90\u{b0} CCW)", 90),
                    DMDO_180 => ("Landscape (flipped 180\u{b0})", 180),
                    DMDO_270 => ("Portrait (rotated 270\u{b0} CCW)", 270),
                    _ => ("Unknown", 0),
                }
            } else {
                ("Unknown (DEVMODE unavailable)", 0)
            };

            let mut limitations = Vec::new();
            if !have_devmode {
                limitations.push("Current display settings are unavailable".into());
            }
            let (mut dpi_x, mut dpi_y) = (0, 0);
            let dpi = match GetDpiForMonitor(*hmon, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) {
                Ok(()) if dpi_x > 0 && dpi_y > 0 => Some((dpi_x, dpi_y)),
                Ok(()) => {
                    limitations.push("Monitor DPI was reported as zero".into());
                    None
                }
                Err(e) => {
                    limitations.push(format!("Monitor DPI unavailable: {e}"));
                    None
                }
            };
            monitors.push(Monitor {
                index: i as u32,
                device: device_name,
                primary: is_primary,
                bounds: Rect::from_native(rc)?,
                work_area: Rect::from_native(work)?,
                orientation: orientation.into(),
                orientation_degrees,
                refresh_hz: if have_devmode {
                    devmode.dmDisplayFrequency
                } else {
                    0
                },
                bits_per_pixel: if have_devmode {
                    devmode.dmBitsPerPel
                } else {
                    0
                },
                pels_width: if have_devmode { devmode.dmPelsWidth } else { 0 },
                pels_height: if have_devmode {
                    devmode.dmPelsHeight
                } else {
                    0
                },
                dpi_x: dpi.map(|d| d.0),
                dpi_y: dpi.map(|d| d.1),
                scale_x: dpi.map(|d| f64::from(d.0) / 96.0),
                scale_y: dpi.map(|d| f64::from(d.1) / 96.0),
                limitations,
            });
        }

        let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if vw <= 0 || vh <= 0 || monitors.is_empty() {
            bail!("No accessible interactive desktop monitors are available");
        }
        let virtual_screen = Rect {
            x: GetSystemMetrics(SM_XVIRTUALSCREEN),
            y: GetSystemMetrics(SM_YVIRTUALSCREEN),
            width: vw as u32,
            height: vh as u32,
        };
        virtual_screen.validate()?;
        Ok(Geometry {
            virtual_screen,
            monitors,
        })
    }
}

pub fn info() -> Result<String> {
    let geometry = geometry()?;
    fn legacy_rect(rect: Rect) -> serde_json::Value {
        json!({
            "Left": rect.x, "Top": rect.y, "Right": rect.right(), "Bottom": rect.bottom(),
            "Width": rect.width, "Height": rect.height,
        })
    }
    let monitors: Vec<_> = geometry
        .monitors
        .iter()
        .map(|m| {
            json!({
                "Index": m.index, "Device": m.device, "Primary": m.primary,
                "Bounds": legacy_rect(m.bounds), "WorkArea": legacy_rect(m.work_area),
                "Orientation": m.orientation, "OrientationDegrees": m.orientation_degrees,
                "RefreshHz": m.refresh_hz, "BitsPerPixel": m.bits_per_pixel,
                "PelsWidth": m.pels_width, "PelsHeight": m.pels_height,
                "DpiX": m.dpi_x, "DpiY": m.dpi_y, "ScaleX": m.scale_x, "ScaleY": m.scale_y,
                "Limitations": m.limitations,
            })
        })
        .collect();
    Ok(pretty(&json!({
        "MonitorCount": monitors.len(), "Monitors": monitors,
        "VirtualScreen": {
            "OriginX": geometry.virtual_screen.x, "OriginY": geometry.virtual_screen.y,
            "Width": geometry.virtual_screen.width, "Height": geometry.virtual_screen.height,
            "Note": "Mouse and screen_capture coordinates live in this space. A monitor with negative Left/Top is left of / above the primary.",
        },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_coordinates_intersect_without_unsigned_wrap() {
        let desktop = Rect {
            x: -1920,
            y: -1080,
            width: 3840,
            height: 2160,
        };
        let area = Rect {
            x: -2000,
            y: -100,
            width: 200,
            height: 200,
        };
        assert_eq!(
            desktop.intersect(&area),
            Some(Rect {
                x: -1920,
                y: -100,
                width: 120,
                height: 200
            })
        );
        assert_eq!(
            desktop.intersect(&Rect {
                x: 1920,
                y: 0,
                width: 1,
                height: 1
            }),
            None
        );
    }

    #[test]
    fn rectangles_reject_zero_and_coordinate_overflow() {
        assert!(Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 1
        }
        .validate()
        .is_err());
        assert!(Rect {
            x: i32::MAX,
            y: 0,
            width: 1,
            height: 1
        }
        .validate()
        .is_err());
        assert!(Rect {
            x: i32::MIN,
            y: 0,
            width: u32::MAX,
            height: 1
        }
        .validate()
        .is_err());
    }

    #[test]
    fn rectangles_accept_numeric_strings() {
        let rect: Rect =
            serde_json::from_str(r#"{"x":"-1920","y":"-100","width":"800","height":"600"}"#)
                .unwrap();
        assert_eq!(
            rect,
            Rect {
                x: -1920,
                y: -100,
                width: 800,
                height: 600
            }
        );
    }
}
