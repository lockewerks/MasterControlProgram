use super::display::{self, DpiScope, Geometry, Rect};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use std::io::Write;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use windows::core::BOOL;
use windows::Win32::Foundation::{HWND, LPARAM, RECT};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::desktop::windows::{WindowIdentity, WindowRecord};
use crate::desktop::{require_session, Operation, SessionIdentity};

const MAX_CAPTURE_PIXELS: u64 = 40_000_000;
const MAX_JPEG_BYTES: usize = 64 * 1024 * 1024;
static CAPTURE: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone)]
pub(crate) enum CaptureSource {
    Desktop,
    Monitor(u32),
    Window(WindowRecord),
    Region(Rect),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CaptureIdentity {
    Desktop,
    Monitor {
        index: u32,
        device: String,
    },
    Window {
        window_ref: String,
        identity: WindowIdentity,
    },
    Region,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureContent {
    VisibleDesktop,
    WindowVisibleRegion,
    #[serde(rename = "window_region_with_potential_occlusion")]
    WindowOccludedRegion,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Occluder {
    pub hwnd: u64,
    pub bounds: Rect,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CursorMetadata {
    pub state: &'static str,
    pub composited: bool,
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub hotspot_x: Option<u32>,
    pub hotspot_y: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CaptureMetadata {
    pub origin_x: i32,
    pub origin_y: i32,
    pub width: u32,
    pub height: u32,
    pub scale_x: f64,
    pub scale_y: f64,
    pub requested_bounds: Rect,
    pub physical_bounds: Rect,
    pub target: CaptureIdentity,
    pub session: SessionIdentity,
    pub geometry: Geometry,
    pub method: &'static str,
    pub content: CaptureContent,
    pub visible_regions: Vec<Rect>,
    pub occluding_windows: Vec<Occluder>,
    pub occlusion_check_complete: bool,
    pub cursor: CursorMetadata,
    pub overlay_exclusion: &'static str,
    pub captured_at_unix_ms: u64,
    pub limitations: Vec<String>,
}

pub(crate) struct CaptureFrame {
    pub metadata: CaptureMetadata,
    pub bgra: Vec<u8>,
    // Keep the permit through OCR and encoding, not only the GDI allocation.
    _capture: MutexGuard<'static, ()>,
}

pub(crate) struct CapturedImage {
    pub base64_jpeg: String,
    pub metadata: CaptureMetadata,
}

struct BoundedJpeg(Vec<u8>);

impl Write for BoundedJpeg {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let total = self
            .0
            .len()
            .checked_add(data.len())
            .filter(|n| *n <= MAX_JPEG_BYTES)
            .ok_or_else(|| {
                std::io::Error::other("Encoded capture exceeds the 64 MiB JPEG limit")
            })?;
        self.0
            .try_reserve(total - self.0.len())
            .map_err(std::io::Error::other)?;
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CaptureFrame {
    #[cfg(test)]
    pub(crate) fn fixture(bounds: Rect, bgra: Vec<u8>) -> Self {
        assert_eq!(
            validate_allocation(bounds.width, bounds.height).unwrap(),
            bgra.len()
        );
        Self {
            metadata: CaptureMetadata {
                origin_x: bounds.x,
                origin_y: bounds.y,
                width: bounds.width,
                height: bounds.height,
                scale_x: 1.0,
                scale_y: 1.0,
                requested_bounds: bounds,
                physical_bounds: bounds,
                target: CaptureIdentity::Region,
                session: SessionIdentity {
                    session_id: 1,
                    desktop: "fixture".into(),
                    coordinate_space: "physical_virtual_screen_pixels",
                },
                geometry: Geometry {
                    virtual_screen: bounds,
                    monitors: Vec::new(),
                },
                method: "fixture",
                content: CaptureContent::VisibleDesktop,
                visible_regions: vec![bounds],
                occluding_windows: Vec::new(),
                occlusion_check_complete: true,
                cursor: CursorMetadata {
                    state: "hidden",
                    composited: false,
                    x: None,
                    y: None,
                    hotspot_x: None,
                    hotspot_y: None,
                    error: None,
                },
                overlay_exclusion: "not_running",
                captured_at_unix_ms: 0,
                limitations: Vec::new(),
            },
            bgra,
            _capture: CAPTURE.lock().unwrap(),
        }
    }

    pub fn encode(&self, operation: &Operation) -> Result<CapturedImage> {
        operation.check()?;
        validate_allocation(self.metadata.width, self.metadata.height)?;
        let mut jpeg = BoundedJpeg(Vec::new());
        jpeg_encoder::Encoder::new(&mut jpeg, 80)
            .encode(
                &self.bgra,
                u16::try_from(self.metadata.width)?,
                u16::try_from(self.metadata.height)?,
                jpeg_encoder::ColorType::Bgra,
            )
            .context("JPEG encoding failed")?;
        operation.check()?;
        Ok(CapturedImage {
            base64_jpeg: STANDARD.encode(&jpeg.0),
            metadata: self.metadata.clone(),
        })
    }
}

pub(crate) fn validate_allocation(width: u32, height: u32) -> Result<usize> {
    if width == 0 || height == 0 || width > u16::MAX as u32 || height > u16::MAX as u32 {
        bail!("Capture dimensions must be in 1..=65535 on each axis (JPEG encoder limit)");
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_CAPTURE_PIXELS {
        bail!("Capture exceeds the {MAX_CAPTURE_PIXELS}-pixel allocation limit");
    }
    usize::try_from(
        pixels
            .checked_mul(4)
            .context("Capture allocation overflow")?,
    )
    .context("Capture allocation exceeds the address space")
}

pub(crate) fn capture(
    x: Option<i32>,
    y: Option<i32>,
    width: Option<u32>,
    height: Option<u32>,
) -> Result<CapturedImage> {
    let operation = Operation::new(30_000)?;
    let geometry = display::geometry()?;
    let source = if x.is_none() && y.is_none() && width.is_none() && height.is_none() {
        CaptureSource::Desktop
    } else {
        CaptureSource::Region(Rect {
            x: x.unwrap_or(geometry.virtual_screen.x),
            y: y.unwrap_or(geometry.virtual_screen.y),
            width: width.unwrap_or(geometry.virtual_screen.width),
            height: height.unwrap_or(geometry.virtual_screen.height),
        })
    };
    capture_geometry(source, geometry, &operation)?.encode(&operation)
}

pub(crate) fn capture_target(source: CaptureSource, operation: &Operation) -> Result<CaptureFrame> {
    capture_geometry(source, display::geometry()?, operation)
}

fn capture_geometry(
    source: CaptureSource,
    geometry: Geometry,
    operation: &Operation,
) -> Result<CaptureFrame> {
    operation.check()?;
    let session = require_session(None)?;
    let _dpi = DpiScope::enter()?;
    let capture = CAPTURE.try_lock().map_err(|_| {
        anyhow::anyhow!("A capture or OCR operation is already using the bounded image buffer")
    })?;
    let (requested, target, window) = match source {
        CaptureSource::Desktop => (geometry.virtual_screen, CaptureIdentity::Desktop, None),
        CaptureSource::Monitor(index) => {
            let monitor = geometry
                .monitors
                .iter()
                .find(|m| m.index == index)
                .with_context(|| {
                    format!("Monitor index {index} is not present in the current display geometry")
                })?;
            (
                monitor.bounds,
                CaptureIdentity::Monitor {
                    index,
                    device: monitor.device.clone(),
                },
                None,
            )
        }
        CaptureSource::Region(rect) => (rect, CaptureIdentity::Region, None),
        CaptureSource::Window(window) => {
            let hwnd = HWND(window.identity.hwnd as *mut _);
            if window.minimized || unsafe { IsIconic(hwnd) }.as_bool() {
                bail!("Window capture is unavailable: the target is minimized; no offscreen capture was attempted");
            }
            if !window.visible || window.cloaked || !unsafe { IsWindowVisible(hwnd) }.as_bool() {
                bail!("Window capture is unavailable: the target is hidden or cloaked");
            }
            let target = CaptureIdentity::Window {
                window_ref: window.window_ref.clone(),
                identity: window.identity.clone(),
            };
            (window.bounds, target, Some(window))
        }
    };
    requested.validate()?;
    validate_allocation(requested.width, requested.height)?;
    let bounds = requested
        .intersect(&geometry.virtual_screen)
        .context("Capture is unavailable: the requested area is outside the virtual desktop")?;
    let visible_regions: Vec<_> = geometry
        .monitors
        .iter()
        .filter_map(|m| bounds.intersect(&m.bounds))
        .collect();
    if visible_regions.is_empty() {
        bail!("Capture is unavailable: the requested area does not intersect an active monitor");
    }
    let bytes = validate_allocation(bounds.width, bounds.height)?;
    let mut limitations = vec![
        "GDI captures composited visible desktop pixels, not offscreen window content. Protected or exclusive surfaces may be blank; their content cannot be verified.".into(),
        "Image pixels map to physical coordinates as origin + pixel / scale. Monitor DPI scales describe logical UI units, not image resampling.".into(),
    ];
    if requested != bounds {
        limitations.push("The requested area was clipped to the virtual desktop; use the actual origin and dimensions.".into());
    }
    if geometry.monitors.len() > 1 {
        limitations.push(
            "Pixels in gaps between monitors are black and do not represent display content."
                .into(),
        );
    }
    let (occluding_windows, occlusion_check_complete) = match &window {
        Some(window) => {
            limitations.push("The image contains whatever is currently visible over the window rectangle, including other windows. Nonrectangular and transparent occlusion is not inferred.".into());
            occluders(window.identity.hwnd, bounds, &mut limitations)?
        }
        None => (Vec::new(), true),
    };
    let content = if window.is_some() {
        if occluding_windows.is_empty() && occlusion_check_complete {
            CaptureContent::WindowVisibleRegion
        } else {
            CaptureContent::WindowOccludedRegion
        }
    } else {
        CaptureContent::VisibleDesktop
    };
    operation.check()?;
    let mut bgra = Vec::new();
    bgra.try_reserve_exact(bytes)
        .context("Cannot allocate the capture pixel buffer")?;
    bgra.resize(bytes, 0);
    let cursor;
    let overlay_exclusion;
    unsafe {
        let screen = ScreenDc::get()?;
        let (surface, bits) = Surface::new(screen.0, bounds.width, bounds.height)?;
        let exclusion = crate::overlay::suppress_for_capture(operation.remaining())?;
        overlay_exclusion = if exclusion.suppressed() {
            "temporarily_suppressed_and_compositor_synchronized"
        } else {
            "overlay_not_running"
        };
        operation.check()?;
        std::ptr::write_bytes(bits, 0, bytes);
        for region in &visible_regions {
            operation.check()?;
            BitBlt(
                surface.dc.0,
                region.x - bounds.x,
                region.y - bounds.y,
                region.width as i32,
                region.height as i32,
                Some(screen.0),
                region.x,
                region.y,
                SRCCOPY | CAPTUREBLT,
            )
            .context("BitBlt could not read the visible desktop")?;
        }
        cursor = composite_cursor(surface.dc.0, bounds);
        if !GdiFlush().as_bool() {
            bail!("GdiFlush failed: {}", windows::core::Error::from_thread());
        }
        std::ptr::copy_nonoverlapping(bits, bgra.as_mut_ptr(), bytes);
        drop(exclusion);
    }
    operation.check()?;
    let captured_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock precedes the Unix epoch")?
        .as_millis() as u64;
    Ok(CaptureFrame {
        metadata: CaptureMetadata {
            origin_x: bounds.x,
            origin_y: bounds.y,
            width: bounds.width,
            height: bounds.height,
            scale_x: 1.0,
            scale_y: 1.0,
            requested_bounds: requested,
            physical_bounds: bounds,
            target,
            session,
            geometry,
            method: "gdi_visible_desktop_region",
            content,
            visible_regions,
            occluding_windows,
            occlusion_check_complete,
            cursor,
            overlay_exclusion,
            captured_at_unix_ms,
            limitations,
        },
        bgra,
        _capture: capture,
    })
}

struct ScreenDc(HDC);

impl ScreenDc {
    unsafe fn get() -> Result<Self> {
        let dc = unsafe { GetDC(None) };
        if dc.is_invalid() {
            bail!("GetDC failed: {}", windows::core::Error::from_thread());
        }
        Ok(Self(dc))
    }
}

impl Drop for ScreenDc {
    fn drop(&mut self) {
        if unsafe { ReleaseDC(None, self.0) } == 0 {
            tracing::warn!("ReleaseDC failed for the capture DC");
        }
    }
}

struct MemoryDc(HDC);

impl Drop for MemoryDc {
    fn drop(&mut self) {
        if !unsafe { DeleteDC(self.0) }.as_bool() {
            tracing::warn!("DeleteDC failed for the capture DC");
        }
    }
}

struct Bitmap(HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !unsafe { DeleteObject(self.0.into()) }.as_bool() {
            tracing::warn!("DeleteObject failed for a capture bitmap");
        }
    }
}

struct Surface {
    dc: MemoryDc,
    _bitmap: Bitmap,
    previous: HGDIOBJ,
}

impl Surface {
    unsafe fn new(screen: HDC, width: u32, height: u32) -> Result<(Self, *mut u8)> {
        let raw_dc = unsafe { CreateCompatibleDC(Some(screen)) };
        if raw_dc.is_invalid() {
            bail!(
                "CreateCompatibleDC failed: {}",
                windows::core::Error::from_thread()
            );
        }
        let dc = MemoryDc(raw_dc);
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: i32::try_from(width)?,
                biHeight: -i32::try_from(height)?,
                biPlanes: 1,
                biBitCount: 32,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = std::ptr::null_mut();
        let bitmap = Bitmap(
            unsafe { CreateDIBSection(Some(screen), &info, DIB_RGB_COLORS, &mut bits, None, 0) }
                .context("CreateDIBSection failed")?,
        );
        if bits.is_null() || bitmap.0.is_invalid() {
            bail!("CreateDIBSection returned no pixel buffer");
        }
        let previous = unsafe { SelectObject(dc.0, bitmap.0.into()) };
        if invalid_object(previous) {
            bail!("SelectObject failed for the capture bitmap");
        }
        Ok((
            Self {
                dc,
                _bitmap: bitmap,
                previous,
            },
            bits.cast(),
        ))
    }
}

fn invalid_object(object: HGDIOBJ) -> bool {
    object.is_invalid() || object.0 as isize == -1
}

impl Drop for Surface {
    fn drop(&mut self) {
        if invalid_object(unsafe { SelectObject(self.dc.0, self.previous) }) {
            tracing::warn!("Could not deselect the capture bitmap");
        }
    }
}

struct CursorIcon(HICON);

impl Drop for CursorIcon {
    fn drop(&mut self) {
        if let Err(error) = unsafe { DestroyIcon(self.0) } {
            tracing::warn!(%error, "DestroyIcon failed for a capture cursor");
        }
    }
}

unsafe fn composite_cursor(dc: HDC, bounds: Rect) -> CursorMetadata {
    let mut metadata = CursorMetadata {
        state: "unavailable",
        composited: false,
        x: None,
        y: None,
        hotspot_x: None,
        hotspot_y: None,
        error: None,
    };
    let result = (|| -> Result<()> {
        let mut cursor = CURSORINFO {
            cbSize: std::mem::size_of::<CURSORINFO>() as u32,
            ..Default::default()
        };
        unsafe { GetCursorInfo(&mut cursor) }.context("GetCursorInfo failed")?;
        metadata.x = Some(cursor.ptScreenPos.x);
        metadata.y = Some(cursor.ptScreenPos.y);
        if cursor.flags.0 & CURSOR_SHOWING.0 == 0 {
            metadata.state = if cursor.flags.0 & CURSOR_SUPPRESSED.0 != 0 {
                "suppressed"
            } else {
                "hidden"
            };
            return Ok(());
        }
        let icon =
            CursorIcon(unsafe { CopyIcon(cursor.hCursor.into()) }.context("CopyIcon failed")?);
        let mut info = ICONINFO::default();
        unsafe { GetIconInfo(icon.0, &mut info) }.context("GetIconInfo failed")?;
        let mask = Bitmap(info.hbmMask);
        let color = Bitmap(info.hbmColor);
        metadata.hotspot_x = Some(info.xHotspot);
        metadata.hotspot_y = Some(info.yHotspot);
        let mut bitmap_info = BITMAP::default();
        let handle = if !color.0.is_invalid() {
            color.0
        } else {
            mask.0
        };
        if unsafe {
            GetObjectW(
                handle.into(),
                std::mem::size_of::<BITMAP>() as i32,
                Some((&mut bitmap_info as *mut BITMAP).cast()),
            )
        } == 0
        {
            bail!("GetObjectW failed for cursor bounds");
        }
        let cursor_width = bitmap_info.bmWidth;
        let cursor_height = if color.0.is_invalid() {
            bitmap_info.bmHeight / 2
        } else {
            bitmap_info.bmHeight
        };
        if cursor_width <= 0 || cursor_height <= 0 {
            bail!("Cursor bitmap has invalid dimensions");
        }
        let left = i64::from(cursor.ptScreenPos.x) - i64::from(info.xHotspot);
        let top = i64::from(cursor.ptScreenPos.y) - i64::from(info.yHotspot);
        let rect = Rect {
            x: i32::try_from(left)?,
            y: i32::try_from(top)?,
            width: cursor_width as u32,
            height: cursor_height as u32,
        };
        if bounds.intersect(&rect).is_none() {
            metadata.state = "outside_capture";
            return Ok(());
        }
        unsafe {
            DrawIconEx(
                dc,
                i32::try_from(left - i64::from(bounds.x))?,
                i32::try_from(top - i64::from(bounds.y))?,
                icon.0,
                0,
                0,
                0,
                None,
                DI_NORMAL,
            )
        }
        .context("DrawIconEx failed")?;
        metadata.state = "composited";
        metadata.composited = true;
        Ok(())
    })();
    if let Err(error) = result {
        metadata.error = Some(format!("{error:#}"));
    }
    metadata
}

struct OcclusionScan {
    target: u64,
    bounds: Rect,
    found: bool,
    count: usize,
    complete: bool,
    windows: Vec<Occluder>,
    errors: Vec<String>,
}

unsafe extern "system" fn scan_occlusion(hwnd: HWND, data: LPARAM) -> BOOL {
    let scan = unsafe { &mut *(data.0 as *mut OcclusionScan) };
    if hwnd.0 as u64 == scan.target {
        scan.found = true;
        return BOOL(0);
    }
    scan.count += 1;
    if scan.count > 4096 || scan.windows.len() >= 128 {
        scan.complete = false;
        return BOOL(0);
    }
    if crate::overlay::is_overlay(hwnd)
        || !unsafe { IsWindowVisible(hwnd) }.as_bool()
        || unsafe { IsIconic(hwnd) }.as_bool()
    {
        return BOOL(1);
    }
    let mut cloaked: u32 = 0;
    if let Err(error) = unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            (&mut cloaked as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    } {
        scan.complete = false;
        if scan.errors.len() < 8 {
            scan.errors.push(format!(
                "Cloaking state unavailable for HWND {}: {error}",
                hwnd.0 as u64
            ));
        }
    }
    if cloaked != 0 {
        return BOOL(1);
    }
    let mut rect = RECT::default();
    match unsafe { GetWindowRect(hwnd, &mut rect) } {
        Ok(()) => {
            if let Ok(rect) = Rect::from_native(rect) {
                if let Some(bounds) = scan.bounds.intersect(&rect) {
                    scan.windows.push(Occluder {
                        hwnd: hwnd.0 as u64,
                        bounds,
                    });
                }
            }
        }
        Err(error) => {
            scan.complete = false;
            if scan.errors.len() < 8 {
                scan.errors.push(format!(
                    "Occlusion bounds unavailable for HWND {}: {error}",
                    hwnd.0 as u64
                ));
            }
        }
    }
    BOOL(1)
}

fn occluders(
    target: u64,
    bounds: Rect,
    limitations: &mut Vec<String>,
) -> Result<(Vec<Occluder>, bool)> {
    let mut scan = OcclusionScan {
        target,
        bounds,
        found: false,
        count: 0,
        complete: true,
        windows: Vec::new(),
        errors: Vec::new(),
    };
    let result = unsafe { EnumWindows(Some(scan_occlusion), LPARAM(&mut scan as *mut _ as isize)) };
    if let Err(error) = result {
        if !scan.found && scan.complete {
            return Err(error).context("Could not enumerate window occlusion");
        }
    }
    if !scan.found {
        scan.complete = false;
        limitations.push("Window z-order changed or the occlusion scan limit was reached; occlusion is uncertain.".into());
    }
    limitations.extend(scan.errors);
    Ok((scan.windows, scan.complete))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_dimensions_bound_allocations_and_jpeg_casts() {
        assert_eq!(validate_allocation(1920, 1080).unwrap(), 8_294_400);
        for (w, h) in [
            (0, 1),
            (1, 0),
            (65536, 1),
            (1, 65536),
            (u32::MAX, u32::MAX),
            (65535, 65535),
        ] {
            assert!(validate_allocation(w, h).is_err(), "{w}x{h}");
        }
        assert!(validate_allocation(65535, 1).is_ok());
    }

    #[test]
    fn jpeg_output_is_bounded() {
        let mut output = BoundedJpeg(Vec::new());
        output.write_all(&[1, 2, 3]).unwrap();
        assert_eq!(output.0, [1, 2, 3]);
        output.0.resize(MAX_JPEG_BYTES, 0);
        assert!(output.write_all(&[4]).is_err());
    }

    #[test]
    fn jpeg_dimensions_and_metadata_keep_the_physical_origin() {
        let frame = CaptureFrame::fixture(
            Rect {
                x: -200,
                y: -100,
                width: 2,
                height: 1,
            },
            vec![0, 0, 255, 0, 0, 255, 0, 0],
        );
        let encoded = frame.encode(&Operation::new(1000).unwrap()).unwrap();
        let bytes = STANDARD.decode(encoded.base64_jpeg).unwrap();
        assert_eq!(&bytes[..2], &[0xff, 0xd8]);
        let header = bytes
            .windows(2)
            .position(|marker| marker == [0xff, 0xc0])
            .unwrap();
        assert_eq!(
            u16::from_be_bytes([bytes[header + 5], bytes[header + 6]]),
            1
        );
        assert_eq!(
            u16::from_be_bytes([bytes[header + 7], bytes[header + 8]]),
            2
        );
        assert_eq!(encoded.metadata.origin_x, -200);
        assert_eq!(encoded.metadata.origin_y, -100);
        assert_eq!(encoded.metadata.scale_x, 1.0);
    }

    #[test]
    fn jpeg_axes_encode_at_the_u16_boundary() {
        for (width, height) in [(u16::MAX as u32, 1), (1, u16::MAX as u32)] {
            let frame = CaptureFrame::fixture(
                Rect {
                    x: -200,
                    y: -100,
                    width,
                    height,
                },
                vec![0; validate_allocation(width, height).unwrap()],
            );
            let encoded = frame.encode(&Operation::new(5000).unwrap()).unwrap();
            let bytes = STANDARD.decode(encoded.base64_jpeg).unwrap();
            let header = bytes
                .windows(2)
                .position(|marker| marker == [0xff, 0xc0])
                .unwrap();
            assert_eq!(
                u16::from_be_bytes([bytes[header + 5], bytes[header + 6]]) as u32,
                height
            );
            assert_eq!(
                u16::from_be_bytes([bytes[header + 7], bytes[header + 8]]) as u32,
                width
            );
        }
    }

    #[test]
    fn unsupported_targets_fail_without_claiming_offscreen_content() {
        use crate::desktop::windows::{Fixture, WindowCatalog};
        let fixture = Fixture::start();
        let window = WindowCatalog::new().record_for_hwnd(fixture.hwnd).unwrap();
        let error = capture_target(
            CaptureSource::Window(window.clone()),
            &Operation::new(1000).unwrap(),
        )
        .err()
        .expect("A hidden window cannot be captured");
        assert!(error.to_string().contains("hidden or cloaked"), "{error:#}");
        let mut minimized = window;
        minimized.minimized = true;
        let error = capture_target(
            CaptureSource::Window(minimized),
            &Operation::new(1000).unwrap(),
        )
        .err()
        .expect("A minimized window cannot be captured");
        assert!(
            error.to_string().contains("no offscreen capture"),
            "{error:#}"
        );
        assert!(capture_target(
            CaptureSource::Monitor(u32::MAX),
            &Operation::new(1000).unwrap(),
        )
        .is_err());
        assert!(capture_target(
            CaptureSource::Region(Rect {
                x: i32::MAX - 1,
                y: i32::MAX - 1,
                width: 1,
                height: 1,
            }),
            &Operation::new(1000).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn native_gdi_failures_release_owned_objects_without_capturing_the_desktop() {
        use windows::Win32::System::Threading::{
            GetCurrentProcess, GetGuiResources, GR_GDIOBJECTS,
        };
        let _capture = CAPTURE.lock().unwrap();
        unsafe {
            let outside = Rect {
                x: i32::MIN,
                y: i32::MIN,
                width: 2,
                height: 2,
            };
            // Cursor copying initializes process-local Windows caches. Measure
            // repeated allocations after warming that path as well as the DC.
            {
                let screen = ScreenDc::get().unwrap();
                let (surface, _) = Surface::new(screen.0, 2, 2).unwrap();
                assert!(!composite_cursor(surface.dc.0, outside).composited);
            }
            let before = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
            for _ in 0..16 {
                let screen = ScreenDc::get().unwrap();
                assert!(Surface::new(screen.0, 0, 1).is_err());
                let (surface, _) = Surface::new(screen.0, 2, 2).unwrap();
                let cursor = composite_cursor(surface.dc.0, outside);
                assert!(!cursor.composited);
            }
            assert_eq!(GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS), before);
        }
    }
}
