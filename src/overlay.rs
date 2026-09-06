//! # Activity Glow
//!
//! A soft red glow around the edge of the desktop, lit whenever a tool reaches
//! out and drives the machine: moves the mouse, clicks, types, or photographs
//! the screen.
//!
//! The rest of this server talks to a language model. This is the one part that
//! talks to the human sitting at the keyboard. Without it, a cursor sliding
//! across the desktop under its own power is indistinguishable from a haunting,
//! and the only record that anything happened lives in a log file the person
//! watching their mouse move is definitionally not reading.
//!
//! It is a notification, not a permission prompt. Nothing waits on it and
//! nothing is blocked by it. By the time you see the glow, it already happened.
//!
//! ## Shape of the thing
//!
//! One layered, click-through, always-on-top window spanning the whole virtual
//! screen, painted with a red gradient that is opaque at the outer boundary and
//! gone by 8% of the way in. An ADSR envelope drives its opacity: 0.25s attack,
//! 1s hold, 3s release, and a retrigger ramps back up from wherever the fade
//! had got to instead of snapping to full. A burst of tool calls therefore
//! reads as one continuous glow rather than a strobe, which matters when the
//! caller is running click, screenshot, click at machine speed.
//!
//! ## Why it needs its own thread
//!
//! Windows are owned by threads, and a thread that owns a window owes it a
//! message pump. The tokio workers cannot provide one: the input tools block
//! their worker with `std::thread::sleep` for up to 600ms per mouse glide (see
//! `win32::input::glide_to`), so a pump living there would stall exactly when
//! the glow is supposed to be animating. So the overlay gets a dedicated OS
//! thread, and the tool handlers reach it with a single `PostMessageW`.
//!
//! ## Screenshots
//!
//! Capture does not light the glow. The capture path briefly suppresses it,
//! waits for the compositor, then restores the existing envelope.
//!
//! This started out using `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` to
//! keep out of captures unconditionally, and that was a mistake worth recording.
//! The flag is meant to keep a window on the physical display while removing it
//! from every capture path. On a desktop served by an indirect or virtual
//! display driver there is no physical path left to keep it on, so the window is
//! withheld from the panel too, and the glow becomes something that renders
//! perfectly and that nobody can ever see.
//!
//! The trap is that the same flag hides the window from every screenshot, so
//! "correctly excluded" and "not drawing at all" produce byte-identical
//! captures. No software instrument on the machine can separate them. It took a
//! person looking at their own screen to notice, which is what `src/spike.rs`
//! exists for. `MCP_OVERLAY_AFFINITY=exclude` opts back in on hardware where it
//! genuinely works.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    COLORREF, ERROR_CLASS_ALREADY_EXISTS, GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, POINT,
    SIZE, WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    AC_SRC_ALPHA, AC_SRC_OVER, BITMAPINFO, BITMAPINFOHEADER, BLENDFUNCTION, CreateCompatibleDC,
    CreateDIBSection, DIB_RGB_COLORS, DeleteDC, DeleteObject, GdiFlush, HBITMAP, HDC, HGDIOBJ,
    SelectObject,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::INFINITE;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::PCWSTR;

// ─── Tuning ──────────────────────────────────────────────────────────────────

/// Rise time to full intensity. Fast, because the glow needs to be up before
/// the mouse has finished moving, but not so fast it reads as a flash.
const ATTACK: Duration = Duration::from_millis(250);
/// Time held at full after the most recent trigger.
const HOLD: Duration = Duration::from_millis(1000);
/// Fade to nothing. Twelve times the attack, so it breathes out rather than
/// snapping off, and a gap between tool calls is visible as a dip.
const RELEASE: Duration = Duration::from_millis(3000);

/// Frame interval while the level is actually moving. 60fps against a pure
/// opacity ramp with no motion in it, which is more than enough even on a
/// 120Hz panel.
const FRAME: Duration = Duration::from_millis(16);

/// How long the bitmap sticks around after the glow goes dark. It is tens of
/// megabytes on a large desktop and a server that never touches the screen
/// should not be holding it, but a computer-use session retriggers constantly
/// and should not be rebuilding it either.
const DIB_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Band thickness as a fraction of the shorter screen dimension.
const BAND_FRACTION: f64 = 0.08;
/// Alpha at the very edge, before the envelope scales it. Reads as "soft and
/// wide": present in peripheral vision, never obscuring anything.
const DEFAULT_PEAK: f64 = 0.45;

/// A warm signal red rather than #FF0000. Pure red with the other two channels
/// at zero reads as a dead subpixel column at low alpha and clips hard on
/// wide-gamut panels. A little green and blue keeps it looking like light.
const GLOW_R: u32 = 255;
const GLOW_G: u32 = 38;
const GLOW_B: u32 = 28;

const CLASS_NAME: &str = "MCPmcpActivityGlow";

/// Posted by `pulse()` from a tokio worker. Handled in the loop, not the
/// window procedure, because that is where the envelope lives.
const WM_PULSE: u32 = WM_APP + 1;
/// Posted to ourselves from the window procedure when the monitor layout
/// changes, to get the rebuild out of a broadcast message and into the loop.
const WM_REFIT: u32 = WM_APP + 2;
const WM_CAPTURE_BARRIER: u32 = WM_APP + 3;
const WM_CAPTURE_CHANGED: u32 = WM_APP + 4;

// ─── Public surface ──────────────────────────────────────────────────────────

/// The window we post to, or 0 for "not running." Every path that gives up
/// leaves this at 0, so `pulse()` needs no other notion of failure.
static TARGET: AtomicIsize = AtomicIsize::new(0);
static CAPTURE_SUPPRESSED: AtomicBool = AtomicBool::new(false);
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn is_overlay(hwnd: HWND) -> bool {
    let target = TARGET.load(Ordering::Acquire);
    target != 0 && target == hwnd.0 as isize
}

pub(crate) struct CaptureGuard {
    target: isize,
    _lock: MutexGuard<'static, ()>,
}

impl CaptureGuard {
    pub fn suppressed(&self) -> bool {
        self.target != 0
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURE_SUPPRESSED.store(false, Ordering::Release);
        if self.target != 0 && TARGET.load(Ordering::Acquire) == self.target {
            if let Err(error) = unsafe {
                PostMessageW(
                    Some(HWND(self.target as *mut _)),
                    WM_CAPTURE_CHANGED,
                    WPARAM(0),
                    LPARAM(0),
                )
            } {
                tracing::warn!(%error, "Could not notify the activity glow after capture");
            }
        }
    }
}

pub(crate) fn suppress_for_capture(timeout: Duration) -> anyhow::Result<CaptureGuard> {
    let lock = CAPTURE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("Activity glow capture synchronization was poisoned"))?;
    let guard = CaptureGuard {
        target: TARGET.load(Ordering::Acquire),
        _lock: lock,
    };
    if guard.target == 0 {
        return Ok(guard);
    }
    CAPTURE_SUPPRESSED.store(true, Ordering::Release);
    let mut acknowledged = 0usize;
    let delivered = unsafe {
        SendMessageTimeoutW(
            HWND(guard.target as *mut _),
            WM_CAPTURE_BARRIER,
            WPARAM(0),
            LPARAM(0),
            SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
            timeout.as_millis().clamp(1, 1000) as u32,
            Some(&mut acknowledged),
        )
    };
    if delivered.0 == 0 || acknowledged != 1 {
        anyhow::bail!("The activity glow did not acknowledge capture suppression");
    }
    unsafe { windows::Win32::Graphics::Dwm::DwmFlush() }
        .map_err(|e| anyhow::anyhow!("Could not synchronize capture exclusion with the compositor: {e}"))?;
    Ok(guard)
}

/// Start the overlay. Never fails: if anything goes wrong the glow simply does
/// not exist for this session and every `pulse()` is a load and a branch.
///
/// Blocks briefly on the thread reporting back, so the outcome can be logged
/// truthfully at startup rather than optimistically, and so a tool call landing
/// a few milliseconds later does not get dropped on the floor.
pub fn init() {
    let peak = match settings() {
        Some(peak) => peak,
        None => {
            tracing::info!("activity glow: disabled by MCP_OVERLAY");
            return;
        }
    };

    let (tx, rx) = mpsc::channel::<Result<String, String>>();
    if let Err(e) = std::thread::Builder::new()
        .name("activity-glow".into())
        .spawn(move || glow_thread(peak, tx))
    {
        tracing::warn!(err = %e, "activity glow: could not spawn its thread, running without it");
        return;
    }

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(detail)) => tracing::info!("activity glow: armed, {detail}"),
        Ok(Err(e)) => tracing::warn!("activity glow: disabled ({e}), tools will run without it"),
        Err(_) => tracing::warn!("activity glow: thread did not report in, running without it"),
    }
}

/// Light the glow, or push its hold window forward if it is already lit.
///
/// Called from tool handlers on tokio workers. One relaxed load and one
/// non-blocking kernel call, so it costs nothing worth measuring next to the
/// `SendInput` it precedes. It cannot block, cannot fail, and returns `()` so
/// there is no `Result` for a future tool author to accidentally propagate.
pub fn pulse() {
    let target = TARGET.load(Ordering::Relaxed);
    if target == 0 {
        return;
    }
    unsafe {
        // Fails only if the window is gone, in which case the render loop has
        // already torn everything down. Nothing useful to do about it here, and
        // logging would fire several times a second during a computer-use loop.
        let _ = PostMessageW(Some(HWND(target as *mut _)), WM_PULSE, WPARAM(0), LPARAM(0));
    }
}

/// Read `MCP_OVERLAY` and `MCP_OVERLAY_INTENSITY` once, at startup. Returns the
/// peak alpha, or `None` if the user turned the thing off.
///
/// Attack and release are deliberately not configurable. They are perceptual
/// constants, and a knob that lets someone set a 20ms attack on a full-screen
/// red field is a photosensitivity hazard, not a feature. Intensity gives the
/// same relief with none of that.
fn settings() -> Option<f64> {
    if let Ok(v) = std::env::var("MCP_OVERLAY") {
        let v = v.trim().to_ascii_lowercase();
        if v == "0" || v == "off" || v == "false" || v == "no" {
            return None;
        }
    }

    let peak = std::env::var("MCP_OVERLAY_INTENSITY")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map(|v| (v / 255.0).clamp(0.0, 1.0))
        .unwrap_or(DEFAULT_PEAK);

    Some(peak)
}

// ─── Envelope ────────────────────────────────────────────────────────────────

/// Each phase carries the timestamp it started from rather than a running
/// accumulator. That makes the level a pure function of the clock, so a tick
/// that arrives late (a busy machine, a debugger, a suspend and resume) lands
/// at the level it should have rather than wherever the missed frames left it.
#[derive(Clone, Copy)]
enum Phase {
    Idle,
    Attack {
        t0: Instant,
        dur: Duration,
        from: f32,
    },
    Hold {
        until: Instant,
    },
    Release {
        t0: Instant,
        from: f32,
    },
}

/// Level stays linear in time so the retrigger arithmetic is one subtraction.
/// The perceptual curve is applied on the way out, in `shaped_alpha`, which
/// keeps "where were we" and "how bright is that" from contaminating each
/// other.
struct Envelope {
    phase: Phase,
}

impl Envelope {
    fn new() -> Self {
        Self { phase: Phase::Idle }
    }

    /// The level right now, without advancing anything.
    fn level_at(&self, now: Instant) -> f32 {
        match self.phase {
            Phase::Idle => 0.0,
            Phase::Attack { t0, dur, from } => {
                let e = now.saturating_duration_since(t0);
                if e >= dur {
                    1.0
                } else {
                    from + (1.0 - from) * (e.as_secs_f32() / dur.as_secs_f32())
                }
            }
            Phase::Hold { .. } => 1.0,
            Phase::Release { t0, from } => {
                let e = now.saturating_duration_since(t0);
                if e >= RELEASE {
                    0.0
                } else {
                    from * (1.0 - e.as_secs_f32() / RELEASE.as_secs_f32())
                }
            }
        }
    }

    /// Retrigger. Resumes from the current level rather than restarting, which
    /// is the whole point of the shape: a tool call landing two seconds into
    /// the fade eases back up from a third, it does not jump to full and it
    /// does not blink through black on the way.
    ///
    /// The rise is a constant *rate*, not a constant duration, so recovering
    /// from 0.8 takes 50ms rather than a sluggish 250ms. The floor on the
    /// remaining distance keeps a level a hair under 1.0 from producing a
    /// zero-length attack.
    fn trigger(&mut self, now: Instant) {
        let current = self.level_at(now);
        self.phase = if current >= 0.999 {
            Phase::Hold { until: now + HOLD }
        } else {
            Phase::Attack {
                t0: now,
                dur: ATTACK.mul_f32((1.0 - current).max(0.02)),
                from: current,
            }
        };
    }

    /// Returns the current level and how long until the next redraw is worth
    /// doing. `None` means there is nothing left to animate and the caller can
    /// sleep until something wakes it.
    fn advance(&mut self, now: Instant) -> (f32, Option<Duration>) {
        // At most three transitions: Attack, Hold, Release, Idle.
        loop {
            match self.phase {
                Phase::Idle => return (0.0, None),

                Phase::Attack { t0, dur, .. } => {
                    if now.saturating_duration_since(t0) >= dur {
                        // Hold runs from when the attack actually finished, not
                        // from when we got around to noticing, so a late tick
                        // does not quietly extend the glow.
                        self.phase = Phase::Hold {
                            until: t0 + dur + HOLD,
                        };
                        continue;
                    }
                    return (self.level_at(now), Some(FRAME));
                }

                Phase::Hold { until } => {
                    if now >= until {
                        self.phase = Phase::Release { t0: until, from: 1.0 };
                        continue;
                    }
                    // Nothing changes for the rest of the hold, so sleep it out
                    // in a single wait rather than sixty that redraw the same
                    // byte and then go back to sleep.
                    return (1.0, Some(until - now));
                }

                Phase::Release { t0, .. } => {
                    if now.saturating_duration_since(t0) >= RELEASE {
                        self.phase = Phase::Idle;
                        continue;
                    }
                    return (self.level_at(now), Some(FRAME));
                }
            }
        }
    }
}

/// Smoothstep, so both ends of the ramp are flat and neither the arrival at
/// full nor the departure from it has a visible corner in it. A linear alpha
/// fade leaves a long dim smear at the tail, which is most of what makes one
/// look cheap.
fn shaped_alpha(level: f32) -> u8 {
    let l = level.clamp(0.0, 1.0);
    (l * l * (3.0 - 2.0 * l) * 255.0).round() as u8
}

// ─── The bitmap ──────────────────────────────────────────────────────────────

/// A 32-bit premultiplied BGRA DIB section holding the gradient at full
/// intensity, plus the memory DC it is selected into.
///
/// Built once per screen geometry and never repainted. The envelope animates by
/// varying `SourceConstantAlpha` on the blend, which multiplies through the
/// per-pixel alpha, so a frame costs one `UpdateLayeredWindow` and zero pixel
/// work. Repainting five and a half million pixels sixty times a second to fade
/// something out would be an embarrassing way to spend a CPU.
struct Gradient {
    dc: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
    width: i32,
    height: i32,
}

impl Gradient {
    unsafe fn build(width: i32, height: i32, peak: f64) -> anyhow::Result<Self> {
        unsafe {
            if width <= 0 || height <= 0 {
                anyhow::bail!("virtual screen has no area: {width}x{height}");
            }

            let dc = CreateCompatibleDC(None);
            if dc.is_invalid() {
                anyhow::bail!("CreateCompatibleDC failed");
            }

            // Negative height for top-down rows, so row 0 is the top of the
            // screen and the arithmetic below reads the way it looks.
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = width;
            bmi.bmiHeader.biHeight = -height;
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;

            let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
            let bitmap = match CreateDIBSection(Some(dc), &bmi, DIB_RGB_COLORS, &mut bits, None, 0) {
                Ok(b) if !bits.is_null() => b,
                Ok(_) => {
                    let _ = DeleteDC(dc);
                    anyhow::bail!("CreateDIBSection returned no pixel pointer");
                }
                Err(e) => {
                    let _ = DeleteDC(dc);
                    anyhow::bail!("CreateDIBSection failed: {e}");
                }
            };

            paint(bits as *mut u32, width, height, peak);
            // A DIB section is shared memory and GDI batches its calls. Without
            // this the first UpdateLayeredWindow can read the surface before our
            // writes have landed, which shows up as a torn or empty first frame.
            let _ = GdiFlush();

            let previous = SelectObject(dc, bitmap.into());
            Ok(Self {
                dc,
                bitmap,
                previous,
                width,
                height,
            })
        }
    }
}

impl Drop for Gradient {
    fn drop(&mut self) {
        // GDI handles are a finite process resource and this bitmap gets rebuilt
        // on every resolution change. Leaking one per rebuild is the exact bug
        // win32::screen already documents avoiding for cursor icons.
        unsafe {
            SelectObject(self.dc, self.previous);
            let _ = DeleteObject(self.bitmap.into());
            let _ = DeleteDC(self.dc);
        }
    }
}

/// Fill the edge band. Everything further in than `band` is left at zero, which
/// is what `CreateDIBSection` already handed us, so the interior costs nothing.
///
/// Alpha is a pure function of distance to the nearest outer edge, `d`, over a
/// band of `band` pixels. Two lobes rather than one power curve: a cubic that
/// collapses within the first fifth of the band gives the bright core, and a
/// near-linear term carries a long dim tail all the way in for the halo. One
/// power gets you either a hard-edged stripe or a thin line, never a glow.
/// Both lobes reach exactly zero at the inner edge, so there is no seam where
/// the band stops.
unsafe fn paint(bits: *mut u32, width: i32, height: i32, peak: f64) {
    let band = ((width.min(height) as f64) * BAND_FRACTION).round().max(1.0) as i32;

    // One entry per possible distance, so the float work happens a few hundred
    // times instead of a few million.
    let lut: Vec<u32> = (0..=band)
        .map(|d| {
            let u = 1.0 - (f64::from(d) / f64::from(band)).min(1.0);
            let a = peak * (0.72 * u * u * u + 0.28 * u.powf(1.15));
            let a8 = (a * 255.0).round().clamp(0.0, 255.0) as u32;
            // Premultiplied: colour channels are scaled by alpha, so a 40%
            // pixel is (102, 15, 11) and not (255, 38, 28). Get this wrong and
            // the band looks like a fogged windscreen instead of light. The
            // +127 rounds to nearest instead of truncating, which otherwise
            // biases every channel down and makes the halo look muddy.
            let r = (GLOW_R * a8 + 127) / 255;
            let g = (GLOW_G * a8 + 127) / 255;
            let b = (GLOW_B * a8 + 127) / 255;
            // Little-endian BGRA: the bytes land in memory as B, G, R, A.
            (a8 << 24) | (r << 16) | (g << 8) | b
        })
        .collect();

    unsafe {
        for y in 0..height {
            let dy = y.min(height - 1 - y);
            let row = bits.add(y as usize * width as usize);

            if dy < band {
                // Near the top or bottom edge, so every pixel in the row is lit
                // by at least the vertical distance.
                for x in 0..width {
                    let d = dy.min(x.min(width - 1 - x));
                    *row.add(x as usize) = lut[d as usize];
                }
            } else {
                // Middle rows: only the left and right strips. Walking to the
                // halfway point and writing both sides at once handles a screen
                // narrower than two bands without ever writing a pixel with the
                // wrong distance.
                let limit = band.min((width + 1) / 2);
                for x in 0..limit {
                    let v = lut[x as usize];
                    *row.add(x as usize) = v;
                    *row.add((width - 1 - x) as usize) = v;
                }
            }
        }
    }
}

// ─── The window ──────────────────────────────────────────────────────────────

/// Current virtual screen, in the physical pixels the mouse and capture tools
/// already work in. Origin is negative when a monitor sits left of or above the
/// primary, which is fine: the window goes wherever the desktop is.
fn virtual_screen() -> (i32, i32, i32, i32) {
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CAPTURE_BARRIER => {
                if CAPTURE_SUPPRESSED.load(Ordering::Acquire) {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                }
                LRESULT(1)
            }
            // Belt to WS_EX_TRANSPARENT's braces. The tools inject real clicks
            // with SendInput, and a window that answered a hit test would eat
            // them: a spectacular way for a status indicator to break the thing
            // it is reporting on.
            WM_NCHITTEST => LRESULT(HTTRANSPARENT as isize),
            // Same idea one layer up, for the paths that ask about activation
            // directly instead of going through hit testing.
            WM_MOUSEACTIVATE => LRESULT(MA_NOACTIVATE as isize),
            // Claim it and never paint. A layered window's pixels come from
            // UpdateLayeredWindow, so an erase would only cause a flicker.
            WM_ERASEBKGND => LRESULT(1),
            // Broadcast, so it lands here rather than in the queue. Bounce it to
            // the loop, which is where the geometry and the bitmap live.
            WM_DISPLAYCHANGE => {
                let _ = PostMessageW(Some(hwnd), WM_REFIT, WPARAM(0), LPARAM(0));
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// Everything the render loop owns.
struct Glow {
    hwnd: HWND,
    peak: f64,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    gradient: Option<Gradient>,
    visible: bool,
    dark_since: Option<Instant>,
    /// Whether the current gradient's pixels have been handed to the window yet.
    /// Cleared whenever the bitmap is rebuilt.
    uploaded: bool,
    /// Whether this driver honours a blend-only `UpdateLayeredWindow`. Latched
    /// false on the first refusal and never retried.
    blend_only: bool,
    /// Last alpha byte actually pushed, so an unchanged frame costs nothing.
    last_alpha: Option<u8>,
}

impl Glow {
    /// Push the current envelope level to the screen, building the bitmap on
    /// first use. An error here is terminal for the overlay: the caller logs it
    /// once and shuts the whole thing down rather than failing sixty times a
    /// second for the rest of the session.
    unsafe fn render(&mut self, alpha: u8) -> anyhow::Result<()> {
        unsafe {
            // The capture barrier must not be followed by a render that had
            // already sampled the old alpha. Never block the message pump.
            let _render = match CAPTURE_LOCK.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::WouldBlock) => return Ok(()),
                Err(TryLockError::Poisoned(_)) => {
                    anyhow::bail!("Activity glow capture synchronization was poisoned")
                }
            };
            let alpha = if CAPTURE_SUPPRESSED.load(Ordering::Acquire) {
                0
            } else {
                alpha
            };
            if alpha == 0 {
                if self.visible {
                    let _ = ShowWindow(self.hwnd, SW_HIDE);
                    self.visible = false;
                    self.last_alpha = None;
                    self.dark_since = Some(Instant::now());
                }
                return Ok(());
            }

            // Nothing to say. Matters most during the one-second hold, where the
            // byte sits at 255 for sixty consecutive ticks.
            if self.visible && self.last_alpha == Some(alpha) {
                return Ok(());
            }

            if self.gradient.is_none() {
                self.gradient = Some(Gradient::build(self.width, self.height, self.peak)?);
                self.uploaded = false;
            }
            // Copied out so the borrow ends here and the fallback below can
            // still touch `self`. All three are Copy.
            let (source, source_width, source_height) = match self.gradient.as_ref() {
                Some(g) => (g.dc, g.width, g.height),
                None => return Ok(()),
            };
            self.dark_since = None;

            let blend = BLENDFUNCTION {
                BlendOp: AC_SRC_OVER as u8,
                BlendFlags: 0,
                // The envelope, in one byte. Multiplies through the per-pixel
                // alpha of the premultiplied source, which is exactly a uniform
                // opacity scale of the gradient and costs nothing to compute.
                SourceConstantAlpha: alpha,
                AlphaFormat: AC_SRC_ALPHA as u8,
            };
            let position = POINT {
                x: self.x,
                y: self.y,
            };
            let size = SIZE {
                cx: source_width,
                cy: source_height,
            };
            let origin = POINT { x: 0, y: 0 };

            // The animation changes opacity and nothing else, and a null source
            // DC tells UpdateLayeredWindow exactly that: keep the pixels you
            // already have, just restate the blend. Without it every frame
            // re-uploads the whole desktop-sized surface, which on this machine
            // is 22MB sixty times a second for an effect that is one byte of
            // actual change. The first frame after a build still has to hand
            // the pixels over.
            let mut pushed = false;
            if self.uploaded && self.blend_only {
                let shortcut = UpdateLayeredWindow(
                    self.hwnd,
                    None,
                    None,
                    None,
                    None,
                    None,
                    COLORREF(0),
                    Some(&blend),
                    ULW_ALPHA,
                );
                match shortcut {
                    Ok(()) => pushed = true,
                    Err(e) => {
                        // Documented as valid, but drivers are drivers. Fall
                        // back permanently rather than failing the frame.
                        tracing::debug!(err = %e, "activity glow: blend-only update refused, uploading every frame from here");
                        self.blend_only = false;
                    }
                }
            }
            if !pushed {
                UpdateLayeredWindow(
                    self.hwnd,
                    None,
                    Some(&position),
                    Some(&size),
                    Some(source),
                    Some(&origin),
                    COLORREF(0),
                    Some(&blend),
                    ULW_ALPHA,
                )?;
                self.uploaded = true;
            }
            self.last_alpha = Some(alpha);

            if !self.visible {
                // SHOWNOACTIVATE, never SW_SHOW. keyboard_type injects into
                // whatever holds focus, so an indicator that stole it would send
                // the model's keystrokes into a window with no text field and no
                // explanation for where they went.
                let _ = ShowWindow(self.hwnd, SW_SHOWNOACTIVATE);
                self.visible = true;
            }
            Ok(())
        }
    }

    /// Monitor layout changed. The window is one rectangle over the whole
    /// desktop, so this is a resize and a rebuild rather than a teardown: the
    /// HWND stays valid and `pulse()` never sees a stale target.
    unsafe fn refit(&mut self) {
        unsafe {
            let (x, y, width, height) = virtual_screen();
            if (x, y, width, height) == (self.x, self.y, self.width, self.height) {
                return;
            }
            self.x = x;
            self.y = y;
            self.width = width;
            self.height = height;
            // Dropped, not rebuilt. The next render makes a new one at the new
            // size, and if the glow is dark right now we never pay for it.
            self.gradient = None;
            self.uploaded = false;
            self.last_alpha = None;
            let _ = SetWindowPos(
                self.hwnd,
                Some(HWND_TOPMOST),
                x,
                y,
                width,
                height,
                SWP_NOACTIVATE,
            );
            tracing::debug!(width, height, "activity glow: refit to new desktop geometry");
        }
    }
}

// ─── Thread ──────────────────────────────────────────────────────────────────

fn glow_thread(peak: f64, ready: mpsc::Sender<Result<String, String>>) {
    let mut glow = match unsafe { create(peak) } {
        Ok(glow) => glow,
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };

    let (width, height) = (glow.width, glow.height);
    let band = ((width.min(height) as f64) * BAND_FRACTION).round() as i32;
    TARGET.store(glow.hwnd.0 as isize, Ordering::Release);
    let _ = ready.send(Ok(format!(
        "{width}x{height} desktop, {band}px band, hidden from screen capture"
    )));

    // Caught rather than allowed to unwind, so a panic in the render loop still
    // reaches the teardown below. Otherwise the thread dies with TARGET still
    // pointing at a window nobody is pumping, and every subsequent pulse posts
    // into a queue that will never be drained.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&mut glow)));
    if panicked.is_err() {
        tracing::warn!("activity glow: render thread panicked, disarming");
    }

    // Whatever brought us here, stop accepting pulses before tearing the window
    // down, so nothing posts to a handle that is about to stop existing.
    TARGET.store(0, Ordering::Release);
    unsafe {
        let _ = DestroyWindow(glow.hwnd);
    }
}

unsafe fn create(peak: f64) -> anyhow::Result<Glow> {
    unsafe {
        let instance: HINSTANCE = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| anyhow::anyhow!("GetModuleHandleW failed: {e}"))?
            .into();

        let class_name = crate::win32::to_wide(CLASS_NAME);
        let class = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            // Already registered is fine: init() only runs once per process, but
            // there is no reason to die if that ever stops being true.
            let e = GetLastError();
            if e != ERROR_CLASS_ALREADY_EXISTS {
                anyhow::bail!("RegisterClassW failed with Win32 error {}", e.0);
            }
        }

        let (x, y, width, height) = virtual_screen();
        if width <= 0 || height <= 0 {
            anyhow::bail!("no virtual screen to draw on ({width}x{height})");
        }

        let hwnd = CreateWindowExW(
            // LAYERED for per-pixel alpha. TRANSPARENT so injected clicks pass
            // straight through. NOACTIVATE so it never takes focus from the
            // window the model is typing into. TOOLWINDOW to stay out of Alt-Tab
            // and the taskbar. TOPMOST because an indicator sitting behind the
            // window it is warning you about indicates nothing.
            WS_EX_LAYERED
                | WS_EX_TRANSPARENT
                | WS_EX_NOACTIVATE
                | WS_EX_TOOLWINDOW
                | WS_EX_TOPMOST,
            PCWSTR(class_name.as_ptr()),
            PCWSTR::null(),
            WS_POPUP,
            x,
            y,
            width,
            height,
            None,
            None,
            Some(instance),
            None,
        )
        .map_err(|e| anyhow::anyhow!("CreateWindowExW failed: {e}"))?;

        // Off by default. See the module docs: this flag makes the window
        // invisible to the human as well as to captures whenever the desktop is
        // served by an indirect or virtual display driver, and there is no way
        // to detect that from inside the process, because the failure and the
        // success look identical to every screenshot we could take.
        //
        // `screen_capture` no longer lights the glow, so a screenshot on its own
        // is clean without any help from Windows.
        if std::env::var("MCP_OVERLAY_AFFINITY").as_deref() == Ok("exclude") {
            match SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) {
                Ok(()) => tracing::info!("activity glow: excluded from screen capture"),
                Err(e) => tracing::warn!(
                    err = %e,
                    "activity glow: capture exclusion refused, carrying on without it"
                ),
            }
        }

        Ok(Glow {
            hwnd,
            peak,
            x,
            y,
            width,
            height,
            gradient: None,
            visible: false,
            dark_since: None,
            uploaded: false,
            blend_only: true,
            last_alpha: None,
        })
    }
}

/// Wait, drain, advance, draw.
///
/// Idle costs nothing: with the envelope at rest and the bitmap already
/// released, the wait is INFINITE and the thread is parked in the kernel until a
/// `pulse()` posts. While animating it wakes every 16ms. In between, once the
/// glow has gone dark but the bitmap is still around, it wakes exactly once more
/// to free it.
fn run(glow: &mut Glow) {
    let mut envelope = Envelope::new();
    // How long until the animation next needs attention. None means it is at
    // rest, in which case the only reason left to wake is to free the bitmap.
    let mut next_frame: Option<Duration> = None;

    loop {
        let timeout = match (next_frame, glow.dark_since) {
            (Some(d), _) => (d.as_millis() as u32).clamp(1, 1000),
            (None, Some(dark_since)) => {
                let left = DIB_IDLE_TIMEOUT.saturating_sub(dark_since.elapsed());
                (left.as_millis() as u32).max(1)
            }
            (None, None) => INFINITE,
        };

        unsafe {
            // Only signals for messages that arrived since the last peek, which
            // is why the drain below has to empty the queue completely.
            let waited = MsgWaitForMultipleObjects(None, false, timeout, QS_ALLINPUT);
            if waited != WAIT_TIMEOUT {
                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    match msg.message {
                        WM_QUIT => return,
                        WM_PULSE => envelope.trigger(Instant::now()),
                        WM_REFIT => glow.refit(),
                        WM_CAPTURE_CHANGED => {
                            glow.visible = IsWindowVisible(glow.hwnd).as_bool();
                            glow.last_alpha = None;
                        }
                        _ => {
                            let _ = TranslateMessage(&msg);
                            DispatchMessageW(&msg);
                        }
                    }
                }
            }

            let (level, next) = envelope.advance(Instant::now());
            next_frame = next;

            if next.is_some() || glow.visible {
                if let Err(e) = glow.render(shaped_alpha(level)) {
                    // Once, then never again. A monitor pulled mid-fade would
                    // otherwise write sixty identical warnings a second into a
                    // log the user is reading to understand something else.
                    tracing::warn!(err = %e, "activity glow: render failed, disarming");
                    return;
                }
            }

            // Nothing on screen and nobody has asked for anything in a while, so
            // hand the desktop-sized bitmap back.
            if next_frame.is_none()
                && glow.gradient.is_some()
                && glow
                    .dark_since
                    .is_some_and(|t| t.elapsed() >= DIB_IDLE_TIMEOUT)
            {
                glow.gradient = None;
                glow.dark_since = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_barrier_prevents_a_late_render_from_showing_the_glow() {
        let _capture = CAPTURE_LOCK.lock().unwrap();
        let mut glow = Glow {
            hwnd: HWND::default(),
            peak: DEFAULT_PEAK,
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            gradient: None,
            visible: false,
            dark_since: None,
            uploaded: false,
            blend_only: true,
            last_alpha: None,
        };
        unsafe { glow.render(255) }.unwrap();
        assert!(!glow.visible);
        assert!(glow.gradient.is_none());
    }

    /// Step the envelope to `ms` after `start` and report the level, the way
    /// the render loop does.
    fn at(e: &mut Envelope, start: Instant, ms: u64) -> f32 {
        e.advance(start + Duration::from_millis(ms)).0
    }

    fn idle(e: &mut Envelope, start: Instant, ms: u64) -> bool {
        e.advance(start + Duration::from_millis(ms)).1.is_none()
    }

    #[test]
    fn attack_reaches_full_in_a_quarter_second() {
        let start = Instant::now();
        let mut e = Envelope::new();
        e.trigger(start);
        let half = at(&mut e, start, 125);
        assert!((half - 0.5).abs() < 0.01, "half way up by 125ms, got {half}");
        assert_eq!(at(&mut e, start, 250), 1.0);
    }

    #[test]
    fn holds_then_releases_over_three_seconds() {
        let start = Instant::now();
        let mut e = Envelope::new();
        e.trigger(start);
        // Full for the whole hold, which runs 250ms to 1250ms.
        assert_eq!(at(&mut e, start, 300), 1.0);
        assert_eq!(at(&mut e, start, 1_200), 1.0);
        // A third of the way into the 3s fade.
        let third = at(&mut e, start, 2_250);
        assert!((third - 0.666).abs() < 0.01, "one third down, got {third}");
        assert!(idle(&mut e, start, 4_300), "dark by 4.25s");
    }

    /// A single tick that arrives very late still lands at the right level.
    /// The loop can be starved by a busy machine or a suspend, and an envelope
    /// that accumulated per-frame deltas would come out of that stuck bright.
    #[test]
    fn a_late_tick_lands_where_the_clock_says() {
        let start = Instant::now();
        let mut e = Envelope::new();
        e.trigger(start);
        // Straight from trigger to mid-release in one step, skipping the attack
        // and the entire hold.
        let level = at(&mut e, start, 2_250);
        assert!((level - 0.666).abs() < 0.01, "got {level}");
    }

    /// The behaviour the whole envelope exists for: a tool call landing during
    /// the fade ramps back up from where it was, rather than snapping to full
    /// or blinking through black on the way.
    #[test]
    fn retrigger_resumes_from_the_current_level() {
        let start = Instant::now();
        let mut e = Envelope::new();
        e.trigger(start);
        let during_release = at(&mut e, start, 2_250);
        assert!((0.6..0.75).contains(&during_release), "{during_release}");

        e.trigger(start + Duration::from_millis(2_250));
        let resumed = at(&mut e, start, 2_266);
        assert!(resumed > during_release, "should be rising, got {resumed}");
        assert!(
            resumed < during_release + 0.2,
            "should ease up, not snap to full, got {resumed}"
        );

        // Constant rise rate, so recovering the last third takes a third of the
        // full attack rather than the whole 250ms.
        assert_eq!(at(&mut e, start, 2_250 + 84), 1.0);
    }

    /// Retriggering while already at full just pushes the hold out. It must not
    /// restart the attack, which would be a no-op visually but would move the
    /// hold's origin and make a fast tool loop hold forever.
    #[test]
    fn retrigger_at_full_extends_the_hold() {
        let start = Instant::now();
        let mut e = Envelope::new();
        e.trigger(start);
        assert_eq!(at(&mut e, start, 300), 1.0);

        e.trigger(start + Duration::from_millis(300));
        // Original hold would have ended at 1250ms; the new one runs to 1300ms.
        assert_eq!(at(&mut e, start, 1_290), 1.0);
        assert!(at(&mut e, start, 1_400) < 1.0, "released after the new hold");
    }

    #[test]
    fn alpha_is_flat_at_both_ends() {
        assert_eq!(shaped_alpha(0.0), 0);
        assert_eq!(shaped_alpha(1.0), 255);
        assert_eq!(shaped_alpha(0.5), 128);
        // Smoothstep pulls the early ramp down, so the glow does not lurch off
        // the floor the instant a tool fires.
        assert!(shaped_alpha(0.25) < 64);
    }
}
