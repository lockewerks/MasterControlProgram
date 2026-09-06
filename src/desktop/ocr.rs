use crate::desktop::Operation;
use crate::win32::{display::Rect, screen::CaptureFrame};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    mpsc::{self, TryRecvError},
    Arc,
};
use std::time::Duration;
use windows::core::{Interface, HSTRING};
use windows::Foundation::{IClosable, IReference, Rect as BitmapRect};
use windows::Globalization::Language;
use windows::Graphics::Imaging::{
    BitmapAlphaMode, BitmapBufferAccessMode, BitmapPixelFormat, SoftwareBitmap,
};
use windows::Media::Ocr::{OcrEngine, OcrResult as NativeOcrResult};
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::WinRT::{
    IMemoryBufferByteAccess, RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED,
};

const MAX_BITMAP_DIMENSION: u32 = 4096;
const MAX_LINES: usize = 512;
const MAX_WORDS: usize = 2048;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_LINE_TEXT_BYTES: usize = 8 * 1024;
const MAX_WORD_TEXT_BYTES: usize = 1024;
const MAX_TOTAL_TEXT_BYTES: usize = 128 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SOURCE: &str = "windows_ocr";
const SLOT_IDLE: u8 = 0;
const SLOT_ACTIVE: u8 = 1;
const SLOT_QUARANTINED: u8 = 2;
static OCR_SLOT: AtomicU8 = AtomicU8::new(SLOT_IDLE);

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OcrResult {
    pub(crate) source: &'static str,
    pub(crate) processing: &'static str,
    pub(crate) language: String,
    pub(crate) text_angle_degrees: Option<f64>,
    pub(crate) text: String,
    pub(crate) lines: Vec<OcrLine>,
    pub(crate) confidence: Option<f64>,
    pub(crate) uncertainty: &'static str,
    pub(crate) coordinate_space: &'static str,
    pub(crate) bitmap: OcrBitmap,
    pub(crate) truncated: bool,
    pub(crate) truncation: OcrTruncation,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OcrLine {
    pub(crate) source: &'static str,
    pub(crate) text: String,
    pub(crate) words: Vec<OcrWord>,
    pub(crate) confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OcrWord {
    pub(crate) source: &'static str,
    pub(crate) text: String,
    pub(crate) bounds: Rect,
    pub(crate) polygon: [OcrPoint; 4],
    pub(crate) confidence: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub(crate) struct OcrPoint {
    pub(crate) x: f64,
    pub(crate) y: f64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OcrBitmap {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) scale_x: f64,
    pub(crate) scale_y: f64,
    pub(crate) downscaled: bool,
    pub(crate) resampling: &'static str,
    pub(crate) rotation_degrees: u32,
}

#[derive(Debug, Default, Clone, Serialize)]
pub(crate) struct OcrTruncation {
    pub(crate) lines: bool,
    pub(crate) words: bool,
    pub(crate) text: bool,
}

struct Apartment(PhantomData<Rc<()>>);

impl Apartment {
    fn enter() -> Result<Self> {
        match unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
            Ok(()) => Ok(Self(PhantomData)),
            Err(error) if error.code() == RPC_E_CHANGED_MODE => {
                bail!("Windows OCR needs an MTA blocking worker; this thread already has a different COM apartment");
            }
            Err(error) => Err(error).context("Cannot initialize Windows Runtime for local OCR"),
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // RoInitialize increments the apartment count for both S_OK and S_FALSE.
        unsafe { RoUninitialize() };
    }
}

struct Flight<'a> {
    slot: &'a AtomicU8,
    started: AtomicBool,
    completed: AtomicBool,
}

impl<'a> Flight<'a> {
    fn acquire(slot: &'a AtomicU8) -> Result<Self> {
        match slot.compare_exchange(SLOT_IDLE, SLOT_ACTIVE, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(Self {
                slot,
                started: AtomicBool::new(false),
                completed: AtomicBool::new(false),
            }),
            Err(SLOT_QUARANTINED) => {
                bail!("Windows OCR is unavailable after an unmonitorable native operation; restart this process before retrying");
            }
            Err(_) => {
                bail!("Windows OCR is busy with a previous recognition or pending cancellation; only one native operation is allowed");
            }
        }
    }

    fn quarantine(&self) {
        self.slot.store(SLOT_QUARANTINED, Ordering::Release);
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let next =
            if !self.started.load(Ordering::Acquire) || self.completed.load(Ordering::Acquire) {
                SLOT_IDLE
            } else {
                SLOT_QUARANTINED
            };
        let _ = self
            .slot
            .compare_exchange(SLOT_ACTIVE, next, Ordering::AcqRel, Ordering::Acquire);
    }
}

struct CloseOnDrop<T: Interface>(T);

impl<T: Interface> Drop for CloseOnDrop<T> {
    fn drop(&mut self) {
        match self.0.cast::<IClosable>() {
            Ok(closable) => {
                if let Err(error) = closable.Close() {
                    tracing::warn!(%error, resource = std::any::type_name::<T>(), "Could not close an OCR bitmap resource");
                }
            }
            Err(error) => {
                tracing::warn!(%error, resource = std::any::type_name::<T>(), "OCR bitmap resource has no close interface");
            }
        }
    }
}

pub(crate) fn recognize(
    frame: &CaptureFrame,
    language: Option<&str>,
    op: &Operation,
) -> Result<OcrResult> {
    op.check()?;
    let flight = Arc::new(Flight::acquire(&OCR_SLOT)?);
    let _apartment = Apartment::enter()?;
    let source_size = ImageSize {
        width: frame.metadata.width,
        height: frame.metadata.height,
    };
    if source_size.byte_len()? != frame.bgra.len() {
        bail!("Windows OCR requires a tightly packed, top-down BGRA capture of the declared dimensions");
    }
    let (engine, actual_language) = create_engine(language)?;
    op.check()?;
    let maximum =
        OcrEngine::MaxImageDimension().context("Cannot query the local Windows OCR image limit")?;
    let size = fit_dimensions(source_size, maximum)?;
    let mapping = Mapping::new(
        [frame.metadata.origin_x, frame.metadata.origin_y],
        [frame.metadata.scale_x, frame.metadata.scale_y],
        source_size,
        size,
    )?;
    let bitmap = make_bitmap(frame, source_size, size, op)?;
    op.check()?;

    let pending = engine
        .RecognizeAsync(&bitmap)
        .context("Cannot start local Windows OCR recognition")?;
    flight.started.store(true, Ordering::Release);

    let (send, receive) = mpsc::sync_channel(1);
    let completion_flight = Arc::clone(&flight);
    let retained_bitmap = bitmap.clone();
    let retained_engine = engine.clone();
    // These classes and OcrResult are agile in the WinRT metadata and bindings.
    let registration = pending.when(move |result| {
        let _retained = (retained_bitmap, retained_engine);
        completion_flight.completed.store(true, Ordering::Release);
        let _ = send.try_send(result);
    });
    if let Err(error) = registration {
        flight.quarantine();
        let cancellation = pending.Cancel();
        return Err(anyhow!(error)).context(format!(
            "Cannot monitor Windows OCR completion. {}; the global OCR slot is quarantined until process restart",
            cancellation_message(cancellation)
        ));
    }

    let native = loop {
        if let Err(error) = op.check() {
            return Err(error).context(cancellation_message(pending.Cancel()));
        }
        match receive.try_recv() {
            Ok(result) => break result,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                flight.quarantine();
                bail!(
                    "Windows OCR lost its completion callback. {}; the global OCR slot is quarantined until process restart",
                    cancellation_message(pending.Cancel())
                );
            }
        }
        if let Err(error) = op.wait(POLL_INTERVAL.min(op.remaining())) {
            return Err(error).context(cancellation_message(pending.Cancel()));
        }
    };
    op.check()?;
    let native = native.context("Local Windows OCR failed or was canceled by Windows")?;
    collect_result(&native, actual_language, mapping, source_size != size, op)
}

fn cancellation_message(result: windows::core::Result<()>) -> String {
    // IAsyncOperation::Cancel forwards to IAsyncInfo::Cancel in windows 0.62.
    match result {
        Ok(()) => "Windows OCR cancellation requested; the provider may still be running and its single global slot remains occupied until native completion".into(),
        Err(error) => format!(
            "Windows OCR cancellation failed ({error}); its single global slot remains occupied until native completion"
        ),
    }
}

fn create_engine(requested: Option<&str>) -> Result<(OcrEngine, String)> {
    let (engine, requested_tag) = if let Some(tag) = requested {
        if tag.is_empty()
            || tag.len() > 128
            || !tag.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            bail!("OCR language must be a nonempty BCP-47 tag of at most 128 ASCII bytes");
        }
        let language = Language::CreateLanguage(&HSTRING::from(tag))
            .with_context(|| format!("Invalid or unavailable Windows OCR language {tag}"))?;
        let canonical = language
            .LanguageTag()
            .context("Cannot read the requested OCR language tag")?
            .to_string_lossy();
        if !OcrEngine::IsLanguageSupported(&language)
            .context("Cannot query locally installed Windows OCR language support")?
        {
            bail!("Windows OCR language {canonical} is not supported by an installed local OCR capability");
        }
        let engine = OcrEngine::TryCreateFromLanguage(&language).with_context(|| {
            format!("Local Windows OCR capability for language {canonical} is unavailable")
        })?;
        (engine, Some(canonical))
    } else {
        let engine = OcrEngine::TryCreateFromUserProfileLanguages().context(
            "No local Windows OCR engine is available for the installed user-profile languages; an installed OCR language capability is required",
        )?;
        (engine, None)
    };
    let actual = engine
        .RecognizerLanguage()
        .context("Cannot read the local OCR recognizer language")?
        .LanguageTag()
        .context("Cannot read the local OCR recognizer language tag")?
        .to_string_lossy();
    if let Some(requested) = requested_tag {
        // TryCreateFromLanguage can resolve to a different installed language.
        if !actual.eq_ignore_ascii_case(&requested) {
            bail!("Windows OCR resolved requested language {requested} to {actual}; refusing language fallback");
        }
    }
    Ok((engine, actual))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageSize {
    width: u32,
    height: u32,
}

impl ImageSize {
    fn byte_len(self) -> Result<usize> {
        if self.width == 0 || self.height == 0 {
            bail!("OCR image dimensions must be nonzero");
        }
        let bytes = u64::from(self.width)
            .checked_mul(u64::from(self.height))
            .and_then(|pixels| pixels.checked_mul(4))
            .context("OCR image byte length overflow")?;
        usize::try_from(bytes).context("OCR image exceeds the addressable buffer size")
    }
}

fn fit_dimensions(source: ImageSize, native_limit: u32) -> Result<ImageSize> {
    source.byte_len()?;
    let limit = native_limit.min(MAX_BITMAP_DIMENSION);
    if limit == 0 {
        bail!("Windows OCR reported no supported image dimensions");
    }
    let longest = source.width.max(source.height);
    if longest <= limit {
        return Ok(source);
    }
    let scale = |value| (u64::from(value) * u64::from(limit) / u64::from(longest)).max(1) as u32;
    Ok(ImageSize {
        width: scale(source.width),
        height: scale(source.height),
    })
}

#[derive(Debug, Clone, Copy)]
struct BitmapLayout {
    start: i32,
    stride: i32,
}

impl BitmapLayout {
    fn validate(self, size: ImageSize, capacity: usize) -> Result<()> {
        size.byte_len()?;
        let row_bytes = i64::from(size.width) * 4;
        let first = i64::from(self.start);
        let last = first + i64::from(size.height - 1) * i64::from(self.stride);
        let end = first
            .max(last)
            .checked_add(row_bytes)
            .context("OCR bitmap plane byte range overflow")?;
        if i64::from(self.stride).abs() < row_bytes
            || first.min(last) < 0
            || end > i64::try_from(capacity).unwrap_or(i64::MAX)
            || capacity > isize::MAX as usize
        {
            bail!("Windows returned an invalid or undersized OCR bitmap plane");
        }
        Ok(())
    }

    fn row_start(self, y: u32) -> usize {
        (i64::from(self.start) + i64::from(y) * i64::from(self.stride)) as usize
    }
}

fn make_bitmap(
    frame: &CaptureFrame,
    source: ImageSize,
    size: ImageSize,
    op: &Operation,
) -> Result<SoftwareBitmap> {
    let bitmap = SoftwareBitmap::CreateWithAlpha(
        BitmapPixelFormat::Bgra8,
        i32::try_from(size.width)?,
        i32::try_from(size.height)?,
        BitmapAlphaMode::Ignore,
    )
    .context("Cannot allocate a bounded Windows OCR SoftwareBitmap")?;
    {
        let buffer = CloseOnDrop(
            bitmap
                .LockBuffer(BitmapBufferAccessMode::Write)
                .context("Cannot lock the OCR SoftwareBitmap")?,
        );
        let plane = buffer
            .0
            .GetPlaneDescription(0)
            .context("Cannot read the OCR bitmap plane")?;
        if plane.Width != size.width as i32 || plane.Height != size.height as i32 {
            bail!("Windows returned unexpected OCR bitmap plane dimensions");
        }
        let reference = CloseOnDrop(
            buffer
                .0
                .CreateReference()
                .context("Cannot reference the OCR bitmap pixels")?,
        );
        let access: IMemoryBufferByteAccess = reference
            .0
            .cast()
            .context("Windows does not expose the OCR bitmap pixel buffer")?;
        let mut pointer = std::ptr::null_mut();
        let mut capacity = 0;
        unsafe { access.GetBuffer(&mut pointer, &mut capacity) }
            .context("Cannot access the OCR bitmap pixels")?;
        let layout = BitmapLayout {
            start: plane.StartIndex,
            stride: plane.Stride,
        };
        layout.validate(size, capacity as usize)?;
        if pointer.is_null() {
            bail!("Windows returned a null OCR bitmap pixel buffer");
        }
        // The write lock and reference outlive this slice; row bounds include signed stride.
        let pixels = unsafe { std::slice::from_raw_parts_mut(pointer, capacity as usize) };
        write_pixels(&frame.bgra, source, pixels, size, layout, || op.check())?;
    }
    op.check()?;
    Ok(bitmap)
}

fn write_pixels(
    source: &[u8],
    source_size: ImageSize,
    destination: &mut [u8],
    size: ImageSize,
    layout: BitmapLayout,
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<()> {
    if source.len() != source_size.byte_len()? {
        bail!("Invalid source BGRA byte length");
    }
    layout.validate(size, destination.len())?;
    let source_stride = source_size.width as usize * 4;
    for y in 0..size.height {
        if y % 16 == 0 {
            checkpoint()?;
        }
        let source_y = nearest_sample(y, source_size.height, size.height);
        let offset = layout.row_start(y);
        let row = &mut destination[offset..offset + size.width as usize * 4];
        if source_size.width == size.width {
            let start = source_y as usize * source_stride;
            row.copy_from_slice(&source[start..start + row.len()]);
            for pixel in row.as_chunks_mut::<4>().0 {
                pixel[3] = 255;
            }
        } else {
            for (x, pixel) in row.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let source_x = nearest_sample(x as u32, source_size.width, size.width);
                let start = source_y as usize * source_stride + source_x as usize * 4;
                pixel[..3].copy_from_slice(&source[start..start + 3]);
                pixel[3] = 255;
            }
        }
    }
    checkpoint()
}

fn nearest_sample(position: u32, source: u32, target: u32) -> u32 {
    (((u64::from(position) * 2 + 1) * u64::from(source)) / (u64::from(target) * 2))
        .min(u64::from(source - 1)) as u32
}

#[derive(Debug, Clone, Copy)]
struct Mapping {
    origin: [i32; 2],
    scale: [f64; 2],
    bitmap: ImageSize,
}

impl Mapping {
    fn new(
        origin: [i32; 2],
        capture_scale: [f64; 2],
        capture: ImageSize,
        bitmap: ImageSize,
    ) -> Result<Self> {
        capture.byte_len()?;
        bitmap.byte_len()?;
        let scale = [
            capture_scale[0] * f64::from(bitmap.width) / f64::from(capture.width),
            capture_scale[1] * f64::from(bitmap.height) / f64::from(capture.height),
        ];
        if !capture_scale
            .into_iter()
            .chain(scale)
            .all(|v| v.is_finite() && v > 0.0)
        {
            bail!("OCR capture and bitmap scales must be finite and positive");
        }
        Ok(Self {
            origin,
            scale,
            bitmap,
        })
    }

    fn word(self, rect: BitmapRect, angle: Option<f64>) -> Result<(Rect, [OcrPoint; 4])> {
        if ![rect.X, rect.Y, rect.Width, rect.Height]
            .into_iter()
            .all(f32::is_finite)
            || rect.Width <= 0.0
            || rect.Height <= 0.0
        {
            bail!("Windows OCR returned invalid word bounds");
        }
        let angle = angle.unwrap_or(0.0);
        if !angle.is_finite() {
            bail!("Windows OCR returned a non-finite text angle");
        }
        let (sin, cos) = match angle.rem_euclid(360.0) {
            0.0 => (0.0, 1.0),
            90.0 => (1.0, 0.0),
            180.0 => (0.0, -1.0),
            270.0 => (-1.0, 0.0),
            other => other.to_radians().sin_cos(),
        };
        let cx = f64::from(self.bitmap.width) / 2.0;
        let cy = f64::from(self.bitmap.height) / 2.0;
        let left = f64::from(rect.X);
        let top = f64::from(rect.Y);
        let right = left + f64::from(rect.Width);
        let bottom = top + f64::from(rect.Height);
        // TextAngle rotates the overlay clockwise about the submitted bitmap center.
        // No BitmapTransform/EXIF rotation is applied to these captured pixels.
        let polygon =
            [(left, top), (right, top), (right, bottom), (left, bottom)].map(|(x, y)| OcrPoint {
                x: f64::from(self.origin[0])
                    + (cx + cos * (x - cx) - sin * (y - cy)) / self.scale[0],
                y: f64::from(self.origin[1])
                    + (cy + sin * (x - cx) + cos * (y - cy)) / self.scale[1],
            });
        Ok((enclosing_bounds(&polygon)?, polygon))
    }
}

fn enclosing_bounds(polygon: &[OcrPoint; 4]) -> Result<Rect> {
    if !polygon.iter().all(|p| p.x.is_finite() && p.y.is_finite()) {
        bail!("OCR physical word coordinates are not finite");
    }
    let left = polygon
        .iter()
        .map(|p| p.x)
        .fold(f64::INFINITY, f64::min)
        .floor();
    let top = polygon
        .iter()
        .map(|p| p.y)
        .fold(f64::INFINITY, f64::min)
        .floor();
    let right = polygon
        .iter()
        .map(|p| p.x)
        .fold(f64::NEG_INFINITY, f64::max)
        .ceil();
    let bottom = polygon
        .iter()
        .map(|p| p.y)
        .fold(f64::NEG_INFINITY, f64::max)
        .ceil();
    if left < f64::from(i32::MIN)
        || top < f64::from(i32::MIN)
        || right > f64::from(i32::MAX)
        || bottom > f64::from(i32::MAX)
        || right - left > f64::from(i32::MAX)
        || bottom - top > f64::from(i32::MAX)
    {
        bail!("OCR word bounds exceed physical Win32 pixel coordinates");
    }
    let bounds = Rect {
        x: left as i32,
        y: top as i32,
        width: (right - left) as u32,
        height: (bottom - top) as u32,
    };
    bounds
        .validate()
        .context("Invalid physical OCR word bounds")?;
    Ok(bounds)
}

struct TextBudget {
    remaining: usize,
    truncated: bool,
}

impl TextBudget {
    fn take(&mut self, utf16: &[u16], limit: usize) -> String {
        let limit = self.remaining.min(limit);
        let mut text = String::new();
        for character in char::decode_utf16(utf16.iter().copied()) {
            let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
            if text.len() + character.len_utf8() > limit {
                self.truncated = true;
                break;
            }
            text.push(character);
        }
        self.remaining -= text.len();
        text
    }
}

fn capped_count(available: u32, remaining: usize) -> (usize, bool) {
    let available = available as usize;
    (available.min(remaining), available > remaining)
}

fn nullable_angle(value: windows::core::Result<IReference<f64>>) -> Result<Option<f64>> {
    let angle = match value {
        Ok(value) => Some(value.Value().context("Cannot read the OCR text angle")?),
        // windows-core 0.62 maps a successful null interface to Error::empty (S_OK).
        Err(error) if error.code().0 == 0 => None,
        Err(error) => return Err(error).context("Cannot read the OCR text angle"),
    };
    if angle.is_some_and(|value| !value.is_finite()) {
        bail!("Windows OCR returned a non-finite text angle");
    }
    Ok(angle)
}

fn collect_result(
    native: &NativeOcrResult,
    language: String,
    mapping: Mapping,
    downscaled: bool,
    op: &Operation,
) -> Result<OcrResult> {
    op.check()?;
    let angle = nullable_angle(native.TextAngle())?;
    let mut budget = TextBudget {
        remaining: MAX_TOTAL_TEXT_BYTES,
        truncated: false,
    };
    let text = budget.take(
        &native.Text().context("Cannot read OCR text")?,
        MAX_TEXT_BYTES,
    );
    let native_lines = native.Lines().context("Cannot read OCR lines")?;
    let (line_count, lines_truncated) = capped_count(
        native_lines.Size().context("Cannot count OCR lines")?,
        MAX_LINES,
    );
    let mut truncation = OcrTruncation {
        lines: lines_truncated,
        ..Default::default()
    };
    let mut lines = Vec::with_capacity(line_count);
    let mut total_words = 0;
    for index in 0..line_count {
        op.check()?;
        if budget.remaining == 0 {
            budget.truncated = true;
            break;
        }
        if total_words == MAX_WORDS {
            truncation.words = true;
            break;
        }
        let line = native_lines
            .GetAt(index as u32)
            .context("Cannot read an OCR line")?;
        let line_text = budget.take(
            &line.Text().context("Cannot read OCR line text")?,
            MAX_LINE_TEXT_BYTES,
        );
        let native_words = line.Words().context("Cannot read OCR words")?;
        let (count, words_truncated) = capped_count(
            native_words.Size().context("Cannot count OCR words")?,
            MAX_WORDS - total_words,
        );
        truncation.words |= words_truncated;
        let mut words = Vec::with_capacity(count);
        for index in 0..count {
            op.check()?;
            if budget.remaining == 0 {
                budget.truncated = true;
                break;
            }
            let word = native_words
                .GetAt(index as u32)
                .context("Cannot read an OCR word")?;
            let (bounds, polygon) = mapping.word(
                word.BoundingRect().context("Cannot read OCR word bounds")?,
                angle,
            )?;
            let text = budget.take(
                &word.Text().context("Cannot read OCR word text")?,
                MAX_WORD_TEXT_BYTES,
            );
            words.push(OcrWord {
                source: SOURCE,
                text,
                bounds,
                polygon,
                confidence: None,
            });
            total_words += 1;
        }
        lines.push(OcrLine {
            source: SOURCE,
            text: line_text,
            words,
            confidence: None,
        });
    }
    op.check()?;
    truncation.text = budget.truncated;
    Ok(OcrResult {
        source: SOURCE,
        processing: "local",
        language,
        text_angle_degrees: angle,
        text,
        lines,
        confidence: None,
        uncertainty: "OCR is text inference from captured pixels, not guaranteed control identity. Windows OCR provides no confidence scores; null confidence is unavailable, not certainty. A null text angle uses unrotated rectangles and has unknown orientation. Mixed text angles and downscaling can reduce accuracy.",
        coordinate_space: "physical_virtual_screen_pixels",
        bitmap: OcrBitmap {
            width: mapping.bitmap.width,
            height: mapping.bitmap.height,
            scale_x: mapping.scale[0],
            scale_y: mapping.scale[1],
            downscaled,
            resampling: if downscaled { "nearest_neighbor" } else { "none" },
            rotation_degrees: 0,
        },
        truncated: truncation.lines || truncation.words || truncation.text,
        truncation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(width: u32, height: u32) -> ImageSize {
        ImageSize { width, height }
    }

    fn rect(x: f32, y: f32, width: f32, height: f32) -> BitmapRect {
        BitmapRect {
            X: x,
            Y: y,
            Width: width,
            Height: height,
        }
    }

    #[test]
    fn negative_origin_and_capture_and_ocr_scaling() {
        let mapping =
            Mapping::new([-1920, -200], [0.5, 2.0], size(200, 100), size(100, 50)).unwrap();
        let (bounds, polygon) = mapping.word(rect(10.0, 20.0, 30.0, 10.0), None).unwrap();
        assert_eq!(
            bounds,
            Rect {
                x: -1880,
                y: -180,
                width: 120,
                height: 10
            }
        );
        assert_eq!(
            polygon[0],
            OcrPoint {
                x: -1880.0,
                y: -180.0
            }
        );
        assert_eq!(
            polygon[2],
            OcrPoint {
                x: -1760.0,
                y: -170.0
            }
        );
    }

    #[test]
    fn clockwise_rotation_precedes_anisotropic_physical_mapping() {
        let mapping =
            Mapping::new([-300, -100], [0.5, 2.0], size(200, 100), size(200, 100)).unwrap();
        let (bounds, polygon) = mapping
            .word(rect(110.0, 40.0, 20.0, 10.0), Some(90.0))
            .unwrap();
        assert_eq!(
            bounds,
            Rect {
                x: -100,
                y: -70,
                width: 20,
                height: 10
            }
        );
        assert_eq!(
            polygon,
            [
                OcrPoint { x: -80.0, y: -70.0 },
                OcrPoint { x: -80.0, y: -60.0 },
                OcrPoint {
                    x: -100.0,
                    y: -60.0
                },
                OcrPoint {
                    x: -100.0,
                    y: -70.0
                },
            ]
        );
    }

    #[test]
    fn rotated_polygon_is_enclosed_outward_without_clipping() {
        let mapping =
            Mapping::new([-100, -50], [1.0, 1.0], size(200, 100), size(200, 100)).unwrap();
        let (bounds, polygon) = mapping
            .word(rect(0.0, 0.0, 20.0, 10.0), Some(-30.0))
            .unwrap();
        for point in polygon {
            assert!(point.x >= f64::from(bounds.x));
            assert!(point.y >= f64::from(bounds.y));
            assert!(point.x <= bounds.right() as f64);
            assert!(point.y <= bounds.bottom() as f64);
        }
        assert!(bounds.x < -100);
    }

    #[test]
    fn invalid_coordinates_and_scales_are_rejected() {
        for scale in [0.0, -1.0, f64::INFINITY, f64::NAN] {
            assert!(Mapping::new([0, 0], [scale, 1.0], size(2, 2), size(2, 2)).is_err());
        }
        let mapping = Mapping::new([0, 0], [1.0, 1.0], size(2, 2), size(2, 2)).unwrap();
        assert!(mapping
            .word(rect(0.0, 0.0, 1.0, 1.0), Some(f64::NAN))
            .is_err());
        assert!(mapping
            .word(rect(f32::INFINITY, 0.0, 1.0, 1.0), None)
            .is_err());
        assert!(mapping.word(rect(0.0, 0.0, -1.0, 1.0), None).is_err());
        assert!(mapping.word(rect(f32::MAX, 0.0, 1.0, 1.0), None).is_err());
    }

    #[test]
    fn image_limits_preserve_actual_axis_ratios() {
        assert_eq!(
            fit_dimensions(size(1920, 1080), 2600).unwrap(),
            size(1920, 1080)
        );
        assert_eq!(
            fit_dimensions(size(3840, 2160), 2600).unwrap(),
            size(2600, 1462)
        );
        assert_eq!(
            fit_dimensions(size(2160, 3840), 2600).unwrap(),
            size(1462, 2600)
        );
        assert_eq!(
            fit_dimensions(size(1, 100_000), 2600).unwrap(),
            size(1, 2600)
        );
        assert_eq!(
            fit_dimensions(size(10_000, 10_000), u32::MAX).unwrap(),
            size(4096, 4096)
        );
        assert!(fit_dimensions(size(1, 1), 0).is_err());
        assert!(fit_dimensions(size(0, 1), 2600).is_err());
        assert!(size(u32::MAX, u32::MAX).byte_len().is_err());
    }

    #[test]
    fn nearest_scaling_sets_alpha_without_changing_source() {
        let source: Vec<u8> = (0..8).flat_map(|value| [value, value, value, 0]).collect();
        let original = source.clone();
        let mut destination = [0; 8];
        write_pixels(
            &source,
            size(4, 2),
            &mut destination,
            size(2, 1),
            BitmapLayout {
                start: 0,
                stride: 8,
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(destination, [5, 5, 5, 255, 7, 7, 7, 255]);
        assert_eq!(source, original);
    }

    #[test]
    fn signed_bitmap_stride_does_not_flip_the_input() {
        let source = [1, 2, 3, 0, 4, 5, 6, 0];
        let mut destination = [99; 12];
        write_pixels(
            &source,
            size(1, 2),
            &mut destination,
            size(1, 2),
            BitmapLayout {
                start: 8,
                stride: -8,
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(&destination[8..12], &[1, 2, 3, 255]);
        assert_eq!(&destination[0..4], &[4, 5, 6, 255]);
        assert_eq!(&destination[4..8], &[99; 4]);
        assert!(BitmapLayout {
            start: 0,
            stride: -8
        }
        .validate(size(1, 2), 12)
        .is_err());
        assert!(BitmapLayout {
            start: 0,
            stride: 2
        }
        .validate(size(1, 2), 12)
        .is_err());
        assert!(BitmapLayout {
            start: 0,
            stride: 8
        }
        .validate(size(1, 2), 11)
        .is_err());
    }

    #[test]
    fn pixel_copy_observes_a_stopped_operation() {
        let mut destination = [0; 4];
        assert!(write_pixels(
            &[0; 4],
            size(1, 1),
            &mut destination,
            size(1, 1),
            BitmapLayout {
                start: 0,
                stride: 4
            },
            || bail!("canceled")
        )
        .is_err());
        assert_eq!(destination, [0; 4]);
    }

    #[test]
    fn text_caps_preserve_utf8_and_share_an_aggregate_budget() {
        let input: Vec<u16> = "A\u{1f642}BC".encode_utf16().collect();
        let mut budget = TextBudget {
            remaining: 7,
            truncated: false,
        };
        assert_eq!(budget.take(&input, 6), "A\u{1f642}B");
        assert!(budget.truncated);
        assert_eq!(budget.remaining, 1);
        assert_eq!(budget.take(&[b'Z' as u16; 2], 100), "Z");
        assert_eq!(budget.remaining, 0);
        assert!(budget.take(&input, 100).is_empty());
    }

    #[test]
    fn exact_text_caps_and_invalid_utf16_are_explicit() {
        let mut budget = TextBudget {
            remaining: 6,
            truncated: false,
        };
        assert_eq!(budget.take(&[b'a' as u16; 3], 3), "aaa");
        assert!(!budget.truncated);
        assert_eq!(budget.take(&[0xd800], 3), "\u{fffd}");
        assert!(!budget.truncated);
        assert_eq!(budget.remaining, 0);
        assert_eq!(
            capped_count(MAX_WORDS as u32, MAX_WORDS),
            (MAX_WORDS, false)
        );
        assert_eq!(capped_count(u32::MAX, MAX_WORDS), (MAX_WORDS, true));
        assert_eq!(capped_count(1, 0), (0, true));
        assert_eq!(capped_count(0, 0), (0, false));
    }

    #[test]
    fn word_caps_apply_across_lines() {
        let (first, truncated) = capped_count(1500, MAX_WORDS);
        assert_eq!(first, 1500);
        assert!(!truncated);
        let (second, truncated) = capped_count(1000, MAX_WORDS - first);
        assert_eq!(first + second, MAX_WORDS);
        assert!(truncated);
    }

    #[test]
    fn absent_angle_does_not_hide_a_native_failure() {
        assert_eq!(
            nullable_angle(Err(windows::core::Error::empty())).unwrap(),
            None
        );
        let pointer_error =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x80004003_u32 as i32));
        assert!(nullable_angle(Err(pointer_error)).is_err());
    }

    #[test]
    fn outstanding_provider_keeps_its_slot_after_caller_leaves() {
        let slot = AtomicU8::new(SLOT_IDLE);
        let caller = Arc::new(Flight::acquire(&slot).unwrap());
        caller.started.store(true, Ordering::Release);
        let provider = Arc::clone(&caller);
        drop(caller);
        assert!(Flight::acquire(&slot).is_err());
        provider.completed.store(true, Ordering::Release);
        drop(provider);
        assert_eq!(slot.load(Ordering::Acquire), SLOT_IDLE);
        assert!(Flight::acquire(&slot).is_ok());
    }

    #[test]
    fn unconfirmed_or_quarantined_completion_cannot_free_the_slot() {
        let slot = AtomicU8::new(SLOT_IDLE);
        let flight = Flight::acquire(&slot).unwrap();
        flight.started.store(true, Ordering::Release);
        drop(flight);
        assert_eq!(slot.load(Ordering::Acquire), SLOT_QUARANTINED);
        assert!(Flight::acquire(&slot).is_err());

        let slot = AtomicU8::new(SLOT_IDLE);
        let flight = Flight::acquire(&slot).unwrap();
        flight.quarantine();
        flight.completed.store(true, Ordering::Release);
        drop(flight);
        assert_eq!(slot.load(Ordering::Acquire), SLOT_QUARANTINED);
        assert!(Flight::acquire(&slot).is_err());
    }
}
