use super::{pretty, to_wide};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::rc::Rc;
use std::time::{Duration, Instant};
use windows::core::{Error as WindowsError, GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, FILETIME,
    SYSTEMTIME, WIN32_ERROR,
};
use windows::Win32::System::EventLog::*;
use windows::Win32::System::Time::FileTimeToSystemTime;

const DEFAULT_LIMIT: u32 = 50;
const MAX_QUERY_EVENTS: u32 = 1_000;
const MAX_QUERY_SCAN: usize = 10_000;
const MAX_STATS_SCAN: usize = 100_000;
const MAX_CHANNELS: usize = 4_096;
const MAX_SOURCES: usize = 50;
const BATCH_SIZE: usize = 32;
const NEXT_TIMEOUT_MS: u32 = 1_000;
const WORK_BUDGET: Duration = Duration::from_secs(10);
const MAX_NATIVE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_PUBLISHERS: usize = 128;
const MAX_LEVEL_NAMES: usize = 512;
const MAX_STATS_GROUPS: usize = 512;
const MAX_REPORTED_ERRORS: usize = 64;
const BUFFER_ATTEMPTS: usize = 3;

fn is_error(error: &WindowsError, code: WIN32_ERROR) -> bool {
    error.code() == HRESULT::from_win32(code.0)
}

fn native_error(error: &anyhow::Error) -> Option<&WindowsError> {
    error.chain().find_map(|cause| cause.downcast_ref())
}

fn visible_error(error: anyhow::Error) -> anyhow::Error {
    // The tool boundary may use Display instead of anyhow's full-chain formatter.
    let message = format!("{error:#}");
    error.context(message)
}

fn close_handles(handles: &mut [isize], mut close: impl FnMut(EVT_HANDLE)) {
    for handle in handles {
        let raw = std::mem::replace(handle, 0);
        if raw != 0 {
            close(EVT_HANDLE(raw));
        }
    }
}

fn close_native(handle: EVT_HANDLE) {
    unsafe {
        let _ = EvtClose(handle);
    }
}

// Query handles must stay on their creating thread. Children are scoped inside
// the query so that closing the parent never invalidates a live child wrapper.
struct EventHandle {
    raw: EVT_HANDLE,
    _thread_bound: PhantomData<Rc<()>>,
}

impl EventHandle {
    fn new(raw: EVT_HANDLE) -> Result<Self> {
        ensure!(!raw.is_invalid(), "Event Log returned a null handle");
        Ok(Self {
            raw,
            _thread_bound: PhantomData,
        })
    }
}

impl Drop for EventHandle {
    fn drop(&mut self) {
        close_handles(std::slice::from_mut(&mut self.raw.0), close_native);
    }
}

struct EventBatch {
    handles: [isize; BATCH_SIZE],
    count: usize,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for EventBatch {
    fn drop(&mut self) {
        // Also release any handles written by a failed or short EvtNext call.
        close_handles(&mut self.handles, close_native);
    }
}

enum NextBatch {
    Events(Box<EventBatch>),
    Exhausted,
    Timeout,
}

fn next_batch(query: &EventHandle, count: usize, timeout: u32) -> Result<NextBatch> {
    ensure!(
        (1..=BATCH_SIZE).contains(&count),
        "Invalid event batch size"
    );
    let mut batch = EventBatch {
        handles: [0; BATCH_SIZE],
        count: 0,
        _thread_bound: PhantomData,
    };
    let mut returned = 0;
    let result = unsafe {
        EvtNext(
            query.raw,
            &mut batch.handles[..count],
            timeout,
            0,
            &mut returned,
        )
    };
    match result {
        Ok(()) => {
            batch.count = returned as usize;
            ensure!(
                batch.count > 0 && batch.count <= count,
                "EvtNext returned an invalid event count: {returned}"
            );
            ensure!(
                batch.handles[..batch.count].iter().all(|raw| *raw != 0),
                "EvtNext returned a null event handle"
            );
            Ok(NextBatch::Events(Box::new(batch)))
        }
        Err(error) if is_error(&error, ERROR_NO_MORE_ITEMS) => Ok(NextBatch::Exhausted),
        Err(error) if is_error(&error, ERROR_TIMEOUT) => Ok(NextBatch::Timeout),
        Err(error) => Err(error).context("EvtNext failed"),
    }
}

struct NativeBuffer {
    // A byte vector is not guaranteed to satisfy EVT_VARIANT's alignment.
    storage: Vec<EVT_VARIANT>,
    used: usize,
}

impl NativeBuffer {
    fn new(bytes: usize) -> Result<Self> {
        ensure!(
            bytes > 0 && bytes <= MAX_NATIVE_BYTES,
            "Event Log buffer requires {bytes} bytes; maximum is {MAX_NATIVE_BYTES}"
        );
        let count = bytes.div_ceil(size_of::<EVT_VARIANT>());
        Ok(Self {
            storage: vec![EVT_VARIANT::default(); count],
            used: 0,
        })
    }

    fn capacity(&self) -> usize {
        self.storage.len() * size_of::<EVT_VARIANT>()
    }

    fn variant(&self, index: usize) -> Result<&EVT_VARIANT> {
        ensure!(
            index < self.used / size_of::<EVT_VARIANT>(),
            "Missing Event Log property {index}"
        );
        Ok(&self.storage[index])
    }

    fn pointer_offset(&self, pointer: *const u8, bytes: usize) -> Result<usize> {
        let base = self.storage.as_ptr() as usize;
        let offset = (pointer as usize)
            .checked_sub(base)
            .context("Event Log property points outside its buffer")?;
        ensure!(
            offset <= self.used && bytes <= self.used - offset,
            "Event Log property points outside its buffer"
        );
        Ok(offset)
    }

    fn text_at(&self, pointer: *const u16) -> Result<String> {
        let offset = self.pointer_offset(pointer.cast(), size_of::<u16>())?;
        ensure!(
            offset % align_of::<u16>() == 0,
            "Event Log returned an unaligned UTF-16 string"
        );
        let units = unsafe {
            std::slice::from_raw_parts(
                self.storage.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
                (self.used - offset) / size_of::<u16>(),
            )
        };
        decode_wide(units)
    }

    fn text(&self, index: usize) -> Result<Option<String>> {
        let value = self.variant(index)?;
        if value.Type == EvtVarTypeNull.0 as u32 {
            return Ok(None);
        }
        ensure!(
            value.Type == EvtVarTypeString.0 as u32,
            "Expected a string for Event Log property {index}, got type {}",
            value.Type
        );
        self.text_at(unsafe { value.Anonymous.StringVal.0 })
            .map(Some)
    }

    fn unsigned(&self, index: usize) -> Result<Option<u64>> {
        use windows::Win32::System::EventLog::{
            EvtVarTypeByte as EVT_BYTE, EvtVarTypeHexInt32 as EVT_HEX32,
            EvtVarTypeHexInt64 as EVT_HEX64, EvtVarTypeNull as EVT_NULL,
            EvtVarTypeUInt16 as EVT_U16, EvtVarTypeUInt32 as EVT_U32, EvtVarTypeUInt64 as EVT_U64,
        };

        let value = self.variant(index)?;
        let number = unsafe {
            match EVT_VARIANT_TYPE(value.Type as i32) {
                EVT_NULL => return Ok(None),
                EVT_BYTE => u64::from(value.Anonymous.ByteVal),
                EVT_U16 => u64::from(value.Anonymous.UInt16Val),
                EVT_U32 | EVT_HEX32 => u64::from(value.Anonymous.UInt32Val),
                EVT_U64 | EVT_HEX64 => value.Anonymous.UInt64Val,
                _ => bail!(
                    "Expected an unsigned integer for Event Log property {index}, got type {}",
                    value.Type
                ),
            }
        };
        Ok(Some(number))
    }

    fn filetime(&self, index: usize) -> Result<Option<u64>> {
        let value = self.variant(index)?;
        if value.Type == EvtVarTypeNull.0 as u32 {
            return Ok(None);
        }
        ensure!(
            value.Type == EvtVarTypeFileTime.0 as u32,
            "Expected FILETIME for Event Log property {index}, got type {}",
            value.Type
        );
        Ok(Some(unsafe { value.Anonymous.FileTimeVal }))
    }

    fn guid(&self, index: usize) -> Result<Option<String>> {
        let value = self.variant(index)?;
        if value.Type == EvtVarTypeNull.0 as u32 {
            return Ok(None);
        }
        ensure!(
            value.Type == EvtVarTypeGuid.0 as u32,
            "Expected a GUID for Event Log property {index}, got type {}",
            value.Type
        );
        let pointer = unsafe { value.Anonymous.GuidVal };
        let offset = self.pointer_offset(pointer.cast(), size_of::<GUID>())?;
        let guid = unsafe {
            self.storage
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<GUID>()
                .read_unaligned()
        };
        Ok(Some(format!("{guid:?}")))
    }
}

fn decode_wide(units: &[u16]) -> Result<String> {
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .context("Event Log returned an unterminated UTF-16 string")?;
    String::from_utf16(&units[..end]).context("Event Log returned invalid UTF-16")
}

fn native_buffer(
    operation: &str,
    mut fill: impl FnMut(u32, Option<*mut c_void>, &mut u32) -> windows::core::Result<()>,
) -> Result<NativeBuffer> {
    let mut required = 0;
    match fill(0, None, &mut required) {
        Ok(()) => {}
        Err(error) if is_error(&error, ERROR_INSUFFICIENT_BUFFER) => {}
        Err(error) => return Err(error).with_context(|| operation.to_owned()),
    }
    for _ in 0..BUFFER_ATTEMPTS {
        let mut buffer =
            NativeBuffer::new(required as usize).with_context(|| operation.to_owned())?;
        let capacity = buffer.capacity();
        let result = fill(
            capacity as u32,
            Some(buffer.storage.as_mut_ptr().cast()),
            &mut required,
        );
        match result {
            Ok(()) => {
                ensure!(
                    required > 0 && required as usize <= capacity,
                    "{operation} returned an invalid buffer length"
                );
                buffer.used = required as usize;
                return Ok(buffer);
            }
            Err(error) if is_error(&error, ERROR_INSUFFICIENT_BUFFER) => {
                ensure!(
                    required as usize > capacity,
                    "{operation} did not report a larger required buffer"
                );
            }
            Err(error) => return Err(error).with_context(|| operation.to_owned()),
        }
    }
    bail!("{operation} buffer changed size too many times")
}

fn wide_buffer(
    operation: &str,
    max_chars: usize,
    mut fill: impl FnMut(Option<&mut [u16]>, &mut u32) -> windows::core::Result<()>,
) -> Result<String> {
    let mut required = 0;
    match fill(None, &mut required) {
        Ok(()) => {}
        Err(error) if is_error(&error, ERROR_INSUFFICIENT_BUFFER) => {}
        Err(error) => return Err(error).with_context(|| operation.to_owned()),
    }
    for _ in 0..BUFFER_ATTEMPTS {
        ensure!(
            required > 0 && required as usize <= max_chars,
            "{operation} requires {required} UTF-16 characters; maximum is {max_chars}"
        );
        let mut buffer = vec![0u16; required as usize];
        match fill(Some(&mut buffer), &mut required) {
            Ok(()) => {
                ensure!(
                    required > 0 && required as usize <= buffer.len(),
                    "{operation} returned an invalid string length"
                );
                return decode_wide(&buffer[..required as usize])
                    .with_context(|| operation.to_owned());
            }
            Err(error) if is_error(&error, ERROR_INSUFFICIENT_BUFFER) => {
                ensure!(
                    required as usize > buffer.len(),
                    "{operation} did not report a larger required buffer"
                );
            }
            Err(error) => return Err(error).with_context(|| operation.to_owned()),
        }
    }
    bail!("{operation} buffer changed size too many times")
}

fn validate_name(value: &str, field: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} must not be empty");
    ensure!(
        value.encode_utf16().count() <= 1_024,
        "{field} exceeds 1024 UTF-16 characters"
    );
    ensure!(
        !value
            .chars()
            .any(|ch| ch.is_control() || ch == '\u{fffe}' || ch == '\u{ffff}'),
        "{field} contains a control character or an invalid XML character"
    );
    Ok(())
}

fn requested_limit(value: Option<u32>) -> Result<(u32, u32)> {
    let requested = value.unwrap_or(DEFAULT_LIMIT);
    ensure!(requested > 0, "limit must be greater than zero");
    Ok((requested, requested.min(MAX_QUERY_EVENTS)))
}

fn level_number(level: &str) -> Result<u8> {
    match level.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(1),
        "error" => Ok(2),
        "warning" => Ok(3),
        "information" => Ok(4),
        "verbose" => Ok(5),
        _ => {
            bail!("Unknown level {level:?}; use Critical, Error, Warning, Information, or Verbose")
        }
    }
}

fn xpath_literal(value: &str) -> Option<String> {
    if !value.contains('\'') {
        Some(format!("'{value}'"))
    } else if !value.contains('"') {
        Some(format!("\"{value}\""))
    } else {
        // Event Log's XPath subset has no concat() or quote escape syntax.
        None
    }
}

struct Filter {
    xpath: String,
    provider_after_query: Option<String>,
}

fn query_filter(input: &crate::server::EventLogQueryInput) -> Result<Filter> {
    validate_name(&input.log_name, "log_name")?;
    let millis = u64::from(input.hours.unwrap_or(24)) * 3_600_000;
    let mut predicates = vec![format!("TimeCreated[timediff(@SystemTime) <= {millis}]")];
    if let Some(level) = &input.level {
        predicates.push(format!("Level={}", level_number(level)?));
    }
    if let Some(id) = input.event_id {
        ensure!(
            id <= u16::MAX as u32,
            "event_id must be in 0..=65535; qualifiers are separate"
        );
        predicates.push(format!("EventID={id}"));
    }
    let mut provider_after_query = None;
    if let Some(provider) = &input.source {
        validate_name(provider, "source")?;
        if let Some(literal) = xpath_literal(provider) {
            predicates.push(format!("Provider[@Name={literal}]"));
        } else {
            provider_after_query = Some(provider.clone());
        }
    }
    Ok(Filter {
        xpath: format!("*[System[{}]]", predicates.join(" and ")),
        provider_after_query,
    })
}

fn open_query(log_name: &str, xpath: &str) -> Result<EventHandle> {
    let channel = to_wide(log_name);
    let query = to_wide(xpath);
    let raw = unsafe {
        EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    }
    .with_context(|| format!("EvtQuery failed for channel {log_name:?}"))?;
    EventHandle::new(raw)
}

fn system_context() -> Result<EventHandle> {
    EventHandle::new(
        unsafe { EvtCreateRenderContext(None, EvtRenderContextSystem.0) }
            .context("EvtCreateRenderContext failed")?,
    )
}

fn timestamp(ticks: u64) -> Result<String> {
    let filetime = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut time = SYSTEMTIME::default();
    unsafe { FileTimeToSystemTime(&filetime, &mut time) }
        .with_context(|| format!("Invalid FILETIME value {ticks}"))?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        ticks % 10_000_000
    ))
}

struct SystemValues {
    provider: Option<String>,
    id: Option<u64>,
    level: Option<u64>,
    time_created: Option<String>,
    identity: Value,
}

fn system_buffer(context: &EventHandle, event: EVT_HANDLE) -> Result<NativeBuffer> {
    let mut count = 0;
    let buffer = native_buffer("EvtRender(system values)", |size, pointer, used| unsafe {
        EvtRender(
            Some(context.raw),
            event,
            EvtRenderEventValues.0,
            size,
            pointer,
            used,
            &mut count,
        )
    })?;
    ensure!(
        count >= EvtSystemPropertyIdEND.0 as u32
            && count as usize <= buffer.used / size_of::<EVT_VARIANT>(),
        "EvtRender returned an incomplete system property array"
    );
    Ok(buffer)
}

fn render_system(context: &EventHandle, event: EVT_HANDLE) -> Result<SystemValues> {
    let buffer = system_buffer(context, event)?;
    let text = |id: EVT_SYSTEM_PROPERTY_ID| buffer.text(id.0 as usize);
    let number = |id: EVT_SYSTEM_PROPERTY_ID| buffer.unsigned(id.0 as usize);
    let guid = |id: EVT_SYSTEM_PROPERTY_ID| buffer.guid(id.0 as usize);
    let provider = text(EvtSystemProviderName)?;
    let id = number(EvtSystemEventID)?;
    let level = number(EvtSystemLevel)?;
    let ticks = buffer.filetime(EvtSystemTimeCreated.0 as usize)?;
    let time_created = ticks.map(timestamp).transpose()?;
    let identity = json!({
        "Provider": {"Name": provider, "Guid": guid(EvtSystemProviderGuid)?},
        "EventID": id,
        "Qualifiers": number(EvtSystemQualifiers)?,
        "Level": level,
        "Version": number(EvtSystemVersion)?,
        "Task": number(EvtSystemTask)?,
        "Opcode": number(EvtSystemOpcode)?,
        "Keywords": number(EvtSystemKeywords)?,
        "TimeCreatedFileTime": ticks,
        "EventRecordID": number(EvtSystemEventRecordId)?,
        "ActivityID": guid(EvtSystemActivityID)?,
        "RelatedActivityID": guid(EvtSystemRelatedActivityID)?,
        "ProcessID": number(EvtSystemProcessID)?,
        "ThreadID": number(EvtSystemThreadID)?,
        "Channel": text(EvtSystemChannel)?,
        "Computer": text(EvtSystemComputer)?,
    });
    Ok(SystemValues {
        provider,
        id,
        level,
        time_created,
        identity,
    })
}

fn render_xml(event: EVT_HANDLE) -> Result<String> {
    let mut count = 0;
    let buffer = native_buffer("EvtRender(event XML)", |size, pointer, used| unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            size,
            pointer,
            used,
            &mut count,
        )
    })?;
    buffer.text_at(buffer.storage.as_ptr().cast())
}

fn format_message(
    metadata: Option<&EventHandle>,
    event: EVT_HANDLE,
    flags: EVT_FORMAT_MESSAGE_FLAGS,
) -> Result<String> {
    let max_chars = if flags == EvtFormatMessageLevel {
        1_024
    } else {
        MAX_NATIVE_BYTES / 2
    };
    let message = wide_buffer("EvtFormatMessage", max_chars, |buffer, used| unsafe {
        EvtFormatMessage(
            metadata.map(|handle| handle.raw),
            Some(event),
            0,
            None,
            flags.0,
            buffer,
            used,
        )
    })?;
    ensure!(
        !message.is_empty(),
        "EvtFormatMessage returned an empty string"
    );
    Ok(message)
}

#[derive(Clone)]
struct LevelName {
    name: String,
    source: &'static str,
    reason: Option<String>,
}

fn fallback_level(level: Option<u64>) -> String {
    match level {
        Some(0) => "LogAlways".to_owned(),
        Some(1) => "Critical".to_owned(),
        Some(2) => "Error".to_owned(),
        Some(3) => "Warning".to_owned(),
        Some(4) => "Information".to_owned(),
        Some(5) => "Verbose".to_owned(),
        Some(other) => format!("Level {other}"),
        None => "Unknown (level absent)".to_owned(),
    }
}

#[derive(Default)]
struct Publishers {
    metadata: HashMap<String, std::result::Result<EventHandle, String>>,
    levels: HashMap<(Option<String>, Option<u64>), LevelName>,
}

impl Publishers {
    fn metadata(&mut self, provider: &str) -> std::result::Result<&EventHandle, String> {
        if !self.metadata.contains_key(provider) && self.metadata.len() >= MAX_PUBLISHERS {
            self.metadata.clear();
        }
        self.metadata
            .entry(provider.to_owned())
            .or_insert_with(|| {
                let name = to_wide(provider);
                unsafe {
                    EvtOpenPublisherMetadata(None, PCWSTR(name.as_ptr()), PCWSTR::null(), 0, 0)
                }
                .context("EvtOpenPublisherMetadata failed")
                .and_then(EventHandle::new)
                .map_err(|error| format!("{error:#}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn message(
        &mut self,
        event: EVT_HANDLE,
        provider: Option<&str>,
        flags: EVT_FORMAT_MESSAGE_FLAGS,
    ) -> std::result::Result<String, String> {
        let primary = match provider {
            Some(provider) => self.metadata(provider).and_then(|metadata| {
                format_message(Some(metadata), event, flags).map_err(|error| format!("{error:#}"))
            }),
            None => Err("The event has no provider name".to_owned()),
        };
        match primary {
            Ok(message) => Ok(message),
            Err(primary_error) => {
                // Forwarded events may carry RenderingInfo even without an installed publisher.
                format_message(None, event, flags).map_err(|error| {
                    format!("{primary_error}; formatting without publisher metadata: {error:#}")
                })
            }
        }
    }

    fn level(
        &mut self,
        event: EVT_HANDLE,
        provider: Option<&str>,
        level: Option<u64>,
    ) -> LevelName {
        let key = (provider.map(str::to_owned), level);
        if let Some(name) = self.levels.get(&key) {
            return name.clone();
        }
        let formatted = if level.is_some() {
            self.message(event, provider, EvtFormatMessageLevel)
        } else {
            Err("The event's System/Level property is absent".to_owned())
        };
        let name = match formatted {
            Ok(name) => LevelName {
                name,
                source: "EvtFormatMessage",
                reason: None,
            },
            Err(reason) => LevelName {
                name: fallback_level(level),
                source: if level.is_some_and(|level| level <= 5) {
                    "StandardLevelFallback"
                } else {
                    "NumericLevelFallback"
                },
                reason: Some(reason),
            },
        };
        if self.levels.len() >= MAX_LEVEL_NAMES {
            self.levels.clear();
        }
        self.levels.insert(key, name.clone());
        name
    }
}

fn render_event(
    event: EVT_HANDLE,
    values: SystemValues,
    publishers: &mut Publishers,
) -> Result<Value> {
    let xml = render_xml(event)?;
    let level = publishers.level(event, values.provider.as_deref(), values.level);
    let formatted = publishers.message(event, values.provider.as_deref(), EvtFormatMessageEvent);
    let (message, reason) = match formatted {
        Ok(message) => (Some(message), None),
        Err(reason) => (None, Some(reason)),
    };
    Ok(json!({
        "TimeCreated": values.time_created,
        "Id": values.id,
        "LevelDisplayName": level.name,
        "ProviderName": values.provider,
        "Message": message,
        "MessageStatus": if message.is_some() { "Available" } else { "Unavailable" },
        "MessageSource": if message.is_some() { Some("EvtFormatMessage") } else { None },
        "MessageUnavailableReason": reason,
        "Level": values.level,
        "LevelDisplayNameSource": level.source,
        "LevelDisplayNameUnavailableReason": level.reason,
        "System": values.identity,
        "Xml": xml,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Exhausted,
    ResultLimit,
    ScanLimit,
    TimeBudget,
    NextTimeout,
    OutputBudget,
    GroupLimit,
}

impl Stop {
    fn partial(self) -> bool {
        self != Self::Exhausted
    }

    fn reason(self) -> Option<&'static str> {
        match self {
            Self::Exhausted => None,
            Self::ResultLimit => {
                Some("Result limit reached; at least one additional matching event exists")
            }
            Self::ScanLimit => Some("Event scan limit reached; remaining matches are unknown"),
            Self::TimeBudget => Some("Time budget reached; remaining matches are unknown"),
            Self::NextTimeout => Some("EvtNext timed out; remaining matches are unknown"),
            Self::OutputBudget => {
                Some("Event JSON byte budget reached; at least one matching event was omitted")
            }
            Self::GroupLimit => {
                Some("Severity group limit reached; at least one matching event was not counted")
            }
        }
    }

    fn has_more(self) -> Option<bool> {
        match self {
            Self::Exhausted => Some(false),
            Self::ResultLimit | Self::OutputBudget | Self::GroupLimit => Some(true),
            _ => None,
        }
    }
}

fn remaining_timeout(start: Instant) -> Option<u32> {
    // Native calls other than EvtNext have no timeout; this deadline is cooperative.
    WORK_BUDGET
        .checked_sub(start.elapsed())
        .and_then(|remaining| {
            if remaining.is_zero() {
                None
            } else {
                Some(remaining.as_millis().clamp(1, u128::from(NEXT_TIMEOUT_MS)) as u32)
            }
        })
}

fn status(partial: bool, empty: bool) -> &'static str {
    if partial {
        "Partial"
    } else if empty {
        "NoRecords"
    } else {
        "Success"
    }
}

pub fn query(input: &crate::server::EventLogQueryInput) -> Result<String> {
    query_inner(input).map_err(visible_error)
}

fn query_inner(input: &crate::server::EventLogQueryInput) -> Result<String> {
    let (requested, limit) = requested_limit(input.limit)?;
    let filter = query_filter(input)?;
    let start = Instant::now();
    let query = open_query(&input.log_name, &filter.xpath)?;
    let context = system_context()?;
    let mut publishers = Publishers::default();
    let mut events = Vec::new();
    let mut scanned = 0;
    let mut json_bytes = 0;
    let stop = 'read: loop {
        if scanned >= MAX_QUERY_SCAN {
            break Stop::ScanLimit;
        }
        let Some(timeout) = remaining_timeout(start) else {
            break Stop::TimeBudget;
        };
        let wanted = if filter.provider_after_query.is_some() {
            BATCH_SIZE
        } else {
            (limit as usize + 1 - events.len()).min(BATCH_SIZE)
        };
        let batch = match next_batch(&query, wanted.min(MAX_QUERY_SCAN - scanned), timeout)
            .with_context(|| format!("Reading channel {:?}", input.log_name))?
        {
            NextBatch::Events(batch) => batch,
            NextBatch::Exhausted => break Stop::Exhausted,
            NextBatch::Timeout => break Stop::NextTimeout,
        };
        for raw in &batch.handles[..batch.count] {
            if remaining_timeout(start).is_none() {
                break 'read Stop::TimeBudget;
            }
            scanned += 1;
            let event = EVT_HANDLE(*raw);
            let values = render_system(&context, event)
                .with_context(|| format!("Rendering event {scanned} from {:?}", input.log_name))?;
            if let Some(provider) = &filter.provider_after_query {
                if values.provider.as_deref() != Some(provider.as_str()) {
                    continue;
                }
            }
            // The extra matching event distinguishes truncation from an exact-size result.
            if events.len() == limit as usize {
                break 'read Stop::ResultLimit;
            }
            let rendered = render_event(event, values, &mut publishers)
                .with_context(|| format!("Rendering event {scanned} from {:?}", input.log_name))?;
            let bytes = serde_json::to_vec(&rendered)?.len();
            if bytes > MAX_EVENT_JSON_BYTES - json_bytes {
                break 'read Stop::OutputBudget;
            }
            json_bytes += bytes;
            events.push(rendered);
        }
    };
    Ok(pretty(&json!({
        "LogName": input.log_name,
        "Status": status(stop.partial(), events.is_empty()),
        "Events": events,
        "ReturnedCount": events.len(),
        "ScannedEvents": scanned,
        "Hours": input.hours.unwrap_or(24),
        "RequestedLimit": requested,
        "Limit": limit,
        "LimitClamped": requested != limit,
        "Partial": stop.partial(),
        "Truncated": stop.partial(),
        "HasMore": stop.has_more(),
        "Reason": stop.reason(),
        "ProviderFilterAppliedAfterQuery": filter.provider_after_query.is_some(),
        "Limits": {
            "MaxScannedEvents": MAX_QUERY_SCAN,
            "TimeBudgetMs": WORK_BUDGET.as_millis(),
            "EvtNextTimeoutMs": NEXT_TIMEOUT_MS,
            "MaxNativeBufferBytes": MAX_NATIVE_BYTES,
            "MaxCompactEventJsonBytes": MAX_EVENT_JSON_BYTES,
        },
    })))
}

#[derive(Default)]
struct ReportedErrors {
    count: usize,
    access_denied: usize,
    items: Vec<Value>,
}

impl ReportedErrors {
    fn add(&mut self, log_name: &str, operation: &str, error: &anyhow::Error) {
        self.count += 1;
        let native = native_error(error);
        let access_denied = native.is_some_and(|error| is_error(error, ERROR_ACCESS_DENIED));
        self.access_denied += usize::from(access_denied);
        if self.items.len() < MAX_REPORTED_ERRORS {
            self.items.push(json!({
                "LogName": log_name,
                "Operation": operation,
                "Error": format!("{error:#}"),
                "HResult": native.map(|error| format!("0x{:08X}", error.code().0 as u32)),
                "AccessDenied": access_denied,
            }));
        }
    }
}

fn log_property(log: &EventHandle, property: EVT_LOG_PROPERTY_ID) -> Result<NativeBuffer> {
    native_buffer("EvtGetLogInfo", |size, pointer, used| unsafe {
        EvtGetLogInfo(
            log.raw,
            property,
            size,
            pointer.map(|pointer| pointer.cast()),
            used,
        )
    })
}

fn maximum_size(channel: &[u16]) -> Result<u64> {
    let config = EventHandle::new(
        unsafe { EvtOpenChannelConfig(None, PCWSTR(channel.as_ptr()), 0) }
            .context("EvtOpenChannelConfig failed")?,
    )?;
    let buffer = native_buffer(
        "EvtGetChannelConfigProperty(MaxSize)",
        |size, pointer, used| unsafe {
            EvtGetChannelConfigProperty(
                config.raw,
                EvtChannelLoggingConfigMaxSize,
                0,
                size,
                pointer.map(|pointer| pointer.cast()),
                used,
            )
        },
    )?;
    buffer
        .unsigned(0)?
        .context("MaximumSizeInBytes is not available")
}

fn channel_info(name: &str, errors: &mut ReportedErrors) -> Result<Option<(u64, Value)>> {
    let channel = to_wide(name);
    let log = EventHandle::new(
        unsafe { EvtOpenLog(None, PCWSTR(channel.as_ptr()), EvtOpenChannelPath.0) }
            .context("EvtOpenLog failed")?,
    )?;
    let count = log_property(&log, EvtLogNumberOfLogRecords)?
        .unsigned(0)?
        .context("RecordCount is not available")?;
    if count == 0 {
        return Ok(None);
    }
    let maximum = match maximum_size(&channel) {
        Ok(size) => Some(size),
        Err(error) => {
            errors.add(name, "MaximumSizeInBytes", &error);
            None
        }
    };
    let last_write = (|| -> Result<(u64, String)> {
        let ticks = log_property(&log, EvtLogLastWriteTime)?
            .filetime(0)?
            .context("LastWriteTime is not available")?;
        Ok((ticks, timestamp(ticks)?))
    })();
    let (ticks, last_write) = match last_write {
        Ok((ticks, time)) => (Some(ticks), Some(time)),
        Err(error) => {
            errors.add(name, "LastWriteTime", &error);
            (None, None)
        }
    };
    Ok(Some((
        count,
        json!({
            "LogName": name,
            "RecordCount": count,
            "MaximumSizeInBytes": maximum,
            "LastWriteTime": last_write,
            "LastWriteTimeFileTime": ticks,
        }),
    )))
}

pub fn sources() -> Result<String> {
    sources_inner().map_err(visible_error)
}

fn sources_inner() -> Result<String> {
    let start = Instant::now();
    let enumeration = EventHandle::new(
        unsafe { EvtOpenChannelEnum(None, 0) }.context("EvtOpenChannelEnum failed")?,
    )?;
    let mut rows = Vec::new();
    let mut scanned = 0;
    let mut nonempty = 0;
    let mut errors = ReportedErrors::default();
    let reason = loop {
        if scanned >= MAX_CHANNELS {
            break Some(
                "Channel enumeration limit reached; ranking covers inspected channels only",
            );
        }
        if remaining_timeout(start).is_none() {
            break Some("Time budget reached; ranking covers inspected channels only");
        }
        let name = match wide_buffer("EvtNextChannelPath", 1_025, |buffer, used| unsafe {
            EvtNextChannelPath(enumeration.raw, buffer, used)
        }) {
            Ok(name) => name,
            Err(error)
                if native_error(&error)
                    .is_some_and(|error| is_error(error, ERROR_NO_MORE_ITEMS)) =>
            {
                break None;
            }
            Err(error) => return Err(error),
        };
        scanned += 1;
        match channel_info(&name, &mut errors) {
            Ok(Some(row)) => {
                nonempty += 1;
                rows.push(row);
                rows.sort_by(|a, b| {
                    b.0.cmp(&a.0)
                        .then_with(|| a.1["LogName"].as_str().cmp(&b.1["LogName"].as_str()))
                });
                rows.truncate(MAX_SOURCES);
            }
            Ok(None) => {}
            Err(error) => errors.add(&name, "Read channel information", &error),
        }
    };
    let partial = reason.is_some() || errors.count != 0;
    let channels: Vec<_> = rows.into_iter().map(|(_, row)| row).collect();
    Ok(pretty(&json!({
        "Status": status(partial, channels.is_empty()),
        "Channels": channels,
        "ReturnedCount": channels.len(),
        "ScannedChannels": scanned,
        "NonemptyChannels": nonempty,
        "Partial": partial,
        "Truncated": reason.is_some() || nonempty > MAX_SOURCES,
        "Reason": reason.or(if errors.count != 0 {
            Some("Some channels or properties could not be read; see Errors")
        } else { None }),
        "RankingScope": if partial { "Successfully inspected channels only" } else { "All channels" },
        "ErrorCount": errors.count,
        "AccessDeniedCount": errors.access_denied,
        "Errors": errors.items,
        "ErrorsTruncated": errors.count > errors.items.len(),
        "Limits": {
            "ReturnedChannels": MAX_SOURCES,
            "MaxScannedChannels": MAX_CHANNELS,
            "TimeBudgetMs": WORK_BUDGET.as_millis(),
            "MaxReportedErrors": MAX_REPORTED_ERRORS,
        },
    })))
}

pub fn stats(log_name: &str) -> Result<String> {
    stats_inner(log_name).map_err(visible_error)
}

fn stats_inner(log_name: &str) -> Result<String> {
    validate_name(log_name, "log_name")?;
    let start = Instant::now();
    let query = open_query(
        log_name,
        "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]",
    )?;
    let context = system_context()?;
    let mut publishers = Publishers::default();
    let mut counts: HashMap<(String, Option<u64>), u64> = HashMap::new();
    let mut scanned = 0;
    let mut fallback_count = 0u64;
    let mut warnings = Vec::new();
    let mut warnings_truncated = false;
    let stop = 'read: loop {
        if scanned >= MAX_STATS_SCAN {
            break Stop::ScanLimit;
        }
        let Some(timeout) = remaining_timeout(start) else {
            break Stop::TimeBudget;
        };
        let batch = match next_batch(&query, BATCH_SIZE.min(MAX_STATS_SCAN - scanned), timeout)
            .with_context(|| format!("Reading channel {log_name:?}"))?
        {
            NextBatch::Events(batch) => batch,
            NextBatch::Exhausted => break Stop::Exhausted,
            NextBatch::Timeout => break Stop::NextTimeout,
        };
        for raw in &batch.handles[..batch.count] {
            if remaining_timeout(start).is_none() {
                break 'read Stop::TimeBudget;
            }
            let event = EVT_HANDLE(*raw);
            let buffer = system_buffer(&context, event)
                .with_context(|| format!("Reading level in channel {log_name:?}"))?;
            let provider = buffer.text(EvtSystemProviderName.0 as usize)?;
            let numeric_level = buffer.unsigned(EvtSystemLevel.0 as usize)?;
            let level = publishers.level(event, provider.as_deref(), numeric_level);
            let key = (level.name, numeric_level);
            if !counts.contains_key(&key) && counts.len() >= MAX_STATS_GROUPS {
                break 'read Stop::GroupLimit;
            }
            if let Some(reason) = level.reason {
                fallback_count += 1;
                if !warnings.contains(&reason) {
                    if warnings.len() < MAX_REPORTED_ERRORS {
                        warnings.push(reason);
                    } else {
                        warnings_truncated = true;
                    }
                }
            }
            *counts.entry(key).or_default() += 1;
            scanned += 1;
        }
    };
    let mut counts: Vec<_> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let levels: Vec<_> = counts
        .into_iter()
        .map(|((name, level), count)| json!({"Name": name, "Count": count, "Level": level}))
        .collect();
    Ok(pretty(&json!({
        "LogName": log_name,
        "Status": status(stop.partial(), levels.is_empty()),
        "Hours": 24,
        "Levels": levels,
        "CountedEvents": scanned,
        "Partial": stop.partial(),
        "Truncated": stop.partial(),
        "HasMore": stop.has_more(),
        "Reason": stop.reason(),
        "LevelNameFallbackEvents": fallback_count,
        "LevelNameWarnings": warnings,
        "LevelNameWarningsTruncated": warnings_truncated,
        "Limits": {
            "MaxScannedEvents": MAX_STATS_SCAN,
            "MaxSeverityGroups": MAX_STATS_GROUPS,
            "TimeBudgetMs": WORK_BUDGET.as_millis(),
            "EvtNextTimeoutMs": NEXT_TIMEOUT_MS,
        },
    })))
}

pub fn clear(log_name: &str) -> Result<String> {
    clear_inner(log_name).map_err(visible_error)
}

fn clear_inner(log_name: &str) -> Result<String> {
    validate_name(log_name, "log_name")?;
    let channel = to_wide(log_name);
    unsafe { EvtClearLog(None, PCWSTR(channel.as_ptr()), PCWSTR::null(), 0) }
        .with_context(|| format!("EvtClearLog failed for channel {log_name:?}"))?;
    Ok(pretty(&json!({"Cleared": log_name, "Status": "Success"})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> crate::server::EventLogQueryInput {
        crate::server::EventLogQueryInput {
            log_name: "System".to_owned(),
            limit: None,
            level: None,
            source: None,
            event_id: None,
            hours: None,
        }
    }

    #[test]
    fn filters_have_explicit_defaults_and_validated_levels() {
        assert_eq!(
            query_filter(&input()).unwrap().xpath,
            "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
        );
        let mut input = input();
        input.level = Some("wArNiNg".to_owned());
        input.event_id = Some(65535);
        input.hours = Some(0);
        assert_eq!(
            query_filter(&input).unwrap().xpath,
            "*[System[TimeCreated[timediff(@SystemTime) <= 0] and Level=3 and EventID=65535]]"
        );
        for (level, number) in [
            ("Critical", 1),
            ("Error", 2),
            ("Warning", 3),
            ("Information", 4),
            ("Verbose", 5),
        ] {
            assert_eq!(level_number(level).unwrap(), number);
        }
        assert!(level_number("Information or Level=1").is_err());
        input.level = None;
        input.event_id = Some(65536);
        assert!(query_filter(&input).is_err());
        input.event_id = None;
        input.hours = Some(u32::MAX);
        assert!(query_filter(&input)
            .unwrap()
            .xpath
            .contains("15461882262000000"));
    }

    #[test]
    fn provider_quotes_never_change_the_xpath_structure() {
        let mut input = input();
        input.source = Some("Provider's events".to_owned());
        assert!(query_filter(&input)
            .unwrap()
            .xpath
            .contains("Provider[@Name=\"Provider's events\"]"));
        input.source = Some("Provider \"events\" & <data>".to_owned());
        assert!(query_filter(&input)
            .unwrap()
            .xpath
            .contains("Provider[@Name='Provider \"events\" & <data>']"));
        let mixed = "Provider's \"events\"] or Level=1 or [@Name='";
        input.source = Some(mixed.to_owned());
        let filter = query_filter(&input).unwrap();
        assert_eq!(filter.provider_after_query.as_deref(), Some(mixed));
        assert!(!filter.xpath.contains("Provider"));
        assert!(!filter.xpath.contains("Level=1"));
        input.source = Some("invalid\0provider".to_owned());
        assert!(query_filter(&input).is_err());
        input.source = Some("".to_owned());
        assert!(query_filter(&input).is_err());
        input.source = None;
        input.log_name = "System\0Application".to_owned();
        assert!(query_filter(&input).is_err());
        assert!(validate_name("System\n", "log_name").is_err());
        assert!(validate_name(" ", "log_name").is_err());
        assert!(validate_name(&"x".repeat(1025), "log_name").is_err());
    }

    #[test]
    fn query_limits_are_bounded_and_zero_is_not_an_empty_success() {
        assert_eq!(requested_limit(None).unwrap(), (50, 50));
        assert_eq!(requested_limit(Some(1)).unwrap(), (1, 1));
        assert_eq!(
            requested_limit(Some(u32::MAX)).unwrap(),
            (u32::MAX, MAX_QUERY_EVENTS)
        );
        assert!(requested_limit(Some(0)).is_err());
        assert_eq!(Stop::Exhausted.has_more(), Some(false));
        assert_eq!(Stop::ResultLimit.has_more(), Some(true));
        assert_eq!(Stop::NextTimeout.has_more(), None);
        assert_eq!(status(true, true), "Partial");
        assert_eq!(status(false, true), "NoRecords");
    }

    #[test]
    fn cleanup_closes_each_nonzero_handle_once_and_clears_ownership() {
        let mut handles = [11, 0, 17, 23, 0];
        let mut closed = Vec::new();
        close_handles(&mut handles, |handle| closed.push(handle.0));
        close_handles(&mut handles, |handle| closed.push(handle.0));
        assert_eq!(closed, [11, 17, 23]);
        assert_eq!(handles, [0; 5]);
    }

    #[test]
    fn public_error_display_retains_the_native_failure() {
        let native = WindowsError::from_hresult(HRESULT::from_win32(ERROR_ACCESS_DENIED.0));
        let original = native.to_string();
        let error = visible_error(
            anyhow::Error::new(native)
                .context("EvtNext failed")
                .context("Reading channel System"),
        );
        let displayed = error.to_string();
        assert!(displayed.contains("Reading channel System"));
        assert!(displayed.contains("EvtNext failed"));
        assert!(displayed.contains(&original));
        assert!(native_error(&error).is_some_and(|error| is_error(error, ERROR_ACCESS_DENIED)));
    }

    #[test]
    fn variant_buffers_are_aligned_and_keep_full_width_unsigned_values() {
        let mut buffer = NativeBuffer::new(size_of::<EVT_VARIANT>() + 1).unwrap();
        assert_eq!(
            (buffer.storage.as_ptr() as usize) % align_of::<EVT_VARIANT>(),
            0
        );
        buffer.storage[0] = EVT_VARIANT {
            Anonymous: EVT_VARIANT_0 {
                UInt64Val: u64::MAX,
            },
            Count: 0,
            Type: EvtVarTypeUInt64.0 as u32,
        };
        buffer.used = size_of::<EVT_VARIANT>();
        let value = buffer.unsigned(0).unwrap().unwrap();
        assert_eq!(value, u64::MAX);
        assert_eq!(json!(value).to_string(), "18446744073709551615");
        buffer.storage[0].Type |= EVT_VARIANT_TYPE_ARRAY;
        assert!(buffer.unsigned(0).is_err());
        assert!(buffer.variant(1).is_err());
        assert!(NativeBuffer::new(MAX_NATIVE_BYTES + 1).is_err());
    }

    #[test]
    fn strings_cannot_escape_the_native_buffer() {
        let text = to_wide("Provider's \"events\"");
        let offset = size_of::<EVT_VARIANT>();
        let mut buffer = NativeBuffer::new(offset + text.len() * 2).unwrap();
        let pointer = unsafe {
            buffer
                .storage
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<u16>()
        };
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), pointer, text.len());
        }
        buffer.storage[0] = EVT_VARIANT {
            Anonymous: EVT_VARIANT_0 {
                StringVal: PCWSTR(pointer),
            },
            Count: 0,
            Type: EvtVarTypeString.0 as u32,
        };
        buffer.used = offset + text.len() * 2;
        assert_eq!(
            buffer.text(0).unwrap().as_deref(),
            Some("Provider's \"events\"")
        );
        assert!(buffer.text_at(std::ptr::null()).is_err());
        assert!(buffer.text_at(text.as_ptr()).is_err());
        assert!(decode_wide(&[65, 66]).is_err());
        assert!(decode_wide(&[0xd800, 0]).is_err());
    }

    #[test]
    fn timestamps_keep_filetime_epoch_and_all_seven_fractional_digits() {
        assert_eq!(timestamp(0).unwrap(), "1601-01-01T00:00:00.0000000Z");
        assert_eq!(
            timestamp(116_444_736_000_000_001).unwrap(),
            "1970-01-01T00:00:00.0000001Z"
        );
        assert_eq!(
            timestamp(116_444_736_009_876_543).unwrap(),
            "1970-01-01T00:00:00.9876543Z"
        );
        assert!(timestamp(u64::MAX).is_err());
    }

    fn read_only_result(operation: &str, result: Result<String>) -> Option<Value> {
        match result {
            Ok(output) => Some(serde_json::from_str(&output).unwrap()),
            Err(error) => {
                let code = native_error(&error).map(|error| error.code());
                let unavailable = [
                    ERROR_ACCESS_DENIED,
                    windows::Win32::Foundation::ERROR_EVT_CHANNEL_NOT_FOUND,
                    windows::Win32::Foundation::ERROR_FILE_NOT_FOUND,
                    windows::Win32::Foundation::ERROR_SERVICE_DISABLED,
                    WIN32_ERROR(1722),
                ]
                .iter()
                .any(|expected| code == Some(HRESULT::from_win32(expected.0)));
                assert!(unavailable, "{operation} failed: {error:#}");
                eprintln!("{operation} unavailable: {error:#}");
                None
            }
        }
    }

    #[test]
    fn readonly_system_and_application_queries() {
        for channel in ["System", "Application"] {
            let mut input = input();
            input.log_name = channel.to_owned();
            input.limit = Some(2);
            if let Some(result) = read_only_result(channel, query(&input)) {
                let events = result["Events"].as_array().unwrap();
                assert!(events.len() <= 2);
                assert_eq!(
                    result["ReturnedCount"].as_u64().unwrap(),
                    events.len() as u64
                );
                for event in events {
                    assert!(event["Xml"].as_str().unwrap().contains("<Event"));
                    assert_eq!(event["Id"], event["System"]["EventID"]);
                    assert_eq!(event["ProviderName"], event["System"]["Provider"]["Name"]);
                    assert_eq!(event["Level"], event["System"]["Level"]);
                    if event["MessageStatus"] == "Available" {
                        assert!(!event["Message"].as_str().unwrap().is_empty());
                        assert_eq!(event["MessageSource"], "EvtFormatMessage");
                    } else {
                        assert!(event["Message"].is_null());
                        assert!(event["MessageUnavailableReason"].is_string());
                    }
                }
            }
        }
    }

    #[test]
    fn readonly_channel_inventory_and_statistics() {
        if let Some(result) = read_only_result("eventlog_sources", sources()) {
            let channels = result["Channels"].as_array().unwrap();
            assert!(channels.len() <= MAX_SOURCES);
            assert_eq!(
                result["ReturnedCount"].as_u64().unwrap(),
                channels.len() as u64
            );
            assert!(result["Partial"].is_boolean());
            for channel in channels {
                assert!(channel["LogName"].is_string());
                assert!(channel["RecordCount"].as_u64().unwrap() > 0);
                assert!(channel.get("MaximumSizeInBytes").is_some());
                assert!(channel.get("LastWriteTime").is_some());
            }
            assert_eq!(
                result["Errors"].as_array().unwrap().len(),
                (result["ErrorCount"].as_u64().unwrap() as usize).min(MAX_REPORTED_ERRORS)
            );
        }
        if let Some(result) = read_only_result("eventlog_stats(System)", stats("System")) {
            let levels = result["Levels"].as_array().unwrap();
            assert!(levels.len() <= MAX_STATS_GROUPS);
            let count: u64 = levels
                .iter()
                .map(|level| level["Count"].as_u64().unwrap())
                .sum();
            assert_eq!(result["CountedEvents"].as_u64().unwrap(), count);
            assert_eq!(result["Hours"], 24);
            assert!(result["Partial"].is_boolean());
            assert!(levels.iter().all(|level| level["Name"].is_string()));
        }
    }
}
