pub(super) mod recovery;

use std::{
    collections::BTreeMap,
    mem::{offset_of, size_of},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{anyhow, bail, ensure, Context};
use base64::Engine;
use serde_json::json;
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::*,
        System::{Diagnostics::Etw::*, Threading::*},
    },
};

use super::{
    native::{self, Ready},
    EtwProvider, ProcessIdentity, RecordingScope, Sink, TargetIdentity,
};

const PROCESS_GUID: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const LOST_EVENT_GUID: GUID = GUID::from_u128(0x6a399ae0_4bc6_4de9_870b_3657f8947e7e);
const MAX_RAW_PAYLOAD: usize = 8192;

pub(super) fn recover_native_traces() -> anyhow::Result<recovery::RecoveryReport> {
    recovery::recover()
}

#[repr(C)]
struct Properties {
    properties: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; 128],
}

impl Properties {
    fn new(name: &[u16]) -> Self {
        let mut properties = Self {
            properties: EVENT_TRACE_PROPERTIES::default(),
            logger_name: [0; 128],
        };
        properties.logger_name[..name.len()].copy_from_slice(name);
        properties.properties.Wnode.BufferSize = size_of::<Self>() as u32;
        properties.properties.Wnode.ClientContext = 2;
        properties.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.properties.BufferSize = 64;
        properties.properties.MinimumBuffers = 4;
        properties.properties.MaximumBuffers = 16;
        properties.properties.LogFileMode =
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        properties.properties.FlushTimer = 1;
        properties.properties.LoggerNameOffset = offset_of!(Self, logger_name) as u32;
        properties
    }
}

struct Session {
    handle: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    stopped: bool,
    ownership: recovery::Ownership,
}

struct Consumer {
    handle: PROCESSTRACE_HANDLE,
    closed: AtomicBool,
}

impl Consumer {
    fn close(&self) -> anyhow::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let code = unsafe { CloseTrace(self.handle) };
        ensure!(
            code == ERROR_SUCCESS || code == ERROR_CTX_CLOSE_PENDING,
            "CloseTrace failed: Win32 {}",
            code.0
        );
        Ok(())
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            tracing::error!(%error, "closing owned ETW consumer");
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.stopped {
            let mut properties = Properties::new(&self.name);
            let code = unsafe {
                ControlTraceW(
                    self.handle,
                    PCWSTR(self.name.as_ptr()),
                    &mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            if recovery::stopped(code) {
                self.stopped = true;
            } else {
                tracing::error!(code = code.0, "stopping owned ETW session during cleanup");
            }
        }
        if self.stopped {
            if let Err(error) = self.ownership.clear() {
                tracing::error!(%error, "retaining ETW ownership after journal cleanup failure");
            }
        }
    }
}

#[derive(Default)]
struct LossCounters {
    events: AtomicU64,
    buffers: AtomicU64,
}

impl LossCounters {
    fn update(&self, events: u64, buffers: u64) -> (u64, u64) {
        let old_events = self.events.fetch_max(events, Ordering::AcqRel);
        let old_buffers = self.buffers.fetch_max(buffers, Ordering::AcqRel);
        (
            events.saturating_sub(old_events),
            buffers.saturating_sub(old_buffers),
        )
    }
}

struct CallbackContext {
    sink: Sink,
    scope: RecordingScope,
    process_events: bool,
    providers: Vec<GUID>,
    // Exit records do not always repeat the session ID. Only identities observed
    // in this trace are cached, and the creation timestamp must still match.
    processes: Mutex<BTreeMap<(u32, u64), ProcessIdentity>>,
}

pub(super) fn run_process(
    scope: RecordingScope,
    sink: &Sink,
    ready: &mut Option<Ready>,
) -> anyhow::Result<()> {
    run(
        vec![EtwProvider {
            guid: "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716".into(),
            level: Some(5),
            match_any_keyword: Some(0x10),
            match_all_keyword: None,
        }],
        scope,
        true,
        sink,
        ready,
    )
}

pub(super) fn run(
    providers: Vec<EtwProvider>,
    scope: RecordingScope,
    process_events: bool,
    sink: &Sink,
    ready: &mut Option<Ready>,
) -> anyhow::Result<()> {
    let requested: Vec<_> = providers
        .iter()
        .map(|provider| {
            uuid::Uuid::parse_str(&provider.guid).map(|guid| GUID::from_u128(guid.as_u128()))
        })
        .collect::<Result<_, _>>()?;
    let available = enumerate_providers()?;
    for (provider, guid) in providers.iter().zip(&requested) {
        ensure!(available.contains(guid), "ETW provider {} is not registered on this Windows installation; no feature was installed or enabled", provider.guid);
    }
    let name = native::wide(&format!("MasterControlProgram-{}", sink.watch_id));
    let mut properties = Properties::new(&name);
    let ownership = recovery::Ownership::prepare(&sink.watch_id)?;
    properties.properties.Wnode.Guid = ownership.guid()?;
    let mut session = Session {
        handle: CONTROLTRACE_HANDLE::default(),
        name,
        stopped: true,
        ownership,
    };
    let code = unsafe {
        StartTraceW(
            &mut session.handle,
            PCWSTR(session.name.as_ptr()),
            &mut properties.properties,
        )
    };
    ensure!(code == ERROR_SUCCESS, "StartTraceW failed: Win32 {}. ETW requires provider access and usually an elevated token or Performance Log Users membership", code.0);
    session.stopped = false;
    let query = unsafe {
        ControlTraceW(
            session.handle,
            PCWSTR(session.name.as_ptr()),
            &mut properties.properties,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    ensure!(
        query == ERROR_SUCCESS,
        "querying ETW allocation failed: Win32 {}",
        query.0
    );
    validate_buffer_budget(&properties.properties)?;
    for (provider, guid) in providers.iter().zip(&requested) {
        if sink.control.is_canceled() {
            return Ok(());
        }
        let code = unsafe {
            EnableTraceEx2(
                session.handle,
                guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                provider.level.unwrap_or(5),
                provider.match_any_keyword.unwrap_or(0),
                provider.match_all_keyword.unwrap_or(0),
                5000,
                None,
            )
        };
        ensure!(code == ERROR_SUCCESS, "EnableTraceEx2({}) failed: Win32 {}. Provider privileges or capabilities are unavailable", provider.guid, code.0);
    }
    if sink.control.is_canceled() {
        return Ok(());
    }
    let losses = Arc::new(LossCounters::default());
    let mut context = Box::new(CallbackContext {
        sink: sink.clone(),
        scope,
        process_events,
        providers: requested,
        processes: Mutex::new(BTreeMap::new()),
    });
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(session.name.as_mut_ptr()),
        Anonymous1: EVENT_TRACE_LOGFILEW_0 {
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: EVENT_TRACE_LOGFILEW_1 {
            EventRecordCallback: Some(event_callback),
        },
        BufferCallback: Some(buffer_callback),
        Context: (&mut *context as *mut CallbackContext).cast(),
        ..Default::default()
    };
    let consumer_handle = unsafe { OpenTraceW(&mut logfile) };
    ensure!(
        consumer_handle.Value != u64::MAX,
        "OpenTraceW failed: {}",
        windows::core::Error::from_thread()
    );
    let consumer = Arc::new(Consumer {
        handle: consumer_handle,
        closed: AtomicBool::new(false),
    });
    let control = sink.control.clone();
    let handle = session.handle;
    let monitor_name = session.name.clone();
    let monitor_sink = sink.clone();
    let monitor_losses = losses.clone();
    let monitor_consumer = consumer.clone();
    let monitor_ownership = session.ownership.clone();
    let monitor = std::thread::Builder::new()
        .name("observe-etw-stop".into())
        .spawn(move || {
            let waited = unsafe { WaitForSingleObject(control.handle(), INFINITE) };
            let mut properties = Properties::new(&monitor_name);
            let code = unsafe {
                ControlTraceW(
                    handle,
                    PCWSTR(monitor_name.as_ptr()),
                    &mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            if code == ERROR_SUCCESS {
                let (events, buffers) = monitor_losses.update(
                    properties.properties.EventsLost as u64,
                    properties.properties.LogBuffersLost as u64
                        + properties.properties.RealTimeBuffersLost as u64,
                );
                if events != 0 || buffers != 0 {
                    monitor_sink.lost(Some(events), Some(buffers), "etw_provider_loss");
                }
            }
            if code == ERROR_MORE_DATA {
                monitor_sink.lost(None, None, "etw_stop_statistics_truncated_unknown_loss");
            } else if code == ERROR_WMI_INSTANCE_NOT_FOUND {
                monitor_sink.lost(None, None, "etw_session_already_stopped_unknown_loss");
            }
            if !recovery::stopped(code) {
                monitor_sink.fail(format!("ControlTraceW stop failed: Win32 {}; native ownership retained for recovery", code.0));
                // Closing the consumer interrupts ProcessTrace even if stopping the
                // provider session failed. Callback context remains owned by run().
                if let Err(error) = monitor_consumer.close() {
                    monitor_sink.fail(format!("ControlTraceW stop failed: Win32 {}; closing the ETW consumer also failed: {error:#}", code.0));
                    return Err(error);
                }
            }
            ensure!(
                waited == WAIT_OBJECT_0,
                "ETW stop wait failed: {:?}",
                waited
            );
            ensure!(
                recovery::stopped(code),
                "ControlTraceW stop failed: Win32 {}",
                code.0
            );
            monitor_ownership.clear()?;
            Ok::<_, anyhow::Error>(())
        });
    let monitor = match monitor {
        Ok(monitor) => monitor,
        Err(error) => {
            return Err(error).context("starting ETW cancellation worker");
        }
    };
    native::report_ready(sink, ready);
    let result = unsafe { ProcessTrace(&[consumer.handle], None, None) };
    let cancellation_requested = sink.control.is_canceled();
    sink.control.cancel();
    let stop_result = monitor
        .join()
        .map_err(|_| anyhow!("ETW cancellation worker panicked"))?;
    session.stopped = stop_result.is_ok();
    // ProcessTrace has returned, so neither callback can retain our raw context.
    let close = consumer.close();
    stop_result?;
    close?;
    ensure!(
        successful_trace_end(result, cancellation_requested),
        "ProcessTrace failed: Win32 {}",
        result.0
    );
    Ok(())
}

fn successful_trace_end(result: WIN32_ERROR, cancellation_requested: bool) -> bool {
    result == ERROR_SUCCESS
        || result == ERROR_CANCELLED
        || (result == ERROR_WMI_INSTANCE_NOT_FOUND && cancellation_requested)
}

fn enumerate_providers() -> anyhow::Result<Vec<GUID>> {
    let mut length = 0;
    let first = unsafe { TdhEnumerateProviders(None, &mut length) };
    ensure!(
        first == ERROR_INSUFFICIENT_BUFFER.0 || first == ERROR_SUCCESS.0,
        "TdhEnumerateProviders failed: Win32 {first}"
    );
    for _ in 0..3 {
        ensure!(
            (8..=16 * 1024 * 1024).contains(&length),
            "ETW provider enumeration exceeds allocation bound"
        );
        let mut storage = vec![0u64; (length as usize).div_ceil(8)];
        let capacity = storage.len() * 8;
        let status =
            unsafe { TdhEnumerateProviders(Some(storage.as_mut_ptr().cast()), &mut length) };
        if status == ERROR_INSUFFICIENT_BUFFER.0 {
            continue;
        }
        ensure!(
            status == ERROR_SUCCESS.0,
            "TdhEnumerateProviders failed: Win32 {status}"
        );
        ensure!(
            length as usize <= capacity,
            "ETW provider enumeration exceeded buffer"
        );
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) };
        return parse_providers(bytes);
    }
    bail!("ETW provider enumeration changed repeatedly during bounded query")
}

fn parse_providers(bytes: &[u8]) -> anyhow::Result<Vec<GUID>> {
    let count = u32::from_le_bytes(
        bytes
            .get(..4)
            .context("truncated provider enumeration")?
            .try_into()?,
    ) as usize;
    let offset = offset_of!(PROVIDER_ENUMERATION_INFO, TraceProviderInfoArray);
    let end = count
        .checked_mul(size_of::<TRACE_PROVIDER_INFO>())
        .and_then(|size| size.checked_add(offset))
        .context("provider count overflow")?;
    ensure!(end <= bytes.len(), "provider array exceeds returned buffer");
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let pointer = unsafe {
            bytes
                .as_ptr()
                .add(offset + index * size_of::<TRACE_PROVIDER_INFO>())
        };
        let provider = unsafe { pointer.cast::<TRACE_PROVIDER_INFO>().read_unaligned() };
        result.push(provider.ProviderGuid);
    }
    Ok(result)
}

unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() || (*logfile).Context.is_null() {
        return 0;
    }
    let context = &*(*logfile).Context.cast::<CallbackContext>();
    u32::from(!context.sink.control.is_canceled())
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() || (*record).UserContext.is_null() {
        return;
    }
    let context = &*(*record).UserContext.cast::<CallbackContext>();
    if context.sink.control.is_canceled() {
        return;
    }
    if let Err(error) = record_event(&*record, context) {
        context
            .sink
            .fail(format!("ETW event decoding failed: {error:#}"));
    }
}

fn record_event(record: &EVENT_RECORD, context: &CallbackContext) -> anyhow::Result<()> {
    let header = &record.EventHeader;
    if header.ProviderId == LOST_EVENT_GUID {
        let reason = match header.EventDescriptor.Opcode {
            32 => "etw_realtime_lost_events_unknown_count",
            33 => "etw_realtime_lost_buffers_unknown_count",
            _ => "etw_realtime_loss_notification_unknown_type",
        };
        context.sink.lost(None, None, reason);
        return Ok(());
    }
    if !requested_provider(&header.ProviderId, &context.providers) {
        return Ok(());
    }
    let event_id = header.EventDescriptor.Id;
    let timestamp = u64::try_from(header.TimeStamp).context("negative ETW timestamp")?;
    let raw_len = record.UserDataLength as usize;
    ensure!(
        raw_len == 0 || !record.UserData.is_null(),
        "ETW payload pointer is null"
    );
    let retained_len = raw_len.min(MAX_RAW_PAYLOAD);
    let raw = if retained_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), retained_len) }
    };
    let mut details = json!({
        "provider_guid": format!("{:?}", header.ProviderId),
        "event_id":event_id, "version":header.EventDescriptor.Version,
        "level":header.EventDescriptor.Level, "opcode":header.EventDescriptor.Opcode,
        "keyword":header.EventDescriptor.Keyword,
        "emitting_pid":header.ProcessId, "emitting_thread_id":header.ThreadId,
        "activity_id":format!("{:?}", header.ActivityId),
        "payload_base64":base64::engine::general_purpose::STANDARD.encode(raw),
        "payload_bytes":raw_len, "retained_payload_bytes":retained_len,
        "payload_truncated":raw_len != retained_len
    });
    let (kind, identity) = if context.process_events {
        ensure!(
            header.ProviderId == PROCESS_GUID,
            "unexpected provider in process recording"
        );
        if event_id != 1 && event_id != 2 {
            return Ok(());
        }
        let pid = property_u32(record, "ProcessID").context("process event lacks ProcessID")?;
        let creation =
            property_u64(record, "CreateTime").context("process event lacks CreateTime")?;
        let key = (pid, creation);
        let mut identity = native::process_identity(pid, Some(timestamp));
        if identity.process_created_100ns != Some(creation) {
            identity.process_created_100ns = Some(creation);
            identity.session_id = None;
        }
        match property_u32(record, "SessionID") {
            Ok(session) => identity.session_id = Some(session),
            Err(error) => {
                details["session_decode_error"] = json!(format!("{error:#}"));
                let cache = context
                    .processes
                    .lock()
                    .expect("process trace cache poisoned");
                if let Some(previous) = cache.get(&key) {
                    identity.session_id = previous.session_id;
                }
            }
        }
        if event_id == 1 {
            match property_u32(record, "ParentProcessID") {
                Ok(parent) => details["parent_pid"] = json!(parent),
                Err(error) => details["parent_decode_error"] = json!(format!("{error:#}")),
            }
            let mut cache = context
                .processes
                .lock()
                .expect("process trace cache poisoned");
            if cache.len() >= 4096 {
                cache.pop_first();
                details["identity_cache_evicted"] = json!(true);
            }
            cache.insert(key, identity.clone());
        } else {
            context
                .processes
                .lock()
                .expect("process trace cache poisoned")
                .remove(&key);
            match property_u32(record, "ExitCode") {
                Ok(code) => details["exit_code"] = json!(code),
                Err(error) => details["exit_code_decode_error"] = json!(format!("{error:#}")),
            }
        }
        (
            if event_id == 1 {
                "process.created"
            } else {
                "process.exited"
            },
            identity,
        )
    } else {
        details["process_identity_role"] = json!("event_emitter_not_necessarily_event_subject");
        (
            "etw.event",
            native::process_identity(header.ProcessId, Some(timestamp)),
        )
    };
    if !context.scope.matches(Some(&identity), Some(event_id)) {
        return Ok(());
    }
    context.sink.emit(
        kind,
        TargetIdentity {
            process: Some(identity),
            provider_guid: Some(format!("{:?}", header.ProviderId)),
            ..Default::default()
        },
        details,
        Some(timestamp),
    );
    Ok(())
}

fn requested_provider(provider: &GUID, requested: &[GUID]) -> bool {
    *provider != EventTraceGuid && *provider != EventTraceConfigGuid && requested.contains(provider)
}

fn validate_buffer_budget(properties: &EVENT_TRACE_PROPERTIES) -> anyhow::Result<()> {
    ensure!(
        properties.LogFileMode & EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING != 0
            && (1..=64).contains(&properties.BufferSize)
            && (2..=16).contains(&properties.MinimumBuffers)
            && (properties.MinimumBuffers..=16).contains(&properties.MaximumBuffers)
            && properties.NumberOfBuffers <= 16,
        "ETW adjusted the session beyond its 1 MiB native buffer budget"
    );
    Ok(())
}

fn property(record: &EVENT_RECORD, name: &str, expected_size: usize) -> anyhow::Result<Vec<u8>> {
    let wide = native::wide(name);
    let property = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide.as_ptr() as usize as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0;
    let code = unsafe { TdhGetPropertySize(record, None, &[property], &mut size) };
    ensure!(
        code == ERROR_SUCCESS.0,
        "TdhGetPropertySize({name}): Win32 {code}"
    );
    ensure!(
        size as usize == expected_size,
        "unexpected ETW {name} size: {size}"
    );
    let mut data = vec![0; expected_size];
    let code = unsafe { TdhGetProperty(record, None, &[property], &mut data) };
    ensure!(
        code == ERROR_SUCCESS.0,
        "TdhGetProperty({name}): Win32 {code}"
    );
    Ok(data)
}

fn property_u32(record: &EVENT_RECORD, name: &str) -> anyhow::Result<u32> {
    Ok(u32::from_le_bytes(
        property(record, name, 4)?
            .try_into()
            .expect("validated DWORD size"),
    ))
}

fn property_u64(record: &EVENT_RECORD, name: &str) -> anyhow::Result<u64> {
    Ok(u64::from_le_bytes(
        property(record, name, 8)?
            .try_into()
            .expect("validated QWORD size"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_counts_are_deltas_without_double_counting_final_statistics() {
        let losses = LossCounters::default();
        assert_eq!(losses.update(3, 0), (3, 0));
        assert_eq!(losses.update(3, 2), (0, 2));
        assert_eq!(losses.update(2, 0), (0, 0));
        assert_eq!(losses.update(7, 3), (4, 1));
    }

    #[test]
    fn provider_variable_buffers_reject_truncation_and_support_unaligned_bytes() {
        assert!(parse_providers(&[1, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let bytes = [0; 9];
        assert!(parse_providers(&bytes[1..]).unwrap().is_empty());
        assert!(parse_providers(&[255; 8]).is_err());
    }

    #[test]
    fn etw_properties_are_aligned_and_bounded() {
        let name = native::wide("MasterControlProgram-test");
        let properties = Properties::new(&name);
        assert_eq!(
            properties.properties.LoggerNameOffset as usize,
            offset_of!(Properties, logger_name)
        );
        assert!(properties.properties.MaximumBuffers * properties.properties.BufferSize <= 1024);
        assert_eq!(properties.properties.Wnode.ClientContext, 2);
        validate_buffer_budget(&properties.properties).unwrap();
        let mut oversized = properties.properties;
        oversized.NumberOfBuffers = 64;
        assert!(validate_buffer_budget(&oversized).is_err());
    }

    #[test]
    fn missing_trace_is_normal_only_after_requested_cancellation() {
        assert!(successful_trace_end(ERROR_SUCCESS, false));
        assert!(successful_trace_end(ERROR_CANCELLED, true));
        assert!(successful_trace_end(ERROR_WMI_INSTANCE_NOT_FOUND, true));
        assert!(!successful_trace_end(ERROR_WMI_INSTANCE_NOT_FOUND, false));
        assert!(!successful_trace_end(ERROR_ACCESS_DENIED, true));
    }

    #[tokio::test]
    async fn realtime_loss_precedes_filters_and_fails_live_waits_without_inventing_totals() {
        use crate::observation::{
            now_ms, Cancellation, EventFilter, EventsInput, Lifetime, ObservationState, Outcome,
            WaitInput,
        };
        let state = Arc::new(ObservationState::new(false));
        let sink = crate::observation::tests::synthetic(&state, Lifetime::Connection, 8, 65536);
        let wait = state
            .start_wait(
                WaitInput {
                    lifetime: Lifetime::Connection,
                    filter: EventFilter {
                        watch_id: Some(sink.watch_id.clone()),
                        kind: Some("process.created".into()),
                        ..Default::default()
                    },
                    after: Some(state.cursor()),
                    deadline_unix_ms: now_ms() + 1000,
                    background: true,
                },
                "first",
            )
            .await
            .unwrap();
        let mut context = CallbackContext {
            sink: sink.clone(),
            scope: RecordingScope {
                session_id: Some(u32::MAX),
                event_ids: vec![1234],
                ..Default::default()
            },
            process_events: true,
            providers: vec![PROCESS_GUID],
            processes: Mutex::default(),
        };
        let mut logfile = EVENT_TRACE_LOGFILEW {
            EventsLost: u32::MAX,
            Context: (&mut context as *mut CallbackContext).cast(),
            ..Default::default()
        };
        assert_eq!(unsafe { buffer_callback(&mut logfile) }, 1);
        assert!(state
            .read(&EventsInput::default(), "first")
            .unwrap()
            .events
            .is_empty());

        for opcode in [32, 33, 34] {
            let mut record = EVENT_RECORD::default();
            record.EventHeader.ProviderId = LOST_EVENT_GUID;
            record.EventHeader.EventDescriptor.Opcode = opcode;
            record.EventHeader.TimeStamp = i64::MIN;
            record.UserDataLength = u16::MAX;
            record_event(&record, &context).unwrap();
        }
        let result = state
            .await_wait(&wait.id, "first", &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(result.outcome, Outcome::Failed);
        let page = state.read(&EventsInput::default(), "first").unwrap();
        assert!(page.recording_gap);
        assert_eq!(page.events.len(), 3);
        assert!(page.events.iter().all(|event| event.kind == "gap"
            && event.payload["lost_events"].is_null()
            && event.payload["lost_buffers"].is_null()
            && event.payload["counts_known"] == false));
        assert_eq!(page.watches[0].provider_lost_events, 0);
        assert_eq!(page.watches[0].provider_lost_buffers, 0);
        let counters = LossCounters::default();
        let (events, buffers) = counters.update(7, 3);
        sink.lost(Some(events), Some(buffers), "etw_provider_loss");
        let watch = state.watch(&sink.watch_id, "first").unwrap();
        assert_eq!(watch.provider_lost_events, 7);
        assert_eq!(watch.provider_lost_buffers, 3);
        sink.finish(Ok(()));
        state.shutdown().await;
    }

    #[test]
    fn synthetic_metadata_never_becomes_a_provider_event_or_process_failure() {
        assert!(!requested_provider(&EventTraceGuid, &[PROCESS_GUID]));
        assert!(!requested_provider(&EventTraceConfigGuid, &[PROCESS_GUID]));
        assert!(!requested_provider(&EventTraceGuid, &[EventTraceGuid]));
        assert!(requested_provider(&PROCESS_GUID, &[PROCESS_GUID]));
        assert!(!requested_provider(&GUID::zeroed(), &[PROCESS_GUID]));
        let context = CallbackContext {
            sink: Sink {
                state: std::sync::Weak::new(),
                watch_id: uuid::Uuid::new_v4().to_string(),
                control: Arc::new(native::Control::new().unwrap()),
            },
            scope: RecordingScope::default(),
            process_events: true,
            providers: vec![PROCESS_GUID],
            processes: Mutex::default(),
        };
        for provider in [EventTraceGuid, EventTraceConfigGuid, GUID::zeroed()] {
            let mut record = EVENT_RECORD::default();
            record.EventHeader.ProviderId = provider;
            record.EventHeader.TimeStamp = i64::MIN;
            record.UserDataLength = u16::MAX;
            record_event(&record, &context).unwrap();
        }
        assert!(!context.sink.control.is_canceled());
    }
}
