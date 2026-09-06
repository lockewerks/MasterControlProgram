use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use windows::{
    core::{Interface, PCWSTR, PWSTR},
    Win32::{
        Devices::FunctionDiscovery::{PKEY_Device_FriendlyName, PKEY_Device_Manufacturer},
        Foundation::{
            CloseHandle, FILETIME, HANDLE, S_OK, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Media::Audio::{
            Endpoints::{IAudioEndpointVolume, IAudioMeterInformation},
            *,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
                StructuredStorage::{PropVariantClear, PropVariantToStringAlloc, PROPVARIANT},
                CLSCTX_ALL, COINIT_MULTITHREADED, STGM_READ,
            },
            Threading::{
                CreateEventW, GetProcessTimes, OpenProcess, WaitForSingleObject,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
};

use super::{pretty, to_wide};

const MAX_ENDPOINTS: u32 = 1024;
const MAX_SESSIONS: i32 = 4096;
const MAX_CHANNELS: u32 = 64;
const MAX_RECORD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CAPTURE_BUFFER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DataFlow {
    #[default]
    Render,
    Capture,
}

impl DataFlow {
    fn native(self) -> EDataFlow {
        match self {
            Self::Render => eRender,
            Self::Capture => eCapture,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Console,
    #[default]
    Multimedia,
    Communications,
}

impl Role {
    fn native(self) -> ERole {
        match self {
            Self::Console => eConsole,
            Self::Multimedia => eMultimedia,
            Self::Communications => eCommunications,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct EndpointInput {
    #[schemars(
        description = "Exact endpoint ID from audio_devices. Omit for the selected default."
    )]
    pub endpoint_id: Option<String>,
    #[schemars(
        description = "Default endpoint role: console, multimedia (default), communications."
    )]
    pub role: Option<Role>,
    #[schemars(
        description = "render (default) or capture. With an endpoint ID, validates its direction."
    )]
    pub dataflow: Option<DataFlow>,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct VolumeInput {
    #[serde(flatten)]
    pub target: EndpointInput,
    #[schemars(
        description = "Optional volume percentage 0..100. Omit to read without changing volume."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub volume: Option<f32>,
    #[schemars(description = "Optional mute state. Omit to leave mute unchanged.")]
    pub mute: Option<bool>,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct SessionsInput {
    #[serde(flatten)]
    pub target: EndpointInput,
    #[schemars(
        description = "Optional exact process ID filter. Cross-process sessions are marked separately."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub pid: Option<u32>,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct SessionVolumeInput {
    #[serde(flatten)]
    pub target: EndpointInput,
    #[schemars(description = "Exact session instance ID from audio_sessions. Preferred to a PID.")]
    pub session_instance_id: Option<String>,
    #[schemars(
        description = "Exact process ID. Multiple matching sessions are an error, not a group operation."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub pid: Option<u32>,
    #[schemars(
        description = "Process creation FILETIME from audio_sessions. Required for PID-only mutations to reject reused PIDs."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub process_creation_time: Option<u64>,
    #[schemars(description = "Optional session volume percentage 0..100.")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub volume: Option<f32>,
    pub mute: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RecordMode {
    Capture,
    Loopback,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecordInput {
    #[serde(flatten)]
    pub target: EndpointInput,
    #[schemars(
        description = "Required explicit source: capture records a recording endpoint; loopback records playback on a render endpoint."
    )]
    pub mode: RecordMode,
    #[schemars(
        description = "Required recording duration in seconds, 1..300. Captured frames may be fewer when no samples arrive."
    )]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub duration_seconds: u32,
    #[schemars(
        description = "Absolute path for a new local .wav artifact. Existing files are never replaced."
    )]
    pub path: String,
    #[schemars(description = "WASAPI buffer request in milliseconds, 10..1000 (default 100).")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub buffer_ms: Option<u32>,
    #[schemars(
        description = "Maximum WAV size including headers, 1024..268435456 bytes (default 67108864). Recording stops at this bound."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_bytes: Option<u64>,
}

struct Apartment(PhantomData<Rc<()>>);

impl Apartment {
    fn new() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() }
            .context("Initialize Core Audio COM apartment")?;
        Ok(Self(PhantomData))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

struct TaskMemory<T>(*mut T);

impl<T> Drop for TaskMemory<T> {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.cast())) };
    }
}

fn take_string(value: PWSTR) -> Result<String> {
    let memory = TaskMemory(value.0);
    if memory.0.is_null() {
        bail!("Core Audio returned a null string");
    }
    unsafe { PWSTR(memory.0).to_string() }.context("Decode Core Audio string")
}

struct Property(PROPVARIANT);

impl Drop for Property {
    fn drop(&mut self) {
        if let Err(error) = unsafe { PropVariantClear(&mut self.0) } {
            tracing::error!(%error, "Core Audio property cleanup failed");
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            tracing::error!(%error, "Core Audio handle cleanup failed");
        }
    }
}

fn enumerator() -> Result<IMMDeviceEnumerator> {
    unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) }
        .context("Create Core Audio endpoint enumerator")
}

fn endpoint_id(device: &IMMDevice) -> Result<String> {
    take_string(unsafe { device.GetId() }.context("Read endpoint ID")?)
}

fn endpoint_flow(device: &IMMDevice) -> Result<EDataFlow> {
    let endpoint: IMMEndpoint = device
        .cast()
        .context("Query endpoint direction interface")?;
    unsafe { endpoint.GetDataFlow() }.context("Read endpoint direction")
}

fn flow_name(flow: EDataFlow) -> &'static str {
    if flow == eRender {
        "render"
    } else if flow == eCapture {
        "capture"
    } else {
        "unknown"
    }
}

fn state_names(state: DEVICE_STATE) -> Vec<&'static str> {
    [
        (DEVICE_STATE_ACTIVE, "active"),
        (DEVICE_STATE_DISABLED, "disabled"),
        (DEVICE_STATE_NOTPRESENT, "not_present"),
        (DEVICE_STATE_UNPLUGGED, "unplugged"),
    ]
    .into_iter()
    .filter_map(|(flag, name)| (state.0 & flag.0 != 0).then_some(name))
    .collect()
}

fn valid_string(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.contains('\0') || value.len() > 32_768 {
        bail!("{field} must be nonempty, contain no NUL, and be at most 32768 bytes");
    }
    Ok(())
}

fn resolve(input: &EndpointInput) -> Result<IMMDevice> {
    let enumerator = enumerator()?;
    let device = if let Some(id) = &input.endpoint_id {
        valid_string(id, "endpoint_id")?;
        let wide = to_wide(id);
        unsafe { enumerator.GetDevice(PCWSTR(wide.as_ptr())) }
            .with_context(|| format!("Open requested audio endpoint {id:?}"))?
    } else {
        let flow = input.dataflow.unwrap_or_default();
        let role = input.role.unwrap_or_default();
        unsafe { enumerator.GetDefaultAudioEndpoint(flow.native(), role.native()) }
            .with_context(|| format!("Default audio endpoint unavailable for {flow:?}/{role:?}"))?
    };
    let state = unsafe { device.GetState() }.context("Read audio endpoint state")?;
    if state != DEVICE_STATE_ACTIVE {
        bail!(
            "Audio endpoint {} is unavailable: {:?} (state={})",
            endpoint_id(&device)?,
            state_names(state),
            state.0
        );
    }
    if let Some(flow) = input.dataflow {
        let actual = endpoint_flow(&device)?;
        if actual != flow.native() {
            bail!(
                "Requested {:?} endpoint, but {} is {}",
                flow,
                endpoint_id(&device)?,
                flow_name(actual)
            );
        }
    }
    Ok(device)
}

fn property_string(
    device: &IMMDevice,
    key: &windows::Win32::Foundation::PROPERTYKEY,
) -> Result<String> {
    let store =
        unsafe { device.OpenPropertyStore(STGM_READ) }.context("Open endpoint properties")?;
    let value = Property(unsafe { store.GetValue(key) }.context("Read endpoint property")?);
    take_string(
        unsafe { PropVariantToStringAlloc(&value.0) }
            .context("Convert endpoint property to text")?,
    )
}

pub fn devices() -> Result<String> {
    let _apartment = Apartment::new()?;
    let enumerator = enumerator()?;
    let collection =
        unsafe { enumerator.EnumAudioEndpoints(eAll, DEVICE_STATE(DEVICE_STATEMASK_ALL)) }
            .context("Enumerate audio endpoints")?;
    let count = unsafe { collection.GetCount() }.context("Read audio endpoint count")?;
    let mut devices = Vec::new();
    for index in 0..count.min(MAX_ENDPOINTS) {
        let device = unsafe { collection.Item(index) }
            .with_context(|| format!("Read audio endpoint at index {index}"))?;
        let state = unsafe { device.GetState() }.context("Read endpoint state")?;
        let mut value = json!({
            "endpoint_id": endpoint_id(&device)?,
            "dataflow": flow_name(endpoint_flow(&device)?),
            "Status": state_names(state),
            "StatusInfo": state.0,
            "available": state == DEVICE_STATE_ACTIVE,
        });
        for (name, key) in [
            ("Name", PKEY_Device_FriendlyName),
            ("Manufacturer", PKEY_Device_Manufacturer),
        ] {
            match property_string(&device, &key) {
                Ok(text) => value[name] = json!(text),
                Err(error) => {
                    value[name] = Value::Null;
                    value[format!("{name}_error")] = json!(format!("{error:#}"));
                }
            }
        }
        devices.push(value);
    }
    let mut defaults = Vec::new();
    for flow in [DataFlow::Render, DataFlow::Capture] {
        for role in [Role::Console, Role::Multimedia, Role::Communications] {
            let value =
                match unsafe { enumerator.GetDefaultAudioEndpoint(flow.native(), role.native()) } {
                    Ok(device) => json!({
                        "dataflow": flow, "role": role, "status": "available",
                        "endpoint_id": endpoint_id(&device)?,
                    }),
                    Err(error) => json!({
                        "dataflow": flow, "role": role, "status": "unavailable",
                        "endpoint_id": Value::Null, "error": error.to_string(),
                        "hresult": format!("0x{:08X}", error.code().0 as u32),
                    }),
                };
            defaults.push(value);
        }
    }
    let available = devices.iter().any(|value| value["available"] == true);
    Ok(pretty(&json!({
        "Devices": devices, "defaults": defaults, "total": count,
        "truncated": count > MAX_ENDPOINTS,
        "status": if count == 0 { "no_endpoints" } else if available { "available" } else { "no_active_endpoints" },
    })))
}

fn validate_volume(volume: Option<f32>) -> Result<()> {
    if volume.is_some_and(|v| !v.is_finite() || !(0.0..=100.0).contains(&v)) {
        bail!("volume must be a finite number between 0 and 100");
    }
    Ok(())
}

pub fn volume(input: &VolumeInput) -> Result<String> {
    validate_volume(input.volume)?;
    let _apartment = Apartment::new()?;
    let device = resolve(&input.target)?;
    let control: IAudioEndpointVolume =
        unsafe { device.Activate(CLSCTX_ALL, None) }.context("Activate endpoint volume control")?;
    if let Some(volume) = input.volume {
        unsafe { control.SetMasterVolumeLevelScalar(volume / 100.0, std::ptr::null()) }
            .context("Set endpoint volume")?;
    }
    if let Some(mute) = input.mute {
        unsafe { control.SetMute(mute, std::ptr::null()) }.with_context(|| {
            format!("Set endpoint mute (volume_set={})", input.volume.is_some())
        })?;
    }
    let volume = unsafe { control.GetMasterVolumeLevelScalar() }.context(
        "Read endpoint volume after requested changes; any accepted changes remain applied",
    )?;
    let mute = unsafe { control.GetMute() }
        .context("Read endpoint mute after requested changes; any accepted changes remain applied")?
        .as_bool();
    Ok(pretty(&json!({
        "endpoint_id": endpoint_id(&device)?,
        "dataflow": flow_name(endpoint_flow(&device)?),
        "volume": volume * 100.0, "mute": mute,
        "volume_set": input.volume.is_some(), "mute_set": input.mute.is_some(),
        "requested": { "volume": input.volume, "mute": input.mute },
    })))
}

pub fn meter(input: &EndpointInput) -> Result<String> {
    let _apartment = Apartment::new()?;
    let device = resolve(input)?;
    let meter: IAudioMeterInformation =
        unsafe { device.Activate(CLSCTX_ALL, None) }.context("Activate endpoint metering")?;
    let channels =
        unsafe { meter.GetMeteringChannelCount() }.context("Read metering channel count")?;
    if channels == 0 || channels > MAX_CHANNELS {
        bail!(
            "Unsupported metering channel count {channels}; supported range is 1..={MAX_CHANNELS}"
        );
    }
    let mut peaks = vec![0.0; channels as usize];
    unsafe { meter.GetChannelsPeakValues(&mut peaks) }.context("Read channel peak values")?;
    let peak = unsafe { meter.GetPeakValue() }.context("Read endpoint peak value")?;
    Ok(pretty(&json!({
        "endpoint_id": endpoint_id(&device)?, "dataflow": flow_name(endpoint_flow(&device)?),
        "peak": peak, "channel_peaks": peaks, "scale": "linear_0_to_1",
        "observation": "most_recent_metering_period",
    })))
}

#[derive(Clone)]
struct SessionIdentity {
    instance: String,
    pid: u32,
    multiple_processes: bool,
    creation_time: Option<u64>,
}

struct Session {
    control: IAudioSessionControl2,
    identity: SessionIdentity,
    value: Value,
}

fn process_creation_time(pid: u32) -> Result<u64> {
    let handle = OwnedHandle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .with_context(|| format!("Open process {pid} for audio identity"))?,
    );
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) }
        .with_context(|| format!("Read process {pid} creation time"))?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn session_state(state: AudioSessionState) -> &'static str {
    if state == AudioSessionStateActive {
        "active"
    } else if state == AudioSessionStateInactive {
        "inactive"
    } else if state == AudioSessionStateExpired {
        "expired"
    } else {
        "unknown"
    }
}

fn enumerate_sessions(device: &IMMDevice) -> Result<Vec<Session>> {
    let manager: IAudioSessionManager2 =
        unsafe { device.Activate(CLSCTX_ALL, None) }.context("Activate audio session manager")?;
    let enumerator =
        unsafe { manager.GetSessionEnumerator() }.context("Enumerate audio sessions")?;
    let count = unsafe { enumerator.GetCount() }.context("Read audio session count")?;
    if !(0..=MAX_SESSIONS).contains(&count) {
        bail!("Audio session count {count} exceeds supported bound {MAX_SESSIONS}");
    }
    let mut sessions = Vec::with_capacity(count as usize);
    for index in 0..count {
        let control: IAudioSessionControl2 = unsafe { enumerator.GetSession(index) }
            .with_context(|| format!("Read audio session {index}"))?
            .cast()
            .context("Query audio session identity interface")?;
        let instance = take_string(
            unsafe { control.GetSessionInstanceIdentifier() }
                .context("Read session instance ID")?,
        )?;
        let mut pid = 0;
        // The generated wrapper discards AUDCLNT_S_NO_SINGLE_PROCESS. Retain it
        // so a cross-process session cannot masquerade as one process's volume.
        let process_result = unsafe {
            (Interface::vtable(&control).GetProcessId)(Interface::as_raw(&control), &mut pid)
        };
        process_result
            .ok()
            .context("Read audio session process identity")?;
        let multiple_processes = process_result != S_OK;
        let system_sounds = unsafe { control.IsSystemSoundsSession() };
        system_sounds
            .ok()
            .context("Read system-sounds session identity")?;
        let creation = if pid == 0 {
            None
        } else {
            Some(process_creation_time(pid))
        };
        let creation_time = creation
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied();
        let volume: ISimpleAudioVolume =
            control.cast().context("Query session volume interface")?;
        let value = json!({
            "session_instance_id": instance,
            "session_id": take_string(unsafe { control.GetSessionIdentifier() }.context("Read session ID")?)?,
            "pid": pid, "multiple_processes": multiple_processes,
            "process_creation_time": creation_time.map(|value| value.to_string()),
            "process_identity_error": creation.as_ref().and_then(|value| value.as_ref().err()).map(|error| format!("{error:#}")),
            "system_sounds": system_sounds == S_OK,
            "display_name": take_string(unsafe { control.GetDisplayName() }.context("Read session display name")?)?,
            "state": session_state(unsafe { control.GetState() }.context("Read audio session state")?),
            "volume": unsafe { volume.GetMasterVolume() }.context("Read session volume")? * 100.0,
            "mute": unsafe { volume.GetMute() }.context("Read session mute")?.as_bool(),
        });
        sessions.push(Session {
            control,
            identity: SessionIdentity {
                instance,
                pid,
                multiple_processes,
                creation_time,
            },
            value,
        });
    }
    Ok(sessions)
}

pub fn sessions(input: &SessionsInput) -> Result<String> {
    let _apartment = Apartment::new()?;
    let device = resolve(&input.target)?;
    let flow = endpoint_flow(&device)?;
    let volume_scope = session_volume_scope(flow, false)?;
    let sessions = enumerate_sessions(&device)?
        .into_iter()
        .filter(|session| input.pid.is_none_or(|pid| session.identity.pid == pid))
        .map(|session| session.value)
        .collect::<Vec<_>>();
    Ok(pretty(&json!({
        "endpoint_id": endpoint_id(&device)?,
        "dataflow": flow_name(flow),
        "volume_scope": volume_scope,
        "status": if sessions.is_empty() { "no_sessions" } else { "available" },
        "sessions": sessions,
    })))
}

fn select_session(identities: &[SessionIdentity], input: &SessionVolumeInput) -> Result<usize> {
    if input.session_instance_id.is_none() && input.pid.is_none() {
        bail!("Specify session_instance_id or pid from audio_sessions");
    }
    if let Some(instance) = &input.session_instance_id {
        valid_string(instance, "session_instance_id")?;
    }
    if input.session_instance_id.is_none()
        && (input.volume.is_some() || input.mute.is_some())
        && input.process_creation_time.is_none()
    {
        bail!("PID-only mutations require process_creation_time from audio_sessions to reject reused PIDs");
    }
    let matches: Vec<_> = identities
        .iter()
        .enumerate()
        .filter(|(_, session)| {
            input
                .session_instance_id
                .as_ref()
                .is_none_or(|id| *id == session.instance)
                && input
                    .pid
                    .is_none_or(|pid| !session.multiple_processes && pid == session.pid)
                && input
                    .process_creation_time
                    .is_none_or(|time| session.creation_time == Some(time))
        })
        .collect();
    match matches.as_slice() {
        [(index, _)] => Ok(*index),
        [] => bail!(
            "No matching audio session; the endpoint, session or process identity may be stale"
        ),
        _ => bail!(
            "Ambiguous audio target: {} sessions match; specify session_instance_id: {}",
            matches.len(),
            matches
                .iter()
                .map(|(_, s)| s.instance.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn session_volume_scope(flow: EDataFlow, mutating: bool) -> Result<&'static str> {
    if flow == eRender {
        return Ok("session");
    }
    if flow != eCapture {
        bail!("Unsupported audio endpoint direction for session volume");
    }
    if mutating {
        // Shared capture session controls change the endpoint for other apps too.
        bail!(
            "Capture-session volume and mute are endpoint-wide, not per-application. \
             Use audio_volume with an explicit endpoint_id for an endpoint-wide change"
        );
    }
    Ok("endpoint")
}

pub fn session_volume(input: &SessionVolumeInput) -> Result<String> {
    validate_volume(input.volume)?;
    let _apartment = Apartment::new()?;
    let device = resolve(&input.target)?;
    let flow = endpoint_flow(&device)?;
    let volume_scope = session_volume_scope(flow, input.volume.is_some() || input.mute.is_some())?;
    let sessions = enumerate_sessions(&device)?;
    let identities = sessions
        .iter()
        .map(|session| session.identity.clone())
        .collect::<Vec<_>>();
    let index = select_session(&identities, input)?;
    let session = &sessions[index];
    if unsafe { session.control.GetState() }.context("Recheck selected audio session state")?
        == AudioSessionStateExpired
    {
        bail!("Selected audio session has expired; refresh audio_sessions");
    }
    if let Some(expected) = input.process_creation_time {
        let actual = process_creation_time(session.identity.pid)?;
        if actual != expected {
            bail!("Audio process identity changed before volume operation; no changes made");
        }
    }
    let control: ISimpleAudioVolume = session
        .control
        .cast()
        .context("Query session volume control")?;
    if let Some(volume) = input.volume {
        unsafe { control.SetMasterVolume(volume / 100.0, std::ptr::null()) }
            .context("Set session volume")?;
    }
    if let Some(mute) = input.mute {
        unsafe { control.SetMute(mute, std::ptr::null()) }
            .with_context(|| format!("Set session mute (volume_set={})", input.volume.is_some()))?;
    }
    let mut value = session.value.clone();
    value["endpoint_id"] = json!(endpoint_id(&device)?);
    value["dataflow"] = json!(flow_name(flow));
    value["volume_scope"] = json!(volume_scope);
    value["volume"] = json!(
        unsafe { control.GetMasterVolume() }
            .context("Read session volume after changes; accepted changes remain applied")?
            * 100.0
    );
    value["mute"] = json!(unsafe { control.GetMute() }
        .context("Read session mute after changes; accepted changes remain applied")?
        .as_bool());
    value["state"] = json!(session_state(
        unsafe { session.control.GetState() }.context("Read resulting session state")?
    ));
    value["requested"] = json!({ "volume": input.volume, "mute": input.mute });
    Ok(pretty(&value))
}

struct RecordLimits {
    duration: Duration,
    buffer_ms: u32,
    max_bytes: u64,
}

fn record_limits(input: &RecordInput) -> Result<RecordLimits> {
    if !(1..=300).contains(&input.duration_seconds) {
        bail!("duration_seconds must be between 1 and 300");
    }
    let buffer_ms = input.buffer_ms.unwrap_or(100);
    if !(10..=1000).contains(&buffer_ms) {
        bail!("buffer_ms must be between 10 and 1000");
    }
    let max_bytes = input.max_bytes.unwrap_or(64 * 1024 * 1024);
    if !(1024..=MAX_RECORD_BYTES).contains(&max_bytes) {
        bail!("max_bytes must be between 1024 and {MAX_RECORD_BYTES}");
    }
    valid_string(&input.path, "path")?;
    let path = Path::new(&input.path);
    if !path.is_absolute()
        || !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wav"))
    {
        bail!("path must be an absolute path to a new .wav file");
    }
    Ok(RecordLimits {
        duration: Duration::from_secs(u64::from(input.duration_seconds)),
        buffer_ms,
        max_bytes,
    })
}

struct WaveFormat {
    bytes: Vec<u8>,
    tag: u16,
    channels: u16,
    rate: u32,
    byte_rate: u32,
    block_align: u16,
    bits: u16,
    valid_bits: u16,
    channel_mask: Option<u32>,
    sample_format: &'static str,
}

impl WaveFormat {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 18 || bytes.len() > 1024 {
            bail!("Unsupported mix-format size {}", bytes.len());
        }
        let u16_at = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let u32_at = |offset| {
            u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        };
        let tag = u16_at(0);
        let channels = u16_at(2);
        let rate = u32_at(4);
        let byte_rate = u32_at(8);
        let block_align = u16_at(12);
        let bits = u16_at(14);
        if usize::from(u16_at(16)) + 18 != bytes.len() {
            bail!("Mix-format extension size does not match its allocation");
        }
        let (subtype, valid_bits, channel_mask) = match tag {
            1 | 3 => (u32::from(tag), bits, None),
            0xfffe if bytes.len() >= 40 => {
                let subtype = u32_at(24);
                if bytes[28..40] != [0, 0, 16, 0, 128, 0, 0, 170, 0, 56, 155, 113] {
                    bail!("Unsupported extensible mix-format subtype GUID");
                }
                (subtype, u16_at(18), Some(u32_at(20)))
            }
            _ => {
                bail!("Unsupported mix-format tag {tag:#06x}; only PCM and IEEE float are recorded")
            }
        };
        let sample_format = match subtype {
            1 if matches!(bits, 8 | 16 | 24 | 32) => "pcm",
            3 if matches!(bits, 32 | 64) && valid_bits == bits => "ieee_float",
            _ => bail!(
                "Unsupported mix format: subtype={subtype}, bits={bits}, valid_bits={valid_bits}"
            ),
        };
        if channels == 0
            || u32::from(channels) > MAX_CHANNELS
            || rate == 0
            || rate > 768_000
            || valid_bits == 0
            || valid_bits > bits
            || u32::from(block_align) != u32::from(channels) * u32::from(bits / 8)
            || rate.checked_mul(u32::from(block_align)) != Some(byte_rate)
        {
            bail!("Invalid or unsupported WASAPI mix-format dimensions");
        }
        Ok(Self {
            bytes: if tag == 1 && bytes.len() == 18 {
                bytes[..16].to_vec()
            } else {
                bytes.to_vec()
            },
            tag,
            channels,
            rate,
            byte_rate,
            block_align,
            bits,
            valid_bits,
            channel_mask,
            sample_format,
        })
    }

    fn json(&self) -> Value {
        json!({
            "format_tag": self.tag, "sample_format": self.sample_format,
            "channels": self.channels, "sample_rate": self.rate, "bits_per_sample": self.bits,
            "valid_bits_per_sample": self.valid_bits, "block_align": self.block_align,
            "bytes_per_second": self.byte_rate, "channel_mask": self.channel_mask,
        })
    }
}

struct WavArtifact {
    file: Option<File>,
    path: PathBuf,
    data_start: u64,
    data_size_offset: u64,
    frame_count_offset: u64,
    bytes: u32,
    frames: u32,
    committed: bool,
}

impl WavArtifact {
    fn new(path: &Path, format: &WaveFormat) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("Create new WAV artifact {}", path.display()))?;
        let mut artifact = Self {
            file: Some(file),
            path: path.to_path_buf(),
            data_start: 0,
            data_size_offset: 0,
            frame_count_offset: 0,
            bytes: 0,
            frames: 0,
            committed: false,
        };
        let mut header = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
        header.extend_from_slice(&(format.bytes.len() as u32).to_le_bytes());
        header.extend_from_slice(&format.bytes);
        if !header.len().is_multiple_of(2) {
            header.push(0);
        }
        header.extend_from_slice(b"fact");
        header.extend_from_slice(&4u32.to_le_bytes());
        artifact.frame_count_offset = header.len() as u64;
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(b"data");
        artifact.data_size_offset = header.len() as u64;
        header.extend_from_slice(&0u32.to_le_bytes());
        artifact.data_start = header.len() as u64;
        artifact
            .file
            .as_mut()
            .unwrap()
            .write_all(&header)
            .context("Write WAV header")?;
        Ok(artifact)
    }

    fn remaining_frames(&self, max_bytes: u64, block_align: u16) -> u32 {
        let remaining = max_bytes.saturating_sub(self.data_start + u64::from(self.bytes) + 1);
        (remaining / u64::from(block_align)).min(u64::from(u32::MAX)) as u32
    }

    fn append(&mut self, bytes: &[u8], frames: u32, block_align: u16) -> Result<()> {
        if bytes.len() != frames as usize * usize::from(block_align) {
            bail!("Audio packet byte count does not match its frame count");
        }
        let new_bytes = self
            .bytes
            .checked_add(u32::try_from(bytes.len())?)
            .context("WAV size overflow")?;
        let new_frames = self
            .frames
            .checked_add(frames)
            .context("WAV frame count overflow")?;
        self.file
            .as_mut()
            .context("WAV artifact already closed")?
            .write_all(bytes)
            .context("Write WAV samples")?;
        self.bytes = new_bytes;
        self.frames = new_frames;
        Ok(())
    }

    fn finish(&mut self, max_bytes: u64) -> Result<u64> {
        let file = self.file.as_mut().context("WAV artifact already closed")?;
        if !self.bytes.is_multiple_of(2) {
            file.write_all(&[0]).context("Pad WAV data chunk")?;
        }
        let size = self.data_start + u64::from(self.bytes) + u64::from(self.bytes % 2);
        if size > max_bytes || size - 8 > u64::from(u32::MAX) {
            bail!("WAV artifact would exceed its size bound");
        }
        file.seek(SeekFrom::Start(4))
            .context("Seek WAV RIFF size")?;
        file.write_all(&((size - 8) as u32).to_le_bytes())
            .context("Write WAV RIFF size")?;
        file.seek(SeekFrom::Start(self.frame_count_offset))
            .context("Seek WAV frame count")?;
        file.write_all(&self.frames.to_le_bytes())
            .context("Write WAV frame count")?;
        file.seek(SeekFrom::Start(self.data_size_offset))
            .context("Seek WAV data size")?;
        file.write_all(&self.bytes.to_le_bytes())
            .context("Write WAV data size")?;
        file.flush().context("Flush WAV artifact")?;
        file.sync_all().context("Persist WAV artifact")?;
        if file.metadata().context("Read completed WAV size")?.len() != size {
            bail!("WAV artifact length does not match the recorded samples");
        }
        drop(self.file.take());
        self.committed = true;
        Ok(size)
    }
}

impl Drop for WavArtifact {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            if let Err(error) = std::fs::remove_file(&self.path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!(path = %self.path.display(), %error, "Remove incomplete WAV failed");
                }
            }
        }
    }
}

struct CaptureStream<'a> {
    client: &'a IAudioClient,
    running: bool,
}

impl CaptureStream<'_> {
    fn stop(&mut self) -> Result<()> {
        unsafe { self.client.Stop() }.context("Stop WASAPI capture")?;
        self.running = false;
        Ok(())
    }
}

impl Drop for CaptureStream<'_> {
    fn drop(&mut self) {
        if self.running {
            if let Err(error) = unsafe { self.client.Stop() } {
                tracing::error!(%error, "WASAPI stop during cleanup failed");
            }
        }
    }
}

struct CapturePacket<'a> {
    capture: &'a IAudioCaptureClient,
    frames: u32,
    released: bool,
}

impl CapturePacket<'_> {
    fn release(mut self) -> Result<()> {
        self.released = true;
        unsafe { self.capture.ReleaseBuffer(self.frames) }.context("Release WASAPI capture packet")
    }
}

impl Drop for CapturePacket<'_> {
    fn drop(&mut self) {
        if !self.released {
            if let Err(error) = unsafe { self.capture.ReleaseBuffer(self.frames) } {
                tracing::error!(%error, "WASAPI packet cleanup failed");
            }
        }
    }
}

fn capture_checkpoint(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        bail!("Audio recording canceled");
    }
    Ok(())
}

pub fn record(input: &RecordInput, cancelled: &AtomicBool) -> Result<String> {
    let limits = record_limits(input)?;
    capture_checkpoint(cancelled)?;
    let desired_flow = match input.mode {
        RecordMode::Capture => DataFlow::Capture,
        RecordMode::Loopback => DataFlow::Render,
    };
    let mut target = input.target.clone();
    if target
        .dataflow
        .is_some_and(|flow| flow.native() != desired_flow.native())
    {
        bail!(
            "Recording mode {:?} requires a {:?} endpoint",
            input.mode,
            desired_flow
        );
    }
    target.dataflow = Some(desired_flow);
    let _apartment = Apartment::new()?;
    let device = resolve(&target)?;
    let id = endpoint_id(&device)?;
    let client: IAudioClient =
        unsafe { device.Activate(CLSCTX_ALL, None) }.context("Activate WASAPI audio client")?;
    let mix = TaskMemory(unsafe { client.GetMixFormat() }.context("Get endpoint mix format")?);
    if mix.0.is_null() {
        bail!("WASAPI returned a null mix format");
    }
    let format_size = 18 + usize::from(unsafe { (*mix.0).cbSize });
    if format_size > 1024 {
        bail!("WASAPI mix-format extension is too large: {format_size}");
    }
    let format =
        WaveFormat::parse(unsafe { std::slice::from_raw_parts(mix.0.cast::<u8>(), format_size) })?;
    let flags = AUDCLNT_STREAMFLAGS_EVENTCALLBACK
        | if matches!(input.mode, RecordMode::Loopback) {
            AUDCLNT_STREAMFLAGS_LOOPBACK
        } else {
            0
        };
    unsafe {
        client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            flags,
            i64::from(limits.buffer_ms) * 10_000,
            0,
            mix.0,
            None,
        )
    }
    .context("Initialize WASAPI shared-mode capture with the endpoint's actual mix format")?;
    let buffer_frames = unsafe { client.GetBufferSize() }.context("Read WASAPI buffer size")?;
    let buffer_bytes = buffer_frames as usize * usize::from(format.block_align);
    if buffer_frames == 0 || buffer_bytes > MAX_CAPTURE_BUFFER_BYTES {
        bail!("Unsupported WASAPI capture buffer: {buffer_frames} frames, {buffer_bytes} bytes");
    }
    let event = OwnedHandle(
        unsafe { CreateEventW(None, false, false, PCWSTR::null()) }
            .context("Create WASAPI sample event")?,
    );
    unsafe { client.SetEventHandle(event.0) }.context("Set WASAPI sample event")?;
    let capture: IAudioCaptureClient =
        unsafe { client.GetService() }.context("Get WASAPI capture interface")?;
    capture_checkpoint(cancelled)?;
    let mut artifact = WavArtifact::new(Path::new(&input.path), &format)?;
    unsafe { client.Start() }.context("Start explicitly requested audio recording")?;
    let mut stream = CaptureStream {
        client: &client,
        running: true,
    };
    let start = Instant::now();
    let deadline = start + limits.duration;
    let requested_frames = u64::from(input.duration_seconds) * u64::from(format.rate);
    let mut silent_frames = 0u64;
    let mut discontinuities = 0u64;
    let mut timestamp_errors = 0u64;
    let mut first_device_position = None;
    let mut first_qpc = None;
    let mut last_device_position = None;
    let stop_reason = 'recording: loop {
        capture_checkpoint(cancelled)?;
        if Instant::now() >= deadline {
            break "duration";
        }
        let wait_ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 20) as u32;
        match unsafe { WaitForSingleObject(event.0, wait_ms) } {
            WAIT_OBJECT_0 | WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                return Err(
                    anyhow!(windows::core::Error::from_thread()).context("Wait for WASAPI samples")
                )
            }
            wait => bail!("Unexpected WASAPI wait result {}", wait.0),
        }
        loop {
            capture_checkpoint(cancelled)?;
            if Instant::now() >= deadline {
                break 'recording "duration";
            }
            let available =
                unsafe { capture.GetNextPacketSize() }.context("Read WASAPI packet size")?;
            if available == 0 {
                break;
            }
            let (mut data, mut frames, mut flags) = (std::ptr::null_mut(), 0, 0);
            let (mut device_position, mut qpc_position) = (0, 0);
            let acquired = unsafe {
                (Interface::vtable(&capture).GetBuffer)(
                    Interface::as_raw(&capture),
                    &mut data,
                    &mut frames,
                    &mut flags,
                    &mut device_position,
                    &mut qpc_position,
                )
            };
            acquired.ok().context("Acquire WASAPI capture packet")?;
            if acquired == AUDCLNT_S_BUFFER_EMPTY {
                break;
            }
            let packet = CapturePacket {
                capture: &capture,
                frames,
                released: false,
            };
            if frames > buffer_frames {
                bail!("WASAPI packet {frames} frames exceeds its buffer {buffer_frames}");
            }
            let frame_limit = requested_frames.saturating_sub(u64::from(artifact.frames));
            let size_limit = artifact.remaining_frames(limits.max_bytes, format.block_align);
            let write_frames = frames.min(size_limit).min(frame_limit as u32);
            if flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY.0 as u32 != 0 {
                discontinuities += 1;
            }
            if flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR.0 as u32 != 0 {
                timestamp_errors += 1;
            } else if write_frames > 0 {
                first_device_position.get_or_insert(device_position);
                first_qpc.get_or_insert(qpc_position);
                last_device_position = Some(device_position + u64::from(write_frames));
            }
            let length = write_frames as usize * usize::from(format.block_align);
            if length > 0 {
                if flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 {
                    // Eight-bit PCM silence is unsigned midpoint, not zero.
                    let silence = if format.sample_format == "pcm" && format.bits == 8 {
                        128
                    } else {
                        0
                    };
                    artifact.append(&vec![silence; length], write_frames, format.block_align)?;
                    silent_frames += u64::from(write_frames);
                } else {
                    if data.is_null() {
                        bail!("WASAPI returned null sample data for a nonsilent packet");
                    }
                    artifact.append(
                        unsafe { std::slice::from_raw_parts(data, length) },
                        write_frames,
                        format.block_align,
                    )?;
                }
            }
            packet.release()?;
            if u64::from(artifact.frames) >= requested_frames {
                break 'recording "frame_limit";
            }
            if write_frames < frames
                || artifact.remaining_frames(limits.max_bytes, format.block_align) == 0
            {
                break 'recording "size_limit";
            }
            if frames == 0 {
                break;
            }
        }
    };
    stream.stop()?;
    capture_checkpoint(cancelled)?;
    let size = artifact.finish(limits.max_bytes)?;
    if cancelled.load(Ordering::Acquire) {
        artifact.committed = false;
        bail!("Audio recording canceled during artifact finalization");
    }
    Ok(pretty(&json!({
        "path": input.path, "endpoint_id": id, "mode": input.mode,
        "status": if artifact.frames == 0 { "no_samples" } else { "recorded" },
        "stop_reason": stop_reason, "format": format.json(),
        "frames": artifact.frames, "sample_bytes": artifact.bytes, "file_bytes": size,
        "requested_seconds": input.duration_seconds,
        "recorded_seconds": f64::from(artifact.frames) / f64::from(format.rate),
        "elapsed_ms": start.elapsed().as_millis(),
        "silent_frames": silent_frames, "discontinuity_packets": discontinuities,
        "timestamp_error_packets": timestamp_errors,
        "first_device_position_frames": first_device_position,
        "last_device_position_frames": last_device_position,
        "first_qpc_100ns": first_qpc.map(|value| value.to_string()),
        "buffer_frames": buffer_frames, "max_bytes": limits.max_bytes,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_argument_volume_input_is_read_only() {
        let input: VolumeInput = serde_json::from_str("{}").unwrap();
        assert!(input.volume.is_none() && input.mute.is_none());
        assert!(input.target.endpoint_id.is_none() && input.target.dataflow.is_none());
        let schema = serde_json::to_value(schemars::schema_for!(VolumeInput)).unwrap();
        assert!(schema
            .get("required")
            .is_none_or(|v| v.as_array().unwrap().is_empty()));
    }

    #[test]
    fn numeric_string_volume_and_pid_are_preserved() {
        let input: SessionVolumeInput = serde_json::from_value(json!({
            "volume": "41.5", "pid": "1234", "process_creation_time": "132123456789012345"
        }))
        .unwrap();
        assert_eq!(input.volume, Some(41.5));
        assert_eq!(input.pid, Some(1234));
        assert_eq!(input.process_creation_time, Some(132123456789012345));
        validate_volume(Some(0.0)).unwrap();
        validate_volume(Some(100.0)).unwrap();
        for volume in [-1.0, 100.1, f32::NAN, f32::INFINITY] {
            assert!(validate_volume(Some(volume)).is_err());
        }
    }

    #[test]
    fn exact_sessions_reject_ambiguity_and_reused_pids() {
        let identities = vec![
            SessionIdentity {
                instance: "one".into(),
                pid: 10,
                creation_time: Some(20),
                multiple_processes: false,
            },
            SessionIdentity {
                instance: "two".into(),
                pid: 10,
                creation_time: Some(20),
                multiple_processes: false,
            },
        ];
        let mut input = SessionVolumeInput {
            pid: Some(10),
            ..Default::default()
        };
        assert!(select_session(&identities, &input)
            .unwrap_err()
            .to_string()
            .contains("Ambiguous"));
        input.session_instance_id = Some("two".into());
        assert_eq!(select_session(&identities, &input).unwrap(), 1);
        input.process_creation_time = Some(21);
        assert!(select_session(&identities, &input).is_err());
        input.session_instance_id = None;
        input.process_creation_time = None;
        input.mute = Some(true);
        assert!(select_session(&identities, &input)
            .unwrap_err()
            .to_string()
            .contains("creation_time"));
    }

    #[test]
    fn capture_session_mutations_cannot_change_other_applications() {
        assert_eq!(session_volume_scope(eRender, false).unwrap(), "session");
        assert_eq!(session_volume_scope(eRender, true).unwrap(), "session");
        assert_eq!(session_volume_scope(eCapture, false).unwrap(), "endpoint");
        assert!(session_volume_scope(eAll, false).is_err());
        for input in [
            SessionVolumeInput {
                volume: Some(0.0),
                ..Default::default()
            },
            SessionVolumeInput {
                mute: Some(true),
                ..Default::default()
            },
        ] {
            assert!(input.target.dataflow.is_none());
            let error =
                session_volume_scope(eCapture, input.volume.is_some() || input.mute.is_some())
                    .unwrap_err();
            assert!(error.to_string().contains("endpoint-wide"));
        }
    }

    fn pcm_format() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&8000u32.to_le_bytes());
        bytes.extend_from_slice(&16000u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    #[test]
    fn capture_mix_formats_keep_real_encoding_and_dimensions() {
        let mut bytes = pcm_format();
        let pcm = WaveFormat::parse(&bytes).unwrap();
        assert_eq!(pcm.sample_format, "pcm");
        assert_eq!(pcm.bytes.len(), 16);
        assert_eq!(pcm.rate, 8000);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(WaveFormat::parse(&bytes).is_err());
        bytes = pcm_format();
        bytes[0..2].copy_from_slice(&0xfffeu16.to_le_bytes());
        bytes[8..12].copy_from_slice(&32000u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&4u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&32u16.to_le_bytes());
        bytes[16..18].copy_from_slice(&22u16.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 16, 0, 128, 0, 0, 170, 0, 56, 155, 113]);
        let float = WaveFormat::parse(&bytes).unwrap();
        assert_eq!(float.sample_format, "ieee_float");
        assert_eq!(float.channel_mask, Some(4));
        assert_eq!(float.bytes, bytes);
        bytes[28] = 1;
        assert!(WaveFormat::parse(&bytes).is_err());
    }

    #[test]
    fn recording_requires_explicit_source_and_bounded_inputs() {
        let path =
            std::env::temp_dir().join(format!("mcp-audio-unused-{}.wav", uuid::Uuid::new_v4()));
        assert!(serde_json::from_value::<RecordInput>(json!({
            "path": path, "duration_seconds": "1"
        }))
        .is_err());
        let mut input: RecordInput = serde_json::from_value(json!({
            "path": path, "mode": "capture", "duration_seconds": "1", "buffer_ms": "100",
            "max_bytes": "1024"
        }))
        .unwrap();
        record_limits(&input).unwrap();
        let cancelled = AtomicBool::new(true);
        assert!(record(&input, &cancelled)
            .unwrap_err()
            .to_string()
            .contains("canceled"));
        assert!(!path.exists());
        input.duration_seconds = 0;
        assert!(record_limits(&input).is_err());
        input.duration_seconds = 301;
        assert!(record_limits(&input).is_err());
        input.duration_seconds = 1;
        input.max_bytes = Some(MAX_RECORD_BYTES + 1);
        assert!(record_limits(&input).is_err());
        input.max_bytes = None;
        input.buffer_ms = Some(1001);
        assert!(record_limits(&input).is_err());
    }

    #[test]
    fn wav_artifact_records_actual_frames_and_removes_partial_files() {
        let format = WaveFormat::parse(&pcm_format()).unwrap();
        let path =
            std::env::temp_dir().join(format!("mcp-audio-wav-test-{}.wav", uuid::Uuid::new_v4()));
        {
            let mut artifact = WavArtifact::new(&path, &format).unwrap();
            assert!(artifact.remaining_frames(1024, format.block_align) < 512);
            artifact
                .append(&[1, 2, 3, 4], 2, format.block_align)
                .unwrap();
            assert_eq!(artifact.frames, 2);
            let size = artifact.finish(1024).unwrap();
            assert_eq!(size, artifact.data_start + 4);
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(&bytes[..4], b"RIFF");
            assert_eq!(&bytes[8..12], b"WAVE");
            let frame_offset = artifact.frame_count_offset as usize;
            assert_eq!(
                u32::from_le_bytes(bytes[frame_offset..frame_offset + 4].try_into().unwrap()),
                2
            );
            assert_eq!(&bytes[artifact.data_start as usize..], &[1, 2, 3, 4]);
            assert!(WavArtifact::new(&path, &format).is_err());
        }
        std::fs::remove_file(&path).unwrap();
        {
            let mut artifact = WavArtifact::new(&path, &format).unwrap();
            artifact.append(&[1, 2], 1, format.block_align).unwrap();
        }
        assert!(!path.exists());
    }

    #[test]
    fn native_audio_read_only() {
        match devices() {
            Ok(text) => {
                let inventory: Value = serde_json::from_str(&text).unwrap();
                assert!(inventory["Devices"].is_array());
                assert_eq!(inventory["defaults"].as_array().unwrap().len(), 6);
                eprintln!("Audio inventory: {}", inventory["status"]);
                match volume(&VolumeInput::default()) {
                    Ok(text) => {
                        let value: Value = serde_json::from_str(&text).unwrap();
                        assert!((0.0..=100.0).contains(&value["volume"].as_f64().unwrap()));
                        assert!(value["mute"].is_boolean());
                        assert_eq!(value["volume_set"], false);
                        let target = EndpointInput {
                            endpoint_id: Some(value["endpoint_id"].as_str().unwrap().to_owned()),
                            ..Default::default()
                        };
                        match meter(&target) {
                            Ok(text) => {
                                let levels: Value = serde_json::from_str(&text).unwrap();
                                assert!(levels["channel_peaks"].is_array());
                                assert!((0.0..=1.0).contains(&levels["peak"].as_f64().unwrap()));
                            }
                            Err(error) => eprintln!("Endpoint metering unavailable: {error:#}"),
                        }
                        match sessions(&SessionsInput { target, pid: None }) {
                            Ok(text) => {
                                let sessions: Value = serde_json::from_str(&text).unwrap();
                                assert!(sessions["sessions"].is_array());
                                for session in sessions["sessions"].as_array().unwrap() {
                                    assert!(session["session_instance_id"].is_string());
                                    assert!(session["pid"].is_number());
                                    assert!(session["mute"].is_boolean());
                                }
                            }
                            Err(error) => eprintln!("Endpoint sessions unavailable: {error:#}"),
                        }
                    }
                    Err(error) => eprintln!("Default audio volume unavailable: {error:#}"),
                }
            }
            Err(error) => eprintln!("Core Audio unavailable in this test context: {error:#}"),
        }
    }
}
