use std::{fmt::Display, marker::PhantomData, rc::Rc};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use windows::{
    core::{Interface, BSTR},
    Win32::{
        Foundation::SYSTEMTIME,
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED, SAFEARRAY,
            },
            Ole::{
                SafeArrayDestroy, SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound,
                SafeArrayGetUBound, SafeArrayGetVartype,
            },
            SystemInformation::GetLocalTime,
            TaskScheduler::*,
            Variant::{VariantTimeToSystemTime, VARIANT, VT_BSTR},
        },
    },
};

use super::pretty;

const MAX_TASKS: usize = 8192;
const MAX_FOLDERS: usize = 2048;
const MAX_DEPTH: usize = 64;
const MAX_ITEMS: usize = 256;
const MAX_TEXT_UNITS: usize = 32_768;
const MAX_XML_UNITS: usize = 1_048_576;
const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

struct Apartment(PhantomData<Rc<()>>);

impl Apartment {
    fn new() -> Result<Self> {
        com(
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() },
            "Initialize Task Scheduler COM apartment on the calling thread",
        )?;
        Ok(Self(PhantomData))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn com<T>(result: windows::core::Result<T>, operation: impl Display) -> Result<T> {
    result.map_err(|error| {
        anyhow!(
            "{operation} failed (HRESULT 0x{:08X}): {error}",
            error.code().0 as u32
        )
    })
}

fn exposed_error(error: anyhow::Error) -> anyhow::Error {
    anyhow!("{error:#}")
}

fn read<T: Default>(
    operation: &str,
    getter: impl FnOnce(*mut T) -> windows::core::Result<()>,
) -> Result<T> {
    let mut value = T::default();
    com(getter(&mut value), operation)?;
    Ok(value)
}

fn decode(value: BSTR, operation: &str, limit: usize) -> Result<String> {
    if value.len() > limit {
        bail!("{operation} exceeds the {limit} UTF-16 code unit limit");
    }
    String::from_utf16(&value).with_context(|| format!("{operation} contains invalid UTF-16"))
}

fn text(
    operation: &str,
    getter: impl FnOnce(*mut BSTR) -> windows::core::Result<()>,
) -> Result<String> {
    decode(read(operation, getter)?, operation, MAX_TEXT_UNITS)
}

macro_rules! get {
    ($object:ident.$property:ident) => {
        read(
            concat!(stringify!($object), ".", stringify!($property)),
            |out| unsafe { $object.$property(out) },
        )?
    };
}

macro_rules! get_text {
    ($object:ident.$property:ident) => {
        text(
            concat!(stringify!($object), ".", stringify!($property)),
            |out| unsafe { $object.$property(out) },
        )?
    };
}

fn with_service(operation: impl FnOnce(&ITaskService) -> Result<Value>) -> Result<String> {
    let _apartment = Apartment::new()?;
    let service: ITaskService = com(
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) },
        "Create local Task Scheduler service",
    )?;
    let empty = VARIANT::default();
    com(
        unsafe { service.Connect(&empty, &empty, &empty, &empty) },
        "Connect to local Task Scheduler as the current user",
    )?;
    // Only owned JSON leaves this scope. All COM references drop before the apartment.
    let result = pretty(&operation(&service).map_err(exposed_error)?);
    if result.len() > MAX_JSON_BYTES {
        bail!("Task Scheduler result exceeds the {MAX_JSON_BYTES} byte limit");
    }
    Ok(result)
}

fn checked_count(count: i32, maximum: usize, kind: &str) -> Result<usize> {
    let count = usize::try_from(count).with_context(|| format!("{kind} count is negative"))?;
    if count > maximum {
        bail!("{kind} count {count} exceeds the limit of {maximum}; no partial result returned");
    }
    Ok(count)
}

fn validate_component(value: &str, kind: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value == "." || value == ".." {
        bail!(
            "{kind} must be a nonempty, exact name without surrounding whitespace or dot segments"
        );
    }
    if value.encode_utf16().count() > 255
        || value.ends_with('.')
        || value
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        bail!(
            "{kind} contains a separator, wildcard, invalid character, or exceeds 255 UTF-16 units"
        );
    }
    Ok(())
}

fn folder_path(path: Option<&str>) -> Result<String> {
    let path = path.unwrap_or("\\");
    if path == "\\" {
        return Ok(path.to_owned());
    }
    if !path.starts_with('\\') || path.starts_with("\\\\") {
        bail!("Task path must be an absolute local scheduler folder such as \\ or \\MyFolder\\");
    }
    if path.encode_utf16().count() > 260 {
        bail!("Task path exceeds 260 UTF-16 code units");
    }
    let path = path.strip_suffix('\\').unwrap_or(path);
    for segment in path[1..].split('\\') {
        validate_component(segment, "Task path segment")?;
    }
    Ok(path.to_owned())
}

fn target(name: &str, path: Option<&str>) -> Result<String> {
    validate_component(name, "Task name")?;
    let folder = folder_path(path)?;
    let separator = usize::from(folder != "\\");
    if folder.encode_utf16().count() + separator + name.encode_utf16().count() > 260 {
        bail!("Full task path exceeds 260 UTF-16 code units");
    }
    Ok(folder)
}

fn open_folder(service: &ITaskService, path: &str) -> Result<ITaskFolder> {
    com(
        unsafe { service.GetFolder(&BSTR::from(path)) },
        format!("Open Task Scheduler folder {path:?}"),
    )
}

fn open_task(folder: &ITaskFolder, name: &str) -> Result<IRegisteredTask> {
    com(
        unsafe { folder.GetTask(&BSTR::from(name)) },
        format!("Open exact scheduled task {name:?}"),
    )
}

fn native_folder_path(folder: &ITaskFolder) -> Result<String> {
    decode(
        com(unsafe { folder.Path() }, "Read scheduler folder path")?,
        "Scheduler folder path",
        260,
    )
}

fn excluded_folder(path: &str) -> bool {
    path.get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\Microsoft"))
}

fn task_identity(task: &IRegisteredTask) -> Result<(String, String)> {
    let name = decode(
        com(unsafe { task.Name() }, "Read scheduled task name")?,
        "Scheduled task name",
        255,
    )?;
    let path = decode(
        com(unsafe { task.Path() }, "Read scheduled task path")?,
        "Scheduled task path",
        260,
    )?;
    let separator = path
        .rfind('\\')
        .filter(|&i| path.starts_with('\\') && i + 1 < path.len())
        .context("Task Scheduler returned a task path without a folder and leaf name")?;
    Ok((name, path[..=separator].to_owned()))
}

fn state_name(state: TASK_STATE) -> Result<&'static str> {
    match state {
        TASK_STATE_UNKNOWN => Ok("Unknown"),
        TASK_STATE_DISABLED => Ok("Disabled"),
        TASK_STATE_QUEUED => Ok("Queued"),
        TASK_STATE_READY => Ok("Ready"),
        TASK_STATE_RUNNING => Ok("Running"),
        _ => bail!(
            "Task Scheduler returned an unrecognized task state {}",
            state.0
        ),
    }
}

fn date_string(date: f64) -> Result<Option<String>> {
    if date == 0.0 {
        return Ok(None);
    }
    let mut time = SYSTEMTIME::default();
    if !date.is_finite() || unsafe { VariantTimeToSystemTime(date, &mut time) } == 0 {
        bail!("Task Scheduler returned an invalid Automation DATE: {date}");
    }
    // Automation DATE is a local wall-clock time, including its unusual negative fractions.
    let mut result = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    );
    if time.wMilliseconds != 0 {
        result.push_str(&format!(".{:03}", time.wMilliseconds));
    }
    Ok(Some(result))
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct TaskRow {
    task_name: String,
    task_path: String,
    state: &'static str,
    last_run: Option<String>,
    next_run: Option<String>,
}

fn task_row(task: &IRegisteredTask) -> Result<TaskRow> {
    let (task_name, task_path) = task_identity(task)?;
    Ok(TaskRow {
        task_name,
        task_path,
        state: state_name(com(unsafe { task.State() }, "Read scheduled task state")?)?,
        last_run: date_string(com(
            unsafe { task.LastRunTime() },
            "Read scheduled task last run time",
        )?)?,
        next_run: date_string(com(
            unsafe { task.NextRunTime() },
            "Read scheduled task next run time",
        )?)?,
    })
}

pub fn list() -> Result<String> {
    with_service(|service| {
        let mut pending = vec![(open_folder(service, "\\")?, 0usize)];
        let mut folder_count = 1usize;
        let mut rows = Vec::new();
        while let Some((folder, depth)) = pending.pop() {
            let path = native_folder_path(&folder)?;
            if excluded_folder(&path) {
                continue;
            }
            let tasks = com(
                unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) },
                format!("Enumerate tasks in {path:?}"),
            )?;
            let count = checked_count(
                com(unsafe { tasks.Count() }, format!("Count tasks in {path:?}"))?,
                MAX_TASKS - rows.len(),
                "Scheduled task",
            )?;
            for index in 1..=count {
                let task = com(
                    unsafe { tasks.get_Item(&VARIANT::from(index as i32)) },
                    format!("Read task {index} in {path:?}"),
                )?;
                rows.push(
                    task_row(&task)
                        .with_context(|| format!("Read task {index} in folder {path:?}"))?,
                );
            }
            let children = com(
                unsafe { folder.GetFolders(0) },
                format!("Enumerate scheduler subfolders in {path:?}"),
            )?;
            let count = checked_count(
                com(
                    unsafe { children.Count() },
                    format!("Count scheduler subfolders in {path:?}"),
                )?,
                MAX_FOLDERS,
                "Scheduler subfolder",
            )?;
            for index in 1..=count {
                let child = com(
                    unsafe { children.get_Item(&VARIANT::from(index as i32)) },
                    format!("Read scheduler subfolder {index} in {path:?}"),
                )?;
                if excluded_folder(&native_folder_path(&child)?) {
                    continue;
                }
                folder_count += 1;
                if folder_count > MAX_FOLDERS || depth + 1 > MAX_DEPTH {
                    bail!(
                        "Scheduler enumeration exceeds {MAX_FOLDERS} folders or depth {MAX_DEPTH}; \
                         no partial result returned"
                    );
                }
                pending.push((child, depth + 1));
            }
        }
        rows.sort_by_cached_key(|row| (row.task_name.to_lowercase(), row.task_path.to_lowercase()));
        serde_json::to_value(rows).context("Serialize scheduled task list")
    })
}

fn bounded_push(values: &mut Vec<Value>, value: Value, bytes: &mut usize) -> Result<()> {
    *bytes += serde_json::to_vec(&value)
        .context("Measure scheduled task details")?
        .len();
    if *bytes > MAX_JSON_BYTES {
        bail!("Task details exceed the {MAX_JSON_BYTES} byte limit; no partial result returned");
    }
    values.push(value);
    Ok(())
}

fn named_values(collection: &ITaskNamedValueCollection) -> Result<Value> {
    let count = checked_count(get!(collection.Count), MAX_ITEMS, "Task named value")?;
    let mut result = Vec::new();
    let mut bytes = 0;
    for index in 1..=count {
        let pair = com(
            unsafe { collection.get_Item(index as i32) },
            format!("Read task named value {index}"),
        )?;
        bounded_push(
            &mut result,
            json!({"Name": get_text!(pair.Name), "Value": get_text!(pair.Value)}),
            &mut bytes,
        )?;
    }
    Ok(Value::Array(result))
}

fn trigger_label(kind: TASK_TRIGGER_TYPE2) -> String {
    match kind {
        TASK_TRIGGER_EVENT => "Event".to_owned(),
        TASK_TRIGGER_TIME => "Once".to_owned(),
        TASK_TRIGGER_DAILY => "Daily".to_owned(),
        TASK_TRIGGER_WEEKLY => "Weekly".to_owned(),
        TASK_TRIGGER_MONTHLY => "Monthly".to_owned(),
        TASK_TRIGGER_MONTHLYDOW => "MonthlyDayOfWeek".to_owned(),
        TASK_TRIGGER_IDLE => "Idle".to_owned(),
        TASK_TRIGGER_REGISTRATION => "Registration".to_owned(),
        TASK_TRIGGER_BOOT => "AtStartup".to_owned(),
        TASK_TRIGGER_LOGON => "AtLogon".to_owned(),
        TASK_TRIGGER_SESSION_STATE_CHANGE => "SessionStateChange".to_owned(),
        TASK_TRIGGER_CUSTOM_TRIGGER_01 => "Custom".to_owned(),
        _ => format!("Unknown({})", kind.0),
    }
}

fn weekdays(mask: i16) -> Result<Vec<&'static str>> {
    if mask as u16 & !0x7f != 0 {
        bail!(
            "Task trigger returned invalid weekday mask 0x{:04X}",
            mask as u16
        );
    }
    Ok([
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(bit, day)| (mask & (1 << bit) != 0).then_some(day))
    .collect())
}

fn trigger_details(trigger: &ITrigger) -> Result<Value> {
    let kind = get!(trigger.Type);
    let repetition = com(
        unsafe { trigger.Repetition() },
        "Read trigger repetition pattern",
    )?;
    let mut value = json!({
        "Type": trigger_label(kind),
        "TypeCode": kind.0,
        "Id": get_text!(trigger.Id),
        "Enabled": get!(trigger.Enabled).as_bool(),
        "StartBoundary": get_text!(trigger.StartBoundary),
        "EndBoundary": get_text!(trigger.EndBoundary),
        "ExecutionTimeLimit": get_text!(trigger.ExecutionTimeLimit),
        "Repetition": {
            "Interval": get_text!(repetition.Interval),
            "Duration": get_text!(repetition.Duration),
            "StopAtDurationEnd": get!(repetition.StopAtDurationEnd).as_bool(),
        },
    });
    match kind {
        TASK_TRIGGER_TIME => {
            let time: ITimeTrigger = com(trigger.cast(), "Query time trigger interface")?;
            value["RandomDelay"] = json!(get_text!(time.RandomDelay));
        }
        TASK_TRIGGER_DAILY => {
            let daily: IDailyTrigger = com(trigger.cast(), "Query daily trigger interface")?;
            value["DaysInterval"] = json!(get!(daily.DaysInterval));
            value["RandomDelay"] = json!(get_text!(daily.RandomDelay));
        }
        TASK_TRIGGER_WEEKLY => {
            let weekly: IWeeklyTrigger = com(trigger.cast(), "Query weekly trigger interface")?;
            let days = get!(weekly.DaysOfWeek);
            value["DaysOfWeek"] = json!(weekdays(days)?);
            value["DaysOfWeekMask"] = json!(days);
            value["WeeksInterval"] = json!(get!(weekly.WeeksInterval));
            value["RandomDelay"] = json!(get_text!(weekly.RandomDelay));
        }
        TASK_TRIGGER_MONTHLY => {
            let monthly: IMonthlyTrigger = com(trigger.cast(), "Query monthly trigger interface")?;
            value["DaysOfMonthMask"] = json!(get!(monthly.DaysOfMonth) as u32);
            value["MonthsOfYearMask"] = json!(get!(monthly.MonthsOfYear) as u16);
            value["RunOnLastDayOfMonth"] = json!(get!(monthly.RunOnLastDayOfMonth).as_bool());
            value["RandomDelay"] = json!(get_text!(monthly.RandomDelay));
        }
        TASK_TRIGGER_MONTHLYDOW => {
            let monthly: IMonthlyDOWTrigger =
                com(trigger.cast(), "Query monthly weekday trigger interface")?;
            let days = get!(monthly.DaysOfWeek);
            value["DaysOfWeek"] = json!(weekdays(days)?);
            value["DaysOfWeekMask"] = json!(days);
            value["WeeksOfMonthMask"] = json!(get!(monthly.WeeksOfMonth) as u16);
            value["MonthsOfYearMask"] = json!(get!(monthly.MonthsOfYear) as u16);
            value["RunOnLastWeekOfMonth"] = json!(get!(monthly.RunOnLastWeekOfMonth).as_bool());
            value["RandomDelay"] = json!(get_text!(monthly.RandomDelay));
        }
        TASK_TRIGGER_EVENT => {
            let event: IEventTrigger = com(trigger.cast(), "Query event trigger interface")?;
            value["Subscription"] = json!(get_text!(event.Subscription));
            value["Delay"] = json!(get_text!(event.Delay));
            value["ValueQueries"] = named_values(&com(
                unsafe { event.ValueQueries() },
                "Read event trigger value queries",
            )?)?;
        }
        TASK_TRIGGER_BOOT => {
            let boot: IBootTrigger = com(trigger.cast(), "Query startup trigger interface")?;
            value["Delay"] = json!(get_text!(boot.Delay));
        }
        TASK_TRIGGER_LOGON => {
            let logon: ILogonTrigger = com(trigger.cast(), "Query logon trigger interface")?;
            value["Delay"] = json!(get_text!(logon.Delay));
            value["UserId"] = json!(get_text!(logon.UserId));
        }
        TASK_TRIGGER_REGISTRATION => {
            let registration: IRegistrationTrigger =
                com(trigger.cast(), "Query registration trigger interface")?;
            value["Delay"] = json!(get_text!(registration.Delay));
        }
        TASK_TRIGGER_SESSION_STATE_CHANGE => {
            let session: ISessionStateChangeTrigger =
                com(trigger.cast(), "Query session state trigger interface")?;
            value["Delay"] = json!(get_text!(session.Delay));
            value["UserId"] = json!(get_text!(session.UserId));
            value["StateChange"] = json!(get!(session.StateChange).0);
        }
        TASK_TRIGGER_IDLE => {}
        _ => {
            value["TypeSpecificDetails"] = json!("See Xml for the native trigger definition");
        }
    }
    Ok(value)
}

fn triggers(definition: &ITaskDefinition) -> Result<Value> {
    let collection = com(unsafe { definition.Triggers() }, "Read task triggers")?;
    let count = checked_count(get!(collection.Count), MAX_ITEMS, "Task trigger")?;
    let mut result = Vec::new();
    let mut bytes = 0;
    for index in 1..=count {
        let trigger = com(
            unsafe { collection.get_Item(index as i32) },
            format!("Read task trigger {index}"),
        )?;
        bounded_push(
            &mut result,
            trigger_details(&trigger).with_context(|| format!("Serialize task trigger {index}"))?,
            &mut bytes,
        )?;
    }
    Ok(Value::Array(result))
}

struct OwnedArray(*mut SAFEARRAY);

impl Drop for OwnedArray {
    fn drop(&mut self) {
        if !self.0.is_null() {
            if let Err(error) = unsafe { SafeArrayDestroy(self.0) } {
                tracing::error!(
                    hresult = error.code().0,
                    %error,
                    "Task attachment SAFEARRAY cleanup failed"
                );
            }
        }
    }
}

fn attachments(email: &IEmailAction) -> Result<Vec<String>> {
    let mut array = OwnedArray(std::ptr::null_mut());
    com(
        unsafe { email.Attachments(&mut array.0) },
        "Read email task attachments",
    )?;
    if array.0.is_null() {
        return Ok(Vec::new());
    }
    if unsafe { SafeArrayGetDim(array.0) } != 1
        || com(
            unsafe { SafeArrayGetVartype(array.0) },
            "Read task attachment array type",
        )? != VT_BSTR
    {
        bail!("Task attachments must be a one-dimensional BSTR SAFEARRAY");
    }
    let lower = com(
        unsafe { SafeArrayGetLBound(array.0, 1) },
        "Read task attachment lower bound",
    )?;
    let upper = com(
        unsafe { SafeArrayGetUBound(array.0, 1) },
        "Read task attachment upper bound",
    )?;
    let count = i64::from(upper) - i64::from(lower) + 1;
    if !(0..=MAX_ITEMS as i64).contains(&count) {
        bail!("Task attachment array count {count} is outside 0..={MAX_ITEMS}");
    }
    let mut result = Vec::new();
    for offset in 0..count {
        let index = (i64::from(lower) + offset) as i32;
        let mut value = BSTR::default();
        com(
            unsafe { SafeArrayGetElement(array.0, &index, (&mut value as *mut BSTR).cast()) },
            format!("Read task attachment {index}"),
        )?;
        result.push(decode(value, "Task attachment path", MAX_TEXT_UNITS)?);
    }
    Ok(result)
}

fn action_details(action: &IAction) -> Result<Value> {
    let kind = get!(action.Type);
    let mut value = json!({"Id": get_text!(action.Id), "TypeCode": kind.0});
    match kind {
        TASK_ACTION_EXEC => {
            let exec: IExecAction = com(action.cast(), "Query executable action interface")?;
            value["Type"] = json!("Execute");
            value["Execute"] = json!(get_text!(exec.Path));
            value["Arguments"] = json!(get_text!(exec.Arguments));
            value["WorkingDirectory"] = json!(get_text!(exec.WorkingDirectory));
        }
        TASK_ACTION_COM_HANDLER => {
            let handler: IComHandlerAction = com(action.cast(), "Query COM action interface")?;
            value["Type"] = json!("ComHandler");
            value["ClassId"] = json!(get_text!(handler.ClassId));
            value["Data"] = json!(get_text!(handler.Data));
        }
        TASK_ACTION_SEND_EMAIL => {
            let email: IEmailAction = com(action.cast(), "Query email action interface")?;
            value["Type"] = json!("Email");
            value["Server"] = json!(get_text!(email.Server));
            value["Subject"] = json!(get_text!(email.Subject));
            value["To"] = json!(get_text!(email.To));
            value["Cc"] = json!(get_text!(email.Cc));
            value["Bcc"] = json!(get_text!(email.Bcc));
            value["ReplyTo"] = json!(get_text!(email.ReplyTo));
            value["From"] = json!(get_text!(email.From));
            value["Body"] = json!(get_text!(email.Body));
            value["Attachments"] = json!(attachments(&email)?);
            value["HeaderFields"] = named_values(&com(
                unsafe { email.HeaderFields() },
                "Read email task header fields",
            )?)?;
        }
        TASK_ACTION_SHOW_MESSAGE => {
            let message: IShowMessageAction = com(action.cast(), "Query message action interface")?;
            value["Type"] = json!("ShowMessage");
            value["Title"] = json!(get_text!(message.Title));
            value["MessageBody"] = json!(get_text!(message.MessageBody));
        }
        _ => {
            value["Type"] = json!(format!("Unknown({})", kind.0));
            value["TypeSpecificDetails"] = json!("See Xml for the native action definition");
        }
    }
    Ok(value)
}

fn actions(definition: &ITaskDefinition) -> Result<Value> {
    let collection = com(unsafe { definition.Actions() }, "Read task actions")?;
    let count = checked_count(get!(collection.Count), MAX_ITEMS, "Task action")?;
    let mut result = Vec::new();
    let mut bytes = 0;
    for index in 1..=count {
        let action = com(
            unsafe { collection.get_Item(index as i32) },
            format!("Read task action {index}"),
        )?;
        bounded_push(
            &mut result,
            action_details(&action).with_context(|| format!("Serialize task action {index}"))?,
            &mut bytes,
        )?;
    }
    Ok(Value::Array(result))
}

pub fn detail(name: &str, path: Option<&str>) -> Result<String> {
    let path = target(name, path)?;
    with_service(|service| {
        let folder = open_folder(service, &path)?;
        let task = open_task(&folder, name)?;
        let row = task_row(&task)?;
        let definition = com(
            unsafe { task.Definition() },
            "Read registered task definition",
        )?;
        let registration = com(
            unsafe { definition.RegistrationInfo() },
            "Read task registration information",
        )?;
        Ok(json!({
            "Name": row.task_name,
            "Path": row.task_path,
            "State": row.state,
            "Description": get_text!(registration.Description),
            "Author": get_text!(registration.Author),
            "Triggers": triggers(&definition)?,
            "Actions": actions(&definition)?,
            "LastRun": row.last_run,
            "LastResult": com(unsafe { task.LastTaskResult() }, "Read last task result")? as u32,
            "NextRun": row.next_run,
            "TimeBasis": "Local",
            "Xml": decode(
                com(unsafe { task.Xml() }, "Read registered task XML")?,
                "Registered task XML",
                MAX_XML_UNITS,
            )?,
        }))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TriggerKind {
    Once,
    Daily,
    Weekly,
    AtStartup,
    AtLogon,
}

impl TriggerKind {
    fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "daily" => Self::Daily,
            "weekly" => Self::Weekly,
            "atstartup" => Self::AtStartup,
            "atlogon" => Self::AtLogon,
            // The existing tool treats an unmatched trigger name as Once.
            _ => Self::Once,
        }
    }

    fn native(self) -> TASK_TRIGGER_TYPE2 {
        match self {
            Self::Once => TASK_TRIGGER_TIME,
            Self::Daily => TASK_TRIGGER_DAILY,
            Self::Weekly => TASK_TRIGGER_WEEKLY,
            Self::AtStartup => TASK_TRIGGER_BOOT,
            Self::AtLogon => TASK_TRIGGER_LOGON,
        }
    }

    fn boundary(self, at: Option<&str>, today: (u16, u16, u16)) -> Result<Option<String>> {
        match self {
            Self::Once | Self::Daily | Self::Weekly => start_boundary(at, today).map(Some),
            Self::AtStartup | Self::AtLogon => Ok(None),
        }
    }
}

fn valid_date(year: u16, month: u16, day: u16) -> bool {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    (1..=9999).contains(&year) && (1..=days).contains(&day)
}

fn digits(value: &[u8]) -> Result<u16> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        bail!("Task time must contain decimal digits in its date and time fields");
    }
    Ok(value
        .iter()
        .fold(0u16, |n, digit| n * 10 + u16::from(digit - b'0')))
}

fn start_boundary(at: Option<&str>, today: (u16, u16, u16)) -> Result<String> {
    let at = at.unwrap_or("09:00").trim();
    if !at.is_ascii() || at.len() > 64 {
        bail!("Task time must be HH:MM or an ISO datetime of at most 64 ASCII characters");
    }
    let bytes = at.as_bytes();
    if bytes.len() == 5 && bytes[2] == b':' {
        let hour = digits(&bytes[..2])?;
        let minute = digits(&bytes[3..])?;
        if hour > 23 || minute > 59 || !valid_date(today.0, today.1, today.2) {
            bail!("Task time is not a valid local HH:MM or the local date is invalid");
        }
        return Ok(format!(
            "{:04}-{:02}-{:02}T{hour:02}:{minute:02}:00",
            today.0, today.1, today.2
        ));
    }
    if bytes.len() < 16
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
    {
        bail!("Task time must be HH:MM or YYYY-MM-DDTHH:MM[:SS[.fraction]][Z|+/-HH:MM]");
    }
    let year = digits(&bytes[..4])?;
    let month = digits(&bytes[5..7])?;
    let day = digits(&bytes[8..10])?;
    let hour = digits(&bytes[11..13])?;
    let minute = digits(&bytes[14..16])?;
    let mut second = 0;
    let mut cursor = 16;
    let has_seconds = bytes.get(cursor) == Some(&b':');
    if has_seconds {
        if bytes.len() < 19 {
            bail!("ISO task time requires two digits for seconds");
        }
        second = digits(&bytes[17..19])?;
        cursor = 19;
    }
    if !valid_date(year, month, day) || hour > 23 || minute > 59 || second > 59 {
        bail!("Task time contains an invalid Gregorian date or clock time");
    }
    let fraction_start = cursor;
    if bytes.get(cursor) == Some(&b'.') {
        if !has_seconds {
            bail!("Fractional task times must include seconds");
        }
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            bail!("Task time has an empty fractional second");
        }
    }
    let fraction = &at[fraction_start..cursor];
    let zone = &at[cursor..];
    let zone = if zone.eq_ignore_ascii_case("z") {
        "Z"
    } else if zone.is_empty() {
        ""
    } else {
        let bytes = zone.as_bytes();
        if bytes.len() != 6 || !matches!(bytes[0], b'+' | b'-') || bytes[3] != b':' {
            bail!("Task timezone must be Z or a signed HH:MM offset");
        }
        let hour = digits(&bytes[1..3])?;
        let minute = digits(&bytes[4..6])?;
        if hour > 14 || minute > 59 || (hour == 14 && minute != 0) {
            bail!("Task timezone offset must be within -14:00..=+14:00");
        }
        zone
    };
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}{zone}"
    ))
}

fn validate_text(value: &str, kind: &str, required: bool) -> Result<()> {
    if (required && value.trim().is_empty())
        || value.contains('\0')
        || value.encode_utf16().count() > MAX_TEXT_UNITS
    {
        bail!("{kind} is empty, contains NUL, or exceeds {MAX_TEXT_UNITS} UTF-16 code units");
    }
    Ok(())
}

fn current_user(service: &ITaskService) -> Result<String> {
    let user = decode(
        com(
            unsafe { service.ConnectedUser() },
            "Read scheduler connection user",
        )?,
        "Scheduler connection user",
        MAX_TEXT_UNITS,
    )?;
    let domain = decode(
        com(
            unsafe { service.ConnectedDomain() },
            "Read scheduler connection domain",
        )?,
        "Scheduler connection domain",
        MAX_TEXT_UNITS,
    )?;
    if user.is_empty() {
        bail!("Task Scheduler did not identify the current connection user");
    }
    if domain.is_empty() || user.contains('\\') || user.contains('@') {
        Ok(user)
    } else {
        Ok(format!("{domain}\\{user}"))
    }
}

pub fn create(input: &crate::server::TaskCreateInput) -> Result<String> {
    target(&input.name, None)?;
    validate_text(&input.execute, "Task executable", true)?;
    validate_text(&input.trigger, "Task trigger", false)?;
    let arguments = input.argument.as_deref().unwrap_or("");
    let description = input.description.as_deref().unwrap_or("");
    validate_text(arguments, "Task arguments", false)?;
    validate_text(description, "Task description", false)?;
    let kind = TriggerKind::parse(&input.trigger);
    let today = unsafe { GetLocalTime() };
    let boundary = kind.boundary(input.at.as_deref(), (today.wYear, today.wMonth, today.wDay))?;

    with_service(|service| {
        let folder = open_folder(service, "\\")?;
        let definition = com(unsafe { service.NewTask(0) }, "Create task definition")?;
        let registration = com(
            unsafe { definition.RegistrationInfo() },
            "Read new task registration information",
        )?;
        com(
            unsafe { registration.SetDescription(&BSTR::from(description)) },
            "Set task description",
        )?;
        let user = current_user(service)?;
        let principal = com(unsafe { definition.Principal() }, "Read new task principal")?;
        com(
            unsafe { principal.SetUserId(&BSTR::from(user.as_str())) },
            "Set task principal to the current user",
        )?;
        com(
            unsafe { principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN) },
            "Set interactive-token task logon",
        )?;

        let collection = com(unsafe { definition.Triggers() }, "Read new task triggers")?;
        let trigger = com(
            unsafe { collection.Create(kind.native()) },
            "Create task trigger",
        )?;
        com(
            unsafe { trigger.SetEnabled(true.into()) },
            "Enable new task trigger",
        )?;
        if let Some(boundary) = &boundary {
            com(
                unsafe { trigger.SetStartBoundary(&BSTR::from(boundary.as_str())) },
                "Set task trigger start boundary",
            )?;
        }
        match kind {
            TriggerKind::Daily => {
                let daily: IDailyTrigger = com(trigger.cast(), "Query new daily trigger")?;
                com(unsafe { daily.SetDaysInterval(1) }, "Set daily interval")?;
            }
            TriggerKind::Weekly => {
                let weekly: IWeeklyTrigger = com(trigger.cast(), "Query new weekly trigger")?;
                com(
                    unsafe { weekly.SetDaysOfWeek(TASK_MONDAY as i16) },
                    "Set weekly trigger to Monday",
                )?;
                com(unsafe { weekly.SetWeeksInterval(1) }, "Set weekly interval")?;
            }
            _ => {}
        }
        let actions = com(unsafe { definition.Actions() }, "Read new task actions")?;
        let action = com(
            unsafe { actions.Create(TASK_ACTION_EXEC) },
            "Create executable task action",
        )?;
        let exec: IExecAction = com(action.cast(), "Query new executable action")?;
        com(
            unsafe { exec.SetPath(&BSTR::from(input.execute.as_str())) },
            "Set task executable",
        )?;
        com(
            unsafe { exec.SetArguments(&BSTR::from(arguments)) },
            "Set task arguments",
        )?;
        let empty = VARIANT::default();
        let task = com(
            unsafe {
                folder.RegisterTaskDefinition(
                    &BSTR::from(input.name.as_str()),
                    &definition,
                    TASK_CREATE.0,
                    &VARIANT::from(user.as_str()),
                    &empty,
                    TASK_LOGON_INTERACTIVE_TOKEN,
                    &empty,
                )
            },
            format!("Register new root task {:?}", input.name),
        )?;
        let (name, path) =
            task_identity(&task).context("Task was registered, but reading its identity failed")?;
        let state = state_name(com(
            unsafe { task.State() },
            "Task was registered, but reading its state",
        )?)?;
        Ok(json!({"TaskName": name, "TaskPath": path, "State": state}))
    })
}

pub fn delete(name: &str, path: Option<&str>) -> Result<String> {
    let path = target(name, path)?;
    with_service(|service| {
        let folder = open_folder(service, &path)?;
        let task = open_task(&folder, name)?;
        let (actual_name, actual_path) = task_identity(&task)?;
        com(
            unsafe { folder.DeleteTask(&BSTR::from(name), 0) },
            format!("Delete exact task {name:?} from folder {path:?}"),
        )?;
        Ok(json!({"Deleted": actual_name, "Status": "Removed", "Path": actual_path}))
    })
}

pub fn run(name: &str, path: Option<&str>) -> Result<String> {
    let path = target(name, path)?;
    with_service(|service| {
        let folder = open_folder(service, &path)?;
        let task = open_task(&folder, name)?;
        let (actual_name, actual_path) = task_identity(&task)?;
        let _instance = com(
            unsafe { task.Run(&VARIANT::default()) },
            format!("Submit run request for task {name:?} in {path:?}"),
        )?;
        let task = open_task(&folder, name)
            .context("Run request was accepted, but reopening the task for readback failed")?;
        let state = state_name(com(
            unsafe { task.State() },
            "Run request was accepted, but reading current task state",
        )?)?;
        Ok(json!({
            "Started": actual_name,
            "Status": state,
            "Path": actual_path,
            "Accepted": true,
            "ApplicationSuccess": null,
            "Completion": "NotObserved",
        }))
    })
}

pub fn toggle(name: &str, path: Option<&str>) -> Result<String> {
    let path = target(name, path)?;
    with_service(|service| {
        let folder = open_folder(service, &path)?;
        let task = open_task(&folder, name)?;
        let (actual_name, actual_path) = task_identity(&task)?;
        let enabled = com(unsafe { task.Enabled() }, "Read task enabled state")?.as_bool();
        com(
            unsafe { task.SetEnabled((!enabled).into()) },
            format!("Toggle exact task {name:?} in folder {path:?}"),
        )?;
        let task = open_task(&folder, name)
            .context("Task enabled state was changed, but reopening it for readback failed")?;
        let actual = com(
            unsafe { task.Enabled() },
            "Task enabled state was changed, but reading it back",
        )?
        .as_bool();
        if actual == enabled {
            bail!("Task enabled-state readback did not match the requested change");
        }
        Ok(json!({
            "Task": actual_name,
            "NewState": if actual { "Enabled" } else { "Disabled" },
            "Path": actual_path,
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_target_one_exact_task_in_root_or_explicit_folder() {
        assert_eq!(target("Backup", None).unwrap(), "\\");
        assert_eq!(target("Backup", Some("\\")).unwrap(), "\\");
        assert_eq!(
            target("Backup", Some("\\Team\\Nightly\\")).unwrap(),
            "\\Team\\Nightly"
        );
        assert_eq!(
            target("Backup", Some("\\Team\\Nightly")).unwrap(),
            "\\Team\\Nightly"
        );
        assert!(target("O'Brien [nightly]", Some("\\Personal")).is_ok());
        assert!(target("\u{65e5}\u{672c}\u{8a9e}", Some("\\\u{500b}\u{4eba}")).is_ok());
    }

    #[test]
    fn unsafe_or_ambiguous_task_paths_are_rejected() {
        for name in [
            "", " ", ".", "..", "*", "a?", "\\Task", "A\\B", "A/B", "Task.", " Task", "Task ",
            "N\0ul",
        ] {
            assert!(target(name, None).is_err(), "accepted task name {name:?}");
        }
        for path in [
            "",
            "Team",
            "\\\\server\\Task",
            "\\Team\\\\Child",
            "\\Team\\\\",
            "\\..\\Team",
            "\\Team\\.\\Child",
            "\\*",
            "\\Te?m",
            "\\Team/Child",
        ] {
            assert!(
                target("Task", Some(path)).is_err(),
                "accepted folder path {path:?}"
            );
        }
        assert!(target(&"a".repeat(256), None).is_err());
        assert!(target(&"x".repeat(250), Some("\\LongFolder")).is_err());
    }

    #[test]
    fn microsoft_prefix_exclusion_matches_the_existing_filter() {
        for path in [
            "\\Microsoft",
            "\\Microsoft\\Windows",
            "\\MICROSOFT\\One",
            "\\MicrosoftExtras",
        ] {
            assert!(excluded_folder(path), "not excluded: {path}");
        }
        for path in [
            "\\",
            "\\Personal",
            "\\Personal\\Microsoft",
            "\\Micro",
            "\\\u{65e5}\u{672c}\u{8a9e}",
        ] {
            assert!(!excluded_folder(path), "unexpectedly excluded: {path}");
        }
    }

    #[test]
    fn time_defaults_use_today_without_rolling_a_past_time_forward() {
        let today = (2026, 9, 5);
        assert_eq!(start_boundary(None, today).unwrap(), "2026-09-05T09:00:00");
        assert_eq!(
            start_boundary(Some("00:01"), today).unwrap(),
            "2026-09-05T00:01:00"
        );
        assert_eq!(
            start_boundary(Some("23:59"), today).unwrap(),
            "2026-09-05T23:59:00"
        );
    }

    #[test]
    fn iso_times_preserve_explicit_dates_and_timezone_offsets() {
        for (input, expected) in [
            ("2024-02-29T09:15", "2024-02-29T09:15:00"),
            ("2024-02-29t09:15:30z", "2024-02-29T09:15:30Z"),
            (
                "2026-12-31T23:59:59.125-06:00",
                "2026-12-31T23:59:59.125-06:00",
            ),
            ("2026-12-31T09:00+14:00", "2026-12-31T09:00:00+14:00"),
            ("2000-02-29T00:00:00", "2000-02-29T00:00:00"),
        ] {
            assert_eq!(start_boundary(Some(input), (2026, 9, 5)).unwrap(), expected);
        }
    }

    #[test]
    fn invalid_calendar_times_are_not_normalized_or_defaulted() {
        for at in [
            "",
            "9:00",
            "24:00",
            "09:60",
            "09:00:00",
            "tomorrow",
            "\u{ff19}:00",
            "2023-02-29T09:00",
            "1900-02-29T09:00",
            "2026-04-31T09:00",
            "0000-01-01T09:00",
            "2026-13-01T09:00",
            "2026-09-00T09:00",
            "2026-01-01 09:00",
            "2026-01-01T24:00",
            "2026-01-01T09:60",
            "2026-01-01T09:00:60",
            "2026-01-01T09:00:1",
            "2026-01-01T09:00:00.",
            "2026-01-01T09:00.5",
            "2026-01-01T09:00+14:01",
            "2026-01-01T09:00+15:00",
            "2026-01-01T09:00+06:60",
            "2026-01-01T09:00Zsuffix",
            "2026-01-01T09:00\0",
        ] {
            assert!(
                start_boundary(Some(at), (2026, 9, 5)).is_err(),
                "accepted time {at:?}"
            );
        }
    }

    #[test]
    fn creation_preserves_trigger_kinds_and_legacy_once_fallback() {
        for (input, expected) in [
            ("Once", TriggerKind::Once),
            ("DAILY", TriggerKind::Daily),
            ("Weekly", TriggerKind::Weekly),
            ("AtStartup", TriggerKind::AtStartup),
            ("atlogon", TriggerKind::AtLogon),
            ("", TriggerKind::Once),
            ("legacy-default", TriggerKind::Once),
        ] {
            assert_eq!(TriggerKind::parse(input), expected);
        }
        assert_eq!(TriggerKind::Weekly.native(), TASK_TRIGGER_WEEKLY);
        assert_eq!(weekdays(TASK_MONDAY as i16).unwrap(), ["Monday"]);
        for kind in [TriggerKind::Once, TriggerKind::Daily, TriggerKind::Weekly] {
            assert_eq!(
                kind.boundary(None, (2026, 9, 5)).unwrap(),
                Some("2026-09-05T09:00:00".to_owned())
            );
            assert!(kind.boundary(Some("bad time"), (2026, 9, 5)).is_err());
        }
        for kind in [TriggerKind::AtStartup, TriggerKind::AtLogon] {
            assert_eq!(kind.boundary(Some("ignored"), (2026, 9, 5)).unwrap(), None);
        }
    }

    #[test]
    fn automation_dates_use_ole_epoch_negative_fraction_rules_and_null_sentinel() {
        assert_eq!(date_string(0.0).unwrap(), None);
        assert_eq!(
            date_string(25569.0).unwrap().as_deref(),
            Some("1970-01-01T00:00:00")
        );
        assert_eq!(
            date_string(2.5).unwrap().as_deref(),
            Some("1900-01-01T12:00:00")
        );
        assert_eq!(
            date_string(-1.25).unwrap().as_deref(),
            Some("1899-12-29T06:00:00")
        );
        assert!(date_string(f64::NAN).is_err());
        assert!(date_string(f64::INFINITY).is_err());
        assert!(date_string(4_000_000.0).is_err());
    }

    #[test]
    fn enumeration_limits_and_invalid_states_are_errors() {
        assert_eq!(checked_count(0, 10, "test").unwrap(), 0);
        assert_eq!(checked_count(10, 10, "test").unwrap(), 10);
        assert!(checked_count(-1, 10, "test").is_err());
        assert!(checked_count(11, 10, "test").is_err());
        assert_eq!(state_name(TASK_STATE_UNKNOWN).unwrap(), "Unknown");
        assert_eq!(state_name(TASK_STATE_READY).unwrap(), "Ready");
        assert!(state_name(TASK_STATE(99)).is_err());
        assert!(weekdays(128).is_err());
    }

    #[test]
    fn com_failures_retain_operation_and_hresult() {
        let error = com::<()>(
            Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                0x80070005u32 as i32,
            ))),
            "Read exact task",
        )
        .context("Serialize task trigger 2")
        .map_err(exposed_error)
        .unwrap_err()
        .to_string();
        assert!(error.contains("Serialize task trigger 2"));
        assert!(error.contains("Read exact task"));
        assert!(error.contains("0x80070005"));
    }

    #[test]
    #[ignore = "Read-only: requires a running local Task Scheduler service and permission to enumerate non-Microsoft folders"]
    fn read_only_scheduler_list_smoke() {
        let result = list().expect("Task Scheduler enumeration capability is unavailable");
        let rows: Value = serde_json::from_str(&result).unwrap();
        let rows = rows.as_array().expect("Task list must be a JSON array");
        for row in rows {
            assert!(row["TaskName"].is_string());
            assert!(row["TaskPath"].is_string());
            assert!(row["State"].is_string());
            assert!(row.get("LastRun").is_some());
            assert!(row.get("NextRun").is_some());
        }
        let Some(first) = rows.first() else {
            eprintln!(
                "Task detail smoke skipped: no tasks remain after excluding \\Microsoft* folders"
            );
            return;
        };
        let name = first["TaskName"].as_str().unwrap();
        let path = first["TaskPath"].as_str().unwrap();
        let result = detail(name, Some(path)).unwrap_or_else(|error| {
            panic!("Read-only task detail failed for {path}{name}: {error:#}")
        });
        let task: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(task["Name"], name);
        assert_eq!(task["Path"], path);
        let triggers = task["Triggers"]
            .as_array()
            .expect("Task triggers must be a JSON array");
        for trigger in triggers {
            assert!(trigger.is_object());
            assert!(trigger["Type"].is_string());
            assert!(trigger["TypeCode"].is_i64());
            assert!(trigger["Enabled"].is_boolean());
            assert!(trigger["StartBoundary"].is_string());
            assert!(trigger["Repetition"].is_object());
        }
        let actions = task["Actions"]
            .as_array()
            .expect("Task actions must be a JSON array");
        for action in actions {
            assert!(action.is_object());
            assert!(action["Type"].is_string());
            assert!(action["TypeCode"].is_i64());
            if action["Type"] == "Execute" {
                assert!(action["Execute"].is_string());
                assert!(action["Arguments"].is_string());
                assert!(action["WorkingDirectory"].is_string());
            }
        }
        let xml = task["Xml"].as_str().expect("Task XML must be a string");
        assert!(xml.contains("<Task"), "Task XML has no Task root element");
        assert!(
            xml.contains("</Task>"),
            "Task XML has no closing Task element"
        );
    }
}
