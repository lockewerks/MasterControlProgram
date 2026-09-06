#![cfg(windows)]

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows::core::BOOL;
use windows::Win32::Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, WaitForSingleObject,
    PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

const RPC_TIMEOUT: Duration = Duration::from_secs(20);
const FIXTURE_HELPER: &str = "mcp_fixture_process";
const FAILURE_TEXT: &str = "Fixture startup failed: the disposable configuration file is missing.";
const STDOUT_END: &[u8] = b"\nfixture-stdout-end\n";
const STDERR_END: &[u8] = b"\nfixture-stderr-end\n";
const LEGACY_TOOLS: &[&str] = &[
    "system_info",
    "cpu_info",
    "memory_info",
    "disk_info",
    "gpu_info",
    "battery_info",
    "network_adapters",
    "process_list",
    "process_detail",
    "process_kill",
    "process_start",
    "process_tree",
    "service_list",
    "service_detail",
    "service_start",
    "service_stop",
    "service_restart",
    "service_set_startup",
    "fs_list",
    "fs_search",
    "fs_info",
    "fs_permissions",
    "fs_streams",
    "fs_drives",
    "fs_share_list",
    "fs_share_create",
    "registry_read",
    "registry_write",
    "registry_delete",
    "registry_list",
    "registry_search",
    "registry_export",
    "network_connections",
    "network_config",
    "network_ping",
    "network_dns_lookup",
    "network_trace_route",
    "network_port_test",
    "network_wifi",
    "network_bandwidth",
    "firewall_rules_list",
    "firewall_rule_create",
    "firewall_rule_delete",
    "firewall_rule_toggle",
    "firewall_status",
    "eventlog_query",
    "eventlog_sources",
    "eventlog_stats",
    "eventlog_clear",
    "task_list",
    "task_detail",
    "task_create",
    "task_delete",
    "task_run",
    "task_toggle",
    "software_list",
    "software_detail",
    "software_uninstall",
    "user_list",
    "user_detail",
    "user_create",
    "user_delete",
    "user_modify",
    "group_list",
    "group_members",
    "group_add_member",
    "group_remove_member",
    "env_list",
    "env_get",
    "env_set",
    "env_delete",
    "path_list",
    "path_add",
    "path_remove",
    "powershell_execute",
    "cmd_execute",
    "wmi_query",
    "feature_list",
    "feature_enable",
    "feature_disable",
    "clipboard_get",
    "clipboard_set",
    "display_info",
    "audio_devices",
    "audio_volume",
    "perf_snapshot",
    "perf_top",
    "perf_counter",
    "screen_capture",
    "cursor_position",
    "mouse_move",
    "mouse_click",
    "mouse_scroll",
    "mouse_drag",
    "keyboard_type",
    "keyboard_key",
    "update_list",
    "update_history",
];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("mcp-integration-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create disposable fixture directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("fixture cleanup failed for {}: {error}", self.0.display());
        }
    }
}

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: mpsc::Receiver<Result<Value, String>>,
    pending: HashMap<u64, Value>,
    stderr: Arc<Mutex<VecDeque<String>>>,
    next_id: u64,
}

fn fixture_command(fixture: &Fixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_MasterControlProgram"));
    command
        .env("MCP_ALLOW_UNELEVATED", "1")
        .env("MCP_POOL_SIZE", "1")
        .env("TEMP", fixture.path())
        .env("TMP", fixture.path())
        .env("RUST_LOG", "warn")
        .current_dir(fixture.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

impl Mcp {
    fn launch(fixture: &Fixture, without_pwsh: bool) -> Self {
        let mut command = fixture_command(fixture);
        // The sentinel prevents a test from asking sudo to display UAC when
        // Inline is configured. Windows privileges remain those of this test.
        command.arg("--elevated");
        if without_pwsh {
            command.env("PATH", fixture.path());
        }
        Self::start(command)
    }

    fn start(command: Command) -> Self {
        let mut client = Self::spawn(command);
        client.initialize();
        client
    }

    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().expect("launch MCP fixture");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let stderr_pipe = child.stderr.take().expect("child stderr");
        let stderr = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let stderr_capture = Arc::clone(&stderr);
        thread::spawn(move || {
            for line in BufReader::new(stderr_pipe).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => format!("stderr read failed: {error}"),
                };
                let mut lines = stderr_capture.lock().expect("stderr lock");
                if lines.len() == 32 {
                    lines.pop_front();
                }
                lines.push_back(line.chars().take(1024).collect());
            }
        });
        let (sender, messages) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let message = match line {
                    Ok(line) => serde_json::from_str(&line)
                        .map_err(|error| format!("invalid MCP JSON: {error}")),
                    Err(error) => Err(format!("stdout read failed: {error}")),
                };
                if sender.send(message).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            messages,
            pending: HashMap::new(),
            stderr,
            next_id: 1,
        }
    }

    fn initialize(&mut self) {
        let id = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mcp-integration-fixture", "version": "1"}
            }),
        );
        let response = self.response(id, RPC_TIMEOUT);
        assert!(response.get("result").is_some(), "initialize failed");
        self.notification("notifications/initialized", json!({}));
    }

    fn connect(fixture: &Fixture, name: &str) -> Self {
        let mut command = fixture_command(fixture);
        command.args(["--connect-host", name]);
        Self::start(command)
    }

    fn wait_for_exit(&mut self) {
        assert_eq!(
            unsafe {
                WaitForSingleObject(
                    HANDLE(self.child.as_raw_handle()),
                    RPC_TIMEOUT.as_millis() as u32,
                )
            },
            WAIT_OBJECT_0,
            "MCP process {} did not exit\n{}",
            self.child.id(),
            self.diagnostics()
        );
        let status = self.child.wait().expect("reap MCP process");
        assert!(
            status.success(),
            "MCP exited with {status}\n{}",
            self.diagnostics()
        );
    }

    fn disconnect(mut self) {
        self.stdin.take();
        self.wait_for_exit();
    }
}

struct Host {
    process: Mcp,
    name: String,
    ready: Value,
}

impl Host {
    fn launch(fixture: &Fixture, name: &str) -> Self {
        let state = fixture.path().join("host-state");
        let mut command = fixture_command(fixture);
        command
            .args(["--elevated", "--local-host", name, "--host-state-dir"])
            .arg(&state)
            .env("PATH", fixture.path());
        let process = Mcp::spawn(command);
        let ready = process
            .messages
            .recv_timeout(RPC_TIMEOUT)
            .unwrap_or_else(|error| panic!("host not ready: {error}\n{}", process.diagnostics()))
            .expect("host ready JSON");
        assert_eq!(ready["host_ready"], true, "{ready}");
        assert_eq!(ready["name"], name);
        assert_eq!(ready["pid"], process.child.id());
        assert_eq!(
            number(&ready["process_creation_time"]),
            process_creation_time(HANDLE(process.child.as_raw_handle()))
        );
        assert_eq!(ready["state_directory"], json!(state));
        assert!(ready["epoch"].is_string());
        Self {
            process,
            name: name.to_owned(),
            ready,
        }
    }

    fn connect(&self, fixture: &Fixture) -> Mcp {
        Mcp::connect(fixture, &self.name)
    }

    fn shutdown(&mut self, client: &mut Mcp) {
        let result = json_text(&client.tool("host_shutdown", json!({})));
        assert_eq!(result["shutdown_requested"], true);
        assert!(client.stdin.is_some(), "bridge input must remain open");
        client.wait_for_exit();
        self.process.wait_for_exit();
        assert!(
            matches!(
                self.process.messages.recv_timeout(RPC_TIMEOUT),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            "host stdout must contain only its ready record"
        );
    }
}

struct FixtureProcess {
    handle: OwnedHandle,
    pid: u32,
    created: u64,
}

impl FixtureProcess {
    fn open(record: &Value) -> Self {
        let pid = number(&record["pid"])
            .try_into()
            .expect("fixture PID fits u32");
        let created = number(&record["process_creation_time"]);
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                false,
                pid,
            )
        }
        .expect("open only the fixture process");
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        // Do not arm termination until the returned FILETIME has been checked.
        assert_eq!(
            process_creation_time(HANDLE(handle.as_raw_handle())),
            created,
            "fixture PID was reused"
        );
        Self {
            handle,
            pid,
            created,
        }
    }

    fn raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }

    fn assert_alive(&self) {
        assert_eq!(
            unsafe { WaitForSingleObject(self.raw(), 0) },
            WAIT_TIMEOUT,
            "fixture {}:{} exited unexpectedly",
            self.pid,
            self.created
        );
    }

    fn wait_for_exit(&self) -> u32 {
        assert_eq!(
            unsafe { WaitForSingleObject(self.raw(), RPC_TIMEOUT.as_millis() as u32) },
            WAIT_OBJECT_0,
            "fixture {}:{} did not exit",
            self.pid,
            self.created
        );
        let mut exit_code = 0;
        unsafe { GetExitCodeProcess(self.raw(), &mut exit_code) }.expect("fixture exit code");
        exit_code
    }

    fn debugger_attached(&self) -> bool {
        let mut attached = BOOL::default();
        unsafe { CheckRemoteDebuggerPresent(self.raw(), &mut attached) }
            .expect("inspect debugger state through the retained fixture handle");
        attached.as_bool()
    }
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(self.raw(), 0) } == WAIT_TIMEOUT {
            if let Err(error) = unsafe { TerminateProcess(self.raw(), 99) } {
                eprintln!(
                    "fixture {}:{} cleanup failed: {error}",
                    self.pid, self.created
                );
            }
            if unsafe { WaitForSingleObject(self.raw(), 5000) } != WAIT_OBJECT_0 {
                eprintln!(
                    "fixture {}:{} did not stop during cleanup",
                    self.pid, self.created
                );
            }
        }
    }
}

fn process_creation_time(handle: HANDLE) -> u64 {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
        .expect("read exact fixture creation FILETIME");
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

fn number(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .unwrap_or_else(|| panic!("expected an exact unsigned integer, got {value}"))
}

fn fixture_job(fixture: &Fixture, mode: &str, signal: &str) -> Value {
    json!({
        "program": std::env::current_exe().expect("integration test executable"),
        "args": ["--ignored", "--exact", FIXTURE_HELPER, "--nocapture", "--test-threads=1"],
        "cwd": fixture.path(),
        "env": {
            "MCP_INTEGRATION_FIXTURE": fixture.path(),
            "MCP_INTEGRATION_MODE": mode,
            "MCP_INTEGRATION_SIGNAL": signal
        },
        "timeout_ms": 60000
    })
}

fn terminal_until(client: &mut Mcp, id: &Value, cursor: &mut u64, expected: &str) -> Value {
    let deadline = Instant::now() + RPC_TIMEOUT;
    let mut observed = Vec::new();
    loop {
        let result = json_text(&client.tool(
            "terminal_read",
            json!({"id": id, "cursor": *cursor, "max_bytes": 65536}),
        ));
        assert_eq!(result["output"]["gap_bytes"], 0, "{result}");
        assert!(result["output"]["read_error"].is_null(), "{result}");
        *cursor = number(&result["output"]["next_cursor"]);
        observed.extend(
            STANDARD
                .decode(
                    result["output"]["bytes_base64"]
                        .as_str()
                        .expect("terminal bytes"),
                )
                .expect("terminal base64"),
        );
        if String::from_utf8_lossy(&observed).contains(expected) {
            return result;
        }
        assert!(
            Instant::now() < deadline,
            "terminal never produced {expected:?}: {:?}",
            String::from_utf8_lossy(&observed)
        );
        thread::sleep(Duration::from_millis(10));
    }
}

impl Mcp {
    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().expect("MCP stdin is open");
        serde_json::to_writer(&mut *stdin, &value).expect("write JSON-RPC");
        stdin.write_all(b"\n").expect("write MCP delimiter");
        stdin.flush().expect("flush MCP request");
    }

    fn request(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        id
    }

    fn notification(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn tool_request(&mut self, name: &str, arguments: Value) -> u64 {
        self.request("tools/call", json!({"name": name, "arguments": arguments}))
    }

    fn response(&mut self, id: u64, duration: Duration) -> Value {
        if let Some(response) = self.pending.remove(&id) {
            return response;
        }
        let deadline = Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.messages.recv_timeout(remaining) {
                Ok(Ok(message)) => {
                    if let Some(message_id) = message.get("id").and_then(Value::as_u64) {
                        if message_id == id {
                            return message;
                        }
                        self.pending.insert(message_id, message);
                    }
                }
                Ok(Err(error)) => panic!("{error}\n{}", self.diagnostics()),
                Err(error) => panic!("RPC {id} did not complete: {error}\n{}", self.diagnostics()),
            }
        }
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let id = self.tool_request(name, arguments);
        tool_result(self.response(id, RPC_TIMEOUT))
    }

    fn diagnostics(&self) -> String {
        self.stderr
            .lock()
            .expect("stderr lock")
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        self.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => break,
                Err(error) => {
                    eprintln!("MCP fixture status failed: {error}");
                    break;
                }
            }
        }
        if let Err(error) = self.child.kill() {
            eprintln!("MCP fixture termination failed: {error}");
        }
        if let Err(error) = self.child.wait() {
            eprintln!("MCP fixture wait failed: {error}");
        }
    }
}

fn tool_result(response: Value) -> Value {
    assert!(
        response.get("error").is_none(),
        "protocol error: {}",
        response["error"]
    );
    response
        .get("result")
        .expect("tool response has a result")
        .clone()
}

fn assert_success(result: &Value) {
    assert_ne!(result["isError"], true, "tool failed: {}", text(result));
}

fn text(result: &Value) -> String {
    result["content"]
        .as_array()
        .expect("tool content")
        .iter()
        .filter_map(|content| content["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + RPC_TIMEOUT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "fixture signal not observed: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn ps_path(path: &Path) -> String {
    path.to_str()
        .expect("fixture path is Unicode")
        .replace('\'', "''")
}

fn json_text(result: &Value) -> Value {
    assert_success(result);
    serde_json::from_str(&text(result)).expect("structured tool text")
}

fn deadline_ms(duration: Duration) -> u64 {
    (SystemTime::now() + duration)
        .duration_since(UNIX_EPOCH)
        .expect("current time follows epoch")
        .as_millis()
        .try_into()
        .expect("timestamp fits u64")
}

#[test]
fn native_startup_and_legacy_tools_do_not_require_powershell() {
    let fixture = Fixture::new();
    let mut client = Mcp::launch(&fixture, true);
    let id = client.request("tools/list", json!({}));
    let response = client.response(id, RPC_TIMEOUT);
    let tools = response["result"]["tools"].as_array().expect("tool list");
    let names: HashSet<_> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for name in LEGACY_TOOLS {
        assert!(
            names.contains(name),
            "legacy tool {name} is no longer registered"
        );
    }
    let audio = tools
        .iter()
        .find(|tool| tool["name"] == "audio_volume")
        .expect("audio_volume");
    assert!(
        audio["inputSchema"]["required"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "audio_volume must retain its no-argument call"
    );
    assert_success(&client.tool("system_info", json!({})));
    assert_success(&client.tool("process_list", json!({"limit": "1", "sort_by": "pid"})));
    let unavailable = client.tool("powershell_execute", json!({"command": "'not available'"}));
    assert_eq!(
        unavailable["isError"], true,
        "missing pwsh must be a tool error"
    );
    assert_success(&client.tool("memory_info", json!({})));
}

#[test]
fn registration_conflict_exits_before_server_initialization() {
    let fixture = Fixture::new();
    let not_a_directory = fixture.path().join("not-a-directory");
    std::fs::write(&not_a_directory, b"fixture").expect("create log-path guard");
    let output = Command::new(env!("CARGO_BIN_EXE_MasterControlProgram"))
        .args(["--register", "--unregister", "--elevated"])
        .env("PATH", fixture.path())
        .env("MCP_POOL_SIZE", "0")
        .env("TEMP", &not_a_directory)
        .env("TMP", &not_a_directory)
        .stdin(Stdio::null())
        .output()
        .expect("run conflicting CLI flags");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("register and unregister"), "{stderr}");
    assert!(output.stdout.is_empty(), "CLI failure must not start MCP");
}

#[test]
#[ignore = "requires PowerShell 7; exercises disposable processes through real MCP"]
fn powershell_multiline_failures_recover() {
    let fixture = Fixture::new();
    let mut client = Mcp::launch(&fixture, false);
    let multiline = client.tool(
        "powershell_execute",
        json!({"command": "$values = @(\n  'first'\n  'second'\n)\n$values", "timeout_ms": "15000"}),
    );
    assert_success(&multiline);
    let payload: Value = serde_json::from_str(&text(&multiline)).expect("PowerShell JSON wrapper");
    assert_eq!(payload["s"], true);
    assert_eq!(payload["d"], json!(["first", "second"]));

    for command in ["Write-Error 'fixture error'", "cmd /c exit 7"] {
        let result = client.tool("powershell_execute", json!({"command": command}));
        assert_eq!(
            result["isError"], true,
            "failed command was reported as success"
        );
    }

    assert_success(&client.tool("powershell_execute", json!({"command": "'after errors'"})));
}

#[test]
fn filesystem_watch_waits_and_cursor_gaps_are_observed_over_mcp() {
    let fixture = Fixture::new();
    let watched = fixture.path().join("watched");
    std::fs::create_dir(&watched).expect("watch fixture");
    let mut client = Mcp::launch(&fixture, true);
    let watch = json_text(&client.tool(
        "watch_create",
        json!({
            "source": {"kind": "filesystem", "path": watched, "recursive": false},
            "lifetime": "connection",
            "max_duration_ms": "30000",
            "max_events": "2",
            "max_bytes": 8192
        }),
    ));
    let watch_id = watch["id"].as_str().expect("watch ID").to_owned();
    let start_cursor = watch["start_cursor"].clone();
    assert!(
        !start_cursor.is_null(),
        "watch has a recording start cursor"
    );
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = json_text(&client.tool(
            "events_read",
            json!({"filter": {"watch_id": watch_id}, "limit": 2}),
        ));
        let record = state["watches"]
            .as_array()
            .expect("watch status records")
            .iter()
            .find(|record| record["id"] == watch_id)
            .expect("created watch status");
        assert_ne!(record["status"], "failed", "{}", record["error"]);
        if record["status"] == "recording" {
            break;
        }
        assert!(
            Instant::now() < ready_deadline,
            "watch did not start recording"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let waiting = client.tool_request(
        "wait_for",
        json!({
            "after": start_cursor,
            "filter": {"watch_id": watch_id},
            "lifetime": "connection",
            "deadline_unix_ms": deadline_ms(Duration::from_secs(10)).to_string()
        }),
    );
    let native = client.tool_request("memory_info", json!({}));
    assert_success(&tool_result(
        client.response(native, Duration::from_secs(3)),
    ));
    std::fs::write(watched.join("first"), b"first").expect("trigger filesystem notification");
    let outcome = json_text(&tool_result(client.response(waiting, RPC_TIMEOUT)));
    assert_eq!(outcome["outcome"], "satisfied");
    assert_eq!(outcome["event"]["watch_id"], watch_id);

    for index in 0..16 {
        std::fs::write(watched.join(format!("entry-{index}")), b"event")
            .expect("trigger retained event overflow");
    }
    let loss_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let history = json_text(&client.tool(
            "events_read",
            json!({
                "after": start_cursor,
                "filter": {"watch_id": watch_id},
                "limit": "20"
            }),
        ));
        let events = history["events"].as_array().expect("retained events");
        assert!(events.len() <= 2, "watch retention limit must be enforced");
        if history["retention_gap"] == true {
            assert!(!events.is_empty());
            for event in events {
                assert_eq!(event["watch_id"], watch_id);
                assert_eq!(event["cursor"]["epoch"], start_cursor["epoch"]);
                assert!(event["cursor"]["id"].as_u64().is_some());
            }
            break;
        }
        assert!(
            Instant::now() < loss_deadline,
            "retention loss was not reported"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert_success(&client.tool("watch_remove", json!({"id": watch_id})));
    let idle = fixture.path().join("idle");
    std::fs::create_dir(&idle).expect("idle watch fixture");
    let idle_watch = json_text(&client.tool(
        "watch_create",
        json!({
            "source": {"kind": "filesystem", "path": idle, "recursive": false},
            "lifetime": "connection",
            "max_duration_ms": 30000
        }),
    ));
    let watch_id = idle_watch["id"].as_str().expect("idle watch ID");
    let current_cursor = idle_watch["start_cursor"].clone();
    let background = json_text(&client.tool(
        "wait_for",
        json!({
            "after": current_cursor,
            "filter": {"watch_id": watch_id, "kind": "fixture_never_emitted"},
            "lifetime": "connection",
            "background": true,
            "deadline_unix_ms": deadline_ms(Duration::from_secs(10))
        }),
    ));
    let cancellation = json_text(&client.tool("wait_cancel", json!({"id": background["id"]})));
    assert_eq!(cancellation["outcome"], "canceled");
    let timed_out = json_text(&client.tool(
        "wait_for",
        json!({
            "after": current_cursor,
            "filter": {"watch_id": watch_id, "kind": "fixture_never_emitted"},
            "lifetime": "connection",
            "deadline_unix_ms": deadline_ms(Duration::from_millis(100))
        }),
    ));
    assert_eq!(timed_out["outcome"], "timed_out");
    let removed = client.tool("watch_remove", json!({"id": watch_id}));
    assert_success(&removed);
}

#[test]
#[ignore = "requires PowerShell 7; exercises disposable processes through real MCP"]
fn powershell_cancellation_and_responsiveness() {
    let fixture = Fixture::new();
    let mut client = Mcp::launch(&fixture, false);
    assert_success(&client.tool("powershell_execute", json!({"command": "'after errors'"})));

    let started = fixture.path().join("started");
    let release = fixture.path().join("release");
    let command = format!(
        "Set-Content -LiteralPath '{}' -Value 'started'\n\
         while (-not (Test-Path -LiteralPath '{}')) {{ Start-Sleep -Milliseconds 20 }}\n\
         'released'",
        ps_path(&started),
        ps_path(&release),
    );
    let blocked = client.tool_request(
        "powershell_execute",
        json!({"command": command, "timeout_ms": 15000}),
    );
    wait_for_file(&started);
    let native = client.tool_request("system_info", json!({}));
    assert_success(&tool_result(
        client.response(native, Duration::from_secs(3)),
    ));
    std::fs::write(&release, b"release").expect("release only the fixture operation");
    assert_success(&tool_result(client.response(blocked, RPC_TIMEOUT)));

    let mutations = fixture.path().join("mutations");
    let never_release = fixture.path().join("never-release");
    let command = format!(
        "Add-Content -LiteralPath '{}' -Value 'once'\n\
         while (-not (Test-Path -LiteralPath '{}')) {{ Start-Sleep -Milliseconds 20 }}\n\
         'must not leak into a later response'",
        ps_path(&mutations),
        ps_path(&never_release),
    );
    let canceled = client.tool_request(
        "powershell_execute",
        json!({"command": command, "timeout_ms": 15000}),
    );
    wait_for_file(&mutations);
    client.notification(
        "notifications/cancelled",
        json!({"requestId": canceled, "reason": "cancel disposable fixture"}),
    );
    let after = client.tool(
        "powershell_execute",
        json!({"command": "'after cancellation'"}),
    );
    assert_success(&after);
    let payload: Value = serde_json::from_str(&text(&after)).expect("resynchronized wrapper");
    assert_eq!(payload["d"], "after cancellation");
    assert_eq!(
        std::fs::read_to_string(&mutations)
            .expect("mutation count")
            .lines()
            .count(),
        1,
        "a canceled mutating command must never be replayed"
    );
}

#[test]
fn filesystem_revisions_encodings_and_failed_preconditions_over_mcp() {
    let fixture = Fixture::new();
    let path = fixture.path().join("document.txt");
    let mut client = Mcp::launch(&fixture, true);
    let created = json_text(&client.tool(
        "fs_write",
        json!({
            "path": path,
            "data": "one one",
            "encoding": "utf8",
            "consistency": "create_new",
            "bom": "remove"
        }),
    ));
    assert_eq!(created["outcome"], "completed");
    let initial = json_text(&client.tool(
        "fs_read",
        json!({"path": path, "encoding": "utf8", "max_bytes": "1024"}),
    ));
    assert_eq!(initial["data"], "one one");
    assert_eq!(initial["bom"], false);
    assert!(initial["revision"].as_str().is_some());
    let patched = json_text(&client.tool(
        "fs_patch",
        json!({
            "path": path,
            "encoding": "utf8",
            "expected_revision": initial["revision"],
            "find": "one",
            "replacement": "two",
            "expected_matches": "2",
            "timeout_ms": "5000"
        }),
    ));
    assert_eq!(patched["outcome"], "completed");
    assert_eq!(patched["consistency"], "conditional_in_place");
    assert_eq!(patched["identity"], initial["identity"]);
    assert_ne!(patched["revision"], initial["revision"]);
    assert_eq!(std::fs::read(&path).expect("read fixture"), b"two two");

    let stale = client.tool(
        "fs_patch",
        json!({
            "path": path,
            "encoding": "utf8",
            "expected_revision": initial["revision"],
            "find": "two",
            "replacement": "wrong",
            "expected_matches": 2
        }),
    );
    assert_eq!(stale["isError"], true, "a stale revision must fail");
    let wrong_count = client.tool(
        "fs_patch",
        json!({
            "path": path,
            "encoding": "utf8",
            "expected_revision": patched["revision"],
            "find": "two",
            "replacement": "wrong",
            "expected_matches": 1
        }),
    );
    assert_eq!(wrong_count["isError"], true, "an ambiguous patch must fail");
    let existing = client.tool(
        "fs_write",
        json!({
            "path": path,
            "data": "wrong",
            "encoding": "utf8",
            "consistency": "create_new"
        }),
    );
    assert_eq!(
        existing["isError"], true,
        "create_new must not replace a file"
    );
    assert_eq!(
        std::fs::read(&path).expect("fixture after failed preconditions"),
        b"two two"
    );

    let binary_path = fixture.path().join("binary.dat");
    assert_success(&client.tool(
        "fs_write",
        json!({
            "path": binary_path,
            "data": "AAECA/8=",
            "encoding": "base64",
            "consistency": "create_new"
        }),
    ));
    let binary = json_text(&client.tool(
        "fs_read",
        json!({"path": binary_path, "encoding": "base64"}),
    ));
    assert_eq!(binary["data"], "AAECA/8=");
    assert_eq!(binary["bytes"], 5);
    assert_eq!(
        std::fs::read(&binary_path).expect("binary fixture"),
        [0, 1, 2, 3, 255]
    );
}

#[test]
fn combined_stdio_rejects_persistent_execution_without_starting_children() {
    let fixture = Fixture::new();
    let mut client = Mcp::launch(&fixture, true);
    let context = json_text(&client.tool("execution_context", json!({})));
    assert_eq!(context["persistent_available"], false);
    let mut job = fixture_job(&fixture, "wait", "stdio-rejected");
    job["lifetime"] = json!("persistent");
    for (tool, input) in [
        ("job_start", job),
        (
            "terminal_create",
            json!({
                "program": std::env::var("ComSpec").expect("Windows command interpreter"),
                "args": ["/d", "/q"],
                "lifetime": "persistent"
            }),
        ),
    ] {
        let result = client.tool(tool, input);
        assert_eq!(
            result["isError"], true,
            "{tool} accepted persistent lifetime"
        );
        assert!(text(&result).contains("--local-host"), "{}", text(&result));
    }
    for tool in ["job_list", "terminal_list"] {
        let listed = json_text(&client.tool(tool, json!({})));
        assert_eq!(listed["records"], json!([]));
    }
    assert!(!fixture.path().join("stdio-rejected.ready").exists());
    assert_success(&client.tool("memory_info", json!({})));
    client.disconnect();
}

#[test]
fn combined_host_preserves_terminal_state_and_only_historical_output_after_restart() {
    let fixture = Fixture::new();
    let name = format!("mcp-fixture-{}", uuid::Uuid::new_v4());
    let mut host = Host::launch(&fixture, &name);
    let first_epoch = host.ready["epoch"].clone();
    let mut first = host.connect(&fixture);
    let first_context = json_text(&first.tool("execution_context", json!({})));
    assert_eq!(first_context["persistent_available"], true);
    assert_eq!(first_context["actual"]["token"], host.ready["token"]);
    assert_eq!(first_context["history"]["epoch"], first_epoch);

    let terminal = json_text(&first.tool(
        "terminal_create",
        json!({
            "program": std::env::var("ComSpec").expect("Windows command interpreter"),
            "args": ["/d", "/q"],
            "cwd": fixture.path(),
            "lifetime": "persistent",
            "cols": 120,
            "rows": 30
        }),
    ));
    assert_eq!(terminal["lifetime"], "persistent");
    assert!(terminal["owner_connection"].is_null());
    let terminal_process = FixtureProcess::open(&terminal);
    let value = uuid::Uuid::new_v4().simple().to_string();
    assert_success(&first.tool(
        "terminal_input",
        json!({
            "id": terminal["id"],
            "text": format!(
                "@set \"MCP_REGRESSION_VALUE={value}\"\r@echo MCP_FIRST:%MCP_REGRESSION_VALUE%:END\r"
            )
        }),
    ));
    let mut terminal_cursor = 0;
    terminal_until(
        &mut first,
        &terminal["id"],
        &mut terminal_cursor,
        &format!("MCP_FIRST:{value}:END"),
    );

    let owned = json_text(&first.tool("job_start", fixture_job(&fixture, "wait", "disconnect")));
    assert_eq!(owned["lifetime"], "connection");
    assert_eq!(owned["owner_connection"], first_context["connection_id"]);
    let owned_process = FixtureProcess::open(&owned);
    wait_for_file(&fixture.path().join("disconnect.ready"));
    let pending_wait =
        first.tool_request("job_wait", json!({"id": owned["id"], "timeout_ms": 300000}));

    let mut output_input = fixture_job(&fixture, "output", "output");
    output_input["lifetime"] = json!("persistent");
    output_input["output_limit_bytes"] = json!(256);
    let output_job = json_text(&first.tool("job_start", output_input));
    let output_process = FixtureProcess::open(&output_job);
    wait_for_file(&fixture.path().join("output.ready"));
    std::fs::write(fixture.path().join("output.release"), b"release output")
        .expect("release only the output fixture");
    let finished = json_text(&first.tool(
        "job_wait",
        json!({"id": output_job["id"], "timeout_ms": 15000}),
    ));
    assert_eq!(finished["outcome"], "exited", "{finished}");
    assert_eq!(finished["process"]["root_exit_code"], 23);
    assert_eq!(finished["process"]["tree_active_processes"], 0);
    assert_eq!(finished["process"]["output_drained"], true);
    assert_eq!(output_process.wait_for_exit(), 23);

    let mut saved_output = Vec::new();
    for (stream, fill, tail) in [("stdout", b'O', STDOUT_END), ("stderr", b'E', STDERR_END)] {
        let head = json_text(&first.tool(
            "job_output",
            json!({"id": output_job["id"], "stream": stream, "cursor": 0, "max_bytes": 73}),
        ));
        let chunk = &head["output"];
        assert_eq!(head["stream"], stream);
        assert_eq!(head["virtual_terminal_sequences"], false);
        let retained = number(&chunk["retained_from_cursor"]);
        assert!(retained >= 8192 - 256);
        assert_eq!(number(&chunk["gap_bytes"]), retained);
        assert_eq!(number(&chunk["dropped_bytes"]), retained);
        assert_eq!(number(&chunk["start_cursor"]), retained);
        assert_eq!(number(&chunk["end_cursor"]) - retained, 256);
        assert_eq!(number(&chunk["next_cursor"]), retained + 73);
        assert_eq!(chunk["eof"], true);
        assert!(chunk["read_error"].is_null());
        let rest = json_text(&first.tool(
            "job_output",
            json!({
                "id": output_job["id"],
                "stream": stream,
                "cursor": chunk["next_cursor"],
                "max_bytes": 256
            }),
        ));
        assert_eq!(rest["output"]["gap_bytes"], 0);
        assert_eq!(rest["output"]["next_cursor"], chunk["end_cursor"]);
        let mut bytes = STANDARD
            .decode(chunk["bytes_base64"].as_str().expect("first output page"))
            .expect("first output base64");
        bytes.extend(
            STANDARD
                .decode(
                    rest["output"]["bytes_base64"]
                        .as_str()
                        .expect("remaining output"),
                )
                .expect("remaining output base64"),
        );
        let mut expected = vec![fill; 256 - tail.len()];
        expected.extend_from_slice(tail);
        assert_eq!(
            bytes, expected,
            "{stream} was mixed, truncated, or decoded incorrectly"
        );
        saved_output.push((stream, expected, chunk["end_cursor"].clone()));
    }
    assert!(
        !first.pending.contains_key(&pending_wait),
        "a wait for the live fixture unexpectedly completed"
    );
    owned_process.assert_alive();
    first.disconnect();
    owned_process.wait_for_exit();
    terminal_process.assert_alive();

    let mut second = host.connect(&fixture);
    let second_context = json_text(&second.tool("execution_context", json!({})));
    assert_ne!(
        second_context["connection_id"],
        first_context["connection_id"]
    );
    assert_eq!(second_context["history"]["epoch"], first_epoch);
    let inaccessible = second.tool("job_inspect", json!({"id": owned["id"]}));
    assert_eq!(
        inaccessible["isError"], true,
        "another connection saw the owned job"
    );
    let jobs = json_text(&second.tool("job_list", json!({})));
    assert!(jobs["records"]
        .as_array()
        .expect("visible jobs")
        .iter()
        .all(|record| record["id"] != owned["id"]));
    let terminals = json_text(&second.tool("terminal_list", json!({})));
    let retained = terminals["records"]
        .as_array()
        .expect("retained terminals")
        .iter()
        .find(|record| record["id"] == terminal["id"])
        .expect("persistent terminal survives client EOF");
    assert_eq!(retained["pid"], terminal["pid"]);
    assert_eq!(
        retained["process_creation_time"],
        terminal["process_creation_time"]
    );
    assert_eq!(retained["process_state_current"], true);
    assert_success(&second.tool(
        "terminal_input",
        json!({
            "id": terminal["id"],
            "text": "@echo MCP_RECONNECTED:%MCP_REGRESSION_VALUE%:END\r"
        }),
    ));
    terminal_until(
        &mut second,
        &terminal["id"],
        &mut terminal_cursor,
        &format!("MCP_RECONNECTED:{value}:END"),
    );

    let mut observer = host.connect(&fixture);
    let shutdown_job =
        json_text(&observer.tool("job_start", fixture_job(&fixture, "wait", "shutdown")));
    let shutdown_process = FixtureProcess::open(&shutdown_job);
    wait_for_file(&fixture.path().join("shutdown.ready"));
    observer.tool_request(
        "job_wait",
        json!({"id": shutdown_job["id"], "timeout_ms": 300000}),
    );
    assert_success(&observer.tool("memory_info", json!({})));
    host.shutdown(&mut second);
    assert!(
        observer.stdin.is_some(),
        "second bridge input must remain open"
    );
    observer.wait_for_exit();
    shutdown_process.wait_for_exit();
    terminal_process.wait_for_exit();

    let mut restarted = Host::launch(&fixture, &name);
    assert_ne!(restarted.ready["epoch"], first_epoch);
    let mut history = restarted.connect(&fixture);
    let context = json_text(&history.tool("execution_context", json!({})));
    assert_eq!(context["mutations_replayed_on_restart"], false);
    assert_eq!(
        context["live_processes_survive_host_restart_or_reboot"],
        false
    );
    assert_eq!(context["history"]["epoch"], restarted.ready["epoch"]);
    let records = context["history"]["records"]
        .as_array()
        .expect("restored history");
    assert_eq!(
        records.len(),
        2,
        "only explicit persistent executions are checkpointed"
    );
    for original in [&terminal, &output_job] {
        let restored = records
            .iter()
            .find(|record| record["id"] == original["id"])
            .expect("historical execution");
        assert_eq!(restored["epoch"], first_epoch);
        assert_eq!(restored["pid"], original["pid"]);
        assert_eq!(
            restored["process_creation_time"],
            original["process_creation_time"]
        );
        assert_eq!(restored["process_state_current"], false);
        assert_ne!(restored["status"], "running");
    }
    let historical_terminal = json_text(&history.tool(
        "terminal_read",
        json!({"id": terminal["id"], "cursor": terminal_cursor}),
    ));
    assert_eq!(
        historical_terminal["process"]["process_state_current"],
        false
    );
    let write = history.tool(
        "terminal_input",
        json!({"id": terminal["id"], "text": "@echo must-not-replay\r"}),
    );
    assert_eq!(
        write["isError"], true,
        "historical terminal accepted live input"
    );
    for (stream, expected, end_cursor) in saved_output {
        let restored = json_text(&history.tool(
            "job_output",
            json!({"id": output_job["id"], "stream": stream, "cursor": 0, "max_bytes": 256}),
        ));
        assert_eq!(restored["epoch"], first_epoch);
        assert_eq!(restored["process"]["process_state_current"], false);
        assert_eq!(restored["process"]["root_exit_code"], 23);
        assert_eq!(restored["output"]["end_cursor"], end_cursor);
        assert_eq!(
            STANDARD
                .decode(
                    restored["output"]["bytes_base64"]
                        .as_str()
                        .expect("historical bytes")
                )
                .expect("historical base64"),
            expected
        );
    }
    assert_eq!(
        std::fs::read(fixture.path().join("output.mutations")).expect("execution mutation record"),
        b"once\n",
        "a host restart replayed the mutating fixture"
    );
    restarted.shutdown(&mut history);
}

#[test]
#[ignore = "requires an interactive desktop; shows only a disposable nonactivating fixture window"]
fn combined_native_failure_dialog_workflow_collects_snapshots_and_observes_close() {
    let fixture = Fixture::new();
    let name = format!("mcp-dialog-{}", uuid::Uuid::new_v4());
    let title = format!("MCP disposable failure {}", uuid::Uuid::new_v4());
    let mut host = Host::launch(&fixture, &name);
    let mut client = host.connect(&fixture);
    let mut launch = fixture_job(&fixture, "dialog", "dialog");
    launch["env"]["MCP_INTEGRATION_TITLE"] = json!(title);
    let window_query = json!({
        "title": title,
        "class_name": "McpIntegrationFailureDialog",
        "pid": {"$step": "launch", "pointer": "/data/pid"},
        "process_created_100ns": {"$step": "launch", "pointer": "/data/process_creation_time"}
    });
    let workflow = json_text(&client.tool(
        "workflow_start",
        json!({
            "name": "owned failure dialog and read-only process/network snapshots",
            "lifetime": "connection",
            "timeout_ms": 60000,
            "steps": [
                {"name": "launch", "kind": "action", "tool": "job_start", "timeout_ms": 5000,
                 "arguments": launch},
                {"name": "window", "kind": "action", "tool": "ui_wait", "timeout_ms": 15000,
                 "arguments": {"target": {"kind": "window", "query": window_query},
                               "condition": "appear", "timeout_ms": 12000}},
                {"name": "capture", "kind": "action", "tool": "desktop_snapshot", "timeout_ms": 12000,
                 "arguments": {"target": {"kind": "window", "window_ref": {"$step": "window", "pointer": "/data/window/window_ref"}},
                               "image": true, "accessibility": true, "ocr": false,
                               "max_depth": 4, "max_nodes": 32, "timeout_ms": 10000}},
                {"name": "process_snapshot", "kind": "action", "tool": "diagnostics_process", "timeout_ms": 12000,
                 "arguments": {"pid": {"$step": "launch", "pointer": "/data/pid"}}},
                {"name": "network_snapshot", "kind": "action", "tool": "network_connections", "timeout_ms": 5000,
                 "arguments": {}},
                {"name": "close", "kind": "action", "tool": "window_manage", "timeout_ms": 8000,
                 "arguments": {"window_ref": {"$step": "window", "pointer": "/data/window/window_ref"},
                               "action": "close", "timeout_ms": 5000}},
                {"name": "gone", "kind": "action", "tool": "ui_wait", "timeout_ms": 5000,
                 "arguments": {"target": {"kind": "window", "query": window_query},
                               "condition": "disappear", "timeout_ms": 3000}},
                {"name": "exited", "kind": "action", "tool": "job_wait", "timeout_ms": 5000,
                 "arguments": {"id": {"$step": "launch", "pointer": "/data/id"}, "timeout_ms": 3000}}
            ]
        }),
    ));
    let deadline = Instant::now() + RPC_TIMEOUT;
    let launched = loop {
        let status = json_text(&client.tool("workflow_status", json!({"id": workflow["id"]})));
        if let Some(record) = status.pointer("/steps/0/result/data") {
            if record["pid"].is_number() {
                break record.clone();
            }
        }
        assert_eq!(
            status["outcome"], "running",
            "workflow stopped before launch: {status}"
        );
        assert!(
            Instant::now() < deadline,
            "workflow did not publish its fixture identity"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let process = FixtureProcess::open(&launched);
    wait_for_file(&fixture.path().join("dialog.ready"));
    let socket: Value = serde_json::from_slice(
        &std::fs::read(fixture.path().join("dialog.ready")).expect("owned socket signal"),
    )
    .expect("owned socket metadata");
    // Keep an exact cleanup handle before allowing the workflow to close its fixture.
    std::fs::write(fixture.path().join("dialog.release"), b"show owned dialog")
        .expect("release only the native dialog fixture");
    let waiting = client.tool_request(
        "workflow_wait",
        json!({"id": workflow["id"], "deadline_unix_ms": deadline_ms(Duration::from_secs(60))}),
    );
    let completed = json_text(&tool_result(
        client.response(waiting, Duration::from_secs(65)),
    ));
    let record = &completed["workflow"];
    let steps = record["steps"].as_array().expect("workflow step results");
    let summary: Vec<_> = steps
        .iter()
        .map(|step| json!({"name": step["name"], "outcome": step["outcome"], "error": step["error"]}))
        .collect();
    assert_eq!(completed["outcome"], "satisfied", "{summary:?}");
    assert_eq!(record["outcome"], "satisfied", "{summary:?}");
    assert_eq!(record["replayed"], false);
    assert_eq!(
        steps
            .iter()
            .map(|step| step["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "launch",
            "window",
            "capture",
            "process_snapshot",
            "network_snapshot",
            "close",
            "gone",
            "exited"
        ]
    );
    for step in steps {
        assert_eq!(step["outcome"], "satisfied", "{summary:?}");
    }
    let window = &steps[1]["result"]["data"]["window"];
    assert_eq!(window["title"], title);
    assert_eq!(window["identity"]["pid"], launched["pid"]);
    assert_eq!(
        number(&window["identity"]["process_created_100ns"]),
        number(&launched["process_creation_time"])
    );
    let capture = &steps[2]["result"]["data"];
    assert!(capture["snapshot_id"].is_string());
    assert_eq!(capture["capture"]["target"]["kind"], "window");
    assert_eq!(
        capture["capture"]["target"]["window_ref"],
        window["window_ref"]
    );
    assert_eq!(capture["capture"]["target"]["identity"], window["identity"]);
    assert_eq!(capture["capture"]["requested_bounds"], window["bounds"]);
    assert!(number(&capture["capture"]["width"]) > 0);
    assert!(number(&capture["capture"]["height"]) > 0);
    assert_eq!(capture["accessibility"]["result"]["complete"], true);
    let controls = capture["accessibility"]["result"]["elements"]
        .as_array()
        .expect("native accessibility observations");
    let failure = controls
        .iter()
        .find(|element| element["name"] == FAILURE_TEXT)
        .expect("the captured fixture exposes its actual failure text");
    assert_eq!(failure["process"]["pid"], launched["pid"]);
    let image = steps[2]["result"]["tool_result"]["content"]
        .as_array()
        .expect("original MCP capture content")
        .iter()
        .find(|content| content["type"] == "image")
        .expect("workflow retains the real MCP image, not only capture metadata");
    assert_eq!(image["mimeType"], "image/jpeg");
    let jpeg = STANDARD
        .decode(image["data"].as_str().expect("JPEG data"))
        .expect("JPEG base64");
    assert!(jpeg.starts_with(&[0xff, 0xd8, 0xff]) && jpeg.ends_with(&[0xff, 0xd9]));
    let identity = &steps[3]["result"]["data"];
    assert_eq!(identity["pid"], launched["pid"]);
    assert_eq!(
        number(&identity["creation_time"]),
        number(&launched["process_creation_time"])
    );
    let connections = steps[4]["result"]["data"]
        .as_array()
        .expect("read-only TCP table snapshot");
    assert!(
        connections.iter().any(|row| {
            row["PID"] == launched["pid"]
                && row["LocalAddress"] == "127.0.0.1"
                && row["RemoteAddress"] == "127.0.0.1"
                && row["LocalPort"] == socket["server_port"]
                && row["RemotePort"] == socket["client_port"]
                && row["State"] == "Established"
        }),
        "network snapshot did not include the fixture's own established loopback socket"
    );
    assert_eq!(steps[5]["result"]["data"]["accepted"], true);
    assert_eq!(steps[5]["result"]["data"]["observed"], true);
    assert_eq!(steps[6]["result"]["data"]["outcome"], "satisfied");
    assert_eq!(steps[7]["result"]["data"]["outcome"], "exited");
    assert_eq!(steps[7]["result"]["data"]["process"]["root_exit_code"], 0);
    assert_eq!(
        steps[7]["result"]["data"]["process"]["tree_active_processes"],
        0
    );
    assert_eq!(
        steps[7]["result"]["data"]["process"]["output_drained"],
        true
    );
    assert_eq!(process.wait_for_exit(), 0);
    assert_eq!(
        std::fs::read(fixture.path().join("dialog.closed")).expect("graceful fixture close signal"),
        b"WM_CLOSE observed\n"
    );
    host.shutdown(&mut client);
}

#[test]
#[ignore = "native debugger lifecycle against only an exact, disposable fixture process"]
fn combined_debugger_disconnect_detaches_and_resumes_its_exact_target() {
    let fixture = Fixture::new();
    let name = format!("mcp-debug-{}", uuid::Uuid::new_v4());
    let mut host = Host::launch(&fixture, &name);
    let mut first = host.connect(&fixture);
    let mut input = fixture_job(&fixture, "wait", "debug");
    input["lifetime"] = json!("persistent");
    let job = json_text(&first.tool("job_start", input));
    let process = FixtureProcess::open(&job);
    wait_for_file(&fixture.path().join("debug.ready"));
    let identity = json_text(&first.tool("diagnostics_process", json!({"pid": job["pid"]})));
    assert_eq!(number(&identity["creation_time"]), process.created);
    let attached = json_text(&first.tool(
        "debug_attach",
        json!({
            "pid": identity["pid"],
            "creation_time": identity["creation_time"],
            "lifetime": "connection",
            "timeout_ms": 10000
        }),
    ));
    assert_eq!(
        attached["owned"], false,
        "attach must not claim launch ownership"
    );
    let deadline = Instant::now() + RPC_TIMEOUT;
    loop {
        let state = json_text(&first.tool("debug_inspect", json!({"id": attached["id"]})));
        if state["state"] == "stopped" {
            assert!(state["stop"]["stop_id"].is_number());
            break;
        }
        assert!(
            state["state"] == "attaching" || state["state"] == "running",
            "debugger did not stop its fixture: {state}"
        );
        assert!(
            Instant::now() < deadline,
            "debugger did not observe an attach stop"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(process.debugger_attached());
    process.assert_alive();
    first.disconnect();
    let deadline = Instant::now() + RPC_TIMEOUT;
    while process.debugger_attached() {
        assert!(
            Instant::now() < deadline,
            "disconnect left the fixture debugger attached"
        );
        thread::sleep(Duration::from_millis(10));
    }
    process.assert_alive();
    let mut second = host.connect(&fixture);
    let inaccessible = second.tool("debug_inspect", json!({"id": attached["id"]}));
    assert_eq!(
        inaccessible["isError"], true,
        "debugger session leaked across connections"
    );
    std::fs::write(
        fixture.path().join("debug.release"),
        b"prove target resumed",
    )
    .expect("release only the detached fixture");
    assert_eq!(
        process.wait_for_exit(),
        0,
        "detached target was killed or left stopped"
    );
    assert_eq!(
        std::fs::read(fixture.path().join("debug.resumed")).expect("resumed fixture signal"),
        b"resumed\n"
    );
    let completed =
        json_text(&second.tool("job_wait", json!({"id": job["id"], "timeout_ms": 5000})));
    assert_eq!(completed["outcome"], "exited");
    assert_eq!(completed["process"]["root_exit_code"], 0);
    host.shutdown(&mut second);
}

fn fixture_signal(directory: &Path, name: &str, bytes: &[u8]) {
    let pending = directory.join(format!("{name}.pending"));
    std::fs::write(&pending, bytes).expect("write fixture signal");
    std::fs::rename(pending, directory.join(name)).expect("publish complete fixture signal");
}

#[test]
#[ignore = "subprocess helper; inert unless launched with the fixture-specific guard"]
fn mcp_fixture_process() {
    let Some(directory) = std::env::var_os("MCP_INTEGRATION_FIXTURE") else {
        return;
    };
    let directory = PathBuf::from(directory);
    assert_eq!(
        std::env::current_dir().expect("fixture working directory"),
        directory
    );
    let suffix = directory
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("mcp-integration-"))
        .expect("disposable integration directory");
    uuid::Uuid::parse_str(suffix).expect("fixture directory nonce");
    let args: Vec<_> = std::env::args().collect();
    assert!(args.iter().any(|arg| arg == "--ignored"));
    assert!(args
        .windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == FIXTURE_HELPER));
    let signal = std::env::var("MCP_INTEGRATION_SIGNAL").expect("fixture signal prefix");
    assert!(
        !signal.is_empty()
            && signal.len() <= 64
            && signal
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    );
    match std::env::var("MCP_INTEGRATION_MODE")
        .expect("fixture mode")
        .as_str()
    {
        "wait" => {
            fixture_signal(&directory, &format!("{signal}.ready"), b"ready\n");
            wait_for_file(&directory.join(format!("{signal}.release")));
            fixture_signal(&directory, &format!("{signal}.resumed"), b"resumed\n");
        }
        "output" => {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(directory.join(format!("{signal}.mutations")))
                .expect("fixture mutation record")
                .write_all(b"once\n")
                .expect("record a single fixture invocation");
            fixture_signal(&directory, &format!("{signal}.ready"), b"ready\n");
            wait_for_file(&directory.join(format!("{signal}.release")));
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&[b'O'; 8192]).expect("fixture stdout");
            stdout
                .write_all(STDOUT_END)
                .expect("fixture stdout sentinel");
            stdout.flush().expect("flush fixture stdout");
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(&[b'E'; 8192]).expect("fixture stderr");
            stderr
                .write_all(STDERR_END)
                .expect("fixture stderr sentinel");
            stderr.flush().expect("flush fixture stderr");
            std::process::exit(23);
        }
        "dialog" => native_failure_dialog(&directory, &signal),
        mode => panic!("unknown fixture mode {mode}"),
    }
}

fn native_failure_dialog(directory: &Path, signal: &str) {
    use std::net::{TcpListener, TcpStream};
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::Graphics::Gdi::{GetSysColorBrush, UpdateWindow, COLOR_WINDOW};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::*;

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_CLOSE => {
                let _ = unsafe { DestroyWindow(hwnd) };
                LRESULT(0)
            }
            WM_DESTROY => {
                unsafe { PostQuitMessage(0) };
                LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    struct WindowFixture {
        hwnd: HWND,
        instance: HINSTANCE,
    }

    impl Drop for WindowFixture {
        fn drop(&mut self) {
            unsafe {
                if IsWindow(Some(self.hwnd)).as_bool() {
                    let _ = DestroyWindow(self.hwnd);
                }
                let _ = UnregisterClassW(w!("McpIntegrationFailureDialog"), Some(self.instance));
            }
        }
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture-only loopback socket");
    let server_address = listener.local_addr().expect("fixture server address");
    let connection =
        TcpStream::connect(server_address).expect("connect only to the fixture socket");
    let (accepted, _) = listener
        .accept()
        .expect("accept fixture loopback connection");
    let client_address = connection.local_addr().expect("fixture client address");
    fixture_signal(
        directory,
        &format!("{signal}.ready"),
        &serde_json::to_vec(&json!({
            "server_port": server_address.port(),
            "client_port": client_address.port()
        }))
        .expect("fixture socket metadata"),
    );
    wait_for_file(&directory.join(format!("{signal}.release")));

    let instance = HINSTANCE(unsafe { GetModuleHandleW(None) }.expect("fixture module").0);
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
        lpszClassName: w!("McpIntegrationFailureDialog"),
        ..Default::default()
    };
    assert_ne!(
        unsafe { RegisterClassW(&class) },
        0,
        "register owned fixture class"
    );
    let title = std::env::var("MCP_INTEGRATION_TITLE").expect("unique fixture window title");
    let title: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
    let window = WindowFixture {
        hwnd: unsafe {
            CreateWindowExW(
                WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
                w!("McpIntegrationFailureDialog"),
                PCWSTR(title.as_ptr()),
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                120,
                120,
                480,
                180,
                None,
                None,
                Some(instance),
                None,
            )
        }
        .expect("create disposable failure dialog"),
        instance,
    };
    let failure_text: Vec<u16> = FAILURE_TEXT.encode_utf16().chain(Some(0)).collect();
    unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            w!("STATIC"),
            PCWSTR(failure_text.as_ptr()),
            WS_CHILD | WS_VISIBLE,
            16,
            24,
            432,
            96,
            Some(window.hwnd),
            None,
            Some(instance),
            None,
        )
    }
    .expect("create native failure text control");
    unsafe {
        let _ = ShowWindow(window.hwnd, SW_SHOWNOACTIVATE);
        let _ = UpdateWindow(window.hwnd);
    }
    let mut message = MSG::default();
    loop {
        let status = unsafe { GetMessageW(&mut message, None, 0, 0) }.0;
        assert_ne!(status, -1, "fixture message pump failed");
        if status == 0 {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    assert!(!unsafe { IsWindow(Some(window.hwnd)) }.as_bool());
    fixture_signal(
        directory,
        &format!("{signal}.closed"),
        b"WM_CLOSE observed\n",
    );
    drop((accepted, connection, listener));
}
