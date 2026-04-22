//! # The Server — 98 Tools of Pure Windows Domination
//!
//! This is the big one. 98 MCP tools across 19 categories, crammed into one
//! glorious `#[tool_router]` impl block because the rmcp macro demands it.
//!
//! 41 tools bypass PowerShell entirely and go straight to Win32 syscalls.
//! The other 57 tools use the persistent PowerShell pool because Microsoft
//! decided that firewalls, scheduled tasks, and user management should only
//! be accessible through COM objects invented during the Clinton administration.
//!
//! The `ps!` macro handles PowerShell tools. The `native!` macro handles
//! Win32 syscall tools. Both log timing and errors. Both judge you silently.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::ps;

// ─── Input Types ──────────────────────────────────────────────────────────────
// Every tool that takes parameters needs one of these structs.
// schemars::JsonSchema generates the JSON Schema that tells the LLM
// what arguments exist. If you get the descriptions wrong, the AI will
// send you garbage. Ask me how I know.

// Process
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProcessListInput {
    #[schemars(description = "Sort by: cpu, memory, name, pid (default: cpu)")]
    pub sort_by: Option<String>,
    #[schemars(description = "Max processes to return 1-500 (default: 50)")]
    pub limit: Option<u32>,
    #[schemars(description = "Filter by process name substring")]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProcessByPid {
    #[schemars(description = "Process ID")]
    pub pid: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProcessStartInput {
    #[schemars(description = "Path to executable")]
    pub path: String,
    #[schemars(description = "Command line arguments")]
    pub args: Option<String>,
    #[schemars(description = "Working directory")]
    pub working_dir: Option<String>,
}

// Service
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceNameInput {
    #[schemars(description = "Service name (not display name)")]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceSetStartupInput {
    #[schemars(description = "Service name")]
    pub name: String,
    #[schemars(description = "Startup type: Automatic, Manual, or Disabled")]
    pub startup_type: String,
}

// Filesystem
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsPathInput {
    #[schemars(description = "File or directory path")]
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsListInput {
    #[schemars(description = "Directory path")]
    pub path: String,
    #[schemars(description = "Include hidden files (default: false)")]
    pub hidden: Option<bool>,
    #[schemars(description = "Recurse into subdirectories (default: false)")]
    pub recurse: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsSearchInput {
    #[schemars(description = "Root directory to search from")]
    pub path: String,
    #[schemars(description = "File name pattern (supports wildcards like *.txt)")]
    pub pattern: String,
    #[schemars(description = "Max results to return (default: 50)")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsShareCreateInput {
    #[schemars(description = "Share name")]
    pub name: String,
    #[schemars(description = "Local path to share")]
    pub path: String,
    #[schemars(description = "Share description")]
    pub description: Option<String>,
}

// Registry
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegistryPathInput {
    #[schemars(description = "Registry path (e.g. HKLM:\\SOFTWARE\\Microsoft)")]
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegistryValueInput {
    #[schemars(description = "Registry key path")]
    pub path: String,
    #[schemars(description = "Value name")]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegistryWriteInput {
    #[schemars(description = "Registry key path")]
    pub path: String,
    #[schemars(description = "Value name")]
    pub name: String,
    #[schemars(description = "Value data")]
    pub value: String,
    #[schemars(description = "Value type: String, DWord, QWord, ExpandString, MultiString, Binary (default: String)")]
    pub value_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegistrySearchInput {
    #[schemars(description = "Root registry path to search under")]
    pub path: String,
    #[schemars(description = "Search pattern (substring match on key/value names)")]
    pub pattern: String,
    #[schemars(description = "Max results (default: 50)")]
    pub limit: Option<u32>,
}

// Network
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostInput {
    #[schemars(description = "Hostname or IP address")]
    pub host: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PingInput {
    #[schemars(description = "Hostname or IP address")]
    pub host: String,
    #[schemars(description = "Number of pings (default: 4)")]
    pub count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PortTestInput {
    #[schemars(description = "Hostname or IP address")]
    pub host: String,
    #[schemars(description = "Port number")]
    pub port: u16,
}

// Firewall
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FirewallRuleNameInput {
    #[schemars(description = "Firewall rule display name")]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FirewallRuleCreateInput {
    #[schemars(description = "Rule display name")]
    pub name: String,
    #[schemars(description = "Direction: Inbound or Outbound")]
    pub direction: String,
    #[schemars(description = "Action: Allow or Block")]
    pub action: String,
    #[schemars(description = "Protocol: TCP, UDP, or Any")]
    pub protocol: Option<String>,
    #[schemars(description = "Local port(s), comma-separated")]
    pub local_port: Option<String>,
    #[schemars(description = "Remote address(es), comma-separated")]
    pub remote_address: Option<String>,
    #[schemars(description = "Program path")]
    pub program: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FirewallToggleInput {
    #[schemars(description = "Firewall rule display name")]
    pub name: String,
    #[schemars(description = "Enable or disable the rule")]
    pub enabled: bool,
}

// Event Log
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EventLogQueryInput {
    #[schemars(description = "Log name: Application, System, Security, etc.")]
    pub log_name: String,
    #[schemars(description = "Max events to return (default: 50)")]
    pub limit: Option<u32>,
    #[schemars(description = "Filter by level: Critical, Error, Warning, Information, Verbose")]
    pub level: Option<String>,
    #[schemars(description = "Filter by event source name")]
    pub source: Option<String>,
    #[schemars(description = "Filter by event ID")]
    pub event_id: Option<u32>,
    #[schemars(description = "Hours to look back (default: 24)")]
    pub hours: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EventLogNameInput {
    #[schemars(description = "Log name: Application, System, Security, etc.")]
    pub log_name: String,
}

// Tasks
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskNameInput {
    #[schemars(description = "Scheduled task name")]
    pub name: String,
    #[schemars(description = "Task path (default: \\)")]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskCreateInput {
    #[schemars(description = "Task name")]
    pub name: String,
    #[schemars(description = "Program or script to execute")]
    pub execute: String,
    #[schemars(description = "Arguments for the program")]
    pub argument: Option<String>,
    #[schemars(description = "Trigger type: Once, Daily, Weekly, AtStartup, AtLogon")]
    pub trigger: String,
    #[schemars(description = "Start time for Once/Daily/Weekly (e.g. '2024-01-01T09:00:00')")]
    pub at: Option<String>,
    #[schemars(description = "Description")]
    pub description: Option<String>,
}

// Software
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SoftwareNameInput {
    #[schemars(description = "Software name (substring match)")]
    pub name: String,
}

// Users
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserNameInput {
    #[schemars(description = "Username")]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserCreateInput {
    #[schemars(description = "Username")]
    pub name: String,
    #[schemars(description = "Password")]
    pub password: String,
    #[schemars(description = "Full name")]
    pub full_name: Option<String>,
    #[schemars(description = "Description")]
    pub description: Option<String>,
    #[schemars(description = "Password never expires (default: false)")]
    pub no_password_expiry: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserModifyInput {
    #[schemars(description = "Username")]
    pub name: String,
    #[schemars(description = "New full name")]
    pub full_name: Option<String>,
    #[schemars(description = "New description")]
    pub description: Option<String>,
    #[schemars(description = "Enable or disable the account")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GroupNameInput {
    #[schemars(description = "Group name")]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GroupMemberInput {
    #[schemars(description = "Group name")]
    pub group: String,
    #[schemars(description = "Username to add/remove")]
    pub member: String,
}

// Environment
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EnvNameInput {
    #[schemars(description = "Environment variable name")]
    pub name: String,
    #[schemars(description = "Scope: Machine, User, or Process (default: Process)")]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EnvSetInput {
    #[schemars(description = "Environment variable name")]
    pub name: String,
    #[schemars(description = "Value to set")]
    pub value: String,
    #[schemars(description = "Scope: Machine, User, or Process (default: Process)")]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PathModifyInput {
    #[schemars(description = "Path entry to add or remove")]
    pub entry: String,
    #[schemars(description = "Scope: Machine or User (default: User)")]
    pub scope: Option<String>,
}

// PowerShell / CMD / WMI
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PsExecuteInput {
    #[schemars(description = "PowerShell command(s) to execute")]
    pub command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CmdExecuteInput {
    #[schemars(description = "CMD command to execute")]
    pub command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WmiQueryInput {
    #[schemars(description = "WMI/CIM class name (e.g. Win32_Processor)")]
    pub class: String,
    #[schemars(description = "WQL filter expression (e.g. \"Name LIKE '%chrome%'\")")]
    pub filter: Option<String>,
    #[schemars(description = "Properties to select (comma-separated; default: all)")]
    pub properties: Option<String>,
    #[schemars(description = "Namespace (default: root/cimv2)")]
    pub namespace: Option<String>,
}

// Features
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FeatureNameInput {
    #[schemars(description = "Windows feature name")]
    pub name: String,
}

// Clipboard
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClipboardSetInput {
    #[schemars(description = "Text to copy to clipboard")]
    pub text: String,
}

// Computer Use — Screen
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScreenCaptureInput {
    #[schemars(description = "X coordinate of capture region top-left in virtual screen space (default: left edge of virtual screen, which may be negative on multi-monitor setups)")]
    pub x: Option<i32>,
    #[schemars(description = "Y coordinate of capture region top-left in virtual screen space (default: top edge of virtual screen, which may be negative on multi-monitor setups)")]
    pub y: Option<i32>,
    #[schemars(description = "Width of capture region in physical pixels (default: full virtual screen width across all monitors)")]
    pub width: Option<u32>,
    #[schemars(description = "Height of capture region in pixels (default: primary monitor height)")]
    pub height: Option<u32>,
}

// Computer Use — Mouse
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseMoveInput {
    #[schemars(description = "Target X coordinate in virtual screen pixels (matches screen_capture coordinates exactly — can be negative for monitors left of primary)")]
    pub x: i32,
    #[schemars(description = "Target Y coordinate in virtual screen pixels (matches screen_capture coordinates exactly — can be negative for monitors above primary)")]
    pub y: i32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseClickInput {
    #[schemars(description = "X coordinate to click at in virtual screen pixels (default: current position)")]
    pub x: Option<i32>,
    #[schemars(description = "Y coordinate to click at in virtual screen pixels (default: current position)")]
    pub y: Option<i32>,
    #[schemars(description = "Button: left, right, or middle (default: left)")]
    pub button: Option<String>,
    #[schemars(description = "Click count: 1=single, 2=double, 3=triple (default: 1)")]
    pub count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseScrollInput {
    #[schemars(description = "X coordinate to scroll at in virtual screen pixels (default: current position)")]
    pub x: Option<i32>,
    #[schemars(description = "Y coordinate to scroll at in virtual screen pixels (default: current position)")]
    pub y: Option<i32>,
    #[schemars(description = "Scroll clicks: positive=up, negative=down")]
    pub clicks: i32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseDragInput {
    #[schemars(description = "Start X coordinate in virtual screen pixels")]
    pub start_x: i32,
    #[schemars(description = "Start Y coordinate in virtual screen pixels")]
    pub start_y: i32,
    #[schemars(description = "End X coordinate in virtual screen pixels")]
    pub end_x: i32,
    #[schemars(description = "End Y coordinate in virtual screen pixels")]
    pub end_y: i32,
    #[schemars(description = "Button: left, right, or middle (default: left)")]
    pub button: Option<String>,
}

// Computer Use — Keyboard
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeyboardTypeInput {
    #[schemars(description = "Text to type (supports full Unicode including emoji)")]
    pub text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeyboardKeyInput {
    #[schemars(description = "Key combo to press, e.g. 'ctrl+c', 'alt+tab', 'enter', 'shift+f5'. Supported: ctrl, shift, alt, win, a-z, 0-9, f1-f24, enter, tab, escape, backspace, delete, space, up/down/left/right, home, end, pageup, pagedown, insert, printscreen")]
    pub keys: String,
}

// Performance
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PerfTopInput {
    #[schemars(description = "Sort by: cpu or memory (default: cpu)")]
    pub sort_by: Option<String>,
    #[schemars(description = "Number of processes (default: 15)")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PerfCounterInput {
    #[schemars(description = "Performance counter path (e.g. '\\Processor(_Total)\\% Processor Time')")]
    pub counter: String,
}

// ─── Server ───────────────────────────────────────────────────────────────────
// The actual MCP server struct. It holds an Arc to the PowerShell pool
// and a ToolRouter generated by the #[tool_router] macro.
// Clone is derived because rmcp needs to clone the handler. The Arc
// ensures all clones share the same pool. We're not animals.

#[derive(Clone)]
pub struct MasterControlProgram {
    /// The PowerShell sweatshop. 57 tools still need this.
    ps: Arc<ps::Pool>,
    /// Auto-generated tool router. Maps tool names to handler methods.
    /// Don't touch this — the macro handles it.
    tool_router: ToolRouter<Self>,
}

// Helpers — because typing Ok(CallToolResult::success(vec![Content::text(...)]))
// ninety goddamn times would make anyone lose the will to live.
fn ok(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

fn err(msg: impl std::fmt::Display) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(msg.to_string())]))
}

/// Macro for PowerShell-backed tools. Sends the command to the PS pool,
/// times it, logs it, and wraps the result. Used by the 57 tools that are
/// trapped in PowerShell purgatory because Windows has no direct API for them.
macro_rules! ps {
    ($self:expr, $cmd:expr) => {{
        let start = std::time::Instant::now();
        // Cursed trick to get the enclosing function name at compile time.
        // Define a dummy fn, get its type name, strip the suffix. It works.
        // No, I will not explain further.
        let tool_name = {
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str { std::any::type_name::<T>() }
            let full = type_name_of(f);
            // strip "::f" and crate prefix to get tool name
            full.rsplit("::").nth(1).unwrap_or("unknown")
        };
        tracing::info!(tool = tool_name, "▶ call");
        let result = $self.ps.exec_pretty($cmd).await;
        let ms = start.elapsed().as_millis();
        match result {
            Ok(v) => {
                tracing::info!(tool = tool_name, ms = ms as u64, bytes = v.len(), "✓ done");
                ok(v)
            }
            Err(e) => {
                tracing::error!(tool = tool_name, ms = ms as u64, err = %e, "✗ fail");
                err(e)
            }
        }
    }};
}

/// Macro for native Win32 syscall tools. Same logging/timing as ps! but
/// calls directly into our win32:: modules. Sub-millisecond responses.
/// This is what happens when you stop asking PowerShell nicely and just
/// call the goddamn kernel yourself.
macro_rules! native {
    ($expr:expr) => {{
        let start = std::time::Instant::now();
        let tool_name = {
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str { std::any::type_name::<T>() }
            let full = type_name_of(f);
            full.rsplit("::").nth(1).unwrap_or("unknown")
        };
        tracing::info!(tool = tool_name, "▶ native");
        let result = $expr;
        let ms = start.elapsed().as_millis();
        match result {
            Ok(v) => {
                tracing::info!(tool = tool_name, ms = ms as u64, bytes = v.len(), "✓ native done");
                ok(v)
            }
            Err(e) => {
                tracing::error!(tool = tool_name, ms = ms as u64, err = %e, "✗ native fail");
                err(e)
            }
        }
    }};
}

// ─── 98 Tools ─────────────────────────────────────────────────────────────────
// Buckle up. This is 98 MCP tool definitions in one impl block.
// The #[tool_router] macro scans this entire block and generates a
// dispatcher that maps tool names to handler methods. Every #[tool]
// attribute becomes a callable MCP tool with auto-generated JSON Schema.
//
// native!() = direct Win32 syscall, <1ms    (41 tools — the fast ones)
// ps!()     = PowerShell pool, 200-1500ms   (57 tools — the slow but necessary ones)

#[tool_router]
impl MasterControlProgram {
    pub fn new(ps_pool: ps::Pool) -> Self {
        Self {
            ps: Arc::new(ps_pool),
            tool_router: Self::tool_router(),
        }
    }

    // ── System Information (7) ────────────────────────────────────────────

    #[tool(description = "Get Windows OS version, build, architecture, hostname, uptime, and memory summary")]
    async fn system_info(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::sysinfo::system_info())
    }

    #[tool(description = "Get CPU details: name, cores, logical processors, clock speed, and current load percentage")]
    async fn cpu_info(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,LoadPercentage,Manufacturer")
    }

    #[tool(description = "Get RAM usage: total, available, used, and utilization percentage")]
    async fn memory_info(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::sysinfo::memory_info())
    }

    #[tool(description = "Get disk drives and volumes with size, free space, filesystem type, and health")]
    async fn disk_info(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::sysinfo::disk_info())
    }

    #[tool(description = "Get GPU details: name, driver version, adapter RAM, and video mode")]
    async fn gpu_info(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,@{N='AdapterRAM_MB';E={[math]::Round($_.AdapterRAM/1MB)}},VideoModeDescription,CurrentRefreshRate,Status")
    }

    #[tool(description = "Get battery status, charge percentage, and estimated runtime")]
    async fn battery_info(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "$b = Get-CimInstance Win32_Battery; if($b) { $b | Select-Object Name,Status,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,DesignVoltage } else { @{Status='No battery detected'} }")
    }

    #[tool(description = "List all network adapters with status, speed, MAC address, and IP addresses")]
    async fn network_adapters(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed,MediaType | ForEach-Object { $ip = (Get-NetIPAddress -InterfaceAlias $_.Name -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength,AddressFamily); $_ | Add-Member -NotePropertyName IPAddresses -NotePropertyValue $ip -PassThru }")
    }

    // ── Process Management (5) ────────────────────────────────────────────

    #[tool(description = "List running processes with PID, name, CPU time, memory usage, and handle count. Sortable and filterable.")]
    async fn process_list(
        &self,
        Parameters(input): Parameters<ProcessListInput>,
    ) -> Result<CallToolResult, McpError> {
        let limit = input.limit.unwrap_or(50).min(500);
        native!(crate::win32::process::list(input.sort_by.as_deref(), limit, input.filter.as_deref()))
    }

    #[tool(description = "Get detailed info on a specific process: full path, command line, owner, threads, modules, start time")]
    async fn process_detail(
        &self,
        Parameters(input): Parameters<ProcessByPid>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::detail(input.pid))
    }

    #[tool(description = "Kill/terminate a process by PID. Use with caution — this force-terminates the process.")]
    async fn process_kill(
        &self,
        Parameters(input): Parameters<ProcessByPid>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::kill(input.pid))
    }

    #[tool(description = "Start a new process with optional arguments and working directory. Returns the new process info.")]
    async fn process_start(
        &self,
        Parameters(input): Parameters<ProcessStartInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::start(&input.path, input.args.as_deref(), input.working_dir.as_deref()))
    }

    #[tool(description = "Show process tree — all processes with their parent process IDs for hierarchy visualization")]
    async fn process_tree(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::tree())
    }

    // ── Service Management (6) ────────────────────────────────────────────

    #[tool(description = "List all Windows services with their status, startup type, and display name")]
    async fn service_list(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::service::list())
    }

    #[tool(description = "Get detailed info on a specific service: description, dependencies, account, PID")]
    async fn service_detail(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::service::detail(&input.name))
    }

    #[tool(description = "Start a stopped Windows service. Requires admin privileges.")]
    async fn service_start(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::service::start(&input.name))
    }

    #[tool(description = "Stop a running Windows service. Requires admin privileges.")]
    async fn service_stop(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::service::stop(&input.name))
    }

    #[tool(description = "Restart a Windows service. Requires admin privileges.")]
    async fn service_restart(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::service::restart(&input.name))
    }

    #[tool(description = "Change a service's startup type (Automatic, Manual, Disabled). Requires admin.")]
    async fn service_set_startup(
        &self,
        Parameters(input): Parameters<ServiceSetStartupInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::service::set_startup(&input.name, &input.startup_type))
    }

    // ── File System (8) ───────────────────────────────────────────────────

    #[tool(description = "List directory contents with file names, sizes, dates, and attributes")]
    async fn fs_list(
        &self,
        Parameters(input): Parameters<FsListInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::filesystem::list(&input.path, input.hidden.unwrap_or(false), input.recurse.unwrap_or(false)))
    }

    #[tool(description = "Search for files by name pattern (supports wildcards) recursively from a root path")]
    async fn fs_search(
        &self,
        Parameters(input): Parameters<FsSearchInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::filesystem::search(&input.path, &input.pattern, input.limit.unwrap_or(50)))
    }

    #[tool(description = "Get detailed file or folder info: size, timestamps, attributes, owner")]
    async fn fs_info(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::filesystem::info(&input.path))
    }

    #[tool(description = "Get NTFS permissions (ACL) for a file or directory")]
    async fn fs_permissions(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        let path = input.path.replace('\'', "''");
        ps!(
            self,
            &format!("Get-Acl -Path '{path}' | Select-Object -ExpandProperty Access | Select-Object FileSystemRights,AccessControlType,IdentityReference,IsInherited,InheritanceFlags,PropagationFlags")
        )
    }

    #[tool(description = "List NTFS alternate data streams on a file")]
    async fn fs_streams(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        let path = input.path.replace('\'', "''");
        ps!(
            self,
            &format!("Get-Item -Path '{path}' -Stream * | Select-Object Stream,Length")
        )
    }

    #[tool(description = "List all drives with type, filesystem, total and free space")]
    async fn fs_drives(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Root,@{N='UsedGB';E={[math]::Round($_.Used/1GB,2)}},@{N='FreeGB';E={[math]::Round($_.Free/1GB,2)}},Description")
    }

    #[tool(description = "List all network (SMB) shares on this machine")]
    async fn fs_share_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-SmbShare | Select-Object Name,Path,Description,ShareState,ShareType,CurrentUsers")
    }

    #[tool(description = "Create a new network (SMB) share. Requires admin.")]
    async fn fs_share_create(
        &self,
        Parameters(input): Parameters<FsShareCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let path = input.path.replace('\'', "''");
        let desc = input.description.as_deref().unwrap_or("").replace('\'', "''");
        ps!(
            self,
            &format!("New-SmbShare -Name '{name}' -Path '{path}' -Description '{desc}' -FullAccess 'Everyone' | Select-Object Name,Path,Description,ShareState")
        )
    }

    // ── Registry (6) ─────────────────────────────────────────────────────

    #[tool(description = "Read a registry key's values. Returns all values under the specified key.")]
    async fn registry_read(
        &self,
        Parameters(input): Parameters<RegistryPathInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::registry::read(&input.path))
    }

    #[tool(description = "Write/set a registry value. Creates the key if it doesn't exist. Requires admin for HKLM.")]
    async fn registry_write(
        &self,
        Parameters(input): Parameters<RegistryWriteInput>,
    ) -> Result<CallToolResult, McpError> {
        let vtype = input.value_type.as_deref().unwrap_or("String");
        native!(crate::win32::registry::write(&input.path, &input.name, &input.value, vtype))
    }

    #[tool(description = "Delete a registry value or entire key. Requires admin for HKLM.")]
    async fn registry_delete(
        &self,
        Parameters(input): Parameters<RegistryValueInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::registry::delete(&input.path, &input.name))
    }

    #[tool(description = "List subkeys and values under a registry key")]
    async fn registry_list(
        &self,
        Parameters(input): Parameters<RegistryPathInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::registry::list_key(&input.path))
    }

    #[tool(description = "Search registry keys and values by name pattern under a root path")]
    async fn registry_search(
        &self,
        Parameters(input): Parameters<RegistrySearchInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::registry::search(&input.path, &input.pattern, input.limit.unwrap_or(50)))
    }

    #[tool(description = "Export a registry key and its subkeys to .reg format text")]
    async fn registry_export(
        &self,
        Parameters(input): Parameters<RegistryPathInput>,
    ) -> Result<CallToolResult, McpError> {
        let path = input.path.replace('\'', "''");
        // Convert PS path to reg.exe path (HKLM:\X -> HKLM\X)
        ps!(
            self,
            &format!("$regpath = '{path}' -replace ':',''; $tmp = [System.IO.Path]::GetTempFileName(); reg export $regpath $tmp /y | Out-Null; $content = Get-Content $tmp -Raw; Remove-Item $tmp; $content")
        )
    }

    // ── Network (8) ──────────────────────────────────────────────────────

    #[tool(description = "Show active TCP/UDP network connections with local/remote addresses, ports, state, and owning process")]
    async fn network_connections(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::network::connections())
    }

    #[tool(description = "Get IP configuration for all network adapters: IP, subnet, gateway, DNS")]
    async fn network_config(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::network::config())
    }

    #[tool(description = "Ping a host and return response times, TTL, and packet loss")]
    async fn network_ping(
        &self,
        Parameters(input): Parameters<PingInput>,
    ) -> Result<CallToolResult, McpError> {
        let host = input.host.replace('\'', "''");
        let count = input.count.unwrap_or(4);
        ps!(
            self,
            &format!("Test-Connection -ComputerName '{host}' -Count {count} | Select-Object Address,@{{N='ResponseTimeMs';E={{$_.Latency}}}},Status,BufferSize")
        )
    }

    #[tool(description = "Resolve a hostname via DNS, returning IP addresses and record types")]
    async fn network_dns_lookup(
        &self,
        Parameters(input): Parameters<HostInput>,
    ) -> Result<CallToolResult, McpError> {
        let host = input.host.replace('\'', "''");
        ps!(
            self,
            &format!("Resolve-DnsName -Name '{host}' | Select-Object Name,Type,IPAddress,NameHost,TTL")
        )
    }

    #[tool(description = "Trace the network route to a host, showing each hop")]
    async fn network_trace_route(
        &self,
        Parameters(input): Parameters<HostInput>,
    ) -> Result<CallToolResult, McpError> {
        let host = input.host.replace('\'', "''");
        ps!(
            self,
            &format!("Test-Connection -ComputerName '{host}' -Traceroute | Select-Object Hop,Address,@{{N='ResponseTimeMs';E={{$_.Latency}}}},Status")
        )
    }

    #[tool(description = "Test if a specific TCP port is open on a remote host")]
    async fn network_port_test(
        &self,
        Parameters(input): Parameters<PortTestInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::network::port_test(&input.host, input.port))
    }

    #[tool(description = "Show available WiFi networks and current connection info")]
    async fn network_wifi(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "$iface = netsh wlan show interfaces; $networks = netsh wlan show networks mode=bssid; @{Interface=$iface;Networks=$networks}")
    }

    #[tool(description = "Get current network throughput (bytes/sec sent and received per interface)")]
    async fn network_bandwidth(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets,@{N='ReceivedMB';E={[math]::Round($_.ReceivedBytes/1MB,2)}},@{N='SentMB';E={[math]::Round($_.SentBytes/1MB,2)}}")
    }

    // ── Firewall (5) ─────────────────────────────────────────────────────

    #[tool(description = "List all Windows Firewall rules with name, direction, action, and enabled status")]
    async fn firewall_rules_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-NetFirewallRule | Select-Object -First 100 DisplayName,Direction,Action,Enabled,Profile | Sort-Object DisplayName")
    }

    #[tool(description = "Create a new Windows Firewall rule. Requires admin.")]
    async fn firewall_rule_create(
        &self,
        Parameters(input): Parameters<FirewallRuleCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let dir = input.direction.replace('\'', "''");
        let action = input.action.replace('\'', "''");
        let mut cmd = format!("New-NetFirewallRule -DisplayName '{name}' -Direction {dir} -Action {action}");
        if let Some(proto) = &input.protocol {
            cmd.push_str(&format!(" -Protocol {}", proto.replace('\'', "''")));
        }
        if let Some(port) = &input.local_port {
            cmd.push_str(&format!(" -LocalPort {}", port.replace('\'', "''")));
        }
        if let Some(addr) = &input.remote_address {
            cmd.push_str(&format!(" -RemoteAddress {}", addr.replace('\'', "''")));
        }
        if let Some(prog) = &input.program {
            cmd.push_str(&format!(" -Program '{}'", prog.replace('\'', "''")));
        }
        cmd.push_str(" | Select-Object DisplayName,Direction,Action,Enabled");
        ps!(self, &cmd)
    }

    #[tool(description = "Delete a Windows Firewall rule by display name. Requires admin.")]
    async fn firewall_rule_delete(
        &self,
        Parameters(input): Parameters<FirewallRuleNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Remove-NetFirewallRule -DisplayName '{name}'; @{{Deleted='{name}';Status='Removed'}}")
        )
    }

    #[tool(description = "Enable or disable a Windows Firewall rule. Requires admin.")]
    async fn firewall_rule_toggle(
        &self,
        Parameters(input): Parameters<FirewallToggleInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let enabled = if input.enabled { "True" } else { "False" };
        ps!(
            self,
            &format!("Set-NetFirewallRule -DisplayName '{name}' -Enabled {enabled} -PassThru | Select-Object DisplayName,Enabled,Direction,Action")
        )
    }

    #[tool(description = "Get Windows Firewall profile status for Domain, Private, and Public networks")]
    async fn firewall_status(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogFileName,LogAllowed,LogBlocked")
    }

    // ── Event Log (4) ────────────────────────────────────────────────────

    #[tool(description = "Query Windows Event Log with filters for log name, level, source, event ID, and time range")]
    async fn eventlog_query(
        &self,
        Parameters(input): Parameters<EventLogQueryInput>,
    ) -> Result<CallToolResult, McpError> {
        let log = input.log_name.replace('\'', "''");
        let limit = input.limit.unwrap_or(50);
        let hours = input.hours.unwrap_or(24);

        let mut filter_parts = vec![format!("LogName='{log}'")];
        if let Some(level) = &input.level {
            let lvl_num = match level.to_lowercase().as_str() {
                "critical" => "1",
                "error" => "2",
                "warning" => "3",
                "information" => "4",
                "verbose" => "5",
                _ => "4",
            };
            filter_parts.push(format!("Level={lvl_num}"));
        }
        if let Some(source) = &input.source {
            filter_parts.push(format!("ProviderName='{}'", source.replace('\'', "''")));
        }
        if let Some(eid) = input.event_id {
            filter_parts.push(format!("Id={eid}"));
        }
        filter_parts.push(format!(
            "StartTime=(Get-Date).AddHours(-{hours})"
        ));

        let filter_str = filter_parts.join(";");
        ps!(
            self,
            &format!("Get-WinEvent -FilterHashtable @{{{filter_str}}} -MaxEvents {limit} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message")
        )
    }

    #[tool(description = "List available event log sources/channels")]
    async fn eventlog_sources(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object RecordCount -gt 0 | Select-Object LogName,RecordCount,MaximumSizeInBytes,LastWriteTime | Sort-Object RecordCount -Descending | Select-Object -First 50")
    }

    #[tool(description = "Get event log summary statistics by severity for a specific log")]
    async fn eventlog_stats(
        &self,
        Parameters(input): Parameters<EventLogNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let log = input.log_name.replace('\'', "''");
        ps!(
            self,
            &format!("Get-WinEvent -FilterHashtable @{{LogName='{log}';StartTime=(Get-Date).AddHours(-24)}} -ErrorAction SilentlyContinue | Group-Object LevelDisplayName | Select-Object Name,Count | Sort-Object Count -Descending")
        )
    }

    #[tool(description = "Clear an event log. Requires admin. WARNING: This permanently deletes all events in the log.")]
    async fn eventlog_clear(
        &self,
        Parameters(input): Parameters<EventLogNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let log = input.log_name.replace('\'', "''");
        ps!(
            self,
            &format!("wevtutil cl '{log}'; @{{Cleared='{log}';Status='Success'}}")
        )
    }

    // ── Scheduled Tasks (6) ──────────────────────────────────────────────

    #[tool(description = "List all scheduled tasks with name, state, last run time, and next run time")]
    async fn task_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-ScheduledTask | Where-Object TaskPath -notlike '\\Microsoft*' | Select-Object TaskName,TaskPath,State,@{N='LastRun';E={(Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue).LastRunTime}},@{N='NextRun';E={(Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue).NextRunTime}} | Sort-Object TaskName")
    }

    #[tool(description = "Get full details of a scheduled task including triggers, actions, and conditions")]
    async fn task_detail(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let path = input.path.as_deref().unwrap_or("\\").replace('\'', "''");
        ps!(
            self,
            &format!("$t = Get-ScheduledTask -TaskName '{name}' -TaskPath '{path}'; $i = $t | Get-ScheduledTaskInfo; @{{Name=$t.TaskName;Path=$t.TaskPath;State=$t.State;Description=$t.Description;Author=$t.Author;Triggers=($t.Triggers|Select-Object CimClass,Enabled);Actions=($t.Actions|Select-Object Execute,Arguments,WorkingDirectory);LastRun=$i.LastRunTime;LastResult=$i.LastTaskResult;NextRun=$i.NextRunTime}}")
        )
    }

    #[tool(description = "Create a new scheduled task with a trigger and action")]
    async fn task_create(
        &self,
        Parameters(input): Parameters<TaskCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let exe = input.execute.replace('\'', "''");
        let arg = input.argument.as_deref().unwrap_or("").replace('\'', "''");
        let desc = input.description.as_deref().unwrap_or("").replace('\'', "''");
        let trigger_cmd = match input.trigger.to_lowercase().as_str() {
            "daily" => {
                let at = input.at.as_deref().unwrap_or("09:00");
                format!("New-ScheduledTaskTrigger -Daily -At '{at}'")
            }
            "weekly" => {
                let at = input.at.as_deref().unwrap_or("09:00");
                format!("New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At '{at}'")
            }
            "atstartup" => "New-ScheduledTaskTrigger -AtStartup".to_string(),
            "atlogon" => "New-ScheduledTaskTrigger -AtLogon".to_string(),
            _ => {
                let at = input.at.as_deref().unwrap_or("09:00");
                format!("New-ScheduledTaskTrigger -Once -At '{at}'")
            }
        };
        ps!(
            self,
            &format!("$action = New-ScheduledTaskAction -Execute '{exe}' -Argument '{arg}'; $trigger = {trigger_cmd}; Register-ScheduledTask -TaskName '{name}' -Action $action -Trigger $trigger -Description '{desc}' | Select-Object TaskName,TaskPath,State")
        )
    }

    #[tool(description = "Delete a scheduled task. Requires admin.")]
    async fn task_delete(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false; @{{Deleted='{name}';Status='Removed'}}")
        )
    }

    #[tool(description = "Run a scheduled task immediately")]
    async fn task_run(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Start-ScheduledTask -TaskName '{name}'; @{{Started='{name}';Status='Running'}}")
        )
    }

    #[tool(description = "Enable or disable a scheduled task")]
    async fn task_toggle(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        // Check current state and toggle
        ps!(
            self,
            &format!("$t = Get-ScheduledTask -TaskName '{name}'; if($t.State -eq 'Disabled'){{Enable-ScheduledTask -TaskName '{name}'; @{{Task='{name}';NewState='Enabled'}}}}else{{Disable-ScheduledTask -TaskName '{name}'; @{{Task='{name}';NewState='Disabled'}}}}")
        )
    }

    // ── Installed Software (3) ───────────────────────────────────────────

    #[tool(description = "List installed software with name, version, publisher, and install date")]
    async fn software_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "@(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue) | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,@{N='SizeMB';E={[math]::Round($_.EstimatedSize/1024,1)}} | Sort-Object DisplayName")
    }

    #[tool(description = "Get detailed info about a specific installed application (by name substring)")]
    async fn software_detail(
        &self,
        Parameters(input): Parameters<SoftwareNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("@(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue) | Where-Object {{ $_.DisplayName -like '*{name}*' }} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,UninstallString,@{{N='SizeMB';E={{[math]::Round($_.EstimatedSize/1024,1)}}}}")
        )
    }

    #[tool(description = "Uninstall software by name. Finds the uninstall string and executes it. Requires admin.")]
    async fn software_uninstall(
        &self,
        Parameters(input): Parameters<SoftwareNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("$app = @(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue) | Where-Object {{ $_.DisplayName -like '*{name}*' }} | Select-Object -First 1; if($app.UninstallString){{ Start-Process cmd -ArgumentList '/c',$app.UninstallString -Wait -NoNewWindow; @{{Uninstalled=$app.DisplayName;Status='Completed'}} }}else{{ @{{Status='Not found or no uninstall string'}} }}")
        )
    }

    // ── Users & Groups (9) ───────────────────────────────────────────────

    #[tool(description = "List all local user accounts with status, last logon, and group membership")]
    async fn user_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-LocalUser | Select-Object Name,FullName,Enabled,LastLogon,PasswordRequired,PasswordLastSet,Description")
    }

    #[tool(description = "Get detailed info about a specific local user including group memberships")]
    async fn user_detail(
        &self,
        Parameters(input): Parameters<UserNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("$u = Get-LocalUser -Name '{name}'; $groups = (Get-LocalGroup | Where-Object {{ (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).Name -like '*{name}' }}).Name; @{{Name=$u.Name;FullName=$u.FullName;Enabled=$u.Enabled;LastLogon=$u.LastLogon;PasswordRequired=$u.PasswordRequired;PasswordLastSet=$u.PasswordLastSet;PasswordExpires=$u.PasswordExpires;Description=$u.Description;SID=$u.SID.Value;Groups=$groups}}")
        )
    }

    #[tool(description = "Create a new local user account. Requires admin.")]
    async fn user_create(
        &self,
        Parameters(input): Parameters<UserCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let pass = input.password.replace('\'', "''");
        let mut cmd = format!(
            "$pw = ConvertTo-SecureString '{pass}' -AsPlainText -Force; New-LocalUser -Name '{name}' -Password $pw"
        );
        if let Some(full) = &input.full_name {
            cmd.push_str(&format!(" -FullName '{}'", full.replace('\'', "''")));
        }
        if let Some(desc) = &input.description {
            cmd.push_str(&format!(" -Description '{}'", desc.replace('\'', "''")));
        }
        if input.no_password_expiry.unwrap_or(false) {
            cmd.push_str(" -PasswordNeverExpires");
        }
        cmd.push_str(" | Select-Object Name,FullName,Enabled,SID");
        ps!(self, &cmd)
    }

    #[tool(description = "Delete a local user account. Requires admin.")]
    async fn user_delete(
        &self,
        Parameters(input): Parameters<UserNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Remove-LocalUser -Name '{name}'; @{{Deleted='{name}';Status='Removed'}}")
        )
    }

    #[tool(description = "Modify a local user account's properties. Requires admin.")]
    async fn user_modify(
        &self,
        Parameters(input): Parameters<UserModifyInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let mut parts = vec![format!("Set-LocalUser -Name '{name}'")];
        if let Some(full) = &input.full_name {
            parts.push(format!("-FullName '{}'", full.replace('\'', "''")));
        }
        if let Some(desc) = &input.description {
            parts.push(format!("-Description '{}'", desc.replace('\'', "''")));
        }
        let cmd = parts.join(" ");
        let enable_cmd = match input.enabled {
            Some(true) => format!("; Enable-LocalUser -Name '{name}'"),
            Some(false) => format!("; Disable-LocalUser -Name '{name}'"),
            None => String::new(),
        };
        ps!(
            self,
            &format!("{cmd}{enable_cmd}; Get-LocalUser -Name '{name}' | Select-Object Name,FullName,Enabled,Description")
        )
    }

    #[tool(description = "List all local groups")]
    async fn group_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-LocalGroup | Select-Object Name,Description,SID")
    }

    #[tool(description = "List members of a local group")]
    async fn group_members(
        &self,
        Parameters(input): Parameters<GroupNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Get-LocalGroupMember -Group '{name}' | Select-Object Name,ObjectClass,PrincipalSource")
        )
    }

    #[tool(description = "Add a user to a local group. Requires admin.")]
    async fn group_add_member(
        &self,
        Parameters(input): Parameters<GroupMemberInput>,
    ) -> Result<CallToolResult, McpError> {
        let group = input.group.replace('\'', "''");
        let member = input.member.replace('\'', "''");
        ps!(
            self,
            &format!("Add-LocalGroupMember -Group '{group}' -Member '{member}'; @{{Group='{group}';Added='{member}';Status='Success'}}")
        )
    }

    #[tool(description = "Remove a user from a local group. Requires admin.")]
    async fn group_remove_member(
        &self,
        Parameters(input): Parameters<GroupMemberInput>,
    ) -> Result<CallToolResult, McpError> {
        let group = input.group.replace('\'', "''");
        let member = input.member.replace('\'', "''");
        ps!(
            self,
            &format!("Remove-LocalGroupMember -Group '{group}' -Member '{member}'; @{{Group='{group}';Removed='{member}';Status='Success'}}")
        )
    }

    // ── Environment Variables (7) ────────────────────────────────────────

    #[tool(description = "List all environment variables for Machine, User, and Process scopes")]
    async fn env_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "@{Machine=[Environment]::GetEnvironmentVariables('Machine');User=[Environment]::GetEnvironmentVariables('User')}")
    }

    #[tool(description = "Get a specific environment variable's value")]
    async fn env_get(
        &self,
        Parameters(input): Parameters<EnvNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let scope = input.scope.as_deref().unwrap_or("Process");
        ps!(
            self,
            &format!("@{{Name='{name}';Scope='{scope}';Value=[Environment]::GetEnvironmentVariable('{name}','{scope}')}}")
        )
    }

    #[tool(description = "Set an environment variable. Machine scope requires admin.")]
    async fn env_set(
        &self,
        Parameters(input): Parameters<EnvSetInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let value = input.value.replace('\'', "''");
        let scope = input.scope.as_deref().unwrap_or("Process");
        ps!(
            self,
            &format!("[Environment]::SetEnvironmentVariable('{name}','{value}','{scope}'); @{{Name='{name}';Value='{value}';Scope='{scope}';Status='Set'}}")
        )
    }

    #[tool(description = "Delete an environment variable. Machine scope requires admin.")]
    async fn env_delete(
        &self,
        Parameters(input): Parameters<EnvNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let scope = input.scope.as_deref().unwrap_or("Process");
        ps!(
            self,
            &format!("[Environment]::SetEnvironmentVariable('{name}',$null,'{scope}'); @{{Name='{name}';Scope='{scope}';Status='Deleted'}}")
        )
    }

    #[tool(description = "List all entries in the PATH environment variable, separated by scope")]
    async fn path_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "@{Machine=([Environment]::GetEnvironmentVariable('Path','Machine') -split ';' | Where-Object {$_});User=([Environment]::GetEnvironmentVariable('Path','User') -split ';' | Where-Object {$_})}")
    }

    #[tool(description = "Add a directory to PATH. Machine scope requires admin.")]
    async fn path_add(
        &self,
        Parameters(input): Parameters<PathModifyInput>,
    ) -> Result<CallToolResult, McpError> {
        let entry = input.entry.replace('\'', "''");
        let scope = input.scope.as_deref().unwrap_or("User");
        ps!(
            self,
            &format!("$p = [Environment]::GetEnvironmentVariable('Path','{scope}'); if($p -split ';' -notcontains '{entry}'){{ [Environment]::SetEnvironmentVariable('Path',\"$p;{entry}\",'{scope}'); @{{Added='{entry}';Scope='{scope}';Status='Added'}} }}else{{ @{{Entry='{entry}';Status='Already exists'}} }}")
        )
    }

    #[tool(description = "Remove a directory from PATH. Machine scope requires admin.")]
    async fn path_remove(
        &self,
        Parameters(input): Parameters<PathModifyInput>,
    ) -> Result<CallToolResult, McpError> {
        let entry = input.entry.replace('\'', "''");
        let scope = input.scope.as_deref().unwrap_or("User");
        ps!(
            self,
            &format!("$p = ([Environment]::GetEnvironmentVariable('Path','{scope}') -split ';' | Where-Object {{ $_ -ne '{entry}' }}) -join ';'; [Environment]::SetEnvironmentVariable('Path',$p,'{scope}'); @{{Removed='{entry}';Scope='{scope}';Status='Removed'}}")
        )
    }

    // ── PowerShell / CMD / WMI (3) ──────────────────────────────────────

    #[tool(description = "Execute arbitrary PowerShell commands. The ultimate escape hatch — run any PowerShell you want.")]
    async fn powershell_execute(
        &self,
        Parameters(input): Parameters<PsExecuteInput>,
    ) -> Result<CallToolResult, McpError> {
        match self.ps.execute(&input.command).await {
            Ok(output) => ok(output),
            Err(e) => err(e),
        }
    }

    #[tool(description = "Execute a CMD command via cmd.exe")]
    async fn cmd_execute(
        &self,
        Parameters(input): Parameters<CmdExecuteInput>,
    ) -> Result<CallToolResult, McpError> {
        let cmd = input.command.replace('\'', "''");
        match self.ps.execute(&format!("cmd /c '{cmd}'")).await {
            Ok(output) => ok(output),
            Err(e) => err(e),
        }
    }

    #[tool(description = "Execute a WMI/CIM query. Specify the class name and optional filter/properties.")]
    async fn wmi_query(
        &self,
        Parameters(input): Parameters<WmiQueryInput>,
    ) -> Result<CallToolResult, McpError> {
        let class = input.class.replace('\'', "''");
        let ns = input.namespace.as_deref().unwrap_or("root/cimv2").replace('\'', "''");
        let mut cmd = format!("Get-CimInstance -ClassName '{class}' -Namespace '{ns}'");
        if let Some(filter) = &input.filter {
            let f = filter.replace('\'', "''");
            cmd.push_str(&format!(" -Filter '{f}'"));
        }
        if let Some(props) = &input.properties {
            cmd.push_str(&format!(" | Select-Object {props}"));
        }
        ps!(self, &cmd)
    }

    // ── Windows Features (3) ─────────────────────────────────────────────

    #[tool(description = "List Windows optional features with their enabled/disabled state")]
    async fn feature_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State | Sort-Object State,FeatureName")
    }

    #[tool(description = "Enable a Windows optional feature. Requires admin. May require reboot.")]
    async fn feature_enable(
        &self,
        Parameters(input): Parameters<FeatureNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Enable-WindowsOptionalFeature -Online -FeatureName '{name}' -NoRestart | Select-Object FeatureName,Online,RestartNeeded")
        )
    }

    #[tool(description = "Disable a Windows optional feature. Requires admin. May require reboot.")]
    async fn feature_disable(
        &self,
        Parameters(input): Parameters<FeatureNameInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        ps!(
            self,
            &format!("Disable-WindowsOptionalFeature -Online -FeatureName '{name}' -NoRestart | Select-Object FeatureName,Online,RestartNeeded")
        )
    }

    // ── Clipboard (2) ────────────────────────────────────────────────────

    #[tool(description = "Get the current clipboard text content")]
    async fn clipboard_get(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::clipboard::get())
    }

    #[tool(description = "Set the clipboard to the specified text")]
    async fn clipboard_set(
        &self,
        Parameters(input): Parameters<ClipboardSetInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::clipboard::set(&input.text))
    }

    // ── Display & Audio (3) ──────────────────────────────────────────────

    #[tool(description = "Get display/monitor info: resolution, refresh rate, color depth")]
    async fn display_info(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-CimInstance Win32_VideoController | Select-Object Name,VideoModeDescription,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,CurrentBitsPerPixel,DriverVersion,Status")
    }

    #[tool(description = "List audio playback and recording devices")]
    async fn audio_devices(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status,StatusInfo")
    }

    #[tool(description = "Get or set system audio volume (0-100)")]
    async fn audio_volume(&self) -> Result<CallToolResult, McpError> {
        // Using PowerShell audio COM
        ps!(self, "Add-Type -TypeDefinition 'using System.Runtime.InteropServices; [Guid(\"5CDF2C82-841E-4546-9722-0CF74078229A\"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IAudioEndpointVolume { int _0(); int _1(); int _2(); int _3(); int SetMasterVolumeLevelScalar(float fLevel, System.Guid pguidEventContext); int _5(); int GetMasterVolumeLevelScalar(out float pfLevel); int GetMute(out bool pbMute); }'; @{Info='Use powershell_execute with audio commands for volume control. This tool shows audio device info.'; Devices=(Get-CimInstance Win32_SoundDevice | Select-Object Name,Status)}")
    }

    // ── Performance Monitoring (3) ───────────────────────────────────────

    #[tool(description = "Get a system performance snapshot: CPU load, memory usage, disk I/O, and top processes")]
    async fn perf_snapshot(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "$cpu = (Get-CimInstance Win32_Processor).LoadPercentage; $os = Get-CimInstance Win32_OperatingSystem; $mem = [math]::Round(100*(1-$os.FreePhysicalMemory/$os.TotalVisibleMemorySize),1); $disk = Get-Counter '\\PhysicalDisk(_Total)\\% Disk Time' -ErrorAction SilentlyContinue; @{CPU_Percent=$cpu; Memory_Percent=$mem; Memory_UsedMB=[math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/1024); Memory_TotalMB=[math]::Round($os.TotalVisibleMemorySize/1024); Disk_Percent=if($disk){[math]::Round($disk.CounterSamples[0].CookedValue,1)}else{'N/A'}}")
    }

    #[tool(description = "Show top processes by CPU or memory usage")]
    async fn perf_top(
        &self,
        Parameters(input): Parameters<PerfTopInput>,
    ) -> Result<CallToolResult, McpError> {
        let limit = input.limit.unwrap_or(15);
        native!(crate::win32::process::list(input.sort_by.as_deref(), limit, None))
    }

    #[tool(description = "Read a specific Windows performance counter by path")]
    async fn perf_counter(
        &self,
        Parameters(input): Parameters<PerfCounterInput>,
    ) -> Result<CallToolResult, McpError> {
        let counter = input.counter.replace('\'', "''");
        ps!(
            self,
            &format!("Get-Counter -Counter '{counter}' | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue,Timestamp")
        )
    }

    // ── Computer Use (8) ──────────────────────────────────────────────
    // The crown jewels. Full autonomous computer control: see the screen,
    // move the mouse, click things, type text, press key combos. These are
    // all native Win32 via SendInput and GDI — no PowerShell in the loop.

    #[tool(description = "Capture a screenshot of the full virtual screen (all monitors) or a specific region. Returns the image as JPEG. Coordinates used here match exactly what the mouse tools expect — in virtual screen pixels, which can be negative on multi-monitor setups. Use this to see what's on screen before taking actions.")]
    async fn screen_capture(
        &self,
        Parameters(input): Parameters<ScreenCaptureInput>,
    ) -> Result<CallToolResult, McpError> {
        let start = std::time::Instant::now();
        tracing::info!(tool = "screen_capture", "▶ native");
        match crate::win32::screen::capture(input.x, input.y, input.width, input.height) {
            Ok((b64, w, h)) => {
                let ms = start.elapsed().as_millis();
                tracing::info!(tool = "screen_capture", ms = ms as u64, "✓ native done");
                Ok(CallToolResult::success(vec![
                    Content::image(b64, "image/jpeg"),
                    Content::text(format!("Screenshot captured: {w}x{h} pixels")),
                ]))
            }
            Err(e) => {
                let ms = start.elapsed().as_millis();
                tracing::error!(tool = "screen_capture", ms = ms as u64, err = %e, "✗ native fail");
                err(e)
            }
        }
    }

    #[tool(description = "Get the current mouse cursor position as screen coordinates (X, Y)")]
    async fn cursor_position(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::input::cursor_position())
    }

    #[tool(description = "Move the mouse cursor to the specified screen coordinates")]
    async fn mouse_move(
        &self,
        Parameters(input): Parameters<MouseMoveInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::input::mouse_move(input.x, input.y))
    }

    #[tool(description = "Click a mouse button at the current or specified position. Supports left/right/middle click, single/double/triple click.")]
    async fn mouse_click(
        &self,
        Parameters(input): Parameters<MouseClickInput>,
    ) -> Result<CallToolResult, McpError> {
        let button = input.button.as_deref().unwrap_or("left");
        let count = input.count.unwrap_or(1);
        native!(crate::win32::input::mouse_click(input.x, input.y, button, count))
    }

    #[tool(description = "Scroll the mouse wheel at the current or specified position. Positive clicks = scroll up, negative = scroll down.")]
    async fn mouse_scroll(
        &self,
        Parameters(input): Parameters<MouseScrollInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::input::mouse_scroll(input.x, input.y, input.clicks))
    }

    #[tool(description = "Click and drag from one screen position to another. Useful for moving windows, selecting text, drawing, etc.")]
    async fn mouse_drag(
        &self,
        Parameters(input): Parameters<MouseDragInput>,
    ) -> Result<CallToolResult, McpError> {
        let button = input.button.as_deref().unwrap_or("left");
        native!(crate::win32::input::mouse_drag(input.start_x, input.start_y, input.end_x, input.end_y, button))
    }

    #[tool(description = "Type literal text strings by injecting Unicode character events. Use this ONLY for typing visible text into fields, editors, or documents — NOT for keyboard shortcuts, hotkeys, or special keys. For Ctrl+C, Enter, Escape, Tab, arrow keys, F-keys, or any modifier combo, use keyboard_key instead.")]
    async fn keyboard_type(
        &self,
        Parameters(input): Parameters<KeyboardTypeInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::input::keyboard_type(&input.text))
    }

    #[tool(description = "Press a keyboard shortcut, hotkey, or special key. Use this for ALL non-text key actions: Ctrl+C, Ctrl+V, Ctrl+Z, Ctrl+N, Ctrl+S, Alt+Tab, Alt+F4, Win+D, Enter, Escape, Tab, Backspace, Delete, Space, arrow keys (up/down/left/right), F1-F24, Home, End, PageUp, PageDown, Insert, PrintScreen, or any modifier combo like Ctrl+Shift+S. Format: keys joined with '+' (e.g. 'ctrl+c', 'alt+tab', 'shift+f5'). Single keys work too: 'enter', 'escape', 'b', 'x'. For typing visible text into fields or editors, use keyboard_type instead.")]
    async fn keyboard_key(
        &self,
        Parameters(input): Parameters<KeyboardKeyInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::input::keyboard_key(&input.keys))
    }

    // ── Windows Update (2) ───────────────────────────────────────────────

    #[tool(description = "List installed Windows updates (hotfixes) with KB numbers and install dates")]
    async fn update_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | Sort-Object InstalledOn -Descending")
    }

    #[tool(description = "Get Windows Update history including successful and failed updates")]
    async fn update_history(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "$session = New-Object -ComObject Microsoft.Update.Session; $searcher = $session.CreateUpdateSearcher(); $count = $searcher.GetTotalHistoryCount(); $searcher.QueryHistory(0, [Math]::Min($count,50)) | Select-Object Date,Title,@{N='Status';E={switch($_.ResultCode){1{'InProgress'};2{'Succeeded'};3{'SucceededWithErrors'};4{'Failed'};5{'Aborted'}}}},Description | Where-Object Title")
    }
}

// ─── ServerHandler impl ──────────────────────────────────────────────────────
// The #[tool_handler] macro auto-implements list_tools() and call_tool()
// by wiring them to our tool_router. All we need to provide is get_info()
// which tells the MCP client "hey, I exist, and I have tools."

#[tool_handler]
impl ServerHandler for MasterControlProgram {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("MasterControlProgram", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Windows 11 System Control MCP Server. 98 tools across 19 categories: \
                 system info, processes, services, filesystem, registry, network, firewall, \
                 event logs, scheduled tasks, software, users/groups, environment variables, \
                 PowerShell/CMD/WMI execution, Windows features, clipboard, display/audio, \
                 performance monitoring, Windows updates, and computer use (screen capture, \
                 mouse control, keyboard input for full autonomous desktop interaction)."
                    .to_string(),
            )
    }
}
