//! MCP tool routing, request cancellation, and shared local subsystem lifetimes.
//! Native calls run outside the async executor; PowerShell is initialized lazily.

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
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
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[schemars(description = "Filter by process name substring")]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProcessByPid {
    #[schemars(description = "Process ID")]
    #[serde(deserialize_with = "crate::coerce::num")]
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
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
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
    #[schemars(
        description = "Value type: String, DWord, QWord, ExpandString, MultiString, Binary (default: String)"
    )]
    pub value_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegistrySearchInput {
    #[schemars(description = "Root registry path to search under")]
    pub path: String,
    #[schemars(description = "Search pattern (substring match on key/value names)")]
    pub pattern: String,
    #[schemars(description = "Max results (default: 50)")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
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
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PortTestInput {
    #[schemars(description = "Hostname or IP address")]
    pub host: String,
    #[schemars(description = "Port number")]
    #[serde(deserialize_with = "crate::coerce::num")]
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
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[schemars(description = "Filter by level: Critical, Error, Warning, Information, Verbose")]
    pub level: Option<String>,
    #[schemars(description = "Filter by event source name")]
    pub source: Option<String>,
    #[schemars(description = "Filter by event ID")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub event_id: Option<u32>,
    #[schemars(description = "Hours to look back (default: 24)")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
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
    #[schemars(
        description = "Total deadline in milliseconds, 1-3600000 (default: MCP_PS_TIMEOUT_MS or 30000). Timeout does not undo accepted actions."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CmdExecuteInput {
    #[schemars(description = "CMD command to execute")]
    pub command: String,
    #[schemars(
        description = "Total deadline in milliseconds, 1-3600000 (default: MCP_PS_TIMEOUT_MS or 30000). Timeout does not undo accepted actions."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
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

// Computer Use: Screen
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScreenCaptureInput {
    #[schemars(
        description = "X coordinate of capture region top-left in virtual screen space (default: left edge of virtual screen, which may be negative on multi-monitor setups)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub x: Option<i32>,
    #[schemars(
        description = "Y coordinate of capture region top-left in virtual screen space (default: top edge of virtual screen, which may be negative on multi-monitor setups)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub y: Option<i32>,
    #[schemars(
        description = "Width of capture region in physical pixels (default: full virtual screen width across all monitors)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub width: Option<u32>,
    #[schemars(
        description = "Height of capture region in physical pixels (default: full virtual screen height across all monitors)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub height: Option<u32>,
}

// Computer Use: Mouse
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseMoveInput {
    #[schemars(
        description = "Target X coordinate in virtual screen pixels (matches screen_capture coordinates exactly; can be negative for monitors left of primary)"
    )]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub x: i32,
    #[schemars(
        description = "Target Y coordinate in virtual screen pixels (matches screen_capture coordinates exactly; can be negative for monitors above primary)"
    )]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub y: i32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseClickInput {
    #[schemars(
        description = "X coordinate to click at in virtual screen pixels (default: current position)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub x: Option<i32>,
    #[schemars(
        description = "Y coordinate to click at in virtual screen pixels (default: current position)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub y: Option<i32>,
    #[schemars(description = "Button: left, right, or middle (default: left)")]
    pub button: Option<String>,
    #[schemars(description = "Click count: 1=single, 2=double, 3=triple (default: 1)")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseScrollInput {
    #[schemars(
        description = "X coordinate to scroll at in virtual screen pixels (default: current position)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub x: Option<i32>,
    #[schemars(
        description = "Y coordinate to scroll at in virtual screen pixels (default: current position)"
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub y: Option<i32>,
    #[schemars(description = "Scroll clicks: positive=up, negative=down")]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub clicks: i32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MouseDragInput {
    #[schemars(description = "Start X coordinate in virtual screen pixels")]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub start_x: i32,
    #[schemars(description = "Start Y coordinate in virtual screen pixels")]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub start_y: i32,
    #[schemars(description = "End X coordinate in virtual screen pixels")]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub end_x: i32,
    #[schemars(description = "End Y coordinate in virtual screen pixels")]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub end_y: i32,
    #[schemars(description = "Button: left, right, or middle (default: left)")]
    pub button: Option<String>,
}

// Computer Use: Keyboard
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeyboardTypeInput {
    #[schemars(description = "Text to type (supports full Unicode including emoji)")]
    pub text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeyboardKeyInput {
    #[schemars(
        description = "Key combo to press, e.g. 'ctrl+c', 'alt+tab', 'enter', 'shift+f5'. Supported: ctrl, shift, alt, win, a-z, 0-9, f1-f24, enter, tab, escape, backspace, delete, space, up/down/left/right, home, end, pageup, pagedown, insert, printscreen"
    )]
    pub keys: String,
}

// Performance
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PerfTopInput {
    #[schemars(description = "Sort by: cpu or memory (default: cpu)")]
    pub sort_by: Option<String>,
    #[schemars(description = "Number of processes (default: 15)")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PerfCounterInput {
    #[schemars(
        description = "Performance counter path (e.g. '\\Processor(_Total)\\% Processor Time')"
    )]
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
    pub(crate) ps: Arc<ps::Pool>,
    pub(crate) desktop: Arc<crate::desktop::Desktop>,
    pub(crate) execution: Arc<crate::execution::ExecutionManager>,
    pub(crate) execution_connection: String,
    pub(crate) execution_connection_cancel: tokio_util::sync::CancellationToken,
    pub(crate) observation: Arc<crate::observation::ObservationState>,
    pub(crate) workflows: Arc<crate::workflow::WorkflowState>,
    pub(crate) diagnostics: Arc<crate::diagnostics::DiagnosticsManager>,
    pub(crate) diagnostics_connection: String,
    /// Auto-generated tool router. Maps tool names to handler methods.
    /// Don't touch this. The macro handles it.
    pub(crate) tool_router: ToolRouter<Self>,
}

// Helpers, because typing Ok(CallToolResult::success(vec![Content::text(...)]))
// ninety goddamn times would make anyone lose the will to live.
pub(crate) fn ok(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub(crate) fn err(msg: impl std::fmt::Display) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(msg.to_string())]))
}

pub(crate) fn lifecycle_result<const N: usize>(
    results: [(&str, anyhow::Result<()>); N],
) -> anyhow::Result<()> {
    let errors: Vec<_> = results
        .into_iter()
        .filter_map(|(stage, result)| result.err().map(|error| format!("{stage}: {error:#}")))
        .collect();
    anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

async fn call_until_cancelled(
    call: impl std::future::Future<Output = Result<CallToolResult, McpError>>,
    cancelled: impl std::future::Future<Output = ()>,
) -> Result<CallToolResult, McpError> {
    tokio::select! {
        biased;
        _ = cancelled => err("Tool request cancelled; an already accepted action may have taken effect"),
        result = call => result,
    }
}

/// Preserve the PowerShell result envelope and surface provider errors.
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
                err(format!("{e:#}"))
            }
        }
    }};
}

/// Native provider work must not block unrelated async requests.
macro_rules! native {
    ($expr:expr) => {
        native!(@run crate::runtime::blocking, $expr)
    };
    (@run $runner:path, $expr:expr) => {{
        let start = std::time::Instant::now();
        let tool_name = {
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str { std::any::type_name::<T>() }
            let full = type_name_of(f);
            full.rsplit("::").nth(1).unwrap_or("unknown")
        };
        tracing::info!(tool = tool_name, "▶ native");
        let result = $runner(move || $expr).await;
        let ms = start.elapsed().as_millis();
        match result {
            Ok(v) => {
                tracing::info!(tool = tool_name, ms = ms as u64, bytes = v.len(), "✓ native done");
                ok(v)
            }
            Err(e) => {
                tracing::error!(tool = tool_name, ms = ms as u64, err = %e, "✗ native fail");
                err(format!("{e:#}"))
            }
        }
    }};
}

/// Desktop actions share one input lock and pulse only when the blocking work
/// starts. Passive reads, including screenshots, use `native!` without a pulse.
macro_rules! interactive {
    ($expr:expr) => {{
        native!(@run crate::runtime::interactive, $expr)
    }};
}

#[tool_router]
impl MasterControlProgram {
    pub fn new(ps_pool: ps::Pool) -> anyhow::Result<Self> {
        Self::new_with_execution(
            ps_pool,
            Arc::new(crate::execution::ExecutionManager::new(
                crate::context::PersistenceContext::connection_owned()?,
            )?),
        )
    }

    pub(crate) fn new_with_execution(
        ps_pool: ps::Pool,
        execution: Arc<crate::execution::ExecutionManager>,
    ) -> anyhow::Result<Self> {
        let execution_connection = uuid::Uuid::new_v4().to_string();
        execution.register_connection(&execution_connection)?;
        let execution_connection_cancel =
            execution.connection_cancellation(&execution_connection)?;
        let (observation, workflows) = if execution.is_persistent() {
            let checkpoint: Arc<dyn crate::observation::CheckpointStore> =
                Arc::new(execution.context().clone());
            (
                crate::observation::ObservationState::open(checkpoint.clone())?,
                crate::workflow::WorkflowState::open(checkpoint)?,
            )
        } else {
            (
                Arc::new(crate::observation::ObservationState::new(false)),
                Arc::new(crate::workflow::WorkflowState::new(false)),
            )
        };
        let diagnostics = Arc::new(crate::diagnostics::DiagnosticsManager::new(
            execution.is_persistent(),
        ));
        let diagnostics_connection = execution_connection.clone();
        diagnostics.register_connection(&diagnostics_connection)?;
        Ok(Self {
            ps: Arc::new(ps_pool),
            desktop: Arc::new(crate::desktop::Desktop::new()),
            execution,
            execution_connection,
            execution_connection_cancel,
            observation,
            workflows,
            diagnostics,
            diagnostics_connection,
            tool_router: Self::tool_router()
                + Self::provider_router()
                + Self::desktop_router()
                + Self::execution_router()
                + Self::observation_router()
                + Self::workflow_router()
                + Self::system_control_router()
                + Self::administration_router()
                + Self::diagnostics_router(),
        })
    }

    pub(crate) fn for_connection(&self, execution_connection: String) -> anyhow::Result<Self> {
        self.execution.register_connection(&execution_connection)?;
        self.diagnostics
            .register_connection(&execution_connection)?;
        let mut server = self.clone();
        server.execution_connection_cancel = self
            .execution
            .connection_cancellation(&execution_connection)?;
        server.diagnostics_connection = execution_connection.clone();
        server.execution_connection = execution_connection;
        server.desktop = Arc::new(crate::desktop::Desktop::new());
        Ok(server)
    }

    pub(crate) async fn shutdown_connection(&self) -> anyhow::Result<()> {
        self.execution_connection_cancel.cancel();
        self.workflows
            .shutdown_connection(&self.execution_connection);
        self.observation
            .shutdown_connection(&self.execution_connection);
        let diagnostics_cleanup = self
            .diagnostics
            .disconnect(&self.diagnostics_connection)
            .await;
        let execution = self.execution.clone();
        let connection = self.execution_connection.clone();
        let execution_cleanup =
            tokio::task::spawn_blocking(move || execution.shutdown_connection(&connection))
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result);
        lifecycle_result([
            ("diagnostics disconnect", diagnostics_cleanup),
            ("execution disconnect", execution_cleanup),
        ])
    }

    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.workflows.shutdown().await;
        self.observation.shutdown().await;
        let diagnostics_cleanup = self.diagnostics.shutdown().await;
        let execution = self.execution.clone();
        let execution_cleanup = tokio::task::spawn_blocking(move || execution.shutdown())
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result);
        lifecycle_result([
            ("diagnostics shutdown", diagnostics_cleanup),
            ("execution shutdown", execution_cleanup),
        ])
    }

    // ── System Information (7) ────────────────────────────────────────────

    #[tool(
        description = "Get Windows OS version, build, architecture, hostname, uptime, and memory summary"
    )]
    async fn system_info(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::sysinfo::system_info())
    }

    #[tool(
        description = "Get CPU details: name, cores, logical processors, clock speed, and current load percentage"
    )]
    async fn cpu_info(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,LoadPercentage,Manufacturer")
    }

    #[tool(description = "Get RAM usage: total, available, used, and utilization percentage")]
    async fn memory_info(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::sysinfo::memory_info())
    }

    #[tool(
        description = "Get disk drives and volumes with size, free space, filesystem type, and health"
    )]
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

    #[tool(
        description = "List all network adapters with status, speed, MAC address, and IP addresses"
    )]
    async fn network_adapters(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed,MediaType | ForEach-Object { $ip = (Get-NetIPAddress -InterfaceAlias $_.Name -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength,AddressFamily); $_ | Add-Member -NotePropertyName IPAddresses -NotePropertyValue $ip -PassThru }")
    }

    // ── Process Management (5) ────────────────────────────────────────────

    #[tool(
        description = "List running processes with PID, name, CPU time, memory usage, and handle count. Sortable and filterable."
    )]
    async fn process_list(
        &self,
        Parameters(input): Parameters<ProcessListInput>,
    ) -> Result<CallToolResult, McpError> {
        let limit = input.limit.unwrap_or(50).min(500);
        native!(crate::win32::process::list(
            input.sort_by.as_deref(),
            limit,
            input.filter.as_deref()
        ))
    }

    #[tool(
        description = "Get detailed info on a specific process: full path, command line, owner, threads, modules, start time"
    )]
    async fn process_detail(
        &self,
        Parameters(input): Parameters<ProcessByPid>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::detail(input.pid))
    }

    #[tool(
        description = "Kill/terminate a process by PID. Use with caution: this force-terminates the process."
    )]
    async fn process_kill(
        &self,
        Parameters(input): Parameters<ProcessByPid>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::kill(input.pid))
    }

    #[tool(
        description = "Start a new process with optional arguments and working directory. Returns the new process info."
    )]
    async fn process_start(
        &self,
        Parameters(input): Parameters<ProcessStartInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::start(
            &input.path,
            input.args.as_deref(),
            input.working_dir.as_deref()
        ))
    }

    #[tool(
        description = "Show process tree: all processes with their parent process IDs for hierarchy visualization"
    )]
    async fn process_tree(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::process::tree())
    }

    // ── Service Management (6) ────────────────────────────────────────────

    #[tool(
        description = "List all Windows services with their status, startup type, and display name"
    )]
    async fn service_list(&self) -> Result<CallToolResult, McpError> {
        crate::system_control::run(crate::win32::service::list).await
    }

    #[tool(
        description = "Get detailed info on a specific service: description, dependencies, account, PID"
    )]
    async fn service_detail(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || crate::win32::service::detail(&input.name)).await
    }

    #[tool(description = "Start a stopped Windows service. Requires admin privileges.")]
    async fn service_start(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || crate::win32::service::start(&input.name)).await
    }

    #[tool(description = "Stop a running Windows service. Requires admin privileges.")]
    async fn service_stop(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || crate::win32::service::stop(&input.name)).await
    }

    #[tool(description = "Restart a Windows service. Requires admin privileges.")]
    async fn service_restart(
        &self,
        Parameters(input): Parameters<ServiceNameInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || crate::win32::service::restart(&input.name)).await
    }

    #[tool(
        description = "Change a service's startup type (Automatic, Manual, Disabled). Requires admin."
    )]
    async fn service_set_startup(
        &self,
        Parameters(input): Parameters<ServiceSetStartupInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || {
            crate::win32::service::set_startup(&input.name, &input.startup_type)
        })
        .await
    }

    // ── File System (8) ───────────────────────────────────────────────────

    #[tool(description = "List directory contents with file names, sizes, dates, and attributes")]
    async fn fs_list(
        &self,
        Parameters(input): Parameters<FsListInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || {
            crate::win32::filesystem::list(
                &input.path,
                input.hidden.unwrap_or(false),
                input.recurse.unwrap_or(false),
            )
        })
        .await
    }

    #[tool(
        description = "Search for files by name pattern (supports wildcards) recursively from a root path"
    )]
    async fn fs_search(
        &self,
        Parameters(input): Parameters<FsSearchInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || {
            crate::win32::filesystem::search(&input.path, &input.pattern, input.limit.unwrap_or(50))
        })
        .await
    }

    #[tool(description = "Get detailed file or folder info: size, timestamps, attributes, owner")]
    async fn fs_info(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || crate::win32::filesystem::info(&input.path)).await
    }

    #[tool(description = "Get NTFS permissions (ACL) for a file or directory")]
    async fn fs_permissions(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::system_control::run(move || crate::win32::filesystem::permissions(&input.path)).await
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
        ps!(
            self,
            "Get-SmbShare | Select-Object Name,Path,Description,ShareState,ShareType,CurrentUsers"
        )
    }

    #[tool(description = "Create a new network (SMB) share. Requires admin.")]
    async fn fs_share_create(
        &self,
        Parameters(input): Parameters<FsShareCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        let name = input.name.replace('\'', "''");
        let path = input.path.replace('\'', "''");
        let desc = input
            .description
            .as_deref()
            .unwrap_or("")
            .replace('\'', "''");
        ps!(
            self,
            &format!("New-SmbShare -Name '{name}' -Path '{path}' -Description '{desc}' -FullAccess 'Everyone' | Select-Object Name,Path,Description,ShareState")
        )
    }

    // ── Registry (6) ─────────────────────────────────────────────────────

    #[tool(
        description = "Read a registry key's values. Returns all values under the specified key."
    )]
    async fn registry_read(
        &self,
        Parameters(input): Parameters<RegistryPathInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::registry::read(&input.path))
    }

    #[tool(
        description = "Write/set a registry value. Creates the key if it doesn't exist. Requires admin for HKLM."
    )]
    async fn registry_write(
        &self,
        Parameters(input): Parameters<RegistryWriteInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::registry::write(
            &input.path,
            &input.name,
            &input.value,
            input.value_type.as_deref().unwrap_or("String")
        ))
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
        native!(crate::win32::registry::search(
            &input.path,
            &input.pattern,
            input.limit.unwrap_or(50)
        ))
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

    #[tool(
        description = "Show active TCP/UDP network connections with local/remote addresses, ports, state, and owning process"
    )]
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
            &format!(
                "Resolve-DnsName -Name '{host}' | Select-Object Name,Type,IPAddress,NameHost,TTL"
            )
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

    #[tool(
        description = "Get current network throughput (bytes/sec sent and received per interface)"
    )]
    async fn network_bandwidth(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets,@{N='ReceivedMB';E={[math]::Round($_.ReceivedBytes/1MB,2)}},@{N='SentMB';E={[math]::Round($_.SentBytes/1MB,2)}}")
    }

    // ── Firewall (5) ─────────────────────────────────────────────────────

    #[tool(
        description = "List all Windows Firewall rules with name, direction, action, and enabled status"
    )]
    async fn firewall_rules_list(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::firewall::list())
    }

    #[tool(description = "Create a new Windows Firewall rule. Requires admin.")]
    async fn firewall_rule_create(
        &self,
        Parameters(input): Parameters<FirewallRuleCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        let command = provider_compat::firewall_create(&input);
        let result = crate::runtime::blocking(move || crate::win32::firewall::create(&input)).await;
        match result {
            Ok(value) => {
                tracing::info!(tool = "firewall_rule_create", bytes = value.len(), "native create completed");
                ok(value)
            }
            Err(error) if error.is::<crate::win32::firewall::RequiresDistinctRuleIdentity>() => {
                tracing::info!(tool = "firewall_rule_create", reason = %error, "using NetSecurity for a distinct rule identifier");
                ps!(self, &command)
            }
            Err(error) => {
                tracing::error!(tool = "firewall_rule_create", error = %error, "native create failed");
                err(format!("{error:#}"))
            }
        }
    }

    #[tool(description = "Delete a Windows Firewall rule by display name. Requires admin.")]
    async fn firewall_rule_delete(
        &self,
        Parameters(input): Parameters<FirewallRuleNameInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(command) = provider_compat::firewall_delete(&input.name) {
            return ps!(self, &command);
        }
        native!(crate::win32::firewall::delete(&input.name))
    }

    #[tool(description = "Enable or disable a Windows Firewall rule. Requires admin.")]
    async fn firewall_rule_toggle(
        &self,
        Parameters(input): Parameters<FirewallToggleInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(command) = provider_compat::firewall_toggle(&input.name, input.enabled) {
            return ps!(self, &command);
        }
        native!(crate::win32::firewall::toggle(&input.name, input.enabled))
    }

    #[tool(
        description = "Get Windows Firewall profile status for Domain, Private, and Public networks"
    )]
    async fn firewall_status(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::firewall::status())
    }

    // ── Event Log (4) ────────────────────────────────────────────────────

    #[tool(
        description = "Query Windows Event Log with filters for log name, level, source, event ID, and time range"
    )]
    async fn eventlog_query(
        &self,
        Parameters(input): Parameters<EventLogQueryInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::eventlog::query(&input))
    }

    #[tool(description = "List available event log sources/channels")]
    async fn eventlog_sources(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::eventlog::sources())
    }

    #[tool(description = "Get event log summary statistics by severity for a specific log")]
    async fn eventlog_stats(
        &self,
        Parameters(input): Parameters<EventLogNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::eventlog::stats(&input.log_name))
    }

    #[tool(
        description = "Clear an event log. Requires admin. WARNING: This permanently deletes all events in the log."
    )]
    async fn eventlog_clear(
        &self,
        Parameters(input): Parameters<EventLogNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::eventlog::clear(&input.log_name))
    }

    // ── Scheduled Tasks (6) ──────────────────────────────────────────────

    #[tool(
        description = "List all scheduled tasks with name, state, last run time, and next run time"
    )]
    async fn task_list(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::tasks::list())
    }

    #[tool(
        description = "Get full details of a scheduled task including triggers, actions, and conditions"
    )]
    async fn task_detail(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(command) = provider_compat::task_detail(&input) {
            return ps!(self, &command);
        }
        native!(crate::win32::tasks::detail(
            &input.name,
            input.path.as_deref()
        ))
    }

    #[tool(description = "Create a new scheduled task with a trigger and action")]
    async fn task_create(
        &self,
        Parameters(input): Parameters<TaskCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::tasks::create(&input))
    }

    #[tool(description = "Delete a scheduled task. Requires admin.")]
    async fn task_delete(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(command) = provider_compat::task_delete(&input) {
            return ps!(self, &command);
        }
        native!(crate::win32::tasks::delete(
            &input.name,
            input.path.as_deref()
        ))
    }

    #[tool(description = "Run a scheduled task immediately")]
    async fn task_run(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::tasks::run(&input.name, input.path.as_deref()))
    }

    #[tool(description = "Enable or disable a scheduled task")]
    async fn task_toggle(
        &self,
        Parameters(input): Parameters<TaskNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::tasks::toggle(
            &input.name,
            input.path.as_deref()
        ))
    }

    // ── Installed Software (3) ───────────────────────────────────────────

    #[tool(description = "List installed software with name, version, publisher, and install date")]
    async fn software_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "@(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue) | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,@{N='SizeMB';E={[math]::Round($_.EstimatedSize/1024,1)}} | Sort-Object DisplayName")
    }

    #[tool(
        description = "Get detailed info about a specific installed application (by name substring)"
    )]
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

    #[tool(
        description = "Uninstall software by name. Finds the uninstall string and executes it. Requires admin."
    )]
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

    #[tool(
        description = "List all local user accounts with status, last logon, and group membership"
    )]
    async fn user_list(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::user_list())
    }

    #[tool(
        description = "Get detailed info about a specific local user including group memberships"
    )]
    async fn user_detail(
        &self,
        Parameters(input): Parameters<UserNameInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(command) = provider_compat::user_detail(&input.name) {
            return ps!(self, &command);
        }
        native!(crate::win32::accounts::user_detail(&input.name))
    }

    #[tool(description = "Create a new local user account. Requires admin.")]
    async fn user_create(
        &self,
        Parameters(input): Parameters<UserCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::user_create(&input))
    }

    #[tool(description = "Delete a local user account. Requires admin.")]
    async fn user_delete(
        &self,
        Parameters(input): Parameters<UserNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::user_delete(&input.name))
    }

    #[tool(description = "Modify a local user account's properties. Requires admin.")]
    async fn user_modify(
        &self,
        Parameters(input): Parameters<UserModifyInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::user_modify(&input))
    }

    #[tool(description = "List all local groups")]
    async fn group_list(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::group_list())
    }

    #[tool(description = "List members of a local group")]
    async fn group_members(
        &self,
        Parameters(input): Parameters<GroupNameInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::group_members(&input.name))
    }

    #[tool(description = "Add a user to a local group. Requires admin.")]
    async fn group_add_member(
        &self,
        Parameters(input): Parameters<GroupMemberInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::group_add_member(
            &input.group,
            &input.member
        ))
    }

    #[tool(description = "Remove a user from a local group. Requires admin.")]
    async fn group_remove_member(
        &self,
        Parameters(input): Parameters<GroupMemberInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::accounts::group_remove_member(
            &input.group,
            &input.member
        ))
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

    #[tool(
        description = "Execute arbitrary PowerShell commands. The ultimate escape hatch: run any PowerShell you want."
    )]
    async fn powershell_execute(
        &self,
        Parameters(input): Parameters<PsExecuteInput>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .ps
            .execute_with_timeout(&input.command, input.timeout_ms)
            .await
        {
            Ok(output) => ok(output),
            Err(e) => err(format!("{e:#}")),
        }
    }

    #[tool(description = "Execute a CMD command via cmd.exe")]
    async fn cmd_execute(
        &self,
        Parameters(input): Parameters<CmdExecuteInput>,
    ) -> Result<CallToolResult, McpError> {
        let cmd = input.command.replace('\'', "''");
        match self
            .ps
            .execute_with_timeout(&format!("cmd /c '{cmd}'"), input.timeout_ms)
            .await
        {
            Ok(output) => ok(output),
            Err(e) => err(format!("{e:#}")),
        }
    }

    #[tool(
        description = "Execute a WMI/CIM query. Specify the class name and optional filter/properties."
    )]
    async fn wmi_query(
        &self,
        Parameters(input): Parameters<WmiQueryInput>,
    ) -> Result<CallToolResult, McpError> {
        let class = input.class.replace('\'', "''");
        let ns = input
            .namespace
            .as_deref()
            .unwrap_or("root/cimv2")
            .replace('\'', "''");
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

    #[tool(
        description = "Get per-monitor geometry: bounds rect (virtual screen coordinates), work area, orientation (landscape/portrait/flipped with explicit degrees), refresh rate, bit depth. Also reports the full virtual screen envelope that mouse and screen_capture coordinates live in. Native Win32 via EnumDisplayMonitors + GetMonitorInfoW + EnumDisplaySettingsW."
    )]
    async fn display_info(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::display::info())
    }

    #[tool(description = "List audio playback and recording devices")]
    async fn audio_devices(&self) -> Result<CallToolResult, McpError> {
        native!(crate::win32::audio::devices())
    }

    #[tool(description = "Get or set system audio volume (0-100)")]
    async fn audio_volume(
        &self,
        Parameters(input): Parameters<crate::win32::audio::VolumeInput>,
    ) -> Result<CallToolResult, McpError> {
        native!(crate::win32::audio::volume(&input))
    }

    // ── Performance Monitoring (3) ───────────────────────────────────────

    #[tool(
        description = "Get a system performance snapshot: CPU load, memory usage, disk I/O, and top processes"
    )]
    async fn perf_snapshot(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "$cpu = (Get-CimInstance Win32_Processor).LoadPercentage; $os = Get-CimInstance Win32_OperatingSystem; $mem = [math]::Round(100*(1-$os.FreePhysicalMemory/$os.TotalVisibleMemorySize),1); $disk = Get-Counter '\\PhysicalDisk(_Total)\\% Disk Time' -ErrorAction SilentlyContinue; @{CPU_Percent=$cpu; Memory_Percent=$mem; Memory_UsedMB=[math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/1024); Memory_TotalMB=[math]::Round($os.TotalVisibleMemorySize/1024); Disk_Percent=if($disk){[math]::Round($disk.CounterSamples[0].CookedValue,1)}else{'N/A'}}")
    }

    #[tool(description = "Show top processes by CPU or memory usage")]
    async fn perf_top(
        &self,
        Parameters(input): Parameters<PerfTopInput>,
    ) -> Result<CallToolResult, McpError> {
        let limit = input.limit.unwrap_or(15);
        native!(crate::win32::process::list(
            input.sort_by.as_deref(),
            limit,
            None
        ))
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
    // all native Win32 via SendInput and GDI. No PowerShell in the loop.

    #[tool(
        description = "Capture a screenshot of the full virtual screen (all monitors) or a specific region. Returns the image as JPEG. Coordinates used here match exactly what the mouse tools expect, in virtual screen pixels, which can be negative on multi-monitor setups. Use this to see what's on screen before taking actions."
    )]
    async fn screen_capture(
        &self,
        Parameters(input): Parameters<ScreenCaptureInput>,
    ) -> Result<CallToolResult, McpError> {
        let start = std::time::Instant::now();
        tracing::info!(tool = "screen_capture", "▶ native");

        match crate::runtime::blocking(move || {
            crate::win32::screen::capture(input.x, input.y, input.width, input.height)
        })
        .await
        {
            Ok(image) => {
                let ms = start.elapsed().as_millis();
                tracing::info!(tool = "screen_capture", ms = ms as u64, "✓ native done");
                let metadata = match serde_json::to_value(image.metadata) {
                    Ok(metadata) => metadata,
                    Err(error) => return err(error),
                };
                let mut result = CallToolResult::success(vec![
                    Content::image(image.base64_jpeg, "image/jpeg"),
                    Content::text(metadata.to_string()),
                ]);
                result.structured_content = Some(metadata);
                Ok(result)
            }
            Err(e) => {
                let ms = start.elapsed().as_millis();
                tracing::error!(tool = "screen_capture", ms = ms as u64, err = %e, "✗ native fail");
                err(format!("{e:#}"))
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
        interactive!(crate::win32::input::mouse_move(input.x, input.y))
    }

    #[tool(
        description = "Click a mouse button at the current or specified position. Supports left/right/middle click, single/double/triple click."
    )]
    async fn mouse_click(
        &self,
        Parameters(input): Parameters<MouseClickInput>,
    ) -> Result<CallToolResult, McpError> {
        let count = input.count.unwrap_or(1);
        interactive!(crate::win32::input::mouse_click(
            input.x,
            input.y,
            input.button.as_deref().unwrap_or("left"),
            count
        ))
    }

    #[tool(
        description = "Scroll the mouse wheel at the current or specified position. Positive clicks = scroll up, negative = scroll down."
    )]
    async fn mouse_scroll(
        &self,
        Parameters(input): Parameters<MouseScrollInput>,
    ) -> Result<CallToolResult, McpError> {
        interactive!(crate::win32::input::mouse_scroll(
            input.x,
            input.y,
            input.clicks
        ))
    }

    #[tool(
        description = "Click and drag from one screen position to another. Useful for moving windows, selecting text, drawing, etc."
    )]
    async fn mouse_drag(
        &self,
        Parameters(input): Parameters<MouseDragInput>,
    ) -> Result<CallToolResult, McpError> {
        interactive!(crate::win32::input::mouse_drag(
            input.start_x,
            input.start_y,
            input.end_x,
            input.end_y,
            input.button.as_deref().unwrap_or("left")
        ))
    }

    #[tool(
        description = "Type literal text strings by injecting Unicode character events. Use this ONLY for typing visible text into fields, editors, or documents. NOT for keyboard shortcuts, hotkeys, or special keys. For Ctrl+C, Enter, Escape, Tab, arrow keys, F-keys, or any modifier combo, use keyboard_key instead."
    )]
    async fn keyboard_type(
        &self,
        Parameters(input): Parameters<KeyboardTypeInput>,
    ) -> Result<CallToolResult, McpError> {
        interactive!(crate::win32::input::keyboard_type(&input.text))
    }

    #[tool(
        description = "Press a keyboard shortcut, hotkey, or special key. Use this for ALL non-text key actions: Ctrl+C, Ctrl+V, Ctrl+Z, Ctrl+N, Ctrl+S, Alt+Tab, Alt+F4, Win+D, Enter, Escape, Tab, Backspace, Delete, Space, arrow keys (up/down/left/right), F1-F24, Home, End, PageUp, PageDown, Insert, PrintScreen, or any modifier combo like Ctrl+Shift+S. Format: keys joined with '+' (e.g. 'ctrl+c', 'alt+tab', 'shift+f5'). Single keys work too: 'enter', 'escape', 'b', 'x'. For typing visible text into fields or editors, use keyboard_type instead."
    )]
    async fn keyboard_key(
        &self,
        Parameters(input): Parameters<KeyboardKeyInput>,
    ) -> Result<CallToolResult, McpError> {
        interactive!(crate::win32::input::keyboard_key(&input.keys))
    }

    // ── Windows Update (2) ───────────────────────────────────────────────

    #[tool(
        description = "List installed Windows updates (hotfixes) with KB numbers and install dates"
    )]
    async fn update_list(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | Sort-Object InstalledOn -Descending")
    }

    #[tool(description = "Get Windows Update history including successful and failed updates")]
    async fn update_history(&self) -> Result<CallToolResult, McpError> {
        ps!(self, "$session = New-Object -ComObject Microsoft.Update.Session; $searcher = $session.CreateUpdateSearcher(); $count = $searcher.GetTotalHistoryCount(); $searcher.QueryHistory(0, [Math]::Min($count,50)) | Select-Object Date,Title,@{N='Status';E={switch($_.ResultCode){1{'InProgress'};2{'Succeeded'};3{'SucceededWithErrors'};4{'Failed'};5{'Aborted'}}}},Description | Where-Object Title")
    }
}

// ─── ServerHandler impl ──────────────────────────────────────────────────────
// rmcp signals request cancellation without dropping the handler future.
// Select at the router boundary so every tool releases its operation guards.

impl ServerHandler for MasterControlProgram {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let cancelled = context.ct.clone();
        let call = ToolCallContext::new(self, request, context);
        call_until_cancelled(self.tool_router.call(call), async {
            tokio::select! {
                _ = cancelled.cancelled() => {}
                _ = self.execution_connection_cancel.cancelled() => {}
            }
        })
        .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "MasterControlProgram",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Local Windows control over MCP stdio. Native system administration, \
                 UI Automation, scoped screenshots and OCR, mouse and keyboard input, \
                 ConPTY terminals, owned jobs, event observation, deterministic workflows, \
                 audio, and diagnostics. PowerShell remains available for arbitrary commands. \
                 Persistent lifetimes require an explicitly started local host and explicit \
                 lifetime selection. Windows acceptance does not establish application completion; \
                 inspect reported postconditions, errors, privilege limits, and recording gaps."
                    .to_string(),
            )
    }
}

mod provider_compat {
    fn cim_uses_pattern(value: &str) -> bool {
        // Backticks also need the cmdlet's wildcard parser, even when they escape
        // a character that the native API would otherwise accept literally.
        value.chars().any(|character| matches!(character, '*' | '?' | '[' | ']' | '`'))
    }

    fn local_name_uses_pattern(value: &str) -> bool {
        // LocalAccounts uses ContainsWildcardCharacters before choosing between
        // pattern matching and literal lookup. Its literal branch never unescapes.
        let mut characters = value.chars();
        while let Some(character) = characters.next() {
            if character == '`' {
                let _ = characters.next();
            } else if matches!(character, '*' | '?' | '[' | ']') {
                return true;
            }
        }
        false
    }

    fn literal(value: &str) -> String {
        let mut quoted = String::from("'");
        for character in value.chars() {
            quoted.push(character);
            // PowerShell tokenizes these smart quotes as string delimiters too.
            if matches!(character, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
                quoted.push(character);
            }
        }
        quoted.push('\'');
        quoted
    }

    fn list_literal(value: &str) -> String {
        format!("@({})", value.split(',').map(|part| literal(part.trim())).collect::<Vec<_>>().join(","))
    }

    pub(super) fn firewall_create(input: &super::FirewallRuleCreateInput) -> String {
        let mut command = format!(
            "New-NetFirewallRule -DisplayName {} -Direction {} -Action {} -ErrorAction Stop",
            literal(&input.name), literal(input.direction.trim()), literal(input.action.trim()),
        );
        if let Some(protocol) = &input.protocol {
            command.push_str(&format!(" -Protocol {}", literal(protocol.trim())));
        }
        if let Some(ports) = &input.local_port {
            command.push_str(&format!(" -LocalPort {}", list_literal(ports)));
        }
        if let Some(addresses) = &input.remote_address {
            command.push_str(&format!(" -RemoteAddress {}", list_literal(addresses)));
        }
        if let Some(program) = &input.program {
            command.push_str(&format!(" -Program {}", literal(program)));
        }
        command.push_str(" | Select-Object DisplayName,Direction,Action,Enabled");
        command
    }

    fn firewall_targets(name: &str) -> String {
        format!(
            "$rules = @(Get-NetFirewallRule -DisplayName {} -ErrorAction Stop); \
             if ($rules.Count -eq 0) {{ throw 'No firewall rules match the display-name selector' }}; ",
            literal(name),
        )
    }

    pub(super) fn firewall_delete(name: &str) -> Option<String> {
        cim_uses_pattern(name).then(|| format!(
            "{}$rules | Remove-NetFirewallRule -ErrorAction Stop; \
             @{{Deleted={};Status='Removed';Matched=$rules.Count}}",
            firewall_targets(name), literal(name),
        ))
    }

    pub(super) fn firewall_toggle(name: &str, enabled: bool) -> Option<String> {
        cim_uses_pattern(name).then(|| format!(
            "{}$rules | Set-NetFirewallRule -Enabled {} -PassThru -ErrorAction Stop \
             | Select-Object DisplayName,Enabled,Direction,Action",
            firewall_targets(name), if enabled { "True" } else { "False" },
        ))
    }

    fn task_targets(input: &super::TaskNameInput) -> Option<String> {
        let path = input.path.as_deref().unwrap_or("\\");
        (cim_uses_pattern(&input.name) || cim_uses_pattern(path)).then(|| format!(
            "$tasks = @(Get-ScheduledTask -TaskName {} -TaskPath {} -ErrorAction Stop); \
             if ($tasks.Count -eq 0) {{ throw 'No scheduled tasks match the name/path selector' }}; ",
            literal(&input.name), literal(path),
        ))
    }

    pub(super) fn task_detail(input: &super::TaskNameInput) -> Option<String> {
        task_targets(input).map(|query| format!(
            "{query}$info = @($tasks | Get-ScheduledTaskInfo -ErrorAction Stop); \
             @{{Name=$tasks.TaskName;Path=$tasks.TaskPath;State=$tasks.State; \
             Description=$tasks.Description;Author=$tasks.Author; \
             Triggers=($tasks.Triggers|Select-Object CimClass,Enabled); \
             Actions=($tasks.Actions|Select-Object Execute,Arguments,WorkingDirectory); \
             LastRun=$info.LastRunTime;LastResult=$info.LastTaskResult;NextRun=$info.NextRunTime;Matched=$tasks.Count}}"
        ))
    }

    pub(super) fn task_delete(input: &super::TaskNameInput) -> Option<String> {
        task_targets(input).map(|query| format!(
            "{query}$tasks | Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop; \
             @{{Deleted={};Path={};Status='Removed';Matched=$tasks.Count}}",
            literal(&input.name), literal(input.path.as_deref().unwrap_or("\\")),
        ))
    }

    pub(super) fn user_detail(name: &str) -> Option<String> {
        local_name_uses_pattern(name).then(|| format!(
            "$users = @(Get-LocalUser -Name {} -ErrorAction Stop); \
             if ($users.Count -eq 0) {{ throw 'No local users match the name selector' }}; \
             $memberships = @(Get-LocalGroup -ErrorAction Stop | ForEach-Object {{ \
                 $group = $_; \
                 $sids = @(Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object {{ $_.SID.Value }}); \
                 [pscustomobject]@{{Name=$group.Name;Sids=$sids}} \
             }}); \
             $users | ForEach-Object {{ \
                 $user = $_; \
                 $groups = @($memberships | Where-Object {{ $_.Sids -contains $user.SID.Value }} | Select-Object -ExpandProperty Name); \
                 @{{Name=$user.Name;FullName=$user.FullName;Enabled=$user.Enabled;LastLogon=$user.LastLogon; \
                 PasswordRequired=$user.PasswordRequired;PasswordLastSet=$user.PasswordLastSet; \
                 PasswordExpires=$user.PasswordExpires;Description=$user.Description;SID=$user.SID.Value;Groups=$groups}} \
             }}",
            literal(name),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn create_input() -> crate::server::FirewallRuleCreateInput {
            crate::server::FirewallRuleCreateInput {
                name: "Example".into(),
                direction: "Inbound".into(),
                action: "Allow".into(),
                protocol: Some("TCP".into()),
                local_port: Some("80, 443,1000-2000".into()),
                remote_address: Some("192.0.2.1, 198.51.100.0/24".into()),
                program: Some(r"C:\Program Files\Example.exe".into()),
            }
        }

        #[test]
        fn exact_selectors_stay_native_and_patterns_use_the_cmdlet_parser() {
            for name in ["Example", "O'Brien", "R\u{e8}gle"] {
                assert!(!cim_uses_pattern(name));
                assert!(firewall_delete(name).is_none());
                assert!(firewall_toggle(name, true).is_none());
                assert!(user_detail(name).is_none());
                let input = crate::server::TaskNameInput { name: name.into(), path: None };
                assert!(task_detail(&input).is_none());
                assert!(task_delete(&input).is_none());
            }
            for name in ["Example*", "A?B", "[AB]C", "A]B", "literal`*", "literal``name"] {
                assert!(cim_uses_pattern(name));
                assert!(firewall_delete(name).is_some());
                assert!(firewall_toggle(name, false).is_some());
                let input = crate::server::TaskNameInput { name: name.into(), path: None };
                for command in [task_detail(&input).unwrap(), task_delete(&input).unwrap()] {
                    assert!(command.contains("-TaskPath '\\'"));
                }
            }
            let input = crate::server::TaskNameInput { name: "Example".into(), path: Some("\\Vendor*\\Jobs\\".into()) };
            assert!(task_detail(&input).unwrap().contains("-TaskPath '\\Vendor*\\Jobs\\'"));
            assert!(task_delete(&input).unwrap().contains("-TaskPath '\\Vendor*\\Jobs\\'"));
        }

        #[test]
        fn local_name_patterns_preserve_literal_backtick_lookup() {
            for name in ["a`*b", "a`?b", "a`[b", "a`]b", "a``b", "a`xb", "a`"] {
                assert!(!local_name_uses_pattern(name), "{name}");
                assert!(user_detail(name).is_none());
                assert!(cim_uses_pattern(name));
            }
            for name in ["a*b", "a?b", "a[b", "a]b", "a``*b", "a`*b*"] {
                assert!(local_name_uses_pattern(name), "{name}");
                assert!(user_detail(name).is_some());
            }
        }

        #[test]
        fn routes_without_legacy_pattern_support_and_default_reads_stay_native() {
            let source = include_str!("server.rs");
            for tool in [
                "task_run", "task_toggle", "task_create", "user_create", "user_delete",
                "user_modify", "group_members", "group_add_member", "group_remove_member",
                "firewall_rules_list", "firewall_status", "task_list", "user_list", "group_list",
            ] {
                let signature = format!("async fn {tool}(");
                let body = source.split_once(&signature).unwrap().1.split("#[tool").next().unwrap();
                assert!(body.contains("native!("), "{tool}");
                assert!(!body.contains("provider_compat::"), "{tool}");
            }
        }

        #[test]
        fn duplicate_create_quotes_every_value_and_leaves_name_allocation_to_netsecurity() {
            let mut input = create_input();
            input.name = "O'Brien\u{2019}; $(throw 'not code')\r\n`*".into();
            let command = firewall_create(&input);
            assert!(command.contains(&format!("-DisplayName {}", literal(&input.name))));
            assert!(command.contains("-LocalPort @('80','443','1000-2000')"));
            assert!(command.contains("-RemoteAddress @('192.0.2.1','198.51.100.0/24')"));
            assert!(command.contains("-Program 'C:\\Program Files\\Example.exe'"));
            assert!(command.contains("-ErrorAction Stop"));
            assert!(!command.contains(" -Name "));
            assert!(!command.contains(" -Force"));
            assert_eq!(literal("'\u{2018}\u{2019}\u{201a}\u{201b}"),
                "'''\u{2018}\u{2018}\u{2019}\u{2019}\u{201a}\u{201a}\u{201b}\u{201b}'");
        }

        const FIREWALL_MOCKS: &str = r#"
            $global:McpCompatWrites = @()
            $global:McpCompatBound = $null
            function Get-NetFirewallRule {
                [CmdletBinding()] param([string]$DisplayName)
                if ($DisplayName -eq 'none*') { return }
                if ($DisplayName -eq 'read-error*') { Write-Error 'mock native query denied'; return }
                [pscustomobject]@{Name='fixture-one';DisplayName=$DisplayName;Direction='Inbound';Action='Allow';Enabled=$false}
                [pscustomobject]@{Name='fixture-two';DisplayName=$DisplayName;Direction='Outbound';Action='Block';Enabled=$false}
            }
            function New-NetFirewallRule {
                [CmdletBinding()] param([string]$DisplayName,[string]$Name,[string]$Direction,
                    [string]$Action,[string]$Protocol,[string[]]$LocalPort,
                    [string[]]$RemoteAddress,[string]$Program)
                if ($PSBoundParameters.ContainsKey('Name')) { throw 'mock unique identifier was overridden' }
                $global:McpCompatBound = @{
                    DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Protocol=$Protocol
                    LocalPort=$LocalPort;RemoteAddress=$RemoteAddress;Program=$Program
                }
                $global:McpCompatWrites += 'create'
                [pscustomobject]@{DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Enabled=$true}
            }
            function Remove-NetFirewallRule {
                [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject)
                process { $global:McpCompatWrites += $InputObject.Name }
            }
            function Set-NetFirewallRule {
                [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject,[string]$Enabled,[switch]$PassThru)
                process {
                    $global:McpCompatWrites += $InputObject.Name
                    if ($InputObject.DisplayName -eq 'write-error*') { Write-Error 'mock native write denied'; return }
                    $InputObject.Enabled = [bool]::Parse($Enabled)
                    if ($PassThru) { $InputObject }
                }
            }
        "#;

        #[tokio::test]
        #[ignore = "Requires pwsh; every firewall cmdlet is mocked and no real rules are changed"]
        async fn firewall_pool_fallbacks_preserve_arguments_multi_match_and_failure() -> anyhow::Result<()> {
            let pool = crate::ps::Pool::new(1).await?;
            let mut input = create_input();
            input.name = "O'Brien\u{2018}\u{2019}\u{201a}\u{201b};$(throw 'injected')\r\nliteral`*".into();
            let command = firewall_create(&input);
            let result = pool.exec_json(&format!("{FIREWALL_MOCKS}; {command}")).await?;
            assert_eq!(result["DisplayName"], input.name);
            let bound = pool.exec_json("$global:McpCompatBound").await?;
            assert_eq!(bound["LocalPort"], serde_json::json!(["80", "443", "1000-2000"]));
            assert_eq!(bound["RemoteAddress"], serde_json::json!(["192.0.2.1", "198.51.100.0/24"]));
            assert_eq!(bound["Program"], input.program.unwrap());

            let command = firewall_delete("MCP-fixture*").unwrap();
            let result = pool.exec_json(&format!("{FIREWALL_MOCKS}; {command}")).await?;
            assert_eq!(result["Matched"], 2);
            assert_eq!(result["Status"], "Removed");
            assert_eq!(pool.exec_json("$global:McpCompatWrites").await?,
                serde_json::json!(["fixture-one", "fixture-two"]));

            let command = firewall_toggle("MCP-fixture*", true).unwrap();
            let result = pool.exec_json(&format!("{FIREWALL_MOCKS}; {command}")).await?;
            assert_eq!(result.as_array().unwrap().len(), 2);
            assert!(result.as_array().unwrap().iter().all(|rule| rule["Enabled"] == true));

            for (pattern, expected, writes) in [
                ("none*", "No firewall rules match", 0),
                ("read-error*", "mock native query denied", 0),
                ("write-error*", "mock native write denied", 1),
            ] {
                let command = firewall_toggle(pattern, true).unwrap();
                // A failed pool command recycles its worker, so observe mock writes
                // in the same invocation rather than querying a replacement worker.
                let observed = pool.exec_json(&format!(
                    "{FIREWALL_MOCKS}; try {{ {command}; throw 'fixture expected failure' }} \
                     catch {{ @{{error=$_.Exception.Message;writes=$global:McpCompatWrites.Count}} }}"
                )).await?;
                assert!(observed["error"].as_str().unwrap().contains(expected), "{observed}");
                assert_eq!(observed["writes"], writes);
            }
            Ok(())
        }

        const TASK_MOCKS: &str = r#"
            $global:McpCompatWrites = @()
            $global:McpCompatBound = $null
            function Get-ScheduledTask {
                [CmdletBinding()] param([string]$TaskName,[string]$TaskPath)
                $global:McpCompatBound = @{Name=$TaskName;Path=$TaskPath}
                if ($TaskName -eq 'none*') { return }
                if ($TaskName -eq 'read-error*') { Write-Error 'mock task query denied'; return }
                foreach ($number in 1,2) {
                    [pscustomobject]@{
                        TaskName="fixture-$number";TaskPath=$TaskPath;State='Ready';Description='fixture';Author='fixture'
                        Triggers=@([pscustomobject]@{CimClass='Once';Enabled=$true})
                        Actions=@([pscustomobject]@{Execute='fixture.exe';Arguments='fixture';WorkingDirectory='C:\fixture'})
                        FailWrite=($TaskName -eq 'write-error*')
                    }
                }
            }
            function Get-ScheduledTaskInfo {
                [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject)
                process { [pscustomobject]@{LastRunTime='last';LastTaskResult=0;NextRunTime='next'} }
            }
            function Unregister-ScheduledTask {
                [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject,[bool]$Confirm)
                process {
                    if (!$PSBoundParameters.ContainsKey('Confirm') -or $Confirm) { throw 'mock deletion must not prompt' }
                    $global:McpCompatWrites += $InputObject.TaskName
                    if ($InputObject.FailWrite) { Write-Error 'mock task deletion denied' }
                }
            }
        "#;

        #[tokio::test]
        #[ignore = "Requires pwsh; every task cmdlet is mocked and no real tasks are changed"]
        async fn task_pool_fallbacks_preserve_paths_multi_match_and_failure() -> anyhow::Result<()> {
            let pool = crate::ps::Pool::new(1).await?;
            let mut input = crate::server::TaskNameInput { name: "fixture*".into(), path: None };
            let command = task_detail(&input).unwrap();
            let result = pool.exec_json(&format!("{TASK_MOCKS}; {command}")).await?;
            assert_eq!(result["Name"], serde_json::json!(["fixture-1", "fixture-2"]));
            assert_eq!(result["Matched"], 2);
            assert_eq!(result["LastResult"], serde_json::json!([0, 0]));
            assert_eq!(result["Actions"][0]["Execute"], "fixture.exe");
            assert_eq!(pool.exec_json("$global:McpCompatBound.Path").await?, "\\");

            input.name = "O'Brien\u{2019};$(throw 'injected')\r\n*".into();
            input.path = Some("\\Vendor`*\\[AB]Jobs\\O'Brien\\".into());
            let command = task_delete(&input).unwrap();
            let result = pool.exec_json(&format!("{TASK_MOCKS}; {command}")).await?;
            assert_eq!(result["Matched"], 2);
            assert_eq!(result["Deleted"], input.name);
            assert_eq!(result["Path"], input.path.as_deref().unwrap());
            assert_eq!(pool.exec_json("$global:McpCompatWrites").await?,
                serde_json::json!(["fixture-1", "fixture-2"]));
            let bound = pool.exec_json("$global:McpCompatBound").await?;
            assert_eq!(bound["Name"], input.name);
            assert_eq!(bound["Path"], input.path.as_deref().unwrap());

            for (name, expected, writes) in [
                ("none*", "No scheduled tasks match", 0),
                ("read-error*", "mock task query denied", 0),
                ("write-error*", "mock task deletion denied", 1),
            ] {
                input.name = name.into();
                let command = task_delete(&input).unwrap();
                let observed = pool.exec_json(&format!(
                    "{TASK_MOCKS}; try {{ {command}; throw 'fixture expected failure' }} \
                     catch {{ @{{error=$_.Exception.Message;writes=$global:McpCompatWrites.Count}} }}"
                )).await?;
                assert!(observed["error"].as_str().unwrap().contains(expected), "{observed}");
                assert_eq!(observed["writes"], writes);
            }
            Ok(())
        }

        const ACCOUNT_MOCKS: &str = r#"
            $global:McpCompatBound = $null
            $script:McpCompatGroupFailure = $false
            function Get-LocalUser {
                [CmdletBinding()] param([string]$Name)
                $global:McpCompatBound = $Name
                if ($Name -eq 'none*') { return }
                if ($Name -eq 'read-error*') { Write-Error 'mock user query denied'; return }
                if ($Name -eq 'group-error*') { $script:McpCompatGroupFailure = $true }
                [pscustomobject]@{Name='alex';FullName='Alex';Enabled=$true;SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'}}
                [pscustomobject]@{Name='lex';FullName='Lex';Enabled=$false;SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1002'}}
            }
            function Get-LocalGroup {
                [CmdletBinding()] param()
                [pscustomobject]@{Name='group-one'}
                [pscustomobject]@{Name='group-two'}
            }
            function Get-LocalGroupMember {
                [CmdletBinding()] param($Group)
                if ($script:McpCompatGroupFailure) { Write-Error 'mock membership query denied'; return }
                if ($Group.Name -eq 'group-one') {
                    [pscustomobject]@{Name='HOST\unrelated-name';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'}}
                } else {
                    [pscustomobject]@{Name='HOST\alex';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1002'}}
                }
            }
        "#;

        #[tokio::test]
        #[ignore = "Requires pwsh; every account cmdlet is mocked and no real accounts are changed"]
        async fn user_pool_fallbacks_keep_sid_membership_and_surface_lookup_errors() -> anyhow::Result<()> {
            let pool = crate::ps::Pool::new(1).await?;
            let name = "O'Brien\u{2019};$(throw 'injected')\r\n*";
            let command = user_detail(name).unwrap();
            let result = pool.exec_json(&format!("{ACCOUNT_MOCKS}; {command}")).await?;
            assert_eq!(pool.exec_json("$global:McpCompatBound").await?, name);
            assert_eq!(result.as_array().unwrap().len(), 2);
            assert_eq!(result[0]["Name"], "alex");
            assert_eq!(result[0]["SID"], "S-1-5-21-1-2-3-1001");
            assert_eq!(result[0]["Groups"], serde_json::json!(["group-one"]));
            assert_eq!(result[1]["Name"], "lex");
            assert_eq!(result[1]["Groups"], serde_json::json!(["group-two"]));

            for (name, expected) in [
                ("none*", "No local users match"),
                ("read-error*", "mock user query denied"),
                ("group-error*", "mock membership query denied"),
            ] {
                let command = user_detail(name).unwrap();
                let error = pool.exec_json(&format!("{ACCOUNT_MOCKS}; {command}")).await.unwrap_err();
                assert!(error.to_string().contains(expected), "{error:#}");
            }
            Ok(())
        }

        #[tokio::test]
        #[ignore = "Requires pwsh and installed Windows providers; queries real tasks/users without changing them"]
        async fn read_only_pool_patterns_match_existing_tasks_and_users() -> anyhow::Result<()> {
            let pool = crate::ps::Pool::new(1).await?;
            let pattern = |name: &str| {
                let mut value = String::new();
                for character in name.chars() {
                    if matches!(character, '*' | '?' | '[' | ']' | '`') {
                        value.push('`');
                    }
                    value.push(character);
                }
                value.push('*');
                value
            };
            let task = pool.exec_json(
                r"Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Select-Object -First 1 TaskName,TaskPath",
            ).await?;
            if let (Some(name), Some(path)) = (task["TaskName"].as_str(), task["TaskPath"].as_str()) {
                let input = crate::server::TaskNameInput { name: pattern(name), path: Some(path.into()) };
                let result = pool.exec_json(&task_detail(&input).unwrap()).await?;
                let found = &result["Name"];
                assert!(found == name || found.as_array().is_some_and(|names| names.iter().any(|value| value == name)));
                assert!(result["Matched"].as_u64().is_some_and(|count| count > 0));
            } else {
                eprintln!("Task selector read-only probe unavailable: no registered tasks in the default root folder");
            }
            let user = pool.exec_json(
                "Get-LocalUser -ErrorAction Stop | Select-Object -First 1 Name,@{N='SID';E={$_.SID.Value}}",
            ).await?;
            if let (Some(name), Some(sid)) = (user["Name"].as_str(), user["SID"].as_str()) {
                let result = pool.exec_json(&user_detail(&pattern(name)).unwrap()).await?;
                let rows = match &result {
                    serde_json::Value::Array(rows) => rows.as_slice(),
                    row => std::slice::from_ref(row),
                };
                assert!(rows.iter().any(|row| row["Name"] == name && row["SID"] == sid));
                assert!(rows.iter().all(|row| row["Groups"].is_array()));
            } else {
                eprintln!("User selector read-only probe unavailable: no local users returned");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_tools_keep_existing_names_and_read_only_audio_defaults() {
        let tools = super::MasterControlProgram::tool_router()
            + super::MasterControlProgram::provider_router();
        for name in [
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
            "user_list",
            "user_detail",
            "user_create",
            "user_delete",
            "user_modify",
            "group_list",
            "group_members",
            "group_add_member",
            "group_remove_member",
            "audio_devices",
            "audio_volume",
            "audio_meter",
            "audio_sessions",
            "audio_session_volume",
            "audio_record",
        ] {
            assert!(tools.get(name).is_some(), "Missing provider tool {name}");
        }
        let volume = tools.get("audio_volume").unwrap();
        assert!(volume
            .input_schema
            .get("required")
            .is_none_or(|value| value.as_array().unwrap().is_empty()));
        let recording = tools.get("audio_record").unwrap();
        let required = recording.input_schema["required"].as_array().unwrap();
        for field in ["mode", "duration_seconds", "path"] {
            assert!(required.iter().any(|value| value == field));
        }
    }

    #[test]
    fn shell_timeouts_preserve_numeric_string_inputs_and_legacy_calls() {
        let ps: super::PsExecuteInput =
            serde_json::from_str(r#"{"command":"1","timeout_ms":"4000"}"#).unwrap();
        let cmd: super::CmdExecuteInput =
            serde_json::from_str(r#"{"command":"echo ok","timeout_ms":4000}"#).unwrap();
        assert_eq!(ps.timeout_ms, Some(4000));
        assert_eq!(cmd.timeout_ms, Some(4000));
        let legacy: super::PsExecuteInput = serde_json::from_str(r#"{"command":"1"}"#).unwrap();
        assert_eq!(legacy.timeout_ms, None);
        assert!(serde_json::from_str::<super::CmdExecuteInput>(
            r#"{"command":"echo ok","timeout_ms":-1}"#
        )
        .is_err());
    }

    #[test]
    fn input_coordinates_counts_and_wheel_clicks_keep_numeric_coercion() {
        let movement: super::MouseMoveInput =
            serde_json::from_str(r#"{"x":"-2147483648","y":"2147483647"}"#).unwrap();
        assert_eq!((movement.x, movement.y), (i32::MIN, i32::MAX));
        let click: super::MouseClickInput =
            serde_json::from_str(r#"{"x":"-1920","y":"-100","count":"0"}"#).unwrap();
        assert_eq!(
            (click.x, click.y, click.count),
            (Some(-1920), Some(-100), Some(0))
        );
        let scroll: super::MouseScrollInput = serde_json::from_str(r#"{"clicks":"-2"}"#).unwrap();
        assert_eq!(scroll.clicks, -2);
        assert!(scroll.x.is_none() && scroll.y.is_none());
    }

    /// The tool #99 problem. Every one of these injects input at the seat, so
    /// reaching one through plain `native!` means the machine gets driven with
    /// no glow and nobody watching the desktop is told. Nothing else in the
    /// type system catches that, so catch it here.
    #[test]
    fn every_input_tool_pulses_the_overlay() {
        let src = include_str!("server.rs");
        for tool in [
            "mouse_move",
            "mouse_click",
            "mouse_scroll",
            "mouse_drag",
            "keyboard_type",
            "keyboard_key",
        ] {
            assert!(
                !src.contains(&format!("native!(crate::win32::input::{tool}")),
                "{tool} is wired through native! instead of interactive!,                  so it will drive the machine without lighting the glow"
            );
            assert!(
                src.contains(&format!("interactive!(crate::win32::input::{tool}")),
                "{tool} no longer goes through interactive!, so the activity                  glow has silently stopped covering it"
            );
        }
    }

    #[test]
    fn passive_capture_uses_blocking_runtime_without_glow() {
        let src = include_str!("server.rs");
        let capture = src
            .split("async fn screen_capture(")
            .nth(1)
            .unwrap()
            .split("async fn cursor_position(")
            .next()
            .unwrap();
        assert!(capture.contains("crate::runtime::blocking(move ||"));
        assert!(!capture.contains("overlay::pulse()"));
        assert!(!capture.contains("runtime::interactive("));
    }

    #[tokio::test]
    async fn request_cancellation_drops_the_inflight_tool_future() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let observed = dropped.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(super::call_until_cancelled(
            async move {
                let _guard = Guard(observed);
                started_tx.send(()).unwrap();
                std::future::pending().await
            },
            async move {
                cancel_rx.await.unwrap();
            },
        ));
        started_rx.await.unwrap();
        cancel_tx.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap().is_error, Some(true));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn already_cancelled_request_does_not_start_a_tool() {
        let result = super::call_until_cancelled(
            async {
                panic!("cancelled request executed");
            },
            std::future::ready(()),
        )
        .await
        .unwrap();
        assert_eq!(result.is_error, Some(true));
    }
}
