mod debugger;
mod dump;
mod handles;
mod native;
#[cfg(test)]
mod smoke;
mod stacks;
mod waits;

use std::future::Future;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rmcp::{
    handler::server::wrapper::Parameters, model::CallToolResult, schemars, service::RequestContext,
    tool, tool_router, ErrorData as McpError, RoleServer,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

use crate::server::{err, ok, MasterControlProgram};
pub(crate) use debugger::DiagnosticsManager;
use native::{CancelOnDrop, Deadline, Process};

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct TargetInput {
    #[serde(deserialize_with = "crate::coerce::num")]
    pub pid: u32,
    #[schemars(
        description = "Exact FILETIME creation_time returned by diagnostics_process, accepts numeric string. Required to reject PID reuse."
    )]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub creation_time: u64,
}

#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DumpKind {
    #[default]
    Mini,
    Full,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DumpInput {
    #[serde(flatten)]
    pub target: TargetInput,
    #[schemars(
        description = "New absolute local drive path. Existing files, device paths, streams, and network shares are rejected."
    )]
    pub path: String,
    #[serde(default)]
    pub kind: DumpKind,
    #[serde(default)]
    pub include_handles: bool,
    #[schemars(description = "Maximum artifact bytes, 1048576-2147483648, default 268435456.")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_bytes: Option<u64>,
    #[schemars(
        description = "Cooperative deadline, 1-120000 ms, default 30000. Native provider calls cannot be forcibly terminated."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StacksInput {
    #[serde(flatten)]
    pub target: TargetInput,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub thread_id: Option<u32>,
    #[schemars(description = "1-256 threads, default 32.")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_threads: Option<usize>,
    #[schemars(description = "1-256 frames per thread, default 64.")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_frames: Option<usize>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitChainInput {
    #[serde(flatten)]
    pub target: TargetInput,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub thread_id: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_threads: Option<usize>,
    #[schemars(description = "Follow wait ownership into other processes. Default false.")]
    #[serde(default)]
    pub follow_owners: bool,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HandlesInput {
    #[serde(flatten)]
    pub target: TargetInput,
    #[schemars(
        description = "1-4096 results, default 256. Captured handle metadata only, no potentially blocking object-name queries."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<usize>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    #[default]
    Connection,
    Persistent,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugAttachInput {
    #[serde(flatten)]
    pub target: TargetInput,
    #[schemars(
        description = "connection (default) detaches on disconnect; persistent requires an explicitly started local resident host. Neither survives reboot."
    )]
    #[serde(default)]
    pub lifetime: Lifetime,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub event_capacity: Option<usize>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugLaunchInput {
    #[schemars(
        description = "Absolute executable path, launched directly without a shell. Only this process is debugged, not its children."
    )]
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub lifetime: Lifetime,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub event_capacity: Option<usize>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugSessionInput {
    pub id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugActionInput {
    pub id: String,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContinueDisposition {
    #[default]
    Default,
    Handled,
    NotHandled,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugContinueInput {
    pub id: String,
    #[schemars(
        description = "Exact stop_id from debug_inspect or the stopped event. Rejects stale/double continuations."
    )]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub stop_id: u64,
    #[schemars(
        description = "Default handles debugger-owned breaks and passes other exceptions to the target. Explicit handled suppresses that exception."
    )]
    #[serde(default)]
    pub disposition: ContinueDisposition,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugEventsInput {
    pub id: String,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub after_cursor: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum InspectionCommand {
    Threads,
    Modules,
    Registers {
        #[serde(deserialize_with = "crate::coerce::num")]
        thread_id: u32,
    },
    ReadMemory {
        #[schemars(
            description = "Unsigned numeric address, accepts decimal numeric strings. Use debug_evaluate to resolve a register/hex expression."
        )]
        #[serde(deserialize_with = "crate::coerce::num")]
        address: u64,
        #[serde(deserialize_with = "crate::coerce::num")]
        length: usize,
    },
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugCommandInput {
    pub id: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub stop_id: u64,
    #[serde(flatten)]
    pub command: InspectionCommand,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebugEvaluateInput {
    pub id: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub stop_id: u64,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub thread_id: u32,
    #[schemars(
        description = "Read-only expression: unsigned decimal, 0x hexadecimal, or @register, optionally + or - an unsigned constant. No calls, memory writes, or scripting."
    )]
    pub expression: String,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

fn bounded(
    value: Option<usize>,
    default: usize,
    min: usize,
    max: usize,
    name: &str,
) -> Result<usize> {
    let value = value.unwrap_or(default);
    if !(min..=max).contains(&value) {
        bail!("{name} must be between {min} and {max}");
    }
    Ok(value)
}

fn response<T: Serialize>(result: Result<T>) -> Result<CallToolResult, McpError> {
    match result.and_then(|value| serde_json::to_string(&value).map_err(Into::into)) {
        Ok(value) => ok(value),
        Err(error) => err(format!("{error:#}")),
    }
}

async fn blocking<T, F>(
    context: RequestContext<RoleServer>,
    timeout_ms: Option<u64>,
    work: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Deadline) -> Result<T> + Send + 'static,
{
    static CAPACITY: Semaphore = Semaphore::const_new(4);
    let deadline = Deadline::new(timeout_ms.unwrap_or(30_000))?;
    let _cancel = CancelOnDrop(deadline.clone());
    let permit = tokio::select! {
        biased;
        _ = context.ct.cancelled() => bail!("diagnostic operation canceled before execution"),
        permit = tokio::time::timeout(deadline.remaining(), CAPACITY.acquire()) =>
            permit.context("diagnostics capacity deadline exceeded")??,
    };
    let operation = deadline.clone();
    let mut task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation.check()?;
        work(operation)
    });
    tokio::select! {
        result = &mut task => result.context("diagnostics native worker failed")?,
        _ = context.ct.cancelled() => {
            deadline.cancel();
            // Do not acknowledge cancellation while a worker still owns a
            // suspension or native callback buffer. Future drop also cancels.
            let outcome = task.await.context("diagnostics cleanup worker failed")?;
            match outcome {
                Ok(_) => bail!("diagnostic operation canceled; native cleanup completed"),
                Err(error) => bail!("diagnostic operation canceled; worker finished: {error:#}"),
            }
        }
    }
}

async fn request<T, F, Fut>(
    context: RequestContext<RoleServer>,
    timeout_ms: Option<u64>,
    work: F,
) -> Result<T>
where
    F: FnOnce(Deadline) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let deadline = Deadline::new(timeout_ms.unwrap_or(10_000))?;
    let _cancel = CancelOnDrop(deadline.clone());
    tokio::select! {
        biased;
        _ = context.ct.cancelled() => bail!("debugger request canceled; inspect session/events before repeating a mutating command"),
        result = tokio::time::timeout(deadline.remaining(), work(deadline.clone())) =>
            result.context("debugger request timed out; inspect session/events before repeating a mutating command")?,
    }
}

#[tool_router(router = diagnostics_router, vis = "pub(crate)")]
impl MasterControlProgram {
    #[tool(
        description = "Read exact native process identity: PID, creation FILETIME, session, architecture, protection and token privileges. Use creation_time as a precondition for diagnostics/debug attach."
    )]
    async fn diagnostics_process(
        &self,
        Parameters(input): Parameters<crate::server::ProcessByPid>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            blocking(context, Some(10_000), move |_| {
                Ok(Process::open(input.pid, None, PROCESS_ACCESS_RIGHTS(0))?.identity)
            })
            .await,
        )
    }

    #[tool(
        description = "Write a native MiniDumpWriteDump artifact to a fresh exclusive local file, with bounded bytes, cancellation and exact target identity. Returns captured flags and flushed file size."
    )]
    async fn process_dump(
        &self,
        Parameters(input): Parameters<DumpInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            blocking(context, input.timeout_ms, move |deadline| {
                dump::capture(input, deadline)
            })
            .await,
        )
    }

    #[tool(
        description = "Capture bounded native user-mode thread stacks using DbgHelp. Each suspended thread is resumed exactly once. Supports matching architectures and x64-to-WOW64, reports partial/unavailable unwinds."
    )]
    async fn process_stacks(
        &self,
        Parameters(input): Parameters<StacksInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            blocking(context, input.timeout_ms, move |deadline| {
                stacks::capture(input, deadline)
            })
            .await,
        )
    }

    #[tool(
        description = "Inspect native asynchronous WCT wait chains, cycles and inaccessible owners. Results are observations, not demonstrated failure causes."
    )]
    async fn process_wait_chain(
        &self,
        Parameters(input): Parameters<WaitChainInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            blocking(context, input.timeout_ms, move |deadline| {
                waits::capture(input, deadline)
            })
            .await,
        )
    }

    #[tool(
        description = "Inspect process handles through supported Windows PSS snapshots: types, access masks, reference counts and related process/thread IDs. No blocking file/device name resolution."
    )]
    async fn process_handles(
        &self,
        Parameters(input): Parameters<HandlesInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            blocking(context, input.timeout_ms, move |deadline| {
                handles::capture(input, deadline)
            })
            .await,
        )
    }

    #[tool(
        description = "Attach an addressable native debugger session to an exact process identity. Existing targets are never killed on detach/disconnect. Persistent lifetime requires an explicitly running local host."
    )]
    async fn debug_attach(
        &self,
        Parameters(input): Parameters<DebugAttachInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let manager = Arc::clone(&self.diagnostics);
        response(
            request(context, input.timeout_ms, |deadline| {
                manager.attach(input, &self.diagnostics_connection, deadline)
            })
            .await,
        )
    }

    #[tool(
        description = "Launch an executable directly under a native debugger thread. Only this process is owned/debugged. stdin/stdout/stderr go to NUL, never MCP pipes; OutputDebugString events are captured. No shell or automatic replay."
    )]
    async fn debug_launch(
        &self,
        Parameters(input): Parameters<DebugLaunchInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let manager = Arc::clone(&self.diagnostics);
        response(
            request(context, input.timeout_ms, |deadline| {
                manager.launch(input, &self.diagnostics_connection, deadline)
            })
            .await,
        )
    }

    #[tool(
        description = "List this connection's debugger sessions and explicitly persistent sessions retained by the local host."
    )]
    async fn debug_list(&self) -> Result<CallToolResult, McpError> {
        response(self.diagnostics.list(&self.diagnostics_connection))
    }

    #[tool(
        description = "Inspect debugger state, exact target, ownership, current stop_id, exit status and failures. Running/accepted does not mean the target application completed an action."
    )]
    async fn debug_inspect(
        &self,
        Parameters(input): Parameters<DebugSessionInput>,
    ) -> Result<CallToolResult, McpError> {
        response(
            self.diagnostics
                .inspect(&input.id, &self.diagnostics_connection),
        )
    }

    #[tool(
        description = "Read bounded debugger event/output history by cursor, including explicit retention gaps. No history before attach/launch is reconstructed."
    )]
    async fn debug_events(
        &self,
        Parameters(input): Parameters<DebugEventsInput>,
    ) -> Result<CallToolResult, McpError> {
        response(self.diagnostics.events(input, &self.diagnostics_connection))
    }

    #[tool(
        description = "Continue the exact stopped debug event. Default disposition handles debugger breaks and passes application exceptions through. Reports native event continuation, not application completion."
    )]
    async fn debug_continue(
        &self,
        Parameters(input): Parameters<DebugContinueInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            request(context, input.timeout_ms, |deadline| {
                self.diagnostics.command(
                    &input.id,
                    &self.diagnostics_connection,
                    debugger::Command::Continue {
                        stop_id: input.stop_id,
                        disposition: input.disposition,
                    },
                    deadline,
                )
            })
            .await,
        )
    }

    #[tool(
        description = "Request a native break of a running debug target. Inspect state/events to observe the resulting stop; command acceptance is not a stopped-state observation."
    )]
    async fn debug_break(
        &self,
        Parameters(input): Parameters<DebugActionInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            request(context, input.timeout_ms, |deadline| {
                self.diagnostics.command(
                    &input.id,
                    &self.diagnostics_connection,
                    debugger::Command::Break,
                    deadline,
                )
            })
            .await,
        )
    }

    #[tool(
        description = "Continue any intentionally stopped event with its default exception disposition and detach the native debugger. Does not terminate either attached or launched targets."
    )]
    async fn debug_detach(
        &self,
        Parameters(input): Parameters<DebugActionInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            request(context, input.timeout_ms, |deadline| {
                self.diagnostics.command(
                    &input.id,
                    &self.diagnostics_connection,
                    debugger::Command::Detach,
                    deadline,
                )
            })
            .await,
        )
    }

    #[tool(
        description = "Explicitly terminate only a process launched by this debugger session. Rejects attached/unowned processes. Inspect events for the observed exit; does not claim to terminate child trees."
    )]
    async fn debug_terminate(
        &self,
        Parameters(input): Parameters<DebugActionInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            request(context, input.timeout_ms, |deadline| {
                self.diagnostics.command(
                    &input.id,
                    &self.diagnostics_connection,
                    debugger::Command::Terminate,
                    deadline,
                )
            })
            .await,
        )
    }

    #[tool(
        description = "Run a typed, read-only native debugger inspection while stopped: threads, modules, registers, or bounded read_memory (base64 bytes). Requires the exact stop_id."
    )]
    async fn debug_command(
        &self,
        Parameters(input): Parameters<DebugCommandInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            request(context, input.timeout_ms, |deadline| {
                self.diagnostics.command(
                    &input.id,
                    &self.diagnostics_connection,
                    debugger::Command::Inspect {
                        stop_id: input.stop_id,
                        inspection: input.command,
                    },
                    deadline,
                )
            })
            .await,
        )
    }

    #[tool(
        description = "Evaluate an unsigned literal or @register with optional checked + or - constant against a stopped target's native context. Read-only, no shell, function calls or memory writes."
    )]
    async fn debug_evaluate(
        &self,
        Parameters(input): Parameters<DebugEvaluateInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        response(
            request(context, input.timeout_ms, |deadline| {
                self.diagnostics.command(
                    &input.id,
                    &self.diagnostics_connection,
                    debugger::Command::Evaluate {
                        stop_id: input.stop_id,
                        thread_id: input.thread_id,
                        expression: input.expression,
                    },
                    deadline,
                )
            })
            .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_router_registers_all_diagnostic_tools_and_identity_preconditions() {
        let router = MasterControlProgram::diagnostics_router();
        let names: std::collections::BTreeSet<_> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        let expected: std::collections::BTreeSet<_> = [
            "diagnostics_process",
            "process_dump",
            "process_stacks",
            "process_wait_chain",
            "process_handles",
            "debug_attach",
            "debug_launch",
            "debug_list",
            "debug_inspect",
            "debug_events",
            "debug_continue",
            "debug_break",
            "debug_detach",
            "debug_terminate",
            "debug_command",
            "debug_evaluate",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(names, expected);
        let dump = router.get("process_dump").unwrap();
        assert!(dump.input_schema["properties"]["creation_time"].is_object());
        assert!(dump.input_schema["properties"]["pid"].is_object());
    }

    #[test]
    fn numeric_string_inputs_keep_exact_identity_and_bounds() {
        let input: StacksInput = serde_json::from_value(serde_json::json!({
            "pid": "123", "creation_time": "133987654321234567", "max_frames": "64", "timeout_ms": "2000"
        })).unwrap();
        assert_eq!(input.target.creation_time, 133987654321234567);
        assert_eq!(input.max_frames, Some(64));
        let command: DebugCommandInput = serde_json::from_value(serde_json::json!({
            "id": "session", "stop_id": "12", "command": "read_memory", "address": "4096", "length": "16"
        })).unwrap();
        assert!(matches!(
            command.command,
            InspectionCommand::ReadMemory {
                address: 4096,
                length: 16
            }
        ));
        assert!(bounded(Some(0), 32, 1, 256, "limit").is_err());
    }
}
