use rmcp::{
    handler::server::wrapper::Parameters, model::CallToolResult, service::RequestContext, tool,
    tool_router, ErrorData as McpError, RoleServer,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::{
    ExecutionKind, ExecutionManager, ExecutionRecord, IdInput, JobStartInput, OutputInput,
    ResizeInput, TerminalCreateInput, TerminalInput, WaitInput,
};
use crate::server::{err, ok, MasterControlProgram};

async fn run<T, F>(operation: F) -> Result<CallToolResult, McpError>
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        operation()
            .and_then(|result| serde_json::to_string_pretty(&result).map_err(anyhow::Error::from))
    })
    .await
    {
        Ok(Ok(value)) => ok(value),
        Ok(Err(error)) => err(format!("{error:#}")),
        Err(error) => err(format!("execution worker failed: {error}")),
    }
}

pub(super) async fn run_start(
    request: CancellationToken,
    operation: impl FnOnce(CancellationToken) -> anyhow::Result<ExecutionRecord> + Send + 'static,
) -> Result<CallToolResult, McpError> {
    let startup = request.child_token();
    // This guard must remain in the request future, not the detached blocking worker.
    let _guard = startup.clone().drop_guard();
    run(move || operation(startup)).await
}

fn result<T: Serialize>(value: anyhow::Result<T>) -> Result<CallToolResult, McpError> {
    match value.and_then(|value| serde_json::to_string_pretty(&value).map_err(anyhow::Error::from))
    {
        Ok(value) => ok(value),
        Err(error) => err(format!("{error:#}")),
    }
}

fn require_kind(
    manager: &ExecutionManager,
    id: &str,
    owner: &str,
    kind: ExecutionKind,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        manager.inspect(id, owner)?.kind == kind,
        "execution ID has the wrong kind for this tool"
    );
    Ok(())
}

#[tool_router(router = execution_router, vis = "pub(crate)")]
impl MasterControlProgram {
    #[tool(
        description = "Report the actual Windows account, token, session, desktop access and connection/persistent-host lifetime. No automatic cross-session or secure-desktop access."
    )]
    async fn execution_context(&self) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let connection = self.execution_connection.clone();
        run(move || {
            Ok(serde_json::json!({
                "actual": crate::context::ExecutionContext::current()?,
                "persistence": manager.context(),
                "state_directory": manager.state_directory(),
                "connection_id": connection,
                "default_lifetime": "connection",
                "persistent_available": manager.is_persistent(),
                "live_processes_survive_host_restart_or_reboot": false,
                "mutations_replayed_on_restart": false,
                "history": manager.list(&connection, None),
            }))
        })
        .await
    }

    #[tool(
        description = "Create an addressable native ConPTY terminal. program and args select a shell/REPL; cwd/env are per process. lifetime defaults to connection even on a host; persistent requires an explicitly started local host. Output is a bounded combined UTF-8/VT byte stream."
    )]
    async fn terminal_create(
        &self,
        Parameters(input): Parameters<TerminalCreateInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run_start(context.ct, move |startup| {
            manager.create_terminal_cancellable(input, &owner, startup)
        })
        .await
    }

    #[tool(
        description = "Write text (UTF-8) or exact base64 bytes to a terminal, at most 65536 pending bytes. Reports bytes written and uncertain cancellation; writing is not proof the application completed a command. Never replay uncertain writes automatically."
    )]
    async fn terminal_input(
        &self,
        Parameters(input): Parameters<TerminalInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        result(
            self.execution
                .terminal_input(input, &self.execution_connection, context.ct)
                .await,
        )
    }

    #[tool(
        description = "Read a terminal's combined ConPTY byte stream by byte cursor. Returns exact base64, a lossy UTF-8 preview, VT semantics, dropped bytes, cursor gaps, and process/drain state. A read can split UTF-8 code points."
    )]
    async fn terminal_read(
        &self,
        Parameters(input): Parameters<OutputInput>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run(move || {
            require_kind(&manager, &input.id, &owner, ExecutionKind::Terminal)?;
            manager.read(input, &owner)
        })
        .await
    }

    #[tool(
        description = "Resize a live ConPTY terminal to 1-1000 columns and rows without replacing its process or state."
    )]
    async fn terminal_resize(
        &self,
        Parameters(input): Parameters<ResizeInput>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run(move || manager.resize(input, &owner)).await
    }

    #[tool(
        description = "Send Ctrl+C as byte 0x03 to this ConPTY input stream only. Windows/application console modes determine whether it becomes an interrupt. This does not broadcast a console signal or guarantee command termination."
    )]
    async fn terminal_interrupt(
        &self,
        Parameters(input): Parameters<IdInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        result(
            self.execution
                .terminal_input(
                    TerminalInput {
                        id: input.id,
                        text: Some("\u{3}".into()),
                        base64: None,
                        timeout_ms: Some(5000),
                    },
                    &self.execution_connection,
                    context.ct,
                )
                .await,
        )
    }

    #[tool(
        description = "Terminate only the terminal's owned Windows Job Object process tree and close ConPTY after output drains. Retains bounded output and identity for later reads. This is forced termination, not a graceful shell exit."
    )]
    async fn terminal_close(
        &self,
        Parameters(input): Parameters<IdInput>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run(move || {
            require_kind(&manager, &input.id, &owner, ExecutionKind::Terminal)?;
            manager.cancel(&input.id, &owner)
        })
        .await
    }

    #[tool(
        description = "List terminals visible to this connection plus explicitly persistent terminals. Includes historical/restart status and record eviction counts."
    )]
    async fn terminal_list(&self) -> Result<CallToolResult, McpError> {
        result(Ok(self.execution.list(
            &self.execution_connection,
            Some(ExecutionKind::Terminal),
        )))
    }

    #[tool(
        description = "Start a noninteractive program with separate bounded stdout/stderr pipes. The process is placed in an owned Windows Job Object while suspended, before any instruction runs. Returns stable UUID and PID plus creation FILETIME. stdin closes after optional bounded text/base64. No default process deadline; optional timeout_ms terminates the owned tree."
    )]
    async fn job_start(
        &self,
        Parameters(input): Parameters<JobStartInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run_start(context.ct, move |startup| {
            manager.start_job_cancellable(input, &owner, startup)
        })
        .await
    }

    #[tool(
        description = "Inspect a job's exact root identity, root exit code, owned-tree process count, cancellation, and output-drained state. Root exit alone does not imply descendants or their pipes have exited."
    )]
    async fn job_inspect(
        &self,
        Parameters(input): Parameters<IdInput>,
    ) -> Result<CallToolResult, McpError> {
        result((|| {
            require_kind(
                &self.execution,
                &input.id,
                &self.execution_connection,
                ExecutionKind::Job,
            )?;
            self.execution
                .inspect(&input.id, &self.execution_connection)
        })())
    }

    #[tool(
        description = "Read separate job stdout or stderr by byte cursor, at most 262144 bytes. Returns exact base64, lossy UTF-8 preview, dropped/gap counts, and exit/drain state. Child output encoding is not assumed."
    )]
    async fn job_output(
        &self,
        Parameters(input): Parameters<OutputInput>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run(move || {
            require_kind(&manager, &input.id, &owner, ExecutionKind::Job)?;
            manager.read(input, &owner)
        })
        .await
    }

    #[tool(
        description = "Wait up to timeout_ms (0-300000, default 30000) for the entire owned job tree and output pipes, without blocking unrelated MCP tools. Returns exited, timed_out, canceled, failed or interrupted_host_restart. Canceling this wait does not cancel the job."
    )]
    async fn job_wait(
        &self,
        Parameters(input): Parameters<WaitInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(error) = require_kind(
            &self.execution,
            &input.id,
            &self.execution_connection,
            ExecutionKind::Job,
        ) {
            return err(error);
        }
        result(
            self.execution
                .wait(
                    &input.id,
                    &self.execution_connection,
                    input.timeout_ms.unwrap_or(30000),
                    context.ct,
                )
                .await,
        )
    }

    #[tool(
        description = "Request forced termination of a job's exact owned process tree via its retained Windows Job Object handle. Does not reopen a PID, kill unrelated processes, or silently become a graceful interrupt. Inspect/wait observes completion."
    )]
    async fn job_cancel(
        &self,
        Parameters(input): Parameters<IdInput>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        run(move || {
            require_kind(&manager, &input.id, &owner, ExecutionKind::Job)?;
            manager.cancel(&input.id, &owner)
        })
        .await
    }

    #[tool(
        description = "List jobs visible to this connection and explicitly persistent jobs, including bounded historical records, restart gaps and evictions."
    )]
    async fn job_list(&self) -> Result<CallToolResult, McpError> {
        result(Ok(self
            .execution
            .list(&self.execution_connection, Some(ExecutionKind::Job))))
    }

    #[tool(
        description = "Explicitly shut down the manually started local host, terminate its owned terminal/job trees and checkpoint retained history. Active bridges disconnect. Unavailable on ordinary connection-owned stdio servers."
    )]
    async fn host_shutdown(&self) -> Result<CallToolResult, McpError> {
        result(self.execution.request_host_shutdown().map(|()| {
            serde_json::json!({
                "shutdown_requested": true,
                "completion": "the host exits after owned-state cleanup; bridges will disconnect"
            })
        }))
    }
}
