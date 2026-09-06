use super::*;

#[tool_router(router = workflow_router, vis = "pub(crate)")]
impl crate::server::MasterControlProgram {
    #[tool(
        description = "Start a bounded deterministic sequence of named existing-tool actions and event waits. Per-step deadlines, prior-result JSON-pointer bindings and explicit continue_on_error support launch -> owned-window wait -> dialog capture -> process/network evidence. No autonomous reasoning, implicit retries or replay. Persistent workflows require the local host and own a connection scope until completion; actions must explicitly request persistent lifetime to outlive that scope."
    )]
    async fn workflow_start(
        &self,
        Parameters(input): Parameters<StartInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let owns_connection = input.lifetime == Lifetime::Persistent;
        if owns_connection && !self.execution.is_persistent() {
            return tool_result::<WorkflowRecord>(Err(anyhow!(
                "persistent workflows require the explicit local host"
            )));
        }
        let server = if owns_connection {
            match self.for_connection(uuid::Uuid::new_v4().to_string()) {
                Ok(server) => server,
                Err(error) => return tool_result::<WorkflowRecord>(Err(error)),
            }
        } else {
            self.clone()
        };
        let dispatcher = Arc::new(RouterDispatcher {
            server,
            context,
            owns_connection,
            closed: Arc::new(AtomicBool::new(false)),
        });
        let result = self.workflows.start(
            input,
            &self.execution_connection,
            self.observation.clone(),
            dispatcher.clone(),
        );
        match result {
            Ok(record) => {
                if owns_connection {
                    if let Err(error) = self.workflows.flush().await {
                        self.workflows.checkpoint_failed(format!("{error:#}"));
                        return tool_result::<WorkflowRecord>(Err(anyhow!(
                            "workflow {} persistence failed: {error:#}; cancellation requested, inspect workflow_status",
                            record.id
                        )));
                    }
                }
                tool_result(Ok(record))
            }
            Err(error) => {
                if let Err(cleanup) = dispatcher.finish().await {
                    return tool_result::<WorkflowRecord>(Err(anyhow!(
                        "{error:#}; scope cleanup also failed: {cleanup:#}"
                    )));
                }
                tool_result::<WorkflowRecord>(Err(error))
            }
        }
    }

    #[tool(
        description = "Read workflow state and ordered per-step results. Distinguishes action completion, timeout with unknown side effects, cancellation, observed wait outcomes and restart interruption."
    )]
    async fn workflow_status(
        &self,
        Parameters(input): Parameters<IdInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(self.workflows.status(&input.id, &self.execution_connection))
    }

    #[tool(
        description = "List bounded retained workflow identities and outcomes, newest first. Recover persistent workflow IDs after a lost response or disconnect. Full step results remain in workflow_status; limit is at most 64."
    )]
    async fn workflow_list(
        &self,
        Parameters(input): Parameters<HistoryInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(self.workflows.history(&input, &self.execution_connection))
    }

    #[tool(
        description = "Request workflow cancellation without replaying or reversing completed actions. A native action may still finish. forget=true removes only a terminal workflow."
    )]
    async fn workflow_cancel(
        &self,
        Parameters(input): Parameters<crate::observation::RemoveInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(
            self.workflows
                .cancel(&input.id, &self.execution_connection, input.forget),
        )
    }

    #[tool(
        description = "Await a retained workflow result until an absolute retrieval deadline. Timeout or request cancellation stops retrieval only, not an explicitly persistent workflow."
    )]
    async fn workflow_wait(
        &self,
        Parameters(input): Parameters<WaitWorkflowInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let cancellation = Cancellation::default();
        tokio::select! {
            result = self.workflows.wait(&input.id, &self.execution_connection, input.deadline_unix_ms, &cancellation) => tool_result(result),
            _ = request_canceled(&context, &self.execution_connection_cancel) => {
                tool_result(self.workflows.status(&input.id, &self.execution_connection)
                    .map(|workflow| WaitWorkflowResult { outcome: Outcome::Canceled, workflow }))
            }
        }
    }
}
