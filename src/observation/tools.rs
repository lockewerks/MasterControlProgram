use super::*;

#[tool_router(router = observation_router, vis = "pub(crate)")]
impl crate::server::MasterControlProgram {
    #[tool(
        description = "Start bounded native event recording for filesystem, registry, service, process, UI Automation or explicit ETW providers. Only future events are observed. Persistent lifetime requires a running local host. Failed provider setup is retained as status=failed."
    )]
    async fn watch_create(
        &self,
        Parameters(input): Parameters<WatchInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        tokio::select! {
            result = self.observation.create_scoped(input, &self.execution_connection,
                Some(self.execution_connection_cancel.clone())) => {
                let failed = result.as_ref().is_ok_and(|record| record.status == WatchStatus::Failed);
                let mut result = tool_result(result)?;
                if failed { result.is_error = Some(true); }
                Ok(result)
            },
            _ = request_canceled(&context, &self.execution_connection_cancel) =>
                tool_result::<WatchRecord>(Err(anyhow!(
                    "watch startup request canceled; accepted persistent recordings remain visible in events_read"
                ))),
        }
    }

    #[tool(
        description = "Stop one watch and retain its history. forget=true also removes a terminal watch and its retained events. Delayed native shutdown is reported as stopping, never freed unsafely."
    )]
    async fn watch_remove(
        &self,
        Parameters(input): Parameters<RemoveInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(
            self.observation
                .remove(&input.id, &self.execution_connection, input.forget)
                .await,
        )
    }

    #[tool(
        description = "Query bounded retained observation history by cursor and exact filters. Returns recording start times, retention/restart gaps, loss counters and watch failures. No historical reconstruction or causal inference."
    )]
    async fn events_read(
        &self,
        Parameters(input): Parameters<EventsInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(self.observation.read(&input, &self.execution_connection))
    }

    #[tool(
        description = "Wait for an observed event until an absolute Unix-ms deadline. Returns satisfied, timed_out, canceled or failed. background=true returns a retained wait ID; persistent waits survive disconnect only in the explicit host."
    )]
    async fn wait_for(
        &self,
        Parameters(input): Parameters<WaitInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let background = input.background;
        let persistent = input.lifetime == Lifetime::Persistent;
        let record = match self
            .observation
            .start_wait_scoped(
                input,
                &self.execution_connection,
                Some(self.execution_connection_cancel.clone()),
            )
            .await
        {
            Ok(record) => record,
            Err(error) => return tool_result::<WaitRecord>(Err(error)),
        };
        if background {
            return tool_result(Ok(record));
        }
        let _guard = ForegroundWait {
            state: self.observation.clone(),
            id: record.id.clone(),
            owner: self.execution_connection.clone(),
            persistent,
        };
        let cancel = Cancellation::default();
        tokio::select! {
            result = self.observation.await_wait(&record.id, &self.execution_connection, &cancel) => tool_result(result),
            _ = request_canceled(&context, &self.execution_connection_cancel) => {
                if persistent {
                    tool_result(self.observation.wait_status(&record.id, &self.execution_connection)
                        .map(|wait| json!({
                            "outcome": Outcome::Canceled, "wait": wait, "persistent_wait_retained": true
                        })))
                } else {
                    tool_result(self.observation.cancel_wait(&record.id, &self.execution_connection, false))
                }
            }
        }
    }

    #[tool(
        description = "Retrieve a retained wait result, including background or persistent waits, without renewing its deadline."
    )]
    async fn wait_status(
        &self,
        Parameters(input): Parameters<IdInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(
            self.observation
                .wait_status(&input.id, &self.execution_connection),
        )
    }

    #[tool(
        description = "List bounded retained wait identities and outcomes, newest first. Recover persistent wait IDs after a lost response or disconnect. Event payloads remain in wait_status; limit is at most 128."
    )]
    async fn wait_list(
        &self,
        Parameters(input): Parameters<HistoryInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(
            self.observation
                .wait_history(&input, &self.execution_connection),
        )
    }

    #[tool(description = "Cancel a retained event wait. forget=true removes its terminal result.")]
    async fn wait_cancel(
        &self,
        Parameters(input): Parameters<RemoveInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(self.observation.cancel_wait(
            &input.id,
            &self.execution_connection,
            input.forget,
        ))
    }

    #[tool(
        description = "Start bounded ETW or process recording. Select provider GUIDs and process/session/event scope explicitly. Native access errors and lost events are reported. Does not install or enable Windows features."
    )]
    async fn trace_start(
        &self,
        Parameters(input): Parameters<WatchInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        if !matches!(input.source, Source::Etw { .. } | Source::Process { .. }) {
            return tool_result::<WatchRecord>(Err(anyhow!(
                "trace_start requires etw or process source"
            )));
        }
        self.watch_create(Parameters(input), context).await
    }

    #[tool(
        description = "Stop a native trace, retaining bounded event history, exact recording scope and provider loss counters."
    )]
    async fn trace_stop(
        &self,
        Parameters(input): Parameters<IdInput>,
    ) -> Result<CallToolResult, ErrorData> {
        tool_result(
            self.observation
                .remove(&input.id, &self.execution_connection, false)
                .await,
        )
    }
}
