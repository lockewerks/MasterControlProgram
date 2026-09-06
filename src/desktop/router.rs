use super::*;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    tool, tool_router, ErrorData as McpError,
};
use serde::Serialize;

async fn with_deadline<T>(
    timeout_ms: Option<u64>,
    default_ms: u64,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let timeout_ms = timeout_ms.unwrap_or(default_ms);
    if !(1..=MAX_OPERATION_MS).contains(&timeout_ms) {
        anyhow::bail!("timeout_ms must be in 1..={MAX_OPERATION_MS}");
    }
    let budget = Duration::from_millis(timeout_ms);
    let started = Instant::now();
    match tokio::time::timeout(budget, work).await {
        Ok(Err(error)) if started.elapsed() >= budget => {
            Err(anyhow::Error::new(OperationStopped::TimedOut).context(format!(
                "The provider returned an error at the caller deadline: {error:#}. An already accepted action may have taken effect."
            )))
        }
        Ok(result) => result,
        Err(_) => Err(anyhow::Error::new(OperationStopped::TimedOut).context(
            "Provider work is being canceled, not forcibly interrupted. An action already accepted by Windows may have taken effect.",
        )),
    }
}

fn response<T: Serialize>(result: Result<T>) -> Result<CallToolResult, McpError> {
    match result.and_then(|result| Ok(serde_json::to_value(result)?)) {
        Ok(value) => {
            let mut result = CallToolResult::success(vec![Content::text(value.to_string())]);
            result.structured_content = Some(value);
            Ok(result)
        }
        Err(error) => Ok(CallToolResult::error(vec![Content::text(format!(
            "{error:#}"
        ))])),
    }
}

fn snapshot_response(result: Result<SnapshotResult>) -> Result<CallToolResult, McpError> {
    match result {
        Ok(mut snapshot) => {
            let image = snapshot.image.take();
            let requested_analysis = snapshot.ocr.status != "not_requested"
                || snapshot.accessibility.status != "not_requested";
            let available_analysis = snapshot.ocr.result.is_some()
                || snapshot
                    .accessibility
                    .result
                    .as_ref()
                    .is_some_and(|tree| tree.complete || !tree.elements.is_empty());
            let failed = requested_analysis && !available_analysis && image.is_none();
            let mut result = response(Ok(snapshot))?;
            if let Some(image) = image {
                result
                    .content
                    .insert(0, Content::image(image, "image/jpeg"));
            }
            if failed {
                result.is_error = Some(true);
            }
            Ok(result)
        }
        Err(error) => response::<()>(Err(error)),
    }
}

#[tool_router(router = desktop_router, vis = "pub(crate)")]
impl crate::server::MasterControlProgram {
    #[tool(
        description = "Observe desktop, monitor, window or region pixels and a bounded native accessibility tree. Images include physical origin, scaling, DPI, cursor and capture limitations. Window capture is a visible desktop crop, not offscreen content. Optional local OCR and bounded changed-region comparisons."
    )]
    async fn desktop_snapshot(
        &self,
        Parameters(input): Parameters<SnapshotInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        snapshot_response(
            with_deadline(
                input.timeout_ms,
                10_000,
                crate::runtime::blocking_with_timeout(
                    input.timeout_ms.unwrap_or(10_000),
                    move || desktop.snapshot(input),
                ),
            )
            .await,
        )
    }

    #[tool(
        description = "Find native UI Automation controls by window reference, name, automation ID, type, process or physical bounds. Returns bounded typed results and opaque connection-owned element references. Incomplete traversal never establishes uniqueness."
    )]
    async fn ui_find(
        &self,
        Parameters(input): Parameters<UiFindInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        response(
            with_deadline(
                input.timeout_ms,
                5000,
                crate::runtime::blocking_with_timeout(
                    input.timeout_ms.unwrap_or(5000),
                    move || desktop.find(input),
                ),
            )
            .await,
        )
    }

    #[tool(
        description = "Perform a native UI Automation pattern action: invoke, select, add/remove selection, toggle, expand, collapse, scroll, scroll_into_view or focus. Requires an exact live reference or unambiguous bounded query. Reports acceptance separately from observed state; invocation is not proof of application completion."
    )]
    async fn ui_invoke(
        &self,
        Parameters(input): Parameters<UiInvokeInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        let result = with_deadline(
            input.timeout_ms,
            5000,
            crate::runtime::interactive_with_timeout(input.timeout_ms.unwrap_or(5000), move || {
                desktop.invoke(input)
            }),
        )
        .await;
        let failed = result
            .as_ref()
            .is_ok_and(|result| result.accepted != Some(true));
        let mut result = response(result)?;
        if failed {
            result.is_error = Some(true);
        }
        Ok(result)
    }

    #[tool(
        description = "Set a live control's native ValuePattern text or RangeValuePattern number. Does not type into arbitrary focused applications. Reports provider acceptance and whether the requested value was observed."
    )]
    async fn ui_set_value(
        &self,
        Parameters(input): Parameters<UiSetValueInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        let result = with_deadline(
            input.timeout_ms,
            5000,
            crate::runtime::interactive_with_timeout(input.timeout_ms.unwrap_or(5000), move || {
                desktop.set_value(input)
            }),
        )
        .await;
        let failed = result
            .as_ref()
            .is_ok_and(|result| result.accepted != Some(true));
        let mut result = response(result)?;
        if failed {
            result.is_error = Some(true);
        }
        Ok(result)
    }

    #[tool(
        description = "Read bounded text through a live native UI Automation TextPattern. Passive observation, without typing or activity glow."
    )]
    async fn ui_text(
        &self,
        Parameters(input): Parameters<UiTextInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        response(
            with_deadline(
                input.timeout_ms,
                5000,
                crate::runtime::blocking_with_timeout(
                    input.timeout_ms.unwrap_or(5000),
                    move || desktop.text(input),
                ),
            )
            .await,
        )
    }

    #[tool(
        description = "Wait for a window or control to appear, disappear, become enabled or change value. Uses bounded condition observations and a deadline, with explicit satisfied/timed_out/canceled/failed outcomes. Supply operation_id to cancel via desktop_cancel. Ambiguous or incomplete observations fail rather than selecting an unrelated target."
    )]
    async fn ui_wait(
        &self,
        Parameters(mut input): Parameters<UiWaitInput>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let operation_id = input
            .operation_id
            .get_or_insert_with(|| uuid::Uuid::new_v4().to_string())
            .clone();
        let desktop = self.desktop.clone();
        match with_deadline(
            input.timeout_ms,
            10_000,
            crate::runtime::blocking_with_timeout(input.timeout_ms.unwrap_or(10_000), move || {
                desktop.wait(input)
            }),
        )
        .await
        {
            Ok(result) => response(Ok(result)),
            Err(error) => response(Ok(UiWaitResult {
                operation_id,
                outcome: if error.downcast_ref::<OperationStopped>()
                    == Some(&OperationStopped::TimedOut)
                {
                    WaitOutcome::TimedOut
                } else {
                    WaitOutcome::Failed
                },
                window: None,
                element: None,
                observations: None,
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: Some(format!(
                    "{error:#}; the last provider observation is unavailable"
                )),
            })),
        }
    }

    #[tool(
        description = "Signal cancellation of an active desktop observation by its caller-supplied operation_id. Cancellation cannot undo input already accepted by Windows."
    )]
    async fn desktop_cancel(
        &self,
        Parameters(input): Parameters<CancelInput>,
    ) -> Result<CallToolResult, McpError> {
        response(self.desktop.cancel(input))
    }

    #[tool(
        description = "List native windows with opaque references, HWND/PID/process creation identities, physical bounds, DPI and visibility state. Defaults to visible windows in this process's interactive session. Does not focus or alter windows."
    )]
    async fn window_list(
        &self,
        Parameters(input): Parameters<WindowListInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        response(
            with_deadline(
                input.timeout_ms,
                5000,
                crate::runtime::blocking_with_timeout(
                    input.timeout_ms.unwrap_or(5000),
                    move || desktop.window_list(input),
                ),
            )
            .await,
        )
    }

    #[tool(
        description = "Find windows by title, class, exact process identity or visibility. Returns every bounded match and explicit incompleteness; use the returned opaque window_ref for capture or management."
    )]
    async fn window_find(
        &self,
        Parameters(input): Parameters<WindowListInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        response(
            with_deadline(
                input.timeout_ms,
                5000,
                crate::runtime::blocking_with_timeout(
                    input.timeout_ms.unwrap_or(5000),
                    move || desktop.window_list(input),
                ),
            )
            .await,
        )
    }

    #[tool(
        description = "Focus, move, resize, minimize, maximize, restore or gracefully close an exact native window. Close requests WM_CLOSE and never terminates the process. Physical coordinates can be negative. Reports Windows acceptance and observed postcondition separately."
    )]
    async fn window_manage(
        &self,
        Parameters(input): Parameters<WindowManageInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        response(
            with_deadline(
                input.timeout_ms,
                5000,
                crate::runtime::interactive_with_timeout(
                    input.timeout_ms.unwrap_or(5000),
                    move || desktop.window_manage(input),
                ),
            )
            .await,
        )
    }

    #[tool(
        description = "Recognize text locally using installed Windows OCR language support. Returns physical text boxes, rotation mapping and uncertainty, not native control references. Target a desktop, monitor, window or region; no image or text is sent to a network service."
    )]
    async fn desktop_ocr(
        &self,
        Parameters(input): Parameters<OcrInput>,
    ) -> Result<CallToolResult, McpError> {
        let desktop = self.desktop.clone();
        snapshot_response(
            with_deadline(
                input.timeout_ms,
                10_000,
                crate::runtime::blocking_with_timeout(
                    input.timeout_ms.unwrap_or(10_000),
                    move || desktop.ocr(input),
                ),
            )
            .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_deadline_does_not_wait_forever_for_a_provider() {
        let started = Instant::now();
        let result = with_deadline(Some(10), 100, std::future::pending::<Result<()>>()).await;
        assert_eq!(
            result.unwrap_err().downcast_ref::<OperationStopped>(),
            Some(&OperationStopped::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(with_deadline(Some(0), 100, async { Ok(()) }).await.is_err());
    }

    #[tokio::test]
    async fn a_native_failure_at_the_deadline_is_still_a_timed_out_wait() {
        let result = with_deadline(Some(1), 100, async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Err::<(), _>(anyhow::anyhow!("Native operation deadline exceeded"))
        })
        .await;
        assert_eq!(
            result.unwrap_err().downcast_ref::<OperationStopped>(),
            Some(&OperationStopped::TimedOut)
        );
    }
}
