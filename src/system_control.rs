use crate::server::{err, ok, FsPathInput, MasterControlProgram};
use crate::win32::{filesystem as fs, service};
use rmcp::{
    handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
    ErrorData as McpError,
};

pub(crate) async fn run<F>(operation: F) -> Result<CallToolResult, McpError>
where
    F: FnOnce() -> anyhow::Result<String> + Send + 'static,
{
    run_with_timeout(None, operation).await
}

async fn run_with_timeout<F>(
    timeout_ms: Option<u64>,
    operation: F,
) -> Result<CallToolResult, McpError>
where
    F: FnOnce() -> anyhow::Result<String> + Send + 'static,
{
    let result = if let Some(timeout_ms) = timeout_ms {
        crate::runtime::blocking_with_timeout(timeout_ms, operation).await
    } else {
        crate::runtime::blocking(operation).await
    };
    match result {
        Ok(text) => response(text),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "system control operation failed");
            error_response(format!("{error:#}"))
        }
    }
}

fn error_response(text: String) -> Result<CallToolResult, McpError> {
    let value = serde_json::from_str::<serde_json::Value>(&text);
    let mut result = err(text)?;
    if let Ok(value) = value {
        if value.is_object() {
            result.structured_content = Some(value);
        }
    }
    Ok(result)
}

fn response(text: String) -> Result<CallToolResult, McpError> {
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => return err(format!("native provider returned invalid JSON: {error}")),
    };
    let failed = value.get("success") == Some(&serde_json::Value::Bool(false))
        || value.get("error").is_some_and(|error| !error.is_null())
        || value
            .get("outcome")
            .and_then(|outcome| outcome.as_str())
            .is_some_and(|outcome| {
                matches!(
                    outcome,
                    "failed"
                        | "partial"
                        | "partial_or_unobserved"
                        | "timed_out"
                        | "stalled"
                        | "cancelled"
                )
            });
    let mut result = if failed { err(text)? } else { ok(text)? };
    if value.is_object() {
        result.structured_content = Some(value);
    }
    Ok(result)
}

#[tool_router(router = system_control_router, vis = "pub(crate)")]
impl MasterControlProgram {
    #[tool(
        description = "Create an exact-name Windows service with explicit executable, account, dependencies and supported settings. Recovery, SID, description and delayed-start settings are native. Passwords are write-only. Reports partial configuration and observed resulting state; does not start the new service."
    )]
    async fn service_create(
        &self,
        Parameters(input): Parameters<service::ServiceCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || service::create(input)).await
    }

    #[tool(
        description = "Configure an exact-name Windows service's executable, account, dependencies, startup, description, delayed autostart, recovery actions, non-crash failure actions or SID type. Omitted settings are retained; explicit empty supported values clear them. Passwords are not returned. Reports applied steps, native errors and actual resulting configuration."
    )]
    async fn service_configure(
        &self,
        Parameters(input): Parameters<service::ServiceConfigureInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || service::configure(input)).await
    }

    #[tool(
        description = "Mark an exact-name service for deletion and optionally wait for observed absence. Deletion does not stop the service or terminate a process. Distinguishes API acceptance, marked-for-deletion pending state, timeout and absence."
    )]
    async fn service_delete(
        &self,
        Parameters(input): Parameters<service::ServiceDeleteInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms, move || service::delete(input)).await
    }

    #[tool(
        description = "Start, gracefully stop or restart an exact-name service with a bounded deadline. Waits by observed service status, checkpoints and wait hints. Restart only starts after observing stopped. Reports acceptance separately from terminal state, errors and exit codes; never kills service processes."
    )]
    async fn service_control(
        &self,
        Parameters(input): Parameters<service::ServiceTransitionInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms, move || service::transition(input)).await
    }

    #[tool(
        description = "Read a bounded file as explicit UTF-8, UTF-16 LE/BE or base64. Text BOMs are validated, stripped and reported. Returns exact identity and revision for conditional writes. Does not follow reparse points.",
        output_schema = rmcp::handler::server::common::schema_for_type::<fs::FileReadResult>()
    )]
    async fn fs_read(
        &self,
        Parameters(input): Parameters<fs::FsReadInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || fs::read(input)).await
    }

    #[tool(
        description = "Write explicit text/base64 with create_new, unconditional atomic_replace, exact-revision conditional_in_place, or explicitly selected NTFS transactional consistency. Atomic replacement requires metadata=destination_defaults. Conditional in-place writes preserve metadata/security but are not crash atomic; failures report partial bytes. No reparse traversal.",
        output_schema = rmcp::handler::server::common::schema_for_type::<fs::FileMutationResult>()
    )]
    async fn fs_write(
        &self,
        Parameters(input): Parameters<fs::FsWriteInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || fs::write(input)).await
    }

    #[tool(
        description = "Patch literal text only when the exact file revision and exact non-overlapping match count agree. Preserves UTF-8/UTF-16 encoding and BOM. Default conditional_in_place is not crash atomic; explicit transactional requires native TxF support.",
        output_schema = rmcp::handler::server::common::schema_for_type::<fs::FileMutationResult>()
    )]
    async fn fs_patch(
        &self,
        Parameters(input): Parameters<fs::FsPatchInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || fs::patch(input)).await
    }

    #[tool(
        description = "Copy up to 32 revision-checked files to absent destinations by same-volume temporary publication. Choose source owner/group/DACL (protected against destination inheritance) or destination defaults explicitly. Basic metadata is preserved; directories, reparse points, alternate streams and special attributes are rejected. SACL uses destination defaults. Reports per-file partial failures."
    )]
    async fn fs_copy(
        &self,
        Parameters(input): Parameters<fs::FsCopyInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || fs::copy(input)).await
    }

    #[tool(
        description = "Move up to 32 exact-revision files by same-volume, absent-destination handle rename. Preserves file identity, streams and security. Directories and reparse points are unsupported. Reports per-file partial failures; does not silently copy across volumes."
    )]
    async fn fs_move(
        &self,
        Parameters(input): Parameters<fs::FsMoveInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || {
            fs::move_files(input)
        })
        .await
    }

    #[tool(
        description = "Create a symbolic file/directory link or a revision-checked hard link at an absent path. Symbolic targets are stored as supplied and not traversed. Reports actual Windows privilege errors."
    )]
    async fn fs_link_create(
        &self,
        Parameters(input): Parameters<fs::FsLinkCreateInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || fs::link_create(input)).await
    }

    #[tool(
        description = "Inspect the link object without following it: exact identity/revision, symbolic or junction targets, reparse tag and hard-link count. Unknown reparse formats are reported as raw base64."
    )]
    async fn fs_link_inspect(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || fs::link_inspect(&input.path)).await
    }

    #[tool(
        description = "Remove an exact-revision symbolic link, junction or multiply-linked file name through its handle, never its target. Volume mount points and ordinary last-link files are rejected. Reports pending deletion honestly."
    )]
    async fn fs_link_remove(
        &self,
        Parameters(input): Parameters<fs::FsLinkRemoveInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || fs::link_remove(input)).await
    }

    #[tool(
        description = "Inspect native file/directory owner, group, DACL, inheritance, SDDL and security revision. Includes exact SIDs, account lookup errors, and raw unsupported ACE types. SACL is not requested and reparse points are not followed."
    )]
    async fn fs_security(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || fs::security(&input.path)).await
    }

    #[tool(
        description = "Edit a file/directory DACL using exact SIDs, access masks and validated ACE flags. Explicit self/children/recursive scope, bounded traversal and inheritance policy. Merge preserves unrelated ACEs; replace with an empty list deliberately denies all. Never installs a null DACL. Reports actual per-target state and partial failures."
    )]
    async fn fs_acl_modify(
        &self,
        Parameters(input): Parameters<fs::FsAclInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || {
            fs::acl_modify(input)
        })
        .await
    }

    #[tool(
        description = "Set ownership to an exact SID for explicit self/children/recursive scope. Bounded, identity-checked traversal never follows reparse points. Does not enable privileges; reports actual Windows errors and per-target partial results."
    )]
    async fn fs_owner_set(
        &self,
        Parameters(input): Parameters<fs::FsOwnerInput>,
    ) -> Result<CallToolResult, McpError> {
        run_with_timeout(input.timeout_ms.map(u64::from), move || {
            fs::owner_modify(input)
        })
        .await
    }

    #[tool(
        description = "Ask native Restart Manager which processes use an exact file. Returns PID plus process creation time, session and service identities. This is not a complete handle inventory and never requests shutdown."
    )]
    async fn fs_locks(
        &self,
        Parameters(input): Parameters<FsPathInput>,
    ) -> Result<CallToolResult, McpError> {
        run(move || fs::locks(&input.path)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_mutations_are_mcp_errors_with_details() {
        let result =
            response(r#"{"outcome":"partial","accepted":true,"bytes_written":4}"#.to_owned())
                .unwrap();
        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.structured_content.unwrap()["bytes_written"], 4);
        let result = response(r#"{"outcome":"completed","accepted":true}"#.to_owned()).unwrap();
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn structured_service_errors_preserve_acceptance_and_observation() {
        let result = error_response(r#"{"success":false,"outcome":"timed_out","accepted":true,"steps":[{"observed":{"state":"StopPending"}}]}"#.to_owned()).unwrap();
        assert_eq!(result.is_error, Some(true));
        let value = result.structured_content.unwrap();
        assert_eq!(value["accepted"], true);
        assert_eq!(value["steps"][0]["observed"]["state"], "StopPending");
        assert_eq!(
            response(r#"{"success":false,"outcome":"pending"}"#.to_owned())
                .unwrap()
                .is_error,
            Some(true)
        );
        let result = error_response("native access denied".to_owned()).unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
    }

    #[test]
    fn filesystem_tools_are_registered() {
        let router = MasterControlProgram::system_control_router();
        let tools = router.list_all();
        for name in [
            "service_create",
            "service_configure",
            "service_delete",
            "service_control",
            "fs_read",
            "fs_write",
            "fs_patch",
            "fs_copy",
            "fs_move",
            "fs_security",
            "fs_acl_modify",
            "fs_owner_set",
            "fs_link_create",
            "fs_link_inspect",
            "fs_link_remove",
            "fs_locks",
        ] {
            assert!(
                tools.iter().any(|tool| tool.name == name),
                "{name} is not registered"
            );
        }
    }
}
