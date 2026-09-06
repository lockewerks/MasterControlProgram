use crate::server::{err, ok, MasterControlProgram};
use crate::win32::{
    admin_common::*, devices, network_admin, network_proxy, storage, virtualization, wifi_admin,
};
use rmcp::{
    handler::server::wrapper::Parameters, model::CallToolResult, service::RequestContext, tool,
    tool_router, ErrorData as McpError, RoleServer,
};
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

struct CancelOnDrop(AdminContext);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn native_slots() -> Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(4))).clone()
}

fn mutation_slot() -> Arc<Semaphore> {
    static SLOT: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOT.get_or_init(|| Arc::new(Semaphore::new(1))).clone()
}

fn failed(error: &anyhow::Error, context: &AdminContext) -> Result<CallToolResult, McpError> {
    let value = failure(error, context);
    let mut response = err(value.to_string())?;
    response.structured_content = Some(value);
    Ok(response)
}

async fn native<F>(
    timeout_ms: Option<u64>,
    mutating: bool,
    cancellation: CancellationToken,
    work: F,
) -> Result<CallToolResult, McpError>
where
    F: FnOnce(&AdminContext) -> anyhow::Result<Value> + Send + 'static,
{
    let duration = match timeout_duration(timeout_ms) {
        Ok(duration) => duration,
        Err(error) => return err(error),
    };
    let context = AdminContext::new(duration);
    let _cancel = CancelOnDrop(context.clone());
    let worker_context = context.clone();
    let task = async move {
        let mutation = if mutating {
            Some(mutation_slot().acquire_owned().await?)
        } else {
            None
        };
        let slot = native_slots().acquire_owned().await?;
        tokio::task::spawn_blocking(move || {
            // Permits belong to the closure, since Windows cannot cancel every synchronous API.
            let _slot = slot;
            let _mutation = mutation;
            worker_context.check()?;
            work(&worker_context)
        })
        .await?
    };
    let outcome = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            context.cancel();
            return failed(&anyhow::anyhow!(
                "Administration request cancelled. An in-flight Windows operation may still finish; query before retrying."
            ), &context);
        }
        result = tokio::time::timeout(duration, task) => result,
    };
    match outcome {
        Ok(Ok(value)) => {
            let mut response = ok(value.to_string())?;
            response.structured_content = Some(value);
            Ok(response)
        }
        Ok(Err(error)) => {
            tracing::error!(error = %error, "Administration request failed");
            failed(&error, &context)
        }
        Err(_) => {
            context.cancel();
            failed(
                &anyhow::anyhow!(
                    "Administration deadline exceeded. An in-flight Windows API may still finish. \
                 Query the target before retrying; no mutation was automatically replayed."
                ),
                &context,
            )
        }
    }
}

fn provider_value(value: Value) -> anyhow::Result<Value> {
    use anyhow::{bail, ensure, Context};
    match value["administration_ok"].as_bool() {
        Some(true) => value
            .get("data")
            .cloned()
            .context("Provider response omitted data"),
        Some(false) => {
            let code = value["error"]["hresult"]
                .as_i64()
                .context("Provider response omitted HRESULT")?;
            ensure!(
                (i32::MIN as i64..=u32::MAX as i64).contains(&code),
                "Provider HRESULT is out of range"
            );
            let message = value["error"]["message"]
                .as_str()
                .context("Provider response omitted error message")?;
            let id = value["error"]["id"]
                .as_str()
                .context("Provider response omitted error ID")?;
            Err(NativeError {
                api: "PowerShell administration provider".into(),
                domain: "hresult".into(),
                code: code as u32,
                message: format!("{message} ({id})"),
            }
            .into())
        }
        _ => bail!("Malformed administration provider response"),
    }
}

async fn provider<F>(
    pool: Arc<crate::ps::Pool>,
    timeout_ms: Option<u64>,
    mutating: bool,
    cancellation: CancellationToken,
    prepare: F,
) -> Result<CallToolResult, McpError>
where
    F: FnOnce(&AdminContext) -> anyhow::Result<String> + Send + 'static,
{
    let duration = match timeout_duration(timeout_ms) {
        Ok(duration) => duration,
        Err(error) => return err(error),
    };
    let context = AdminContext::new(duration);
    let _cancel = CancelOnDrop(context.clone());
    let worker_context = context.clone();
    let operation_context = context.clone();
    let task = async move {
        let _mutation = if mutating {
            Some(mutation_slot().acquire_owned().await?)
        } else {
            None
        };
        let slot = native_slots().acquire_owned().await?;
        let script = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            worker_context.check()?;
            prepare(&worker_context)
        })
        .await??;
        let command = format!(
            "$ErrorActionPreference='Stop'; try {{ \
             $admin_data = & {{ {script} }}; \
             [pscustomobject]@{{administration_ok=$true; data=$admin_data}} \
             }} catch {{ \
             [pscustomobject]@{{administration_ok=$false; error=[pscustomobject]@{{message=$_.Exception.Message; hresult=$_.Exception.HResult; id=$_.FullyQualifiedErrorId}}}} \
             }}"
        );
        if mutating {
            operation_context.begin_mutation()?;
        } else {
            operation_context.check()?;
        }
        let remaining = operation_context.remaining().as_millis().max(1) as u64;
        provider_value(
            pool.exec_json_with_timeout(&command, Some(remaining))
                .await?,
        )
    };
    let outcome = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            context.cancel();
            return failed(&anyhow::anyhow!("Administration provider request cancelled; query before retrying an uncertain mutation"), &context);
        }
        result = tokio::time::timeout(duration, task) => result,
    };
    match outcome {
        Ok(Ok(value)) => {
            let mut response = ok(value.to_string())?;
            response.structured_content = Some(value);
            Ok(response)
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "Administration provider failed");
            failed(&error, &context)
        }
        Err(_) => {
            context.cancel();
            failed(&anyhow::anyhow!("Administration provider deadline exceeded; an accepted provider operation may still finish and was not replayed"), &context)
        }
    }
}

#[tool_router(router = administration_router, vis = "pub(crate)")]
impl MasterControlProgram {
    #[tool(
        description = "List native interface identities (GUID, LUID and index), administrative/link state and link speed. Use the GUID as the target for configuration; an alias alone is not accepted."
    )]
    async fn network_interfaces(
        &self,
        Parameters(input): Parameters<network_admin::NetworkQuery>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            network_admin::interfaces(&input, context)
        })
        .await
    }

    #[tool(
        description = "Read active IPv4/IPv6 unicast addresses, prefixes, address origins and duplicate-address-detection state, optionally for one exact interface."
    )]
    async fn network_addresses(
        &self,
        Parameters(input): Parameters<network_admin::NetworkQuery>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            network_admin::addresses(&input, context)
        })
        .await
    }

    #[tool(
        description = "Add, update or remove an exact manual IPv4/IPv6 address in the active store. Does not disable DHCP, change unrelated addresses or persist across reboot. Update/remove require the expected existing prefix. Returns observed DAD and prefix state; acceptance does not prove address usability."
    )]
    async fn network_address_set(
        &self,
        Parameters(input): Parameters<network_admin::AddressInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            network_admin::set_address(&input, context)
        })
        .await
    }

    #[tool(
        description = "Read active IPv4/IPv6 routes, optionally scoped to an exact interface. Includes destination prefix, next hop, route metric and origin."
    )]
    async fn network_routes(
        &self,
        Parameters(input): Parameters<network_admin::NetworkQuery>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            network_admin::routes(&input, context)
        })
        .await
    }

    #[tool(
        description = "Add/update/remove an exact active route using interface GUID, family, network prefix and next hop. A zero prefix configures a gateway. Preserves unrelated routes, does not persist across reboot, and returns the resulting entry."
    )]
    async fn network_route_set(
        &self,
        Parameters(input): Parameters<network_admin::RouteInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            network_admin::set_route(&input, context)
        })
        .await
    }

    #[tool(
        description = "Read or replace the static DNS server list for one exact interface and address family using native Windows DNS settings. Omit servers to query; an empty list clears the override. Preserves other families, suffixes and registration settings. Requires Windows 10 build 19041 or newer."
    )]
    async fn network_dns_config(
        &self,
        Parameters(input): Parameters<network_admin::DnsInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(
            input.timeout_ms,
            input.servers.is_some(),
            request.ct,
            move |context| network_admin::dns(&input, context),
        )
        .await
    }

    #[tool(
        description = "Set the administrative up/down state of an exact IP interface. This is not a PnP device disable. Returns actual admin/link state; up does not prove connectivity."
    )]
    async fn network_adapter_set_state(
        &self,
        Parameters(input): Parameters<network_admin::AdapterStateInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            network_admin::set_adapter_state(&input, context)
        })
        .await
    }

    #[tool(
        description = "Read or change DHCP mode for an exact interface GUID/address family in the explicitly selected active or persistent store. Uses the installed NetTCPIP provider because IP Helper does not configure DHCP. Returns configured and active state separately, including pending activation. Does not install providers or change manual addresses/routes implicitly."
    )]
    async fn network_dhcp_config(
        &self,
        Parameters(input): Parameters<network_admin::DhcpInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        provider(
            self.ps.clone(),
            input.timeout_ms,
            input.enabled.is_some(),
            request.ct,
            move |context| network_admin::dhcp_script(&input, context),
        )
        .await
    }

    #[tool(
        description = "Query or change machine WinHTTP static proxy settings or current-token-user WinINet LAN proxy/PAC/auto-detection settings. Omit setting fields to read. Current-user changes require the observed SID; machine WinINet policy is never changed through user scope. Applications may cache these settings."
    )]
    async fn network_proxy_config(
        &self,
        Parameters(input): Parameters<network_proxy::ProxyInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(
            input.timeout_ms,
            input.mutates(),
            request.ct,
            move |context| network_proxy::configure(&input, context),
        )
        .await
    }

    #[tool(
        description = "List native WLAN interfaces and exact saved profile IDs/scopes, plus current connection state. Does not read profile XML or credentials. Reports missing adapters, WLAN service and Windows privacy restrictions."
    )]
    async fn network_wifi_profiles(
        &self,
        Parameters(input): Parameters<wifi_admin::WifiQuery>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            wifi_admin::inventory(&input, context)
        })
        .await
    }

    #[tool(
        description = "Connect an exact saved Wi-Fi profile by interface GUID/profile ID/scope, or disconnect that interface. User profiles require expected_user_sid. Uses no credentials or profile creation. Distinguishes WLAN acceptance from observed profile connection, and never claims Internet connectivity."
    )]
    async fn network_wifi_connect(
        &self,
        Parameters(input): Parameters<wifi_admin::WifiInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            wifi_admin::change(&input, context)
        })
        .await
    }

    #[tool(
        description = "Read current-token-user WSL registration GUIDs, exact names and native distribution configuration without starting a distribution. Reports DLL/utility availability separately from runtime readiness. Does not expose environment values or enable WSL."
    )]
    async fn wsl_instances(
        &self,
        Parameters(input): Parameters<virtualization::VirtualizationQuery>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            virtualization::wsl_inventory(&input, context)
        })
        .await
    }

    #[tool(
        description = "Start an owned WSL status/start/stop/export/import job. Existing instances require exact registration GUID, expected name and current-token SID. Start runs a bounded /bin/sleep keepalive; stop terminates the selected distribution. Export/import use new exact paths. Read job_inspect/job_read/job_wait for exit status and output. No Windows features are installed or enabled."
    )]
    async fn wsl_manage(
        &self,
        Parameters(input): Parameters<virtualization::WslInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        native(input.request_timeout_ms, true, request.ct, move |context| {
            let job = virtualization::wsl_job(&input, context)?;
            launch_job(&manager, &owner, job, context)
        })
        .await
    }

    #[tool(
        description = "Start an owned local Hyper-V provider job to start, gracefully stop, explicitly power off, save, export an exact VM GUID or register an existing .vmcx in place. Uses the installed Hyper-V module, with no feature installation. Read job_inspect/job_read/job_wait: job creation is not VM-operation completion, and accepted VMMS operations may outlive job cancellation."
    )]
    async fn hyperv_manage(
        &self,
        Parameters(input): Parameters<virtualization::HyperVInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.execution.clone();
        let owner = self.execution_connection.clone();
        native(input.request_timeout_ms, true, request.ct, move |context| {
            let job = virtualization::hyperv_job(&input, context)?;
            launch_job(&manager, &owner, job, context)
        })
        .await
    }

    #[tool(
        description = "Read bounded local Hyper-V VM GUIDs, state and configuration through the installed Hyper-V management provider. Reports a missing module as unavailable and service/privilege failures as errors. Never enables or installs Hyper-V."
    )]
    async fn hyperv_instances(
        &self,
        Parameters(input): Parameters<virtualization::VirtualizationQuery>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        provider(
            self.ps.clone(),
            input.timeout_ms,
            false,
            request.ct,
            move |context| {
                context.check()?;
                virtualization::hyperv_inventory_script(&input)
            },
        )
        .await
    }

    #[tool(
        description = "Read a bounded native PnP tree snapshot with exact instance IDs, parent references, class identity, status/problem codes and driver detail. Filters are exact instance/class identities. Missing and inaccessible properties are reported separately; parent nodes may fall outside the bounded result."
    )]
    async fn device_list(
        &self,
        Parameters(input): Parameters<devices::DeviceListInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            devices::list(context, input)
        })
        .await
    }

    #[tool(
        description = "Enable, disable or restart one exact PnP device instance through SetupAPI. Returns native call codes, observed Configuration Manager state, and reboot/restart flags. Restart does not implicitly enable a disabled device. Native acceptance does not independently prove a completed restart cycle."
    )]
    async fn device_set_state(
        &self,
        Parameters(input): Parameters<devices::DeviceStateInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            devices::set_state(context, input)
        })
        .await
    }

    #[tool(
        description = "Read bounded native device-driver associations, including published INF, provider/version/date and present/non-present device identity. Optional exact published-INF filter. This inventory does not include staged packages with no device binding."
    )]
    async fn driver_list(
        &self,
        Parameters(input): Parameters<devices::DriverListInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            devices::drivers(context, input)
        })
        .await
    }

    #[tool(
        description = "Stage an absolute INF, install its compatible drivers by normal Windows rank, or remove an exact unused published oemN.inf. Staging is not device installation. Removal checks present and non-present bindings and never forces removal. Reports published package identity, native errors, observed bindings and reboot information without restarting Windows."
    )]
    async fn driver_package(
        &self,
        Parameters(input): Parameters<devices::DriverPackageInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            devices::manage_driver(context, input)
        })
        .await
    }

    #[tool(
        description = "Enumerate bounded native volumes by exact volume GUID path, with label/filesystem, mount paths and space information. Inaccessible or offline volume properties are returned with native errors rather than dropped."
    )]
    async fn volume_list(
        &self,
        Parameters(input): Parameters<storage::VolumeListInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, false, request.ct, move |context| {
            storage::list_volumes(&input, context)
        })
        .await
    }

    #[tool(
        description = "Set a volume label or add/remove an exact volume mount point. Requires a volume GUID root; mount removal verifies its current target, and mount addition does not overwrite an unrelated mapping. Returns observed state and errors. Does not format volumes or forcibly dismount them."
    )]
    async fn volume_set(
        &self,
        Parameters(input): Parameters<storage::VolumeUpdateInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(input.timeout_ms, true, request.ct, move |context| {
            storage::update_volume(&input, context)
        })
        .await
    }

    #[tool(
        description = "Inspect, attach or detach a local VHD/VHDX/ISO through the Microsoft virtual disk APIs. Mutations require expected_identity copied from image_identity in a prior inspect. Attach defaults to read-only/no-drive-letter and always survives handle closure until explicit detach; it is not a boot attachment. UNC/reparse paths and session-lifetime attachment are unsupported. Returns observed attachment state and native codes."
    )]
    async fn virtual_disk(
        &self,
        Parameters(input): Parameters<storage::VirtualDiskInput>,
        request: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        native(
            input.timeout_ms,
            input.action != storage::VirtualDiskAction::Inspect,
            request.ct,
            move |context| storage::virtual_disk(&input, context),
        )
        .await
    }
}

fn launch_job(
    manager: &crate::execution::ExecutionManager,
    owner: &str,
    job: virtualization::VirtualizationJob,
    context: &AdminContext,
) -> anyhow::Result<Value> {
    use anyhow::Context;
    context.begin_mutation()?;
    let record = manager.start_job_cancellable(
        crate::execution::JobStartInput {
            program: job.program,
            args: job.args,
            timeout_ms: Some(job.timeout_ms),
            output_limit_bytes: Some(262_144),
            ..Default::default()
        },
        owner,
        context.cancellation_token(),
    )?;
    if let Err(error) = context.check() {
        manager.cancel(&record.id, owner).with_context(|| {
            format!("{error}; cleanup of newly created job {} failed", record.id)
        })?;
        anyhow::bail!(
            "{error}; termination requested for newly created job {}",
            record.id
        );
    }
    Ok(serde_json::json!({
        "job": record, "operation": job.operation, "target": job.target,
        "operation_completed": false, "completion_semantics": job.caveat,
        "provider_output": if job.operation.starts_with("hyperv_") { "UTF-8 JSON on stdout" } else { "Native wsl.exe output; use exact output bytes and exit status" },
        "features_installed_or_enabled": false,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn administration_startup_token_observes_request_scope_cancellation() {
        let context = super::AdminContext::new(std::time::Duration::from_secs(1));
        let startup = context.cancellation_token();
        assert!(!startup.is_cancelled());
        drop(super::CancelOnDrop(context.clone()));
        assert!(startup.is_cancelled());
        assert!(context.check().is_err());
    }

    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn administration_deadline_does_not_report_mutation_success() {
        let response = native(Some(100), true, CancellationToken::new(), |context| {
            context.begin_mutation()?;
            std::thread::sleep(Duration::from_millis(150));
            context.check()?;
            Ok(json!({"completed": true}))
        })
        .await
        .unwrap();
        assert_eq!(response.is_error, Some(true));
    }

    #[tokio::test]
    async fn administration_native_work_does_not_block_executor() {
        let start = Instant::now();
        let work = native(Some(1000), false, CancellationToken::new(), |_context| {
            std::thread::sleep(Duration::from_millis(200));
            Ok(json!({"completed": true}))
        });
        let timer = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            start.elapsed()
        };
        let (response, timer_elapsed) = tokio::join!(work, timer);
        assert_eq!(response.unwrap().is_error, Some(false));
        assert!(timer_elapsed < Duration::from_millis(150));
    }

    #[tokio::test]
    async fn administration_pre_cancelled_request_does_not_start_work() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let response = native(Some(1000), true, cancellation, |_context| {
            panic!("A pre-cancelled request must not run");
        })
        .await
        .unwrap();
        assert_eq!(response.is_error, Some(true));
    }

    #[tokio::test]
    async fn administration_native_failure_is_structured_not_success() {
        let response = native(Some(1000), true, CancellationToken::new(), |context| {
            context.begin_mutation()?;
            check_win32("FixtureNativeWrite", 5)?;
            Ok(json!({"completed": true}))
        })
        .await
        .unwrap();
        assert_eq!(response.is_error, Some(true));
        let error = response.structured_content.unwrap();
        assert_eq!(error["native_error"]["code"], 5);
        assert_eq!(error["native_error"]["api"], "FixtureNativeWrite");
        assert_eq!(error["automatically_retried"], false);
    }

    #[tokio::test]
    async fn administration_cancelled_request_does_not_replay_mutation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cancellation = CancellationToken::new();
        let token = cancellation.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let running = started.clone();
        let task = tokio::spawn(native(Some(1000), true, token, move |context| {
            context.begin_mutation()?;
            called.fetch_add(1, Ordering::SeqCst);
            running.notify_one();
            loop {
                context.check()?;
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
        started.notified().await;
        cancellation.cancel();
        assert_eq!(task.await.unwrap().unwrap().is_error, Some(true));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn administration_virtualization_job_seam_preserves_exit_errors() {
        let manager = crate::execution::ExecutionManager::new(
            crate::context::PersistenceContext::connection_owned().unwrap(),
        )
        .unwrap();
        let owner = uuid::Uuid::new_v4().to_string();
        manager.register_connection(&owner).unwrap();
        let job = virtualization::VirtualizationJob {
            program: virtualization::system_directory()
                .unwrap()
                .join("cmd.exe")
                .display()
                .to_string(),
            args: vec!["/d".into(), "/c".into(), "exit 7".into()],
            timeout_ms: 5000,
            operation: "fixture",
            target: json!({"fixture": true}),
            caveat: "Disposable process, no Windows configuration changes.",
        };
        let response = launch_job(
            &manager,
            &owner,
            job,
            &AdminContext::new(Duration::from_secs(5)),
        )
        .unwrap();
        let id = response["job"]["id"].as_str().unwrap();
        let wait = manager
            .wait(id, &owner, 5000, CancellationToken::new())
            .await
            .unwrap();
        manager.shutdown_connection(&owner).unwrap();
        assert_eq!(response["operation_completed"], false);
        assert_eq!(wait.outcome, "exited");
        assert_eq!(wait.process.root_exit_code, Some(7));
        assert!(!wait.process.id.is_empty());
    }

    #[test]
    fn administration_router_registers_native_tools() {
        let router = MasterControlProgram::administration_router();
        assert!(router.has_route("network_interfaces"));
        assert!(router.has_route("network_dns_config"));
        assert!(router.has_route("network_wifi_connect"));
        assert!(router.has_route("network_dhcp_config"));
        assert!(router.has_route("hyperv_instances"));
        assert!(router.has_route("wsl_manage"));
        assert!(router.has_route("device_list"));
        assert!(router.has_route("driver_package"));
        assert!(router.has_route("volume_set"));
        assert!(router.has_route("virtual_disk"));
    }

    #[test]
    fn administration_provider_preserves_hresult_and_unavailable_state() {
        let error = provider_value(json!({
            "administration_ok": false,
            "error": {"hresult": -2147024891i64, "message": "Access denied", "id": "AccessDenied"}
        }))
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<NativeError>().unwrap().code,
            0x80070005
        );
        assert!(provider_value(json!({"data": {}})).is_err());
        assert_eq!(
            provider_value(json!({
                "administration_ok": true,
                "data": {"available": false, "prerequisite": "Hyper-V"}
            }))
            .unwrap()["available"],
            false
        );
    }

    #[tokio::test]
    async fn administration_pool_provider_roundtrip_and_error_fixture() {
        let pool = Arc::new(crate::ps::Pool::new(1).await.unwrap());
        let response = provider(pool.clone(), Some(15_000), false, CancellationToken::new(), |_context| {
            Ok("[pscustomobject]@{\n literal = 'single '' quote`literal $dollar'\n number = 7\n}".into())
        }).await.unwrap();
        assert_eq!(response.is_error, Some(false), "{response:?}");
        let data = response.structured_content.unwrap();
        assert_eq!(data["literal"], "single ' quote`literal $dollar");
        assert_eq!(data["number"], 7);
        let response = provider(
            pool,
            Some(15_000),
            false,
            CancellationToken::new(),
            |_context| {
                Ok(
                    "throw [System.UnauthorizedAccessException]::new('fixture-provider-error')"
                        .into(),
                )
            },
        )
        .await
        .unwrap();
        assert_eq!(response.is_error, Some(true));
        assert_eq!(
            response.structured_content.unwrap()["native_error"]["code"],
            0x80070005u32
        );
    }

    #[tokio::test]
    async fn administration_hyperv_read_only_capability_or_provider_error() {
        let pool = Arc::new(crate::ps::Pool::new(1).await.unwrap());
        let response = provider(
            pool,
            Some(15_000),
            false,
            CancellationToken::new(),
            |_context| {
                virtualization::hyperv_inventory_script(&virtualization::VirtualizationQuery {
                    limit: Some(1),
                    timeout_ms: None,
                })
            },
        )
        .await
        .unwrap();
        let data = response.structured_content.unwrap();
        if response.is_error == Some(true) {
            assert!(data["native_error"]["code"].is_number(), "{data}");
        } else {
            assert!(data["available"].is_boolean(), "{data}");
            assert_eq!(data["features_installed_or_enabled"], false);
            if data["available"] == true {
                assert!(data["machines"].as_array().unwrap().len() <= 1);
            } else {
                assert!(data["prerequisite"].as_str().is_some());
            }
        }
    }
}
