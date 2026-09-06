//! Local stdio server and explicit resident-host lifecycle.
//! Registration and installer hooks run before elevation or server initialization.

mod administration;
mod clients;
mod coerce;
mod connection;
mod context;
mod desktop;
mod diagnostics;
mod elevate;
mod execution;
mod host;
mod installer;
mod observation;
mod overlay;
mod provider_tools;
mod ps;
mod runtime;
mod server;
mod spike;
mod system_control;
mod win32;
mod workflow;

use rmcp::{transport::stdio, ServiceExt};
use std::fs::OpenOptions;
use tracing_subscriber::{self, fmt, prelude::*, EnvFilter};
use windows::Win32::UI::HiDpi::{
    GetAwarenessFromDpiAwarenessContext, GetThreadDpiAwarenessContext,
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};

enum EarlyAction {
    Registration(anyhow::Result<clients::Action>),
    KillStale,
    OverlayDemo,
}

fn early_action(args: &[String]) -> Option<EarlyAction> {
    if let Some(action) = clients::Action::from_args(args) {
        return Some(EarlyAction::Registration(action));
    }
    if args.iter().any(|arg| arg == installer::KILL_FLAG) {
        return Some(EarlyAction::KillStale);
    }
    if args.iter().any(|arg| arg == spike::FLAG) {
        return Some(EarlyAction::OverlayDemo);
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Installer hooks call these, and so can anyone who'd rather not hand-edit
    // somebody else's config file. They run before everything else on purpose:
    // no log file, no pwsh pool, and above all no elevation gate. A CLI
    // subcommand that re-execs itself through sudo would sit there holding a
    // pipe nobody is reading.
    //
    //   --register                 every client installed on this box
    //   --register-claude-desktop  Claude Desktop
    //   --register-chatgpt         ChatGPT desktop, Codex CLI, Codex IDE
    //
    // plus the matching --unregister forms. Name both to get both.
    let args: Vec<String> = std::env::args().collect();
    if let Some(action) = early_action(&args) {
        return match action {
            EarlyAction::Registration(action) => action.and_then(clients::Action::run),
            EarlyAction::KillStale => installer::kill_stale(),
            EarlyAction::OverlayDemo => spike::run(),
        };
    }

    let execution_mode = host::Mode::parse(&args)?;
    if let host::Mode::Connect { name } = &execution_mode {
        // A bridge uses its actual token and cannot start or elevate a host.
        return host::stdio_bridge(name.clone()).await;
    }

    // Dual logging: stderr for the MCP client that spawned us, and a file for
    // the poor bastard who needs to figure out why shit isn't working.
    // tail -f %TEMP%\MasterControlProgram.log  <-- you're welcome
    let log_path = std::env::temp_dir().join("MasterControlProgram.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    // Two layers because apparently one output stream isn't enough for anyone anymore.
    // stderr goes to the MCP client. The file is for human eyeballs.
    let file_layer = fmt::layer()
        .with_writer(std::sync::Mutex::new(log_file))
        .with_ansi(false)
        .with_target(false)
        .with_timer(fmt::time::uptime());

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .with_timer(fmt::time::uptime());

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(file_layer)
        .with(stderr_layer)
        .init();

    tracing::info!(
        "MasterControlProgram v{} starting",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("log file: {}", log_path.display());

    // Elevation gate. Has to clear before the PowerShell pool starts, or the
    // unelevated wrapper spawns three pwsh workers and orphans them the instant
    // it hands off to the elevated child. See src/elevate.rs for why this is
    // sudo and not a manifest or ShellExecuteEx.
    match elevate::gate()? {
        elevate::Gate::Exit(code) => {
            tracing::info!(code, "elevated child finished, exiting");
            std::process::exit(code);
        }
        elevate::Gate::Serve => {}
    }

    // Tell Windows we want real pixels, not the scaled-down fantasy version.
    // Without this, SetCursorPos and GDI capture get virtualized coordinates
    // on any display that isn't running at 100% scaling, so clicks land in the
    // wrong place and screenshots come back shrunk. Per-monitor-v2 means every
    // monitor gets its own real DPI and the virtual-screen coordinates are
    // actual physical pixels spanning the whole desktop.
    //
    // Runs before any DPI-sensitive API. Logging setup and the elevation gate
    // above touch none of them, and the wrapper process exits without drawing.
    let dpi_set_result =
        unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };

    // Verify DPI awareness actually took effect. Maps the awareness enum
    // value to a human-readable label so debugging coordinate issues on
    // scaled displays doesn't require reading the Windows SDK.
    let awareness_label = unsafe {
        let ctx = GetThreadDpiAwarenessContext();
        let awareness = GetAwarenessFromDpiAwarenessContext(ctx);
        match awareness.0 {
            -1 => "INVALID",
            0 => "UNAWARE (coordinates will be virtualized, bad)",
            1 => "SYSTEM_AWARE (single-DPI, bad for mixed-DPI multi-monitor)",
            2 => "PER_MONITOR_AWARE (good)",
            _ => "UNKNOWN",
        }
    };
    match dpi_set_result {
        Ok(()) => tracing::info!(
            "DPI awareness: set PER_MONITOR_AWARE_V2, thread reports {awareness_label}"
        ),
        Err(e) => tracing::warn!(
            "DPI awareness: failed to set V2 ({e}), thread reports {awareness_label}"
        ),
    }

    // The activity glow. Spawns a thread owning one layered, click-through,
    // capture-excluded window over the whole desktop, lit whenever a tool drives
    // the machine, so whoever is sitting here can tell the input is not theirs.
    //
    // After the elevation gate, for the same reason the pwsh pool is: the
    // unelevated wrapper sits inside gate() for the whole session, so anything
    // above that line runs in both processes and we would draw twice.
    //
    // After the DPI call, and that one is not cosmetic. A window inherits DPI
    // awareness from its thread at creation and never changes it. Created
    // unaware, the glow gets stretched by the compositor and sized from
    // virtualized metrics, so on a scaled display it lands in the wrong place
    // at the wrong size. Setting the process default first means the overlay
    // thread inherits PER_MONITOR_AWARE_V2 too.
    //
    // Arm the glow before the client can land its first tool call.
    overlay::init();

    // Validate configuration without starting pwsh. Native tools and the stdio
    // handshake must work even when PowerShell is not installed.
    let ps_pool = ps::Pool::from_env()?;
    let local_host = match execution_mode {
        host::Mode::Host {
            name,
            state_directory,
        } => Some(host::LocalHost::bind(name, state_directory).await?),
        _ => None,
    };
    let server = if let Some(host) = &local_host {
        let context = host.context();
        tokio::task::spawn_blocking(move || {
            let execution = std::sync::Arc::new(execution::ExecutionManager::new(context)?);
            server::MasterControlProgram::new_with_execution(ps_pool, execution)
        })
        .await??
    } else {
        tokio::task::spawn_blocking(move || server::MasterControlProgram::new(ps_pool)).await??
    };
    server.observation.recover_native_traces().await;
    if let Some(host) = local_host {
        return host.run(server).await;
    }

    let disconnected = server.execution_connection_cancel.clone();
    let transport = connection::observe(stdio(), disconnected.clone());
    let outcome = async {
        let service = server.clone().serve(transport).await?;
        tracing::info!("MCP server connected, waiting for requests");
        let cancel = service.cancellation_token();
        let waiting = service.waiting();
        tokio::pin!(waiting);
        tokio::select! {
            result = &mut waiting => result.map(|_| ()).map_err(anyhow::Error::from),
            _ = disconnected.cancelled() => {
                cancel.cancel();
                let cleanup = server.shutdown_connection().await;
                let stopped = tokio::time::timeout(std::time::Duration::from_secs(10), &mut waiting)
                    .await.map_err(|_| anyhow::anyhow!("stdio service did not stop after disconnect"))
                    .and_then(|result| result.map(|_| ()).map_err(anyhow::Error::from));
                server::lifecycle_result([("connection cleanup", cleanup), ("stdio shutdown", stopped)])
            }
        }
    }.await;
    let connection_cleanup = server.shutdown_connection().await;
    let shutdown = server.shutdown().await;
    tracing::info!("MCP server shutting down");
    server::lifecycle_result([
        ("stdio service", outcome),
        ("connection cleanup", connection_cleanup),
        ("server shutdown", shutdown),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(flags: &[&str]) -> Vec<String> {
        std::iter::once("MasterControlProgram")
            .chain(flags.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn registration_precedes_installer_hook_and_overlay() {
        let action = early_action(&args(&["--register", installer::KILL_FLAG, spike::FLAG]));
        assert!(matches!(action, Some(EarlyAction::Registration(_))));
    }

    #[test]
    fn conflicting_registration_exits_before_server_startup() {
        let action = early_action(&args(&["--register", "--unregister", spike::FLAG]));
        assert!(matches!(action, Some(EarlyAction::Registration(Err(_)))));
    }

    #[test]
    fn installer_hook_precedes_overlay_demo() {
        assert!(matches!(
            early_action(&args(&[spike::FLAG, installer::KILL_FLAG])),
            Some(EarlyAction::KillStale)
        ));
        assert!(matches!(
            early_action(&args(&[spike::FLAG])),
            Some(EarlyAction::OverlayDemo)
        ));
        assert!(early_action(&args(&[])).is_none());
    }

    #[test]
    fn startup_order_preserves_elevation_and_early_cli_paths() {
        let src = include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let stages = [
            "early_action(&args)",
            "let log_path",
            "match elevate::gate()",
            "SetProcessDpiAwarenessContext(",
            "overlay::init()",
            "ps::Pool::from_env()",
            "connection::observe(stdio()",
            ".serve(transport)",
        ];
        let positions: Vec<_> = stages
            .iter()
            .map(|stage| src.find(stage).unwrap())
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
