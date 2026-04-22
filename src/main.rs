//! # MasterControlProgram - Entry Point
//!
//! The front door to the most aggressively performant Windows MCP server
//! ever conceived by someone who was tired of PowerShell taking 1.5 seconds
//! to tell them what their own CPU is called.
//!
//! This binary does exactly three things:
//! 1. Sets up logging so you can watch the carnage in real time
//! 2. Spawns a pool of PowerShell processes like some kind of shell necromancer
//! 3. Starts the MCP server and prays to the async gods

mod ps;
mod server;
mod win32;

use rmcp::{ServiceExt, transport::stdio};
use std::fs::OpenOptions;
use tracing_subscriber::{self, EnvFilter, fmt, prelude::*};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tell Windows we want real pixels, not the scaled-down fantasy version.
    // Without this, SetCursorPos and GDI capture get virtualized coordinates
    // on any display that isn't running at 100% scaling — so clicks land in
    // the wrong place and screenshots come back shrunk. Per-monitor-v2 means
    // every monitor gets its own real DPI and the virtual-screen coordinates
    // are actual physical pixels spanning the whole desktop.
    //
    // Must run before any DPI-sensitive API. First line of main. No exceptions.
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
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
        .with(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with(file_layer)
        .with(stderr_layer)
        .init();

    tracing::info!("MasterControlProgram v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("log file: {}", log_path.display());

    // You can override pool size with MCP_POOL_SIZE env var.
    // Default is 3 because three PowerShell processes is already three too many,
    // but some of our tools still need the damn thing.
    let pool_size: usize = std::env::var("MCP_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    // Boot the PowerShell sweatshop and the MCP server
    let ps_pool = ps::Pool::new(pool_size).await?;
    let server = server::MasterControlProgram::new(ps_pool);
    let service = server.serve(stdio()).await.inspect_err(|e| {
        tracing::error!("server error: {:?}", e);
    })?;

    tracing::info!("MCP server connected, waiting for requests");
    service.waiting().await?;
    tracing::info!("MCP server shutting down");
    Ok(())
}
