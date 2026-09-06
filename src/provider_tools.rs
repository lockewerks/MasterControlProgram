use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{
    server::{err, ok, MasterControlProgram},
    win32::audio::{self, EndpointInput, RecordInput, SessionVolumeInput, SessionsInput},
};
use rmcp::{
    handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
    ErrorData as McpError,
};

struct RecordingCancellation(Arc<AtomicBool>);

impl Drop for RecordingCancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

async fn blocking(
    operation: impl FnOnce() -> anyhow::Result<String> + Send + 'static,
) -> Result<CallToolResult, McpError> {
    match crate::runtime::blocking(operation).await {
        Ok(value) => ok(value),
        Err(error) => err(format!("{error:#}")),
    }
}

#[tool_router(router = provider_router, vis = "pub(crate)")]
impl MasterControlProgram {
    #[tool(
        description = "Read native audio endpoint peak levels and per-channel meters. Does not record audio or change volume."
    )]
    async fn audio_meter(
        &self,
        Parameters(input): Parameters<EndpointInput>,
    ) -> Result<CallToolResult, McpError> {
        blocking(move || audio::meter(&input)).await
    }

    #[tool(
        description = "List audio sessions on a playback or capture endpoint with exact session instance IDs, process identities, volume and mute."
    )]
    async fn audio_sessions(
        &self,
        Parameters(input): Parameters<SessionsInput>,
    ) -> Result<CallToolResult, McpError> {
        blocking(move || audio::sessions(&input)).await
    }

    #[tool(
        description = "Read or set playback-session volume/mute by exact session instance ID or unambiguous PID. PID-only changes require the process creation time from audio_sessions. Capture-session reads report endpoint-wide scope; capture changes require audio_volume because they affect other applications."
    )]
    async fn audio_session_volume(
        &self,
        Parameters(input): Parameters<SessionVolumeInput>,
    ) -> Result<CallToolResult, McpError> {
        blocking(move || audio::session_volume(&input)).await
    }

    #[tool(
        description = "Explicitly record an audio input or playback loopback to a new WAV artifact. Requires mode, duration_seconds and an absolute path. Uses the endpoint's actual mix format, bounded buffers/file size, and removes incomplete artifacts on cancellation. Never replaces an existing file."
    )]
    async fn audio_record(
        &self,
        Parameters(input): Parameters<RecordInput>,
    ) -> Result<CallToolResult, McpError> {
        let cancellation = RecordingCancellation(Arc::new(AtomicBool::new(false)));
        let flag = cancellation.0.clone();
        let timeout_ms = (u64::from(input.duration_seconds.clamp(1, 300)) + 5) * 1000;
        match crate::runtime::blocking_with_timeout(timeout_ms, move || {
            audio::record(&input, &flag)
        })
        .await
        {
            Ok(value) => ok(value),
            Err(error) => err(format!("{error:#}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_cancellation_is_owned_by_the_request() {
        let flag = Arc::new(AtomicBool::new(false));
        let guard = RecordingCancellation(flag.clone());
        assert!(!flag.load(Ordering::Acquire));
        drop(guard);
        assert!(flag.load(Ordering::Acquire));
    }
}
