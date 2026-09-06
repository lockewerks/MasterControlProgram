mod bridge;

use std::{
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use rmcp::ServiceExt;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{ERROR_PIPE_BUSY, HANDLE},
        Security::{RevertToSelf, TOKEN_QUERY},
        Storage::FileSystem::{
            CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
        },
        System::{
            Pipes::{
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                ImpersonateNamedPipeClient,
            },
            Threading::{
                GetCurrentThread, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
                PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
};

use crate::{
    context::{
        own, process_creation_time, process_token, raw, validate_name, verify_owner_only,
        PersistenceContext, SecurityDescriptor, TokenContext,
    },
    server::MasterControlProgram,
};

const MAGIC: &[u8] = b"MCP-LOCAL-HOST-1\n";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HELLO_BYTES: usize = 65536;
const MAX_CONNECTIONS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    Stdio,
    Host {
        name: String,
        state_directory: Option<PathBuf>,
    },
    Connect {
        name: String,
    },
}

impl Mode {
    pub(crate) fn parse(args: &[String]) -> anyhow::Result<Self> {
        let (mut host, mut connect, mut state_directory) = (None, None, None);
        let mut arguments = args.iter().skip(1);
        while let Some(argument) = arguments.next() {
            let destination = match argument.as_str() {
                "--local-host" => &mut host,
                "--connect-host" => &mut connect,
                "--host-state-dir" => &mut state_directory,
                _ => continue,
            };
            anyhow::ensure!(destination.is_none(), "duplicate {argument}");
            let value = arguments
                .next()
                .with_context(|| format!("{argument} requires a value"))?;
            anyhow::ensure!(
                !value.starts_with("--") && !value.contains('\0'),
                "invalid value for {argument}"
            );
            *destination = Some(value.clone());
        }
        anyhow::ensure!(
            host.is_none() || connect.is_none(),
            "--local-host and --connect-host are mutually exclusive"
        );
        anyhow::ensure!(
            state_directory.is_none() || host.is_some(),
            "--host-state-dir requires --local-host"
        );
        if let Some(name) = host {
            validate_name(&name)?;
            let state_directory = state_directory.map(PathBuf::from);
            if let Some(path) = &state_directory {
                anyhow::ensure!(path.is_absolute(), "--host-state-dir must be absolute");
            }
            Ok(Self::Host {
                name,
                state_directory,
            })
        } else if let Some(name) = connect {
            validate_name(&name)?;
            Ok(Self::Connect { name })
        } else {
            Ok(Self::Stdio)
        }
    }
}

fn pipe_name(token: &TokenContext, name: &str) -> anyhow::Result<String> {
    Ok(format!(
        r"\\.\pipe\LOCAL\MasterControlProgram-{}",
        token.endpoint_key(name)?
    ))
}

fn listener(name: &str, token: &TokenContext, first: bool) -> anyhow::Result<NamedPipeServer> {
    let descriptor = SecurityDescriptor::owner_only(&token.user_sid, false)?;
    let mut attributes = descriptor.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .in_buffer_size(65536)
        .out_buffer_size(65536)
        .max_instances(MAX_CONNECTIONS + 1);
    let pipe = unsafe {
        options.create_with_security_attributes_raw(name, (&mut attributes as *mut windows::Win32::Security::SECURITY_ATTRIBUTES).cast())
    }.context("create owner-restricted local pipe; another host or a spoofed endpoint may already own this name")?;
    verify_owner_only(raw(&pipe), &token.user_sid)?;
    Ok(pipe)
}

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    protocol: String,
    epoch: String,
    pid: u32,
    process_creation_time: u64,
    connection_id: String,
    token: TokenContext,
}

struct PeerIdentity {
    _process: OwnedHandle,
    pid: u32,
    creation_time: u64,
    token: TokenContext,
}

fn peer_identity(pid: u32) -> anyhow::Result<PeerIdentity> {
    let process = unsafe { own(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?) };
    let token = process_token(raw(&process))?;
    Ok(PeerIdentity {
        pid,
        creation_time: process_creation_time(raw(&process))?,
        token: TokenContext::read(raw(&token))?,
        _process: process,
    })
}

struct RevertImpersonation;

impl Drop for RevertImpersonation {
    fn drop(&mut self) {
        if let Err(error) = unsafe { RevertToSelf() } {
            tracing::error!(%error, "failed to revert pipe client impersonation");
            // Reusing a runtime thread under another token would cross the access boundary.
            std::process::abort();
        }
    }
}

fn authenticate_client(pipe: OwnedHandle, expected: TokenContext) -> anyhow::Result<()> {
    let mut pid = 0;
    unsafe { GetNamedPipeClientProcessId(raw(&pipe), &mut pid)? };
    let peer = peer_identity(pid)?;
    expected.require_same_access(&peer.token)?;
    unsafe { ImpersonateNamedPipeClient(raw(&pipe))? };
    let revert = RevertImpersonation;
    let mut token = HANDLE::default();
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token)? };
    let token = unsafe { own(token) };
    let impersonated = TokenContext::read(raw(&token))?;
    expected.require_same_access(&impersonated)?;
    peer.token.require_same_access(&impersonated)?;
    drop(revert);
    // Re-read the kernel peer PID after inspection rather than trusting any client claim.
    let mut confirmed = 0;
    unsafe { GetNamedPipeClientProcessId(raw(&pipe), &mut confirmed)? };
    anyhow::ensure!(
        confirmed == peer.pid,
        "pipe client identity changed during authentication"
    );
    Ok(())
}

fn file_identity(path: &Path) -> anyhow::Result<(OwnedHandle, (u32, u32, u32))> {
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        own(CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?)
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(raw(&handle), &mut info)? };
    Ok((
        handle,
        (
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ),
    ))
}

fn authenticate_server(pipe: OwnedHandle, expected: TokenContext) -> anyhow::Result<PeerIdentity> {
    let mut pid = 0;
    unsafe { GetNamedPipeServerProcessId(raw(&pipe), &mut pid)? };
    let peer = peer_identity(pid)?;
    expected.require_same_access(&peer.token)?;
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            raw(&peer._process),
            PROCESS_NAME_FORMAT(0),
            PWSTR(image.as_mut_ptr()),
            &mut length,
        )?;
    }
    let image = PathBuf::from(String::from_utf16(&image[..length as usize])?);
    let (_peer_file, peer_file_id) = file_identity(&image)?;
    let (_own_file, own_file_id) = file_identity(&std::env::current_exe()?)?;
    anyhow::ensure!(
        peer_file_id == own_file_id,
        "local pipe server is not this MasterControlProgram executable"
    );
    let mut confirmed = 0;
    unsafe { GetNamedPipeServerProcessId(raw(&pipe), &mut confirmed)? };
    anyhow::ensure!(
        confirmed == peer.pid,
        "pipe server identity changed during authentication"
    );
    Ok(peer)
}

pub(crate) struct LocalHost {
    name: String,
    pipe_name: String,
    listener: NamedPipeServer,
    context: PersistenceContext,
}

impl LocalHost {
    pub(crate) async fn bind(
        name: String,
        state_directory: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let context_name = name.clone();
        let context = tokio::task::spawn_blocking(move || {
            PersistenceContext::persistent_host(&context_name, state_directory.as_deref())
        })
        .await??;
        let pipe_name = pipe_name(&context.execution.token, &name)?;
        let listener = listener(&pipe_name, &context.execution.token, true)?;
        Ok(Self {
            name,
            pipe_name,
            listener,
            context,
        })
    }

    pub(crate) fn context(&self) -> PersistenceContext {
        self.context.clone()
    }

    fn take_connection(&mut self, active: usize) -> anyhow::Result<Option<NamedPipeServer>> {
        if active >= MAX_CONNECTIONS {
            tracing::warn!("local host connection capacity reached");
            self.listener
                .disconnect()
                .context("reject excess local pipe connection")?;
            return Ok(None);
        }
        // Keep an instance bound so another process cannot take the endpoint.
        let next = listener(&self.pipe_name, &self.context.execution.token, false)?;
        Ok(Some(std::mem::replace(&mut self.listener, next)))
    }

    pub(crate) async fn run(mut self, server: MasterControlProgram) -> anyhow::Result<()> {
        let manager = server.execution.clone();
        server.shutdown_connection().await?;
        let stop = manager.shutdown_token();
        let ready = serde_json::json!({
            "host_ready": true, "name": self.name, "epoch": self.context.epoch,
            "pid": self.context.execution.pid,
            "process_creation_time": self.context.execution.process_creation_time,
            "pipe": self.pipe_name,
            "state_directory": self.context.state_directory(),
            "token": self.context.execution.token,
            "persistent_lifetime_requires_explicit_tool_input": true,
        });
        let mut ready = serde_json::to_vec(&ready)?;
        ready.push(b'\n');
        tokio::io::stdout().write_all(&ready).await?;
        tokio::io::stdout().flush().await?;
        let mut clients = JoinSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                _ = stop.cancelled() => break Ok(()),
                signal = tokio::signal::ctrl_c() => break signal.map_err(anyhow::Error::from),
                _ = interval.tick() => {
                    let manager = manager.clone();
                    match tokio::task::spawn_blocking(move || manager.checkpoint()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::error!(%error, "local host execution checkpoint failed; history reports the failure"),
                        Err(error) => break Err(error.into()),
                    }
                }
                connected = self.listener.connect() => {
                    if let Err(error) = connected { break Err(error.into()); }
                    let accepted = match self.take_connection(clients.len()) {
                        Ok(Some(accepted)) => accepted,
                        Ok(None) => continue,
                        Err(error) => break Err(error),
                    };
                    clients.spawn(serve_connection(accepted, server.clone(), self.context.clone(), stop.clone()));
                }
                Some(completed) = clients.join_next(), if !clients.is_empty() => {
                    match completed {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::warn!(%error, "local host connection ended with an error"),
                        Err(error) => tracing::error!(%error, "local host connection task failed"),
                    }
                }
            }
        };
        stop.cancel();
        drop(self.listener);
        let drained = tokio::time::timeout(Duration::from_secs(15), async {
            let mut errors = Vec::new();
            while let Some(client) = clients.join_next().await {
                match client {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(format!("connection shutdown failed: {error:#}")),
                    Err(error) => errors.push(format!("connection shutdown task failed: {error}")),
                }
            }
            anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
            anyhow::Ok(())
        })
        .await;
        let drained = match drained {
            Ok(result) => result,
            Err(_) => {
                clients.abort_all();
                while clients.join_next().await.is_some() {}
                Err(anyhow::anyhow!(
                    "local host connections did not stop within 15 seconds"
                ))
            }
        };
        let cleanup = server.shutdown().await;
        crate::server::lifecycle_result([
            ("host service", result),
            ("host connections", drained),
            ("host state cleanup", cleanup),
        ])
    }
}

async fn serve_connection(
    mut pipe: NamedPipeServer,
    server: MasterControlProgram,
    context: PersistenceContext,
    stop: CancellationToken,
) -> anyhow::Result<()> {
    let owner = uuid::Uuid::new_v4().to_string();
    let handshake = async {
        let mut magic = [0u8; MAGIC.len()];
        pipe.read_exact(&mut magic).await?;
        anyhow::ensure!(magic == MAGIC, "invalid local host protocol prefix");
        let pipe_handle = pipe.as_handle().try_clone_to_owned()?;
        let token = tokio::task::spawn_blocking(move || {
            let expected = TokenContext::current()?;
            authenticate_client(pipe_handle, expected.clone())?;
            anyhow::Ok(expected)
        })
        .await??;
        let hello = Hello {
            protocol: "mcp-local-host-1".into(),
            epoch: context.epoch.clone(),
            pid: context.execution.pid,
            process_creation_time: context.execution.process_creation_time,
            connection_id: owner.clone(),
            token,
        };
        let bytes = serde_json::to_vec(&hello)?;
        anyhow::ensure!(
            bytes.len() <= MAX_HELLO_BYTES,
            "local host hello exceeds its size limit"
        );
        pipe.write_u32_le(bytes.len() as u32).await?;
        pipe.write_all(&bytes).await?;
        anyhow::Ok(())
    };
    tokio::select! {
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake) => result.context("local host authentication timed out")??,
        _ = stop.cancelled() => anyhow::bail!("local host is shutting down"),
    }
    let server = server.for_connection(owner)?;
    let outcome = async {
        let disconnected = server.execution_connection_cancel.clone();
        let transport = crate::connection::observe(tokio::io::split(pipe), disconnected.clone());
        let service = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(10), server.clone().serve(transport)) => result.context("local MCP initialize timed out")??,
            _ = stop.cancelled() => anyhow::bail!("local host is shutting down"),
        };
        let cancel = service.cancellation_token();
        let waiting = service.waiting();
        tokio::pin!(waiting);
        let finished = tokio::select! {
            result = &mut waiting => Some(result),
            _ = stop.cancelled() => None,
            _ = disconnected.cancelled() => None,
        };
        if let Some(result) = finished {
            result?;
        } else {
            cancel.cancel();
            let cleanup = server.shutdown_connection().await;
            let stopped = tokio::time::timeout(Duration::from_secs(10), &mut waiting).await;
            let stopped = stopped.context("local MCP service did not stop after disconnect")
                .and_then(|result| result.map(|_| ()).map_err(anyhow::Error::from));
            crate::server::lifecycle_result([
                ("connection cleanup", cleanup),
                ("MCP service shutdown", stopped),
            ])?;
        }
        anyhow::Ok(())
    }.await;
    let cleanup = server.shutdown_connection().await;
    crate::server::lifecycle_result([("connection", outcome), ("connection cleanup", cleanup)])
}

async fn open_pipe(address: &str, timeout: Duration) -> std::io::Result<NamedPipeClient> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match ClientOptions::new().open(address) {
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep_until(
                    (tokio::time::Instant::now() + Duration::from_millis(10)).min(deadline),
                )
                .await;
            }
            result => return result,
        }
    }
}

pub(crate) async fn connect(name: String) -> anyhow::Result<NamedPipeClient> {
    let token = tokio::task::spawn_blocking(TokenContext::current).await??;
    let address = pipe_name(&token, &name)?;
    let mut pipe = open_pipe(&address, PIPE_BUSY_TIMEOUT).await
        .context("local host is unavailable in this exact account/session/integrity context; start it explicitly, then connect with the same context")?;
    let handle = pipe.as_handle().try_clone_to_owned()?;
    let expected = token.clone();
    let peer = tokio::task::spawn_blocking(move || authenticate_server(handle, expected)).await??;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        pipe.write_all(MAGIC).await?;
        let length = pipe.read_u32_le().await? as usize;
        anyhow::ensure!(
            (1..=MAX_HELLO_BYTES).contains(&length),
            "invalid local host hello length"
        );
        let mut bytes = vec![0; length];
        pipe.read_exact(&mut bytes).await?;
        let hello: Hello = serde_json::from_slice(&bytes).context("invalid local host hello")?;
        anyhow::ensure!(
            hello.protocol == "mcp-local-host-1",
            "unsupported local host protocol"
        );
        anyhow::ensure!(
            hello.pid == peer.pid && hello.process_creation_time == peer.creation_time,
            "local host declared a spoofed process identity"
        );
        token.require_same_access(&hello.token)?;
        uuid::Uuid::parse_str(&hello.epoch).context("invalid host epoch")?;
        uuid::Uuid::parse_str(&hello.connection_id).context("invalid host connection UUID")?;
        anyhow::Ok(())
    })
    .await
    .context("local host handshake timed out")??;
    Ok(pipe)
}

pub(crate) async fn stdio_bridge(name: String) -> anyhow::Result<()> {
    bridge::relay(connect(name).await?).await
}

#[cfg(test)]
mod tests;
