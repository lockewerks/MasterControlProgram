use super::*;

#[test]
fn explicit_cli_modes_do_not_change_stdio_default() -> anyhow::Result<()> {
    let args = |values: &[&str]| values.iter().map(|v| (*v).into()).collect::<Vec<_>>();
    assert_eq!(Mode::parse(&args(&["mcp"]))?, Mode::Stdio);
    assert_eq!(
        Mode::parse(&args(&["mcp", "--connect-host", "dev"]))?,
        Mode::Connect { name: "dev".into() }
    );
    for values in [
        vec!["mcp", "--connect-host"],
        vec!["mcp", "--local-host", "a", "--connect-host", "a"],
        vec!["mcp", "--host-state-dir", "C:\\temp"],
        vec!["mcp", "--local-host", "\\\\remote\\pipe\\x"],
        vec!["mcp", "--connect-host", "a", "--connect-host", "b"],
    ] {
        assert!(Mode::parse(&args(&values)).is_err());
    }
    Ok(())
}

#[test]
fn exact_context_rejects_elevation_session_and_restricted_token_changes() -> anyhow::Result<()> {
    let token = TokenContext::current()?;
    token.require_same_access(&token)?;
    let mut changed = token.clone();
    changed.integrity_rid += 1;
    assert!(token.require_same_access(&changed).is_err());
    changed = token.clone();
    changed.session_id += 1;
    assert!(token.require_same_access(&changed).is_err());
    changed = token.clone();
    changed.elevated = !changed.elevated;
    assert!(token.require_same_access(&changed).is_err());
    changed = token.clone();
    changed.user_sid.push_str("-1");
    assert!(token.require_same_access(&changed).is_err());
    changed = token.clone();
    changed.restricted = !changed.restricted;
    assert!(token.require_same_access(&changed).is_err());
    changed = token.clone();
    changed.logon_id.push('1');
    assert!(token.require_same_access(&changed).is_err());
    Ok(())
}

#[tokio::test]
async fn local_pipe_authentication_and_endpoint_exclusivity() -> anyhow::Result<()> {
    let token = TokenContext::current()?;
    let address = pipe_name(&token, &format!("test-{}", uuid::Uuid::new_v4()))?;
    assert!(address.starts_with(r"\\.\pipe\LOCAL\"));
    let mut server = listener(&address, &token, true)?;
    assert!(listener(&address, &token, true).is_err());
    let mut client = ClientOptions::new().open(&address)?;
    server.connect().await?;
    let client_handle = client.as_handle().try_clone_to_owned()?;
    let expected = token.clone();
    let actual =
        tokio::task::spawn_blocking(move || authenticate_server(client_handle, expected)).await??;
    assert_eq!(actual.pid, std::process::id());
    client.write_all(MAGIC).await?;
    let mut bytes = [0u8; MAGIC.len()];
    server.read_exact(&mut bytes).await?;
    let server_handle = server.as_handle().try_clone_to_owned()?;
    tokio::task::spawn_blocking(move || authenticate_client(server_handle, token)).await??;
    drop(client);
    drop(server);
    Ok(())
}

#[tokio::test]
async fn restricted_same_user_pipe_client_cannot_borrow_host_privileges() -> anyhow::Result<()> {
    use windows::Win32::{
        Security::{
            CreateRestrictedToken, ImpersonateLoggedOnUser, DISABLE_MAX_PRIVILEGE, TOKEN_DUPLICATE,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let token = TokenContext::current()?;
    let address = pipe_name(&token, &format!("restricted-{}", uuid::Uuid::new_v4()))?;
    let mut server = listener(&address, &token, true)?;
    let mut client = tokio::task::spawn_blocking(move || -> anyhow::Result<NamedPipeClient> {
        let mut primary = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut primary,
            )?
        };
        let primary = unsafe { own(primary) };
        let mut restricted = HANDLE::default();
        unsafe {
            CreateRestrictedToken(
                raw(&primary),
                DISABLE_MAX_PRIVILEGE,
                None,
                None,
                None,
                &mut restricted,
            )?
        };
        let restricted = unsafe { own(restricted) };
        unsafe { ImpersonateLoggedOnUser(raw(&restricted))? };
        let revert = RevertImpersonation;
        let client = ClientOptions::new().open(address)?;
        drop(revert);
        Ok(client)
    })
    .await??;
    server.connect().await?;
    client.write_all(MAGIC).await?;
    let mut bytes = [0; MAGIC.len()];
    server.read_exact(&mut bytes).await?;
    let handle = server.as_handle().try_clone_to_owned()?;
    let rejected = tokio::task::spawn_blocking(move || authenticate_client(handle, token)).await?;
    assert!(
        rejected.is_err(),
        "restricted client was allowed to proxy the host token"
    );
    drop(client);
    drop(server);
    Ok(())
}

#[tokio::test]
async fn bridge_rejects_a_spoofed_hello_process_identity() -> anyhow::Result<()> {
    let name = format!("spoof-{}", uuid::Uuid::new_v4());
    let token = TokenContext::current()?;
    let mut server = listener(&pipe_name(&token, &name)?, &token, true)?;
    let peer = tokio::spawn(async move {
        server.connect().await?;
        let mut prefix = [0; MAGIC.len()];
        server.read_exact(&mut prefix).await?;
        let hello = Hello {
            protocol: "mcp-local-host-1".into(),
            epoch: uuid::Uuid::new_v4().to_string(),
            connection_id: uuid::Uuid::new_v4().to_string(),
            pid: std::process::id().wrapping_add(1),
            process_creation_time: 1,
            token,
        };
        let bytes = serde_json::to_vec(&hello)?;
        server.write_u32_le(bytes.len() as u32).await?;
        server.write_all(&bytes).await?;
        anyhow::Ok(())
    });
    let error = connect(name)
        .await
        .err()
        .context("spoofed host hello was accepted")?;
    assert!(
        error.to_string().contains("spoofed process identity"),
        "{error:#}"
    );
    peer.await??;
    Ok(())
}

#[tokio::test]
async fn excess_connection_preserves_listener_and_existing_clients() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join(format!("mcp-capacity-{}", uuid::Uuid::new_v4()));
    let mut host = LocalHost::bind(
        format!("capacity-{}", uuid::Uuid::new_v4()),
        Some(path.clone()),
    )
    .await?;
    let mut clients = Vec::new();
    let mut accepted = Vec::new();
    for active in 0..MAX_CONNECTIONS {
        clients.push(ClientOptions::new().open(&host.pipe_name)?);
        host.listener.connect().await?;
        accepted.push(host.take_connection(active)?.unwrap());
    }
    let mut excess = ClientOptions::new().open(&host.pipe_name)?;
    host.listener.connect().await?;
    assert!(host.take_connection(MAX_CONNECTIONS)?.is_none());
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(2), excess.read(&mut byte)).await?;
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    assert!(listener(&host.pipe_name, &host.context.execution.token, true).is_err());
    clients[0].write_all(b"live").await?;
    let mut bytes = [0; 4];
    accepted[0].read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"live");
    drop(clients.pop());
    drop(accepted.pop());
    let (connected, replacement) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            biased;
            host.listener.connect(),
            async { ClientOptions::new().open(&host.pipe_name) }
        )
    })
    .await?;
    connected?;
    let replacement = replacement?;
    let last = host.take_connection(MAX_CONNECTIONS - 1)?;
    assert!(last.is_some());
    drop(last);
    drop(replacement);
    drop(excess);
    drop(clients);
    drop(accepted);
    drop(host);
    std::fs::remove_dir(path)?;
    Ok(())
}

#[tokio::test]
async fn simultaneous_clients_wait_for_listener_replenishment() -> anyhow::Result<()> {
    let name = format!("simultaneous-{}", uuid::Uuid::new_v4());
    let token = TokenContext::current()?;
    let address = pipe_name(&token, &name)?;
    let mut server = listener(&address, &token, true)?;
    let occupied = ClientOptions::new().open(&address)?;
    server.connect().await?;
    let mut clients = JoinSet::new();
    for _ in 0..8 {
        clients.spawn(connect(name.clone()));
    }
    for _ in 0..8 {
        assert!(
            tokio::time::timeout(Duration::from_millis(25), clients.join_next())
                .await
                .is_err(),
            "a simultaneous client failed instead of waiting for a busy listener"
        );
    }
    let next = listener(&address, &token, false)?;
    let _occupied_server = std::mem::replace(&mut server, next);
    let mut accepted = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        for index in 0..8 {
            server
                .connect()
                .await
                .with_context(|| format!("accept retry fixture {index}"))?;
            let next = listener(&address, &token, false)?;
            let mut pipe = std::mem::replace(&mut server, next);
            let mut prefix = [0; MAGIC.len()];
            pipe.read_exact(&mut prefix)
                .await
                .with_context(|| format!("read retry fixture prefix {index}"))?;
            assert_eq!(&prefix, MAGIC);
            let hello = Hello {
                protocol: "mcp-local-host-1".into(),
                epoch: uuid::Uuid::new_v4().to_string(),
                connection_id: uuid::Uuid::new_v4().to_string(),
                pid: std::process::id(),
                process_creation_time: process_creation_time(unsafe {
                    windows::Win32::System::Threading::GetCurrentProcess()
                })?,
                token: token.clone(),
            };
            let bytes = serde_json::to_vec(&hello)?;
            pipe.write_u32_le(bytes.len() as u32)
                .await
                .with_context(|| format!("write retry fixture length {index}"))?;
            pipe.write_all(&bytes)
                .await
                .with_context(|| format!("write retry fixture hello {index}"))?;
            accepted.push(pipe);
        }
        anyhow::Ok(())
    })
    .await??;
    let mut connected = Vec::new();
    while let Some(client) = clients.join_next().await {
        connected.push(client??);
    }
    assert_eq!(connected.len(), 8);
    drop(occupied);
    Ok(())
}

#[tokio::test]
async fn busy_pipe_retry_has_a_deadline() -> anyhow::Result<()> {
    let token = TokenContext::current()?;
    let address = pipe_name(&token, &format!("busy-timeout-{}", uuid::Uuid::new_v4()))?;
    let server = listener(&address, &token, true)?;
    let _occupied = ClientOptions::new().open(&address)?;
    server.connect().await?;
    let started = tokio::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        open_pipe(&address, Duration::from_millis(50)),
    )
    .await?
    .err()
    .context("busy endpoint unexpectedly admitted another client")?;
    assert_eq!(error.raw_os_error(), Some(ERROR_PIPE_BUSY.0 as i32));
    assert!(started.elapsed() >= Duration::from_millis(50));
    Ok(())
}

#[tokio::test]
async fn missing_endpoint_fails_promptly_without_starting_a_host() -> anyhow::Result<()> {
    let name = format!("unavailable-{}", uuid::Uuid::new_v4());
    let error = tokio::time::timeout(Duration::from_secs(1), connect(name.clone()))
        .await?
        .err()
        .context("unavailable host silently appeared")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error),
        Some(windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.0 as i32),
    );
    let token = TokenContext::current()?;
    let _unclaimed = listener(&pipe_name(&token, &name)?, &token, true)?;
    Ok(())
}
