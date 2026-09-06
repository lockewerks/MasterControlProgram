//! Lazy, bounded PowerShell workers. A lease owns its process while a request
//! is in flight, so cancellation closes its kill-on-close job immediately.
//!
//! PowerShell's stdin mode parses one line at a time. Scripts therefore travel
//! as base64-encoded UTF-8 and are reconstructed with ScriptBlock::Create.

use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::{timeout_at, Duration, Instant};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

const MAX_POOL_SIZE: usize = 16;
const MAX_TIMEOUT_MS: u64 = 3_600_000;
const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDOUT_LINE_BYTES: usize = 1024 * 1024;
const MAX_STDOUT_LINES: usize = 8192;
const MAX_STDERR_BYTES: usize = 1024 * 1024;
const STDERR_TAIL_BYTES: usize = 16 * 1024;
const IO_CHUNK_BYTES: usize = 8192;

#[derive(Clone, Debug)]
struct Config {
    size: usize,
    timeout: Duration,
    acquire_timeout: Duration,
    write_timeout: Duration,
    startup_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 3,
            timeout: Duration::from_millis(30_000),
            acquire_timeout: Duration::from_millis(30_000),
            write_timeout: Duration::from_millis(10_000),
            startup_timeout: Duration::from_millis(15_000),
        }
    }
}

impl Config {
    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<OsString>) -> anyhow::Result<Self> {
        let mut read = |name, default, max| {
            let Some(value) = lookup(name) else {
                return Ok(default);
            };
            let value = value
                .into_string()
                .map_err(|_| anyhow!("{name} must contain Unicode decimal digits"))?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("{name} must be a decimal integer in 1..={max}");
            }
            let value: u64 = value
                .parse()
                .with_context(|| format!("{name} must be a decimal integer in 1..={max}"))?;
            if !(1..=max).contains(&value) {
                bail!("{name} must be in 1..={max}");
            }
            Ok(value)
        };
        Ok(Self {
            size: read("MCP_POOL_SIZE", 3, MAX_POOL_SIZE as u64)? as usize,
            timeout: Duration::from_millis(read("MCP_PS_TIMEOUT_MS", 30_000, MAX_TIMEOUT_MS)?),
            acquire_timeout: Duration::from_millis(read(
                "MCP_PS_ACQUIRE_TIMEOUT_MS",
                30_000,
                MAX_TIMEOUT_MS,
            )?),
            write_timeout: Duration::from_millis(read(
                "MCP_PS_WRITE_TIMEOUT_MS",
                10_000,
                MAX_TIMEOUT_MS,
            )?),
            startup_timeout: Duration::from_millis(read(
                "MCP_PS_STARTUP_TIMEOUT_MS",
                15_000,
                MAX_TIMEOUT_MS,
            )?),
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn check_deadline(deadline: Instant, phase: &str) -> anyhow::Result<()> {
    if Instant::now() >= deadline {
        bail!("PowerShell {phase} timed out");
    }
    Ok(())
}

fn phase_deadline(deadline: Instant, phase_timeout: Duration) -> Instant {
    deadline.min(Instant::now() + phase_timeout)
}

struct Job(OwnedHandle);

impl Job {
    fn new() -> anyhow::Result<Self> {
        let handle =
            unsafe { CreateJobObjectW(None, None) }.context("create PowerShell worker job")?;
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle.0) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                HANDLE(job.0.as_raw_handle()),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            )
        }
        .context("set kill-on-close on PowerShell worker job")?;
        Ok(job)
    }

    fn assign(&self, child: &Child) -> anyhow::Result<()> {
        let handle = child
            .raw_handle()
            .context("PowerShell child has no process handle")?;
        unsafe { AssignProcessToJobObject(HANDLE(self.0.as_raw_handle()), HANDLE(handle)) }
            .context("assign PowerShell worker to its job")
    }
}

struct Frame {
    wire: String,
    response: String,
    delimiter: String,
    stderr_delimiter: String,
}

impl Frame {
    fn new(command: &str) -> anyhow::Result<Self> {
        if command.len() > MAX_SCRIPT_BYTES {
            bail!("PowerShell script exceeds {MAX_SCRIPT_BYTES} UTF-8 bytes");
        }
        let token = uuid::Uuid::new_v4();
        let response = format!("___MCP_RESPONSE_{token}___");
        let delimiter = format!("___MCP_END_{token}___");
        let stderr_delimiter = format!("___MCP_STDERR_{token}___");
        let encoded = BASE64.encode(command.as_bytes());
        let payload_limit = MAX_STDOUT_LINE_BYTES - response.len() - 32;
        // Local preferences let an inner try/catch handle failures normally.
        // Error-stream records also catch explicitly nonterminating errors.
        // Native stderr on a successful executable is not an exit failure.
        // Serialize each success-stream object before retaining it, rather
        // than collecting an unbounded PowerShell array ahead of the pipe.
        let wire = format!(
            "& {{ $__mcpOldExit = $global:LASTEXITCODE; $global:LASTEXITCODE = 0; \
             $ErrorActionPreference = 'Stop'; $PSNativeCommandUseErrorActionPreference = $true; \
             try {{ \
             $__mcpNativeBytes = 0; $__mcpOutputBytes = 0; \
             $__mcpItems = [Collections.Generic.List[string]]::new(); \
             & ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')))) 2>&1 | \
             Microsoft.PowerShell.Core\\ForEach-Object {{ \
             if ($_ -is [System.Management.Automation.ErrorRecord]) {{ \
             if ($_.FullyQualifiedErrorId -notin @('NativeCommandError','NativeCommandErrorMessage')) {{ throw $_ }}; \
             $__mcpDiagnostic = $_.ToString(); \
             $__mcpNativeBytes += [Text.Encoding]::UTF8.GetByteCount($__mcpDiagnostic) + 2; \
             if ($__mcpNativeBytes -gt {MAX_STDERR_BYTES}) {{ throw 'PowerShell native stderr exceeds {MAX_STDERR_BYTES} bytes' }}; \
             [Console]::Error.WriteLine($__mcpDiagnostic) \
             }} else {{ \
             if ($__mcpItems.Count -ge {MAX_STDOUT_LINES}) {{ throw 'PowerShell output exceeds {MAX_STDOUT_LINES} records' }}; \
             $__mcpPart = Microsoft.PowerShell.Utility\\ConvertTo-Json -InputObject $_ -Compress -Depth 10 -WarningAction Stop; \
             $__mcpOutputBytes += [Text.Encoding]::UTF8.GetByteCount($__mcpPart) + 1; \
             if ($__mcpOutputBytes -gt {payload_limit}) {{ throw 'PowerShell serialized output exceeds {payload_limit} bytes' }}; \
             $__mcpItems.Add($__mcpPart) \
             }} \
             }}; \
             if ($__mcpItems.Count -eq 0) {{ $__mcpData = 'null' }} \
             elseif ($__mcpItems.Count -eq 1) {{ $__mcpData = $__mcpItems[0] }} \
             else {{ $__mcpData = '[' + [string]::Join(',', $__mcpItems) + ']' }}; \
             $__mcpJson = '{{\"s\":true,\"d\":' + $__mcpData + '}}' \
             }} catch {{ \
             $__mcpJson = [ordered]@{{s=$false;e=$_.Exception.Message}} | Microsoft.PowerShell.Utility\\ConvertTo-Json -Compress \
             }} finally {{ $global:LASTEXITCODE = $__mcpOldExit }}; \
             [Console]::Out.WriteLine('{response}' + $__mcpJson) \
             }}\n[Console]::Error.Write('{stderr_delimiter}' + [char]10); [Console]::Out.WriteLine('{delimiter}')\n"
        );
        Ok(Self {
            wire,
            response,
            delimiter,
            stderr_delimiter,
        })
    }
}

#[derive(Default)]
struct StderrCapture {
    total: usize,
    tail: VecDeque<u8>,
}

impl StderrCapture {
    fn append(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.total = self.total.saturating_add(bytes.len());
        let excess = self
            .tail
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(STDERR_TAIL_BYTES);
        self.tail.drain(..excess.min(self.tail.len()));
        self.tail
            .extend(bytes.iter().rev().take(STDERR_TAIL_BYTES).rev().copied());
        if self.total > MAX_STDERR_BYTES {
            bail!("PowerShell stderr exceeds {MAX_STDERR_BYTES} bytes");
        }
        Ok(())
    }

    fn context(&self, error: anyhow::Error) -> anyhow::Error {
        if self.tail.is_empty() {
            error
        } else {
            let tail: Vec<u8> = self.tail.iter().copied().collect();
            anyhow!("{error:#}; stderr tail: {}", String::from_utf8_lossy(&tail))
        }
    }
}

async fn drain_stderr<R: AsyncRead + Unpin>(
    stderr: &mut R,
    capture: &mut StderrCapture,
    delimiter: &str,
) -> anyhow::Result<bool> {
    let mut chunk = [0; IO_CHUNK_BYTES];
    let marker = format!("{delimiter}\n");
    let marker = marker.as_bytes();
    let mut pending = Vec::with_capacity(IO_CHUNK_BYTES + marker.len());
    loop {
        let count = stderr
            .read(&mut chunk)
            .await
            .context("read PowerShell stderr")?;
        if count == 0 {
            capture.append(&pending)?;
            return Ok(false);
        }
        pending.extend_from_slice(&chunk[..count]);
        if let Some(position) = pending
            .windows(marker.len())
            .position(|bytes| bytes == marker)
        {
            capture.append(&pending[..position])?;
            if position + marker.len() != pending.len() {
                bail!("unexpected PowerShell stderr after the response delimiter");
            }
            return Ok(true);
        }
        let confirmed = pending.len().saturating_sub(marker.len() - 1);
        capture.append(&pending[..confirmed])?;
        pending.drain(..confirmed);
    }
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    total: &mut usize,
) -> anyhow::Result<usize> {
    line.clear();
    loop {
        let available = reader.fill_buf().await.context("read PowerShell stdout")?;
        if available.is_empty() {
            return Ok(line.len());
        }
        let count = available
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(available.len(), |n| n + 1);
        if line.len().saturating_add(count) > MAX_STDOUT_LINE_BYTES {
            bail!("PowerShell stdout line exceeds {MAX_STDOUT_LINE_BYTES} bytes");
        }
        if total.saturating_add(count) > MAX_STDOUT_BYTES {
            bail!("PowerShell stdout exceeds {MAX_STDOUT_BYTES} bytes");
        }
        let complete = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        *total += count;
        reader.consume(count);
        if complete {
            return Ok(line.len());
        }
    }
}

enum StdoutState {
    Pending,
    Data,
    Closed,
}

async fn stdout_state<R: AsyncBufRead + Unpin>(stdout: &mut R) -> std::io::Result<StdoutState> {
    std::future::poll_fn(|cx| {
        let result = match std::pin::Pin::new(&mut *stdout).poll_fill_buf(cx) {
            std::task::Poll::Ready(Ok([])) => Ok(StdoutState::Closed),
            std::task::Poll::Ready(Ok(_)) => Ok(StdoutState::Data),
            std::task::Poll::Ready(Err(error)) => Err(error),
            std::task::Poll::Pending => Ok(StdoutState::Pending),
        };
        std::task::Poll::Ready(result)
    })
    .await
}

async fn read_response<R: AsyncBufRead + Unpin>(
    stdout: &mut R,
    frame: &Frame,
) -> anyhow::Result<String> {
    let mut total = 0;
    let mut line = Vec::new();
    let mut response = None;
    let mut extra = Vec::new();
    for _ in 0..MAX_STDOUT_LINES {
        if read_bounded_line(stdout, &mut line, &mut total).await? == 0 {
            bail!("PowerShell worker exited or closed stdout before the response delimiter");
        }
        if line.last() != Some(&b'\n') {
            bail!("PowerShell worker closed stdout in the middle of a response line");
        }
        let text = std::str::from_utf8(&line).context("PowerShell stdout is not UTF-8")?;
        let text = text.trim_end_matches(['\r', '\n']);
        if text == frame.delimiter {
            let response: String = response.context("PowerShell response frame is missing")?;
            let parsed: serde_json::Value =
                serde_json::from_str(&response).context("invalid PowerShell response JSON")?;
            match parsed.get("s").and_then(serde_json::Value::as_bool) {
                Some(false) => {
                    let message = parsed
                        .get("e")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("PowerShell reported an unspecified error");
                    bail!("{message}");
                }
                Some(true) if parsed.get("d").is_some() => {}
                _ => bail!("invalid PowerShell response envelope"),
            }
            // Do not carry an already-observable trailer into another request.
            if matches!(
                stdout_state(stdout)
                    .await
                    .context("check PowerShell response trailer")?,
                StdoutState::Data
            ) {
                bail!("unexpected PowerShell stdout after the response delimiter");
            }
            if extra.is_empty() {
                return Ok(response);
            }
            let mut raw = String::from_utf8(extra).context("PowerShell stdout is not UTF-8")?;
            if !raw.ends_with('\n') {
                raw.push('\n');
            }
            raw.push_str(&response);
            return Ok(raw);
        }
        if let Some(position) = text.find(&frame.response) {
            extra.extend_from_slice(&line[..position]);
            let json = &text[position + frame.response.len()..];
            if response.replace(json.to_owned()).is_some() {
                bail!("duplicate PowerShell response frame");
            }
        } else if !text.trim().is_empty() {
            extra.extend_from_slice(&line);
        }
    }
    bail!("PowerShell stdout exceeds {MAX_STDOUT_LINES} lines")
}

async fn exchange<W, R, E>(
    stdin: &mut W,
    stdout: &mut R,
    stderr: &mut E,
    frame: &Frame,
    deadline: Instant,
    write_timeout: Duration,
) -> anyhow::Result<String>
where
    W: AsyncWrite + Unpin,
    R: AsyncBufRead + Unpin,
    E: AsyncRead + Unpin,
{
    check_deadline(deadline, "execution")?;
    let write_deadline = phase_deadline(deadline, write_timeout);
    let mut capture = StderrCapture::default();
    let result = timeout_at(deadline, async {
        // Stdout completing does not prove stderr is drained. Each stream has
        // its own marker, and both readers remain owned by this future.
        let (response, stderr_complete) = tokio::try_join!(
            async {
                timeout_at(write_deadline, async {
                    stdin
                        .write_all(frame.wire.as_bytes())
                        .await
                        .context("write PowerShell command")?;
                    stdin.flush().await.context("flush PowerShell command")
                })
                .await
                .map_err(|_| anyhow!("PowerShell command write timed out"))??;
                read_response(stdout, frame).await
            },
            drain_stderr(stderr, &mut capture, &frame.stderr_delimiter),
        )?;
        if !stderr_complete {
            bail!("PowerShell worker closed stderr before the response delimiter");
        }
        Ok(response)
    })
    .await
    .map_err(|_| anyhow!("PowerShell execution timed out"))
    .and_then(|result| result);
    result.map_err(|error| capture.context(error))
}

struct Worker {
    id: usize,
    job: Option<Job>,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: BufReader<ChildStderr>,
    healthy: bool,
}

impl Worker {
    async fn spawn(
        id: usize,
        program: &OsString,
        config: &Config,
        deadline: Instant,
    ) -> anyhow::Result<Self> {
        let deadline = phase_deadline(deadline, config.startup_timeout);
        check_deadline(deadline, "startup")?;
        let job = Job::new()?;
        let mut child = Command::new(program)
            .args(["-NoProfile", "-NoLogo", "-NonInteractive", "-Command", "-"])
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| {
                format!(
                    "spawn PowerShell worker {id} using {}",
                    program.to_string_lossy()
                )
            })?;
        // Tokio does not expose a suspended child's primary thread. Assignment
        // is synchronous and precedes all stdin, including the startup probe.
        job.assign(&child)?;
        let stdin = child
            .stdin
            .take()
            .context("PowerShell stdin pipe is missing")?;
        let stdout = BufReader::with_capacity(
            IO_CHUNK_BYTES,
            child
                .stdout
                .take()
                .context("PowerShell stdout pipe is missing")?,
        );
        let stderr = BufReader::with_capacity(
            IO_CHUNK_BYTES,
            child
                .stderr
                .take()
                .context("PowerShell stderr pipe is missing")?,
        );
        let mut worker = Self {
            id,
            job: Some(job),
            child,
            stdin,
            stdout,
            stderr,
            healthy: false,
        };
        let probe = Frame::new(
            "if ($PSVersionTable.PSVersion -lt [version]'7.4') { \
             throw 'PowerShell 7.4 or newer is required for native executable error handling' }; \
             [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); \
             [Console]::InputEncoding = [Text.UTF8Encoding]::new($false); \
             'ready'",
        )?;
        let response = worker
            .execute(&probe, config, deadline)
            .await
            .with_context(|| format!("PowerShell worker {id} startup failed"))?;
        let parsed: serde_json::Value = serde_json::from_str(&response)?;
        if parsed.get("d").and_then(serde_json::Value::as_str) != Some("ready") {
            bail!("PowerShell worker {id} startup returned an invalid probe response");
        }
        tracing::debug!(worker = id, "PowerShell worker ready");
        Ok(worker)
    }

    fn is_alive(&mut self) -> anyhow::Result<bool> {
        match self.child.try_wait() {
            Ok(status) => Ok(status.is_none()),
            Err(error) => {
                self.healthy = false;
                Err(error).context("check PowerShell worker exit status")
            }
        }
    }

    async fn execute(
        &mut self,
        frame: &Frame,
        config: &Config,
        deadline: Instant,
    ) -> anyhow::Result<String> {
        // This must happen before the first write or await, not only on error.
        self.healthy = false;
        match stdout_state(&mut self.stdout)
            .await
            .context("check PowerShell stdout before write")?
        {
            StdoutState::Pending => {}
            StdoutState::Data => bail!("unexpected PowerShell stdout before command write"),
            StdoutState::Closed => bail!("PowerShell worker closed stdout before command write"),
        }
        match stdout_state(&mut self.stderr)
            .await
            .context("check PowerShell stderr before write")?
        {
            StdoutState::Pending => {}
            StdoutState::Data => bail!("unexpected PowerShell stderr before command write"),
            StdoutState::Closed => bail!("PowerShell worker closed stderr before command write"),
        }
        let result = tokio::select! {
            biased;
            result = exchange(
                &mut self.stdin,
                &mut self.stdout,
                &mut self.stderr,
                frame,
                deadline,
                config.write_timeout,
            ) => result,
            status = self.child.wait() => {
                match status {
                    Ok(status) => Err(anyhow!(
                        "PowerShell worker {} exited ({status}) before the response delimiter",
                        self.id
                    )),
                    Err(error) => Err(error).context("wait for PowerShell worker exit"),
                }
            }
        };
        if result.is_ok() {
            if matches!(stdout_state(&mut self.stdout).await?, StdoutState::Data) {
                bail!("unexpected PowerShell stdout after the response delimiter");
            }
            if matches!(stdout_state(&mut self.stderr).await?, StdoutState::Data) {
                bail!("unexpected PowerShell stderr after the response delimiter");
            }
            self.healthy = true;
        }
        result
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the last job handle kills the exact owned tree, even when
        // descendants still hold the redirected pipes open.
        drop(self.job.take());
        if let Err(error) = self.child.start_kill() {
            tracing::debug!(worker = self.id, %error, "PowerShell child already exited or kill failed");
        }
        // Windows needs no detached reaper: dropping Child closes its owned
        // process/wait handles. Reclaim an already-signaled child here as well.
        if let Err(error) = self.child.try_wait() {
            tracing::debug!(worker = self.id, %error, "PowerShell exit status unavailable during cleanup");
        }
    }
}

struct State {
    workers: Vec<Option<Worker>>,
    idle: VecDeque<usize>,
}

struct Lease<'a> {
    pool: &'a Pool,
    index: usize,
    worker: Option<Worker>,
    _permit: SemaphorePermit<'a>,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let worker = self.worker.take().filter(|worker| worker.healthy);
        let mut state = lock(&self.pool.state);
        state.workers[self.index] = worker;
        state.idle.push_front(self.index);
    }
}

/// A lazily populated, bounded pool. Requests wait for any free slot rather
/// than a round-robin choice that might already be busy.
pub struct Pool {
    config: Config,
    program: OsString,
    state: Mutex<State>,
    available: Semaphore,
}

impl Pool {
    /// Validate environment settings without starting any processes.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::with_config(
            Config::from_lookup(|name| std::env::var_os(name))?,
            OsString::from("pwsh"),
        )
    }

    /// Compatibility constructor using default deadlines, without spawning.
    #[allow(dead_code)]
    pub async fn new(size: usize) -> anyhow::Result<Self> {
        Self::with_config(
            Config {
                size,
                ..Config::default()
            },
            OsString::from("pwsh"),
        )
    }

    fn with_config(config: Config, program: OsString) -> anyhow::Result<Self> {
        if !(1..=MAX_POOL_SIZE).contains(&config.size) {
            bail!("PowerShell pool size must be in 1..={MAX_POOL_SIZE}");
        }
        let size = config.size;
        Ok(Self {
            config,
            program,
            state: Mutex::new(State {
                workers: (0..size).map(|_| None).collect(),
                idle: (0..size).collect(),
            }),
            available: Semaphore::new(size),
        })
    }

    async fn acquire(&self, deadline: Instant) -> anyhow::Result<Lease<'_>> {
        check_deadline(deadline, "pool acquisition")?;
        let permit = timeout_at(
            phase_deadline(deadline, self.config.acquire_timeout),
            self.available.acquire(),
        )
        .await
        .map_err(|_| anyhow!("PowerShell pool acquisition timed out"))?
        .context("PowerShell pool is closed")?;
        let mut state = lock(&self.state);
        let index = state
            .idle
            .pop_front()
            .context("PowerShell pool has no available slot")?;
        let worker = state.workers[index].take();
        Ok(Lease {
            pool: self,
            index,
            worker,
            _permit: permit,
        })
    }

    #[allow(dead_code)]
    pub async fn execute(&self, command: &str) -> anyhow::Result<String> {
        self.execute_with_timeout(command, None).await
    }

    /// The caller/default timeout is one total budget, including acquisition,
    /// startup, writes and execution. Each configured phase limit can shorten
    /// that budget, but never extend it. Failed commands are never replayed.
    pub async fn execute_with_timeout(
        &self,
        command: &str,
        timeout_ms: Option<u64>,
    ) -> anyhow::Result<String> {
        let timeout = match timeout_ms {
            Some(value) if (1..=MAX_TIMEOUT_MS).contains(&value) => Duration::from_millis(value),
            Some(_) => bail!("PowerShell timeout_ms must be in 1..={MAX_TIMEOUT_MS}"),
            None => self.config.timeout,
        };
        let deadline = Instant::now() + timeout;
        if command.len() > MAX_SCRIPT_BYTES {
            bail!("PowerShell script exceeds {MAX_SCRIPT_BYTES} UTF-8 bytes");
        }
        let mut lease = self.acquire(deadline).await?;
        let frame = Frame::new(command)?;
        if let Some(worker) = lease.worker.as_mut() {
            if !worker.healthy || !worker.is_alive()? {
                drop(lease.worker.take());
            }
        }
        if lease.worker.is_none() {
            lease.worker =
                Some(Worker::spawn(lease.index, &self.program, &self.config, deadline).await?);
        }
        let result = lease
            .worker
            .as_mut()
            .context("PowerShell worker is missing")?
            .execute(&frame, &self.config, deadline)
            .await;
        if let Err(error) = &result {
            tracing::warn!(worker = lease.index, error = %error, "PowerShell request failed");
        }
        result
    }

    pub async fn exec_json(&self, command: &str) -> anyhow::Result<serde_json::Value> {
        self.exec_json_with_timeout(command, None).await
    }

    pub async fn exec_json_with_timeout(
        &self,
        command: &str,
        timeout_ms: Option<u64>,
    ) -> anyhow::Result<serde_json::Value> {
        let raw = self.execute_with_timeout(command, timeout_ms).await?;
        // read_response authenticates the envelope before removing its random
        // prefix and appends it last. Host output cannot masquerade as data.
        let envelope = raw
            .rsplit('\n')
            .next()
            .context("PowerShell response is empty")?;
        let mut parsed: serde_json::Value = serde_json::from_str(envelope)?;
        Ok(parsed["d"].take())
    }

    pub async fn exec_pretty(&self, command: &str) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(
            &self.exec_json(command).await?,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::task::JoinHandle;
    use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    static PROCESS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn setting(name: &str, value: OsString) -> anyhow::Result<Config> {
        Config::from_lookup(|key| (key == name).then(|| value.clone()))
    }

    fn test_pool(size: usize) -> Option<Pool> {
        let executable = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("pwsh.exe"))
                .find(|path| path.is_file())
        });
        let Some(executable) = executable else {
            eprintln!("PowerShell capability test skipped: pwsh.exe is not on PATH");
            return None;
        };
        Some(
            Pool::with_config(
                Config {
                    size,
                    ..Config::default()
                },
                executable.into_os_string(),
            )
            .unwrap(),
        )
    }

    fn response(frame: &Frame, json: &str) -> Vec<u8> {
        format!("{}{json}\r\n{}\r\n", frame.response, frame.delimiter).into_bytes()
    }

    #[test]
    fn configuration_defaults_and_bounds_are_strict() {
        let config = Config::from_lookup(|_| None).unwrap();
        assert_eq!(config.size, 3);
        assert_eq!(config.timeout, Duration::from_millis(30_000));
        assert_eq!(config.acquire_timeout, Duration::from_millis(30_000));
        assert_eq!(config.write_timeout, Duration::from_millis(10_000));
        assert_eq!(config.startup_timeout, Duration::from_millis(15_000));
        for name in [
            "MCP_POOL_SIZE",
            "MCP_PS_TIMEOUT_MS",
            "MCP_PS_ACQUIRE_TIMEOUT_MS",
            "MCP_PS_WRITE_TIMEOUT_MS",
            "MCP_PS_STARTUP_TIMEOUT_MS",
        ] {
            for value in [
                "0",
                "-1",
                "+1",
                "",
                " 1",
                "1 ",
                "1.5",
                "no",
                "999999999999999999999999999999",
            ] {
                assert!(setting(name, value.into()).is_err(), "{name}={value}");
            }
            assert!(setting(name, OsString::from_wide(&[0xd800])).is_err());
            let max = if name == "MCP_POOL_SIZE" {
                MAX_POOL_SIZE as u64
            } else {
                MAX_TIMEOUT_MS
            };
            assert!(setting(name, "1".into()).is_ok());
            assert!(setting(name, max.to_string().into()).is_ok());
            assert!(setting(name, (max + 1).to_string().into()).is_err());
        }
    }

    #[test]
    fn multiline_transport_is_exactly_two_lines() {
        let script = "# comment\n$x = @'\na 'quoted' value\n'@\n$x\n'\u{03bb}'";
        let frame = Frame::new(script).unwrap();
        assert_eq!(frame.wire.lines().count(), 2);
        assert!(frame.wire.contains("[ScriptBlock]::Create"));
        assert!(frame.wire.contains("[Text.Encoding]::UTF8.GetString"));
        assert!(frame.wire.contains(&BASE64.encode(script.as_bytes())));
        assert!(!frame.wire.contains("# comment"));
        assert!(frame
            .wire
            .lines()
            .nth(1)
            .unwrap()
            .contains(&frame.delimiter));
        assert!(Frame::new(&"x".repeat(MAX_SCRIPT_BYTES)).is_ok());
        assert!(Frame::new(&"x".repeat(MAX_SCRIPT_BYTES + 1)).is_err());
    }

    #[tokio::test]
    async fn construction_is_lazy_and_missing_binary_fails_only_on_execution() {
        assert!(Pool::new(0).await.is_err());
        assert!(Pool::new(MAX_POOL_SIZE + 1).await.is_err());
        let default = Pool::new(1).await.unwrap();
        assert!(lock(&default.state).workers.iter().all(Option::is_none));
        let pool = Pool::with_config(
            Config {
                size: 1,
                ..Config::default()
            },
            format!(".\\missing-pwsh-{}.exe", uuid::Uuid::new_v4()).into(),
        )
        .unwrap();
        assert!(lock(&pool.state).workers[0].is_none());
        let error = pool.execute("'unused'").await.unwrap_err();
        assert!(format!("{error:#}").contains("spawn PowerShell"));
        assert_eq!(pool.available.available_permits(), 1);
        assert!(lock(&pool.state).workers[0].is_none());
    }

    #[tokio::test]
    async fn invalid_requests_do_not_start_a_worker() {
        let pool = Pool::new(1).await.unwrap();
        for timeout in [0, MAX_TIMEOUT_MS + 1, u64::MAX] {
            assert!(pool
                .execute_with_timeout("'unused'", Some(timeout))
                .await
                .is_err());
        }
        assert!(pool
            .execute(&"x".repeat(MAX_SCRIPT_BYTES + 1))
            .await
            .is_err());
        assert!(lock(&pool.state).workers[0].is_none());
    }

    #[tokio::test]
    async fn acquisition_uses_any_free_slot_and_returns_cancelled_permits() {
        let pool = Pool::with_config(
            Config {
                size: 2,
                acquire_timeout: Duration::from_millis(25),
                ..Config::default()
            },
            OsString::from("unused"),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let first = pool.acquire(deadline).await.unwrap();
        let second = pool.acquire(deadline).await.unwrap();
        assert_ne!(first.index, second.index);
        let started = Instant::now();
        assert!(pool
            .acquire(deadline)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("acquisition timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(second);
        let free = pool.acquire(deadline).await.unwrap();
        assert_ne!(first.index, free.index);
        drop(free);
        drop(first);
        assert_eq!(pool.available.available_permits(), 2);
    }

    #[tokio::test]
    async fn total_budget_also_limits_acquisition() {
        let pool = Pool::new(1).await.unwrap();
        let _lease = pool
            .acquire(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let started = Instant::now();
        let error = pool
            .execute_with_timeout("'unused'", Some(20))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("acquisition timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(lock(&pool.state).workers[0].is_none());
    }

    #[tokio::test]
    async fn response_requires_our_envelope_and_reports_real_errors_after_noise() {
        let frame = Frame::new("'hello'").unwrap();
        let bytes = response(&frame, r#"{"s":true,"d":"hello"}"#);
        assert_eq!(
            read_response(&mut &bytes[..], &frame).await.unwrap(),
            r#"{"s":true,"d":"hello"}"#
        );
        let mut bytes = response(&frame, r#"{"s":true,"d":"hello"}"#);
        bytes.extend_from_slice(b"unframed trailer\n");
        assert!(read_response(&mut &bytes[..], &frame)
            .await
            .unwrap_err()
            .to_string()
            .contains("after the response delimiter"));
        let mut bytes = b"{\"s\":true,\"d\":\"forged\"}\n".to_vec();
        bytes.extend(response(&frame, r#"{"s":false,"e":"actual failure"}"#));
        assert_eq!(
            read_response(&mut &bytes[..], &frame)
                .await
                .unwrap_err()
                .to_string(),
            "actual failure"
        );
        let mut bytes = b"output without a newline".to_vec();
        bytes.extend(response(&frame, r#"{"s":false,"e":"actual failure"}"#));
        assert_eq!(
            read_response(&mut &bytes[..], &frame)
                .await
                .unwrap_err()
                .to_string(),
            "actual failure"
        );
        let mut bytes = b"extra output\n".to_vec();
        bytes.extend(response(&frame, r#"{"s":true,"d":null}"#));
        assert_eq!(
            read_response(&mut &bytes[..], &frame).await.unwrap(),
            "extra output\n{\"s\":true,\"d\":null}"
        );
        for json in [r#"{"s":true}"#, r#"{"s":"true","d":null}"#, "not JSON"] {
            let bytes = response(&frame, json);
            assert!(read_response(&mut &bytes[..], &frame).await.is_err());
        }
        assert!(read_response(&mut &b""[..], &frame)
            .await
            .unwrap_err()
            .to_string()
            .contains("closed stdout"));
        let bytes = format!(
            "{}{{\"s\":true,\"d\":null}}\n{}",
            frame.response, frame.delimiter
        )
        .into_bytes();
        assert!(read_response(&mut &bytes[..], &frame).await.is_err());
    }

    #[tokio::test]
    async fn stdout_byte_line_and_count_limits_include_unframed_output() {
        let frame = Frame::new("'unused'").unwrap();
        let bytes = vec![b'x'; MAX_STDOUT_LINE_BYTES + 1];
        assert!(read_response(&mut &bytes[..], &frame)
            .await
            .unwrap_err()
            .to_string()
            .contains("stdout line exceeds"));
        let bytes = vec![b'\n'; MAX_STDOUT_LINES + 1];
        assert!(read_response(&mut &bytes[..], &frame)
            .await
            .unwrap_err()
            .to_string()
            .contains("lines"));
        let bytes = ("x".repeat(1023) + "\n")
            .repeat(MAX_STDOUT_BYTES / 1024 + 1)
            .into_bytes();
        assert!(read_response(&mut &bytes[..], &frame)
            .await
            .unwrap_err()
            .to_string()
            .contains("stdout exceeds"));
    }

    #[tokio::test]
    async fn stalled_and_broken_writes_are_bounded() {
        let frame = Frame::new("'unused'").unwrap();
        let (mut writer, peer) = tokio::io::duplex(1);
        let started = Instant::now();
        let error = exchange(
            &mut writer,
            &mut &b""[..],
            &mut tokio::io::empty(),
            &frame,
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("write timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(peer);
        let error = exchange(
            &mut writer,
            &mut &b""[..],
            &mut tokio::io::empty(),
            &frame,
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("write PowerShell"));
    }

    #[tokio::test]
    async fn total_budget_limits_writes_and_delimiter_reads() {
        let frame = Frame::new("'unused'").unwrap();
        let (mut writer, _peer) = tokio::io::duplex(1);
        let error = exchange(
            &mut writer,
            &mut &b""[..],
            &mut tokio::io::empty(),
            &frame,
            Instant::now() + Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        let (reader, _peer) = tokio::io::duplex(1);
        let error = exchange(
            &mut tokio::io::sink(),
            &mut BufReader::new(reader),
            &mut tokio::io::empty(),
            &frame,
            Instant::now() + Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("execution timed out"));
    }

    #[tokio::test]
    async fn stderr_has_a_bounded_tail_and_a_total_limit() {
        let mut capture = StderrCapture::default();
        for _ in 0..4 {
            capture.append(&vec![b'a'; STDERR_TAIL_BYTES]).unwrap();
        }
        capture.append(b"last").unwrap();
        assert_eq!(capture.tail.len(), STDERR_TAIL_BYTES);
        assert!(capture
            .context(anyhow!("failure"))
            .to_string()
            .ends_with("last"));
        let bytes = vec![b'x'; MAX_STDERR_BYTES + 1];
        let (reader, _peer) = tokio::io::duplex(1);
        let frame = Frame::new("'unused'").unwrap();
        let error = exchange(
            &mut tokio::io::sink(),
            &mut BufReader::new(reader),
            &mut &bytes[..],
            &frame,
            Instant::now() + Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("stderr exceeds"));
        assert!(error.to_string().len() < STDERR_TAIL_BYTES + 256);
    }

    #[tokio::test]
    async fn response_waits_for_stderr_marker_and_does_not_miss_buffered_overflow() {
        let frame = Frame::new("'unused'").unwrap();
        let stdout = response(&frame, r#"{"s":true,"d":null}"#);
        let (reader, _peer) = tokio::io::duplex(1);
        let error = exchange(
            &mut tokio::io::sink(),
            &mut &stdout[..],
            &mut BufReader::new(reader),
            &frame,
            Instant::now() + Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));

        let mut stderr = vec![b'x'; MAX_STDERR_BYTES + 1];
        stderr.extend_from_slice(format!("{}\n", frame.stderr_delimiter).as_bytes());
        let error = exchange(
            &mut tokio::io::sink(),
            &mut &stdout[..],
            &mut &stderr[..],
            &frame,
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("stderr exceeds"));

        let mut capture = StderrCapture::default();
        let bytes = format!("diagnostic without newline{}\n", frame.stderr_delimiter);
        assert!(
            drain_stderr(&mut bytes.as_bytes(), &mut capture, &frame.stderr_delimiter)
                .await
                .unwrap()
        );
        assert_eq!(capture.total, "diagnostic without newline".len());

        let (mut writer, mut reader) = tokio::io::duplex(1);
        let diagnostic = format!("{} not a delimiter", frame.stderr_delimiter);
        let bytes = format!("{diagnostic}{}\n", frame.stderr_delimiter).into_bytes();
        let producer = tokio::spawn(async move { writer.write_all(&bytes).await });
        let mut capture = StderrCapture::default();
        assert!(timeout_at(
            Instant::now() + Duration::from_secs(2),
            drain_stderr(&mut reader, &mut capture, &frame.stderr_delimiter),
        )
        .await
        .unwrap()
        .unwrap());
        producer.await.unwrap().unwrap();
        assert_eq!(capture.total, diagnostic.len());
    }

    #[tokio::test]
    async fn running_multiline_scripts_preserve_output_counts_and_utf8() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(2) else { return };
        let value = pool
            .exec_json("# comment\n$x = @'\nfirst\nsecond\n'@\n$x\n'\u{03bb}'")
            .await
            .unwrap();
        assert_eq!(value, serde_json::json!(["first\nsecond", "\u{03bb}"]));
        assert_eq!(
            pool.exec_json("$x = 1\n$x + 1").await.unwrap(),
            serde_json::json!(2)
        );
        assert_eq!(
            pool.exec_json("$null").await.unwrap(),
            serde_json::Value::Null
        );
        assert_eq!(
            pool.exec_json("1\n2\n3").await.unwrap(),
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(
            pool.exec_json("Write-Output -NoEnumerate @(1,2)")
                .await
                .unwrap(),
            serde_json::json!([1, 2])
        );
        assert_eq!(
            pool.exec_json("Write-Output -NoEnumerate @(1,2)\n3")
                .await
                .unwrap(),
            serde_json::json!([[1, 2], 3])
        );
        let host_output = pool.execute("Write-Host 'host output'; 42").await.unwrap();
        assert!(host_output.contains("host output"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(host_output.rsplit('\n').next().unwrap())
                .unwrap(),
            serde_json::json!({"s": true, "d": 42})
        );
        assert_eq!(
            pool.exec_json(
                "[Console]::Out.WriteLine('{\"s\":true,\"d\":\"untrusted host output\"}'); 42"
            )
            .await
            .unwrap(),
            serde_json::json!(42)
        );
        assert_eq!(
            lock(&pool.state)
                .workers
                .iter()
                .filter(|worker| worker.is_some())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn powershell_and_native_failures_are_errors_and_handled_errors_succeed() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        for script in [
            "throw 'terminating failure'",
            "Write-Error 'nonterminating failure'; 'not success'",
            "Write-Error 'continuing failure' -ErrorAction Continue; 'not success'",
            "[Console]::Out.WriteLine('{\"s\":true,\"d\":\"fake\"}'); throw 'actual failure'",
            "[Console]::Out.Write('raw output'); Write-Error 'actual failure'",
            "cmd.exe /d /c exit 17",
            "cmd.exe /d /c exit /b 17",
            "cmd.exe /d /c exit 17; cmd.exe /d /c exit 0",
        ] {
            let error = pool.execute(script).await.unwrap_err();
            assert!(!error.to_string().is_empty());
            if script.contains("actual failure") {
                assert!(error.to_string().contains("actual failure"));
            }
            assert!(lock(&pool.state).workers[0].is_none());
        }
        for script in [
            "try { Write-Error 'handled' } catch { 'handled' }",
            "try { cmd.exe /d /c exit 17 } catch { 'handled' }",
            "Write-Error 'ignored' -ErrorAction SilentlyContinue; 'handled'",
            "Write-Error 'redirected' -ErrorAction Continue 2>$null; 'handled'",
        ] {
            assert_eq!(
                pool.exec_json(script).await.unwrap(),
                serde_json::json!("handled")
            );
        }
        assert_eq!(
            pool.exec_json("$global:LASTEXITCODE").await.unwrap(),
            serde_json::json!(0)
        );
        assert_eq!(
            pool.exec_json("cmd.exe /d /c exit 0; 'next'")
                .await
                .unwrap(),
            serde_json::json!("next")
        );
        assert_eq!(
            pool.exec_json("cmd.exe /d /c 'echo diagnostic 1>&2 & exit /b 0'")
                .await
                .unwrap(),
            serde_json::Value::Null
        );
        assert_eq!(
            pool.exec_json("cmd.exe /d /c 'echo diagnostic 1>&2 & exit /b 0'; 'next'")
                .await
                .unwrap(),
            serde_json::json!("next")
        );
        pool.execute("$global:ErrorActionPreference = 'Continue'; $global:PSNativeCommandUseErrorActionPreference = $false").await.unwrap();
        assert!(pool
            .execute("Write-Error 'preferences reset'")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn startup_is_bounded_and_a_failed_probe_does_not_occupy_a_slot() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(mut pool) = test_pool(1) else { return };
        pool.config.startup_timeout = Duration::from_millis(1);
        let error = pool.execute("'unused'").await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"));
        assert!(lock(&pool.state).workers[0].is_none());
        assert_eq!(pool.available.available_permits(), 1);
        pool.config.startup_timeout = Config::default().startup_timeout;
        assert_eq!(
            pool.exec_json("'ready again'").await.unwrap(),
            serde_json::json!("ready again")
        );
    }

    #[tokio::test]
    async fn late_unframed_output_is_rejected_before_sending_another_command() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        pool.execute("'ready'").await.unwrap();
        let fixture = Fixture::new();
        let mut lease = pool
            .acquire(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let worker = lease.worker.as_mut().unwrap();
        worker
            .stdin
            .write_all(b"[Console]::Out.WriteLine('late output')\n")
            .await
            .unwrap();
        worker.stdin.flush().await.unwrap();
        timeout_at(
            Instant::now() + Duration::from_secs(2),
            worker.stdout.fill_buf(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(lease);
        let script = format!("[IO.File]::WriteAllText('{}', 'ran')", fixture.ps_path());
        let error = pool.execute(&script).await.unwrap_err();
        assert!(error.to_string().contains("before command write"));
        assert_eq!(fs::read_to_string(&fixture.0).unwrap(), "");
        assert!(lock(&pool.state).workers[0].is_none());
        assert_eq!(
            pool.exec_json("'recovered'").await.unwrap(),
            serde_json::json!("recovered")
        );
    }

    #[tokio::test]
    async fn workers_recover_after_timeout_exit_and_output_limit() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        let first_pid = pool.exec_json("$PID").await.unwrap();
        let started = Instant::now();
        let error = pool
            .execute_with_timeout("Start-Sleep -Seconds 30", Some(50))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(lock(&pool.state).workers[0].is_none());
        let second_pid = pool.exec_json("$PID").await.unwrap();
        assert_ne!(first_pid, second_pid);
        assert!(pool
            .execute("exit 23")
            .await
            .unwrap_err()
            .to_string()
            .contains("exited"));
        assert!(lock(&pool.state).workers[0].is_none());
        let script = format!(
            "[Console]::Error.Write(('x' * {}))",
            MAX_STDERR_BYTES + IO_CHUNK_BYTES
        );
        assert!(pool
            .execute(&script)
            .await
            .unwrap_err()
            .to_string()
            .contains("stderr exceeds"));
        assert!(lock(&pool.state).workers[0].is_none());
        let script = format!(
            "& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -NonInteractive -Command \
             \"[Console]::Error.Write(('x' * {}))\"",
            MAX_STDERR_BYTES + 1
        );
        assert!(pool
            .execute(&script)
            .await
            .unwrap_err()
            .to_string()
            .contains("stderr exceeds"));
        assert!(lock(&pool.state).workers[0].is_none());
        assert_ne!(second_pid, pool.exec_json("$PID").await.unwrap());
        let script = format!(
            "[Console]::Out.Write(('x' * {}))",
            MAX_STDOUT_LINE_BYTES + 1
        );
        assert!(pool
            .execute(&script)
            .await
            .unwrap_err()
            .to_string()
            .contains("stdout line exceeds"));
        assert!(lock(&pool.state).workers[0].is_none());
        assert_eq!(
            pool.exec_json("'recovered'").await.unwrap(),
            serde_json::json!("recovered")
        );
    }

    #[tokio::test]
    async fn pipeline_results_are_bounded_before_accumulating_an_unlimited_array() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        let error = pool
            .execute(&format!("1..{}", MAX_STDOUT_LINES + 1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("records"));
        assert!(lock(&pool.state).workers[0].is_none());
        let error = pool
            .execute(&format!("'x' * {MAX_STDOUT_LINE_BYTES}"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("serialized output exceeds"));
        assert!(lock(&pool.state).workers[0].is_none());
        assert_eq!(
            pool.exec_json("1,2,3").await.unwrap(),
            serde_json::json!([1, 2, 3])
        );
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir()
                .unwrap()
                .join(format!(".mcp-pool-test-{}.pid", uuid::Uuid::new_v4()));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            Self(path)
        }

        fn ps_path(&self) -> String {
            self.0.to_string_lossy().replace('\'', "''")
        }

        async fn pids(&self) -> (u32, u32) {
            timeout_at(Instant::now() + Duration::from_secs(15), async {
                loop {
                    let text = fs::read_to_string(&self.0).unwrap_or_default();
                    if let Some((parent, child)) = text.split_once(',') {
                        if let (Ok(parent), Ok(child)) = (parent.parse(), child.parse()) {
                            break (parent, child);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    struct AbortTask<T>(Option<JoinHandle<T>>);

    impl<T> Drop for AbortTask<T> {
        fn drop(&mut self) {
            if let Some(task) = &self.0 {
                task.abort();
            }
        }
    }

    struct ProcessProbe(OwnedHandle);

    impl ProcessProbe {
        fn open(pid: u32) -> Self {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                    false,
                    pid,
                )
            }
            .unwrap();
            Self(unsafe { OwnedHandle::from_raw_handle(handle.0) })
        }

        fn exited(&self) -> bool {
            unsafe { WaitForSingleObject(HANDLE(self.0.as_raw_handle()), 5000) == WAIT_OBJECT_0 }
        }
    }

    impl Drop for ProcessProbe {
        fn drop(&mut self) {
            let handle = HANDLE(self.0.as_raw_handle());
            if unsafe { WaitForSingleObject(handle, 0) } == WAIT_TIMEOUT {
                unsafe {
                    let _ = TerminateProcess(handle, 1);
                    WaitForSingleObject(handle, 5000);
                }
            }
        }
    }

    #[tokio::test]
    async fn cancelling_before_delimiter_kills_worker_and_owned_descendant() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        let pool = Arc::new(pool);
        let fixture = Fixture::new();
        let path = fixture.ps_path();
        let script = format!(
            "$child = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') \
             -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') \
             -NoNewWindow -PassThru; \
             [IO.File]::WriteAllText('{path}', \"$PID,$($child.Id)\"); \
             Start-Sleep -Seconds 30"
        );
        let task_pool = Arc::clone(&pool);
        let mut task = AbortTask(Some(tokio::spawn(async move {
            task_pool.execute(&script).await
        })));
        let pids = fixture.pids().await;
        let worker = ProcessProbe::open(pids.0);
        let descendant = ProcessProbe::open(pids.1);
        task.0.as_ref().unwrap().abort();
        assert!(task.0.take().unwrap().await.unwrap_err().is_cancelled());
        assert!(worker.exited(), "cancelled worker survived its lease");
        assert!(descendant.exited(), "owned descendant survived job closure");
        assert!(lock(&pool.state).workers[0].is_none());
        assert_eq!(pool.available.available_permits(), 1);
        assert_eq!(
            pool.exec_json("'after cancellation'").await.unwrap(),
            serde_json::json!("after cancellation")
        );
    }

    #[tokio::test]
    async fn worker_exit_is_detected_even_when_a_descendant_holds_pipes_open() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        let pool = Arc::new(pool);
        let fixture = Fixture::new();
        let gate = Fixture::new();
        let path = fixture.ps_path();
        let gate_path = gate.ps_path();
        let script = format!(
            "$child = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') \
             -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') \
             -NoNewWindow -PassThru; \
             [IO.File]::WriteAllText('{path}', \"$PID,$($child.Id)\"); \
             while ([IO.File]::ReadAllText('{gate_path}') -ne 'exit') {{ Start-Sleep -Milliseconds 20 }}; \
             exit 23"
        );
        let task_pool = Arc::clone(&pool);
        let mut task = AbortTask(Some(tokio::spawn(async move {
            task_pool.execute(&script).await
        })));
        let pids = fixture.pids().await;
        let worker = ProcessProbe::open(pids.0);
        let descendant = ProcessProbe::open(pids.1);
        fs::write(&gate.0, "exit").unwrap();
        let result = timeout_at(
            Instant::now() + Duration::from_secs(3),
            task.0.as_mut().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(task.0.take());
        assert!(result.unwrap_err().to_string().contains("exited"));
        assert!(worker.exited());
        assert!(descendant.exited());
        assert_eq!(
            pool.exec_json("'after exit'").await.unwrap(),
            serde_json::json!("after exit")
        );
    }

    #[tokio::test]
    async fn dropping_an_idle_pool_kills_its_owned_process_tree() {
        let _serial = PROCESS_TEST_LOCK.lock().await;
        let Some(pool) = test_pool(1) else { return };
        let fixture = Fixture::new();
        let path = fixture.ps_path();
        let script = format!(
            "$child = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') \
             -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') \
             -NoNewWindow -PassThru; \
             [IO.File]::WriteAllText('{path}', \"$PID,$($child.Id)\")"
        );
        pool.execute(&script).await.unwrap();
        let pids = fixture.pids().await;
        let worker = ProcessProbe::open(pids.0);
        let descendant = ProcessProbe::open(pids.1);
        drop(pool);
        assert!(worker.exited());
        assert!(descendant.exited());
    }
}
