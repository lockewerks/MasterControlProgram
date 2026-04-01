//! # The PowerShell Process Pool
//!
//! AKA "the thing that keeps pwsh.exe alive so we don't pay 200ms of startup
//! tax every time some LLM wants to know what firewall rules exist."
//!
//! ## How this shit works:
//!
//! We spawn N persistent PowerShell processes (default 3) and keep them warm.
//! Commands are wrapped in a try/catch, serialized to JSON, and delimited with
//! a UUID marker so we know where one response ends and the next begins.
//!
//! ## The Great Single-Line Discovery of 2026:
//!
//! PowerShell's `-Command -` mode processes each stdin LINE as a separate
//! command. So `try {` on one line and `} catch {` on the next line? LOL no.
//! That's two separate commands. The `catch` becomes "catch: command not found."
//! Everything must be ONE. SINGLE. LINE. I lost hours of my life to this.
//! Microsoft, if you're reading this: what the fuck.

use std::process::Stdio;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

/// 30 seconds ought to be enough for any PowerShell command.
/// If your command takes longer than this, it deserves to die.
const TIMEOUT_SECS: u64 = 30;

/// A single PowerShell worker process. It has feelings. None of them are good.
struct Worker {
    id: usize,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    child: Child,
}

impl Worker {
    /// Spawn a fresh pwsh.exe process and make it our bitch.
    /// -NoProfile: don't load your janky $PROFILE with 47 aliases
    /// -NoLogo: nobody cares about your copyright banner
    /// -NonInteractive: don't you dare prompt me for anything
    /// -Command -: read commands from stdin like a good little subprocess
    async fn spawn(id: usize) -> anyhow::Result<Self> {
        tracing::debug!(worker = id, "spawning pwsh worker");
        let mut child = Command::new("pwsh")
            .args(["-NoProfile", "-NoLogo", "-NonInteractive", "-Command", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());

        // Drain stderr in a background task so PowerShell's whining
        // doesn't clog the pipes and deadlock everything.
        let stderr = child.stderr.take().unwrap();
        let worker_id = id;
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let msg = line.trim();
                        if !msg.is_empty() {
                            tracing::warn!(worker = worker_id, stderr = msg, "pwsh stderr");
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let mut worker = Worker { id, stdin, stdout, child };

        // Warmup: poke the process to make sure it's actually alive and not
        // just sitting there like a zombie pretending to have a stdout pipe.
        tracing::debug!(worker = id, "warming up worker");
        let warmup = worker.execute_raw("Write-Output 'ready'").await?;
        if !warmup.contains("ready") {
            anyhow::bail!("worker {id} warmup failed: got '{warmup}'");
        }
        tracing::info!(worker = id, "pwsh worker ready");

        Ok(worker)
    }

    /// Check if this worker is still breathing.
    async fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Send a command to PowerShell and wait for the response.
    ///
    /// The command gets wrapped in a try/catch that serializes the result to
    /// JSON, followed by a UUID delimiter line. We read stdout until we see
    /// the delimiter, then return everything before it.
    ///
    /// ALL OF THIS MUST BE ON ONE LINE because PowerShell's stdin mode is
    /// dumber than a bag of rocks. See module docs for the full horror story.
    async fn execute_raw(&mut self, command: &str) -> anyhow::Result<String> {
        let delimiter = format!("___MCP_{}___", uuid::Uuid::new_v4());

        // THE LEGENDARY ONE-LINER: try/catch + if/elseif/else + JSON serialization
        // all crammed onto a single line because PowerShell said "fuck your formatting."
        // @() forces array context so .Count always works.
        // ConvertTo-Json -Compress because we're not animals (and multiline JSON
        // would break our line-based delimiter detection).
        let wrapped = format!(
            "try {{ $__r = @( & {{ {cmd} }} ); \
             if ($__r.Count -eq 0) {{ Write-Output '{{\"s\":true,\"d\":null}}' }} \
             elseif ($__r.Count -eq 1) {{ Write-Output (@{{s=$true;d=$__r[0]}} | ConvertTo-Json -Compress -Depth 10) }} \
             else {{ Write-Output (@{{s=$true;d=$__r}} | ConvertTo-Json -Compress -Depth 10) }} \
             }} catch {{ Write-Output (@{{s=$false;e=$_.Exception.Message}} | ConvertTo-Json -Compress) }}\n\
             Write-Output '{delim}'\n",
            cmd = command,
            delim = delimiter,
        );

        self.stdin.write_all(wrapped.as_bytes()).await?;
        self.stdin.flush().await?;

        // Read lines until we hit our delimiter. Anything before it is the result.
        // If we don't see the delimiter in 30 seconds, the command is dead to us.
        let mut result = String::new();
        let mut line = String::new();
        let deadline = timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                line.clear();
                let bytes_read = self.stdout.read_line(&mut line).await?;
                if bytes_read == 0 {
                    anyhow::bail!("pwsh worker {} exited unexpectedly", self.id);
                }
                let trimmed = line.trim();
                if trimmed == delimiter {
                    break;
                }
                if !trimmed.is_empty() {
                    result.push_str(trimmed);
                    result.push('\n');
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        match deadline.await {
            Ok(Ok(())) => Ok(result.trim().to_string()),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                tracing::error!(worker = self.id, "command timed out after {}s", TIMEOUT_SECS);
                Err(anyhow::anyhow!("Command timed out after {TIMEOUT_SECS}s"))
            }
        }
    }
}

/// The PowerShell Process Pool. A round-robin dispatcher that keeps N
/// PowerShell processes alive and distributes commands across them.
///
/// Think of it as a thread pool, but instead of threads, it's entire
/// goddamn operating system processes because Microsoft said "COM objects
/// and WMI are the way" and here we are.
pub struct Pool {
    workers: Vec<Mutex<Worker>>,
    next: std::sync::atomic::AtomicUsize,
}

impl Pool {
    /// Spawn `size` PowerShell workers. Each one takes ~150-200ms to start
    /// because PowerShell is a bloated runtime that loads half the .NET
    /// framework just to say hello. But at least we only pay this cost once.
    pub async fn new(size: usize) -> anyhow::Result<Self> {
        let mut workers = Vec::with_capacity(size);
        for i in 0..size {
            workers.push(Mutex::new(Worker::spawn(i).await?));
        }
        tracing::info!(count = size, "PowerShell pool ready");
        Ok(Pool {
            workers,
            next: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Pick the next worker using the world's simplest load balancer:
    /// just go round and round. Perfectly balanced, as all things should be.
    async fn get_worker(&self) -> &Mutex<Worker> {
        let idx = self
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.workers.len();
        &self.workers[idx]
    }

    /// Execute a raw PowerShell command string. Returns the raw stdout output.
    /// If the worker is dead, respawn it first because we're not quitters.
    pub async fn execute(&self, command: &str) -> anyhow::Result<String> {
        let start = Instant::now();
        let worker_lock = self.get_worker().await;
        let mut worker = worker_lock.lock().await;

        // Necromancy: if the worker died, bring it back from the dead
        if !worker.is_alive().await {
            tracing::warn!(worker = worker.id, "worker dead, respawning");
            *worker = Worker::spawn(worker.id).await?;
        }

        let cmd_preview: String = command.chars().take(80).collect();
        tracing::info!(worker = worker.id, cmd = %cmd_preview, "exec");

        let result = worker.execute_raw(command).await;
        let elapsed = start.elapsed();

        match &result {
            Ok(output) => {
                let out_preview: String = output.chars().take(120).collect();
                tracing::info!(
                    worker = worker.id,
                    ms = elapsed.as_millis() as u64,
                    out = %out_preview,
                    "done"
                );
            }
            Err(e) => {
                tracing::error!(
                    worker = worker.id,
                    ms = elapsed.as_millis() as u64,
                    err = %e,
                    "fail"
                );
            }
        }

        result
    }

    /// Execute a PowerShell command and parse the JSON wrapper we put around it.
    /// Returns the actual data payload, or an error if PowerShell threw a tantrum.
    pub async fn exec_json(&self, command: &str) -> anyhow::Result<serde_json::Value> {
        let raw = self.execute(command).await?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            tracing::error!(raw = %raw, err = %e, "JSON parse failed");
            anyhow::anyhow!("Failed to parse PS output: {e}\nRaw: {raw}")
        })?;

        if parsed.get("s").and_then(|v| v.as_bool()) == Some(true) {
            Ok(parsed.get("d").cloned().unwrap_or(serde_json::Value::Null))
        } else {
            let err_msg = parsed
                .get("e")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown PowerShell error");
            Err(anyhow::anyhow!("{err_msg}"))
        }
    }

    /// Execute and return a pretty-printed JSON string. Because we're classy like that.
    pub async fn exec_pretty(&self, command: &str) -> anyhow::Result<String> {
        let data = self.exec_json(command).await?;
        Ok(serde_json::to_string_pretty(&data)?)
    }
}
