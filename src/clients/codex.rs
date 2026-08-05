//! # ChatGPT / Codex Registration
//!
//! Adds and removes our entry in the Codex config so nobody has to hand-edit
//! TOML to use this from OpenAI's clients.
//!
//! ## One file, three products
//!
//! The ChatGPT desktop app, the Codex CLI and the Codex IDE extension are the
//! same Codex host underneath and share one MCP config:
//!
//!   %USERPROFILE%\.codex\config.toml
//!
//! so a single `[mcp_servers.mastercontrolprogram]` table registers all three.
//!
//! There is no MSIX trap here, which is the pleasant surprise after Claude
//! Desktop. The ChatGPT app does ship as an MSIX package from the Store, but
//! package redirection covers the AppData tree, and this file sits at the root
//! of the profile instead.
//!
//! ## Why toml_edit and not serde
//!
//! Same rule as the Claude side: the file is the user's, not ours. It holds
//! their other MCP servers (often with API keys), their model and approval
//! settings, their per-project trust decisions, and their comments. A serde
//! round-trip through `toml` reads all that into a map and writes back a
//! normalized document: comments gone, tables reordered, inline style flattened.
//! toml_edit rewrites the one table we own and leaves the rest of the bytes
//! alone. Nothing here ever logs the contents.
//!
//! We also truncate and rewrite in place rather than writing a temp file and
//! renaming over it, for the reason spelled out in `claude_desktop`: a rename
//! installs a new file carrying the creating process's security descriptor, and
//! an elevated installer hook would leave an Administrators-owned config in the
//! user's own profile.
//!
//! ## Why we ask for a longer startup timeout
//!
//! Codex gives a stdio server 10 seconds to come up before it gives up on it.
//! We self-elevate through sudo on launch (see `src/elevate.rs`), so the MCP
//! handshake sits behind a UAC prompt with the clock running while the user
//! looks at it. Ten seconds is not enough time to find the mouse. A fresh entry
//! asks for 60; an existing value is left alone, because a number the user
//! tuned themselves is not ours to overwrite.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Table, value};

/// The key we register ourselves under.
pub const SERVER_KEY: &str = "mastercontrolprogram";

const CONFIG_DIR: &str = ".codex";
const CONFIG_NAME: &str = "config.toml";

/// Seconds we ask Codex to wait for the handshake. See the module docs: the
/// default 10 has to cover a UAC prompt, and it does not.
const STARTUP_TIMEOUT_SECS: i64 = 60;

/// `%USERPROFILE%\.codex`. None only when the environment has no USERPROFILE,
/// which means we are running somewhere a user profile does not exist.
fn config_dir() -> Option<PathBuf> {
    let profile = std::env::var("USERPROFILE").ok()?;
    Some(Path::new(&profile).join(CONFIG_DIR))
}

/// Where the Codex host reads its config from. Unlike Claude Desktop this is a
/// single fixed path, so there is nothing to search for and no wrong answer.
pub fn config_path() -> Option<PathBuf> {
    Some(config_dir()?.join(CONFIG_NAME))
}

/// Is one of OpenAI's Store apps installed? They ship as MSIX packages, so a
/// container under `%LOCALAPPDATA%\Packages` is the marker: `OpenAI.ChatGPT_*`
/// for the desktop app, `OpenAI.Codex_*` for the Codex app.
///
/// Best effort. A miss here costs a skipped registration the user can still ask
/// for by name, which is why it is worth doing at all and not worth doing
/// harder.
fn openai_package_present() -> bool {
    let Ok(local) = std::env::var("LOCALAPPDATA") else {
        return false;
    };
    let Ok(entries) = fs::read_dir(Path::new(&local).join("Packages")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        name.starts_with("openai.chatgpt") || name.starts_with("openai.codex")
    })
}

/// Is the Codex CLI on PATH? Catches an install that has never been run, which
/// is the one case where the CLI is present but `.codex` is not.
fn codex_cli_on_path() -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    // npm installs it as a .ps1 plus a .cmd shim, a native build is a bare .exe.
    const NAMES: [&str; 3] = ["codex.exe", "codex.cmd", "codex.ps1"];
    std::env::split_paths(&path)
        .any(|dir| NAMES.iter().any(|name| dir.join(name).is_file()))
}

/// Whether any client that reads this file is on the box.
pub fn installed() -> bool {
    config_dir().is_some_and(|dir| dir.is_dir()) || openai_package_present() || codex_cli_on_path()
}

/// Parse the existing config, or start an empty document if there isn't one.
/// A config that exists but does not parse is a hard error: replacing it would
/// take out every setting and every other server the user has.
fn load(path: &Path) -> Result<DocumentMut> {
    if !path.exists() {
        return Ok(DocumentMut::new());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    raw.parse::<DocumentMut>().with_context(|| {
        format!(
            "{} is not valid TOML. Refusing to overwrite it: fix or move it first.",
            path.display()
        )
    })
}

/// Serialize and write, preserving the existing file's ACL. See the module docs
/// for why this is a truncating write rather than a temp-and-rename.
fn save(path: &Path, doc: &DocumentMut) -> Result<()> {
    let text = doc.to_string();

    // Round-trip before touching the real file. If we somehow produced garbage,
    // the user still has a working config.
    text.parse::<DocumentMut>()
        .context("generated config failed to re-parse; original left untouched")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all().ok();
    Ok(())
}

/// Add or update our entry, pointing at `exe`.
///
/// `named` means the user asked for this client by flag. That is what licenses
/// creating the config when nothing is there yet: the path is fixed and
/// unambiguous, so a file written ahead of the client is a file the client will
/// read when it arrives. Without it we only touch a config for a client we can
/// actually see.
pub fn register(exe: &Path, named: bool) -> Result<()> {
    let Some(path) = config_path() else {
        println!("no USERPROFILE, cannot locate the Codex config; skipping.");
        return Ok(());
    };

    if !named && !installed() {
        println!("Not found, skipping registration.");
        println!("Installed it since? Run: \"{}\" --register-chatgpt", exe.display());
        return Ok(());
    }

    let fresh = !path.exists();
    println!("config: {}", path.display());

    let mut doc = load(&path)?;

    // A table we create is implicit, so the file gets `[mcp_servers.<key>]` and
    // not a bare `[mcp_servers]` header above it. One we found is left however
    // the user (or `codex mcp add`) wrote it.
    let servers = doc.entry("mcp_servers").or_insert_with(|| {
        let mut table = Table::new();
        table.set_implicit(true);
        Item::Table(table)
    });
    let Some(servers) = servers.as_table_mut() else {
        anyhow::bail!("mcp_servers exists but is not a table; not touching it");
    };

    let previous = servers
        .get(SERVER_KEY)
        .and_then(Item::as_table_like)
        .and_then(|entry| entry.get("command"))
        .and_then(|command| command.as_str())
        .map(str::to_owned);

    let entry = servers
        .entry(SERVER_KEY)
        .or_insert_with(|| Item::Table(Table::new()));
    let Some(entry) = entry.as_table_like_mut() else {
        anyhow::bail!("mcp_servers.{SERVER_KEY} exists but is not a table; not touching it");
    };

    let command = exe.display().to_string();
    entry.insert("command", value(&command));
    if entry.get("startup_timeout_sec").is_none() {
        entry.insert("startup_timeout_sec", value(STARTUP_TIMEOUT_SECS));
    }

    match previous.as_deref() {
        Some(p) if p == command => println!("already registered, unchanged"),
        Some(p) => println!("updated existing entry (was: {p})"),
        None if fresh => println!("created the config and added our entry"),
        None => println!("added new entry"),
    }

    save(&path, &doc)?;
    println!("registered '{SERVER_KEY}' -> {command}");
    println!("Restart the ChatGPT app, or start a new Codex session, to pick it up.");
    Ok(())
}

/// Remove our entry, leaving everything else alone.
pub fn unregister() -> Result<()> {
    let Some(path) = config_path() else {
        return Ok(());
    };
    if !path.exists() {
        println!("no config at {}, nothing to remove", path.display());
        return Ok(());
    }
    println!("config: {}", path.display());

    let mut doc = load(&path)?;
    let removed = doc
        .get_mut("mcp_servers")
        .and_then(Item::as_table_like_mut)
        .is_some_and(|servers| servers.remove(SERVER_KEY).is_some());

    if removed {
        save(&path, &doc)?;
        println!("removed '{SERVER_KEY}'");
    } else {
        println!("no '{SERVER_KEY}' entry to remove");
    }
    Ok(())
}
