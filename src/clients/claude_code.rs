//! # Claude Code Registration
//!
//! Adds and removes our entry in `~/.claude.json`, the user-scope config Claude
//! Code reads its MCP servers from. Same shape as the Claude Desktop file: one
//! `mcpServers` object keyed by server name.
//!
//! ## Why not shell out to `claude mcp add`
//!
//! It is the documented route and it is the wrong one here. It needs `claude`
//! on PATH in whatever environment the hook inherits, it prompts on conflict,
//! and it is a Node process we would be spawning from an installer hook to
//! perform a single JSON edit. Writing the file is one dependency fewer and is
//! the same operation the CLI performs.
//!
//! ## Why we write in place
//!
//! For the reasons `claude_desktop` spells out at length, which apply verbatim:
//! the file belongs to the user and holds their other MCP servers, so we parse
//! to a generic `Value`, touch exactly one key, and truncate rather than
//! rename so the file keeps its original ACL. Never log its contents.
//!
//! `~/.claude.json` also carries conversation history, project trust decisions
//! and onboarding state, so clobbering it is considerably worse than losing a
//! server entry.

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::claude_desktop::SERVER_KEY;

const CONFIG_NAME: &str = ".claude.json";

/// The user's home directory. `USERPROFILE` is what Windows actually sets, and
/// it is the one that moves when a hook runs `as = "user"` from an elevated
/// installer, which is the whole reason that setting exists.
fn home() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Where Claude Code reads user-scope MCP servers from, if it has ever run.
///
/// Unlike Claude Desktop there is only one candidate path, so the MSIX
/// ambiguity does not arise. We still refuse to conjure the file: a
/// `~/.claude.json` that Claude Code did not create means it was never
/// installed, and writing one leaves an orphan nothing reads.
pub fn config_path() -> Option<PathBuf> {
    let home = home()?;
    let config = home.join(CONFIG_NAME);
    if config.is_file() {
        return Some(config);
    }
    // Claude Code creates ~/.claude before it writes ~/.claude.json, so the
    // directory is the earlier and more reliable signal that it is installed.
    if home.join(".claude").is_dir() {
        return Some(config);
    }
    None
}

pub fn installed() -> bool {
    config_path().is_some()
}

/// Parse the existing config, or start fresh. A corrupt file is a hard error:
/// silently replacing it would take out the user's history and every other
/// server they have configured.
fn load(path: &Path) -> Result<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_str(&raw).with_context(|| {
        format!(
            "{} is not valid JSON. Refusing to overwrite it: fix or move it first.",
            path.display()
        )
    })?;
    match value {
        Value::Object(map) => Ok(map),
        _ => anyhow::bail!("{} is valid JSON but not an object", path.display()),
    }
}

/// Truncating write, so the file keeps the ACL it already had.
fn save(path: &Path, root: &Map<String, Value>) -> Result<()> {
    let text = serde_json::to_string_pretty(root)?;
    let _: Value = serde_json::from_str(&text)
        .context("generated config failed to re-parse; original left untouched")?;

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
/// Idempotent by construction: the entry is a value in a map under a fixed key,
/// so running this twice replaces it rather than adding a second copy. Running
/// it against an unchanged install is a no-op that rewrites identical bytes.
pub fn register(exe: &Path) -> Result<()> {
    let Some(path) = config_path() else {
        println!("Not found, skipping registration.");
        println!("Install it, then re-run: --register-claude-code");
        return Ok(());
    };
    println!("config: {}", path.display());

    let mut root = load(&path)?;

    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(servers) = servers else {
        anyhow::bail!("mcpServers exists but is not an object; not touching it");
    };

    let previous = servers
        .get(SERVER_KEY)
        .and_then(|e| e.get("command"))
        .and_then(|c| c.as_str())
        .map(str::to_owned);

    let command = exe.display().to_string();
    let mut entry = Map::new();
    entry.insert("command".into(), Value::String(command.clone()));
    // Claude Code defaults `type` to stdio, but it is explicit in everything
    // the CLI writes, and matching that keeps a hand-diff of this file boring.
    entry.insert("type".into(), Value::String("stdio".into()));
    servers.insert(SERVER_KEY.into(), Value::Object(entry));

    match previous.as_deref() {
        Some(p) if p == command => println!("already registered, unchanged"),
        Some(p) => println!("updated existing entry (was: {p})"),
        None => println!("added new entry"),
    }

    save(&path, &root)
}

/// Remove our entry, leaving everything else alone. Absent is success: an
/// uninstall should not fail because the thing it wanted gone already was.
pub fn unregister() -> Result<()> {
    let Some(path) = config_path() else {
        println!("Not found, nothing to remove.");
        return Ok(());
    };
    if !path.is_file() {
        println!("No config at {}, nothing to remove.", path.display());
        return Ok(());
    }
    println!("config: {}", path.display());

    let mut root = load(&path)?;
    let removed = match root.get_mut("mcpServers") {
        Some(Value::Object(servers)) => servers.remove(SERVER_KEY).is_some(),
        _ => false,
    };

    if removed {
        println!("removed entry");
        save(&path, &root)
    } else {
        println!("no entry to remove");
        Ok(())
    }
}
