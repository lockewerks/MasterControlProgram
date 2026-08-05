//! # Claude Desktop Registration
//!
//! Adds and removes our entry in claude_desktop_config.json so nobody has to
//! hand-edit JSON to use this thing.
//!
//! ## The MSIX trap
//!
//! Every guide on the internet says the config lives at
//! `%APPDATA%\Claude\claude_desktop_config.json`. That is true right up until
//! Claude Desktop is installed from the Store as an MSIX package, at which
//! point Windows redirects the app's `%APPDATA%` writes into its package
//! container and the real file lives at
//!
//!   %LOCALAPPDATA%\Packages\Claude_<hash>\LocalCache\Roaming\Claude\
//!
//! The path everyone documents still exists, still looks plausible, and is
//! read by absolutely nobody. Write there and the registration silently does
//! nothing forever. So we look for the package container first and only fall
//! back to the documented path when there isn't one.
//!
//! ## Why we write in place
//!
//! This file is not ours. It holds the user's other MCP servers (frequently
//! with API keys in them), window preferences, trusted folders, and paired
//! devices. Two rules follow from that:
//!
//! 1. Never log its contents. Ever. Somebody's API key is in there.
//! 2. Preserve every key we do not own, which means parse to a generic Value
//!    and touch exactly one entry.
//!
//! We also truncate-and-rewrite the existing file rather than writing a temp
//! file and renaming over it. A rename installs a NEW file, which carries the
//! creating process's security descriptor. Our installer hooks inherit the
//! installer's token, so on an elevated install that new file would end up
//! owned by Administrators, sitting inside the user's own package container,
//! and the sandboxed app would quietly lose the ability to save its settings.
//! Truncating an existing file leaves its ACL alone.

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The key we register ourselves under.
pub const SERVER_KEY: &str = "mastercontrolprogram";

const CONFIG_NAME: &str = "claude_desktop_config.json";

/// Where Claude Desktop actually reads its config from, and which flavour of
/// install we found. Returns None when Claude Desktop isn't installed at all.
pub fn config_path() -> Option<(PathBuf, &'static str)> {
    // MSIX first. The package container wins whenever it exists, because if
    // Claude Desktop is packaged then that is the only file it reads.
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let packages = Path::new(&local).join("Packages");
        if let Ok(entries) = fs::read_dir(&packages) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with("Claude_") {
                    continue;
                }
                let dir = entry.path().join("LocalCache").join("Roaming").join("Claude");
                if dir.is_dir() {
                    return Some((dir.join(CONFIG_NAME), "MSIX / Store"));
                }
            }
        }
    }

    // Plain installs. Only report it if the directory is really there; a
    // missing %APPDATA%\Claude means Claude Desktop was never installed, and
    // conjuring the folder would leave a config nothing reads.
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = Path::new(&appdata).join("Claude");
        if dir.is_dir() {
            return Some((dir.join(CONFIG_NAME), "standard"));
        }
    }

    None
}

/// Whether Claude Desktop is on the box. Presence of the config directory is
/// the only honest test: both install flavours create it, and neither writes
/// anything we could look for before the app has run once.
pub fn installed() -> bool {
    config_path().is_some()
}

/// Parse the existing config, or start a fresh object if there isn't one.
/// A config that exists but is corrupt is a hard error: silently replacing it
/// would take out every other server the user has configured.
fn load(path: &Path) -> Result<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
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

/// Serialize and write, preserving the existing file's ACL. See module docs
/// for why this is a truncating write rather than a temp-and-rename.
fn save(path: &Path, root: &Map<String, Value>) -> Result<()> {
    let text = serde_json::to_string_pretty(root)?;

    // Round-trip before touching the real file. If we somehow produced garbage,
    // the user still has a working config.
    let _: Value = serde_json::from_str(&text)
        .context("generated config failed to re-parse; original left untouched")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
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
pub fn register(exe: &Path) -> Result<()> {
    let Some((path, kind)) = config_path() else {
        // Not an error. Plenty of people run this from Claude Code and have
        // never installed the desktop app; failing the install over it would
        // be obnoxious.
        //
        // We do not create the file either, even when the user names this
        // client explicitly. Which of the two paths is live depends on which
        // install flavour is present, and with neither present there is nothing
        // to read the answer off. Guessing wrong writes the stale orphan the
        // module docs are about: a file that looks right and is read by nobody.
        println!("Not found, skipping registration.");
        println!("Install it, then re-run: --register-claude-desktop");
        return Ok(());
    };
    println!("config ({kind}): {}", path.display());

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

    let mut entry = Map::new();
    entry.insert(
        "command".into(),
        Value::String(exe.display().to_string()),
    );
    servers.insert(SERVER_KEY.into(), Value::Object(entry));

    match previous.as_deref() {
        Some(p) if p == exe.display().to_string() => println!("already registered, unchanged"),
        Some(p) => println!("updated existing entry (was: {p})"),
        None => println!("added new entry"),
    }

    save(&path, &root)?;
    println!("registered '{SERVER_KEY}' -> {}", exe.display());
    println!("Fully quit and reopen Claude Desktop to pick it up.");
    Ok(())
}

/// Remove our entry, leaving everything else alone.
pub fn unregister() -> Result<()> {
    let Some((path, kind)) = config_path() else {
        println!("not found, nothing to remove");
        return Ok(());
    };
    if !path.exists() {
        println!("no config at {}, nothing to remove", path.display());
        return Ok(());
    }
    println!("config ({kind}): {}", path.display());

    let mut root = load(&path)?;
    let removed = match root.get_mut("mcpServers") {
        Some(Value::Object(servers)) => servers.remove(SERVER_KEY).is_some(),
        _ => false,
    };

    if removed {
        save(&path, &root)?;
        println!("removed '{SERVER_KEY}'");
    } else {
        println!("no '{SERVER_KEY}' entry to remove");
    }
    Ok(())
}
