//! # MCP Client Registration
//!
//! Nobody should have to hand-edit a config file to use this thing, so the
//! binary writes itself into the clients that launch local stdio servers on
//! Windows. There are two of those, and they agree on nothing:
//!
//! | Client | File | Format |
//! |---|---|---|
//! | Claude Desktop | `claude_desktop_config.json` | JSON |
//! | ChatGPT desktop, Codex CLI, Codex IDE extension | `~\.codex\config.toml` | TOML |
//!
//! The OpenAI side is three products sharing one Codex host, so a single entry
//! in one file covers all three. Each submodule owns its own path resolution
//! and its own merge, because the two files are wrong in different ways.
//!
//! ## The rules both of them follow
//!
//! These files belong to the user, not to us. They hold other MCP servers,
//! frequently with API keys in them, plus window preferences, trusted folders
//! and approval policy. So: never log their contents, preserve every key we do
//! not own, and rewrite in place rather than replacing the file. See each
//! submodule for the specifics.
//!
//! ## What a run does
//!
//! `--register` takes whatever is installed, which is what the installer runs
//! and what anyone re-running this after an upgrade wants. Naming a client
//! (`--register-chatgpt`) means the user asked for it specifically, so we stop
//! guessing and write it, installed or not, where the path is unambiguous
//! enough to allow that.

pub mod claude_code;
pub mod claude_desktop;
pub mod codex;

use anyhow::Result;
use std::path::Path;

/// A client we know how to register with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Client {
    ClaudeDesktop,
    /// Claude Code, the CLI. Reads user-scope MCP servers from ~/.claude.json.
    ClaudeCode,
    /// The ChatGPT desktop app, the Codex CLI and the Codex IDE extension. One
    /// config file between them, so one variant.
    Codex,
}

impl Client {
    pub const ALL: [Client; 3] =
        [Client::ClaudeDesktop, Client::ClaudeCode, Client::Codex];

    pub fn label(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "Claude Desktop",
            Client::ClaudeCode => "Claude Code",
            Client::Codex => "ChatGPT / Codex",
        }
    }

    /// The flag that selects this client on its own. Quoted back at the user
    /// whenever we skip one, so a client installed later is one command away.
    pub fn flag(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "--register-claude-desktop",
            Client::ClaudeCode => "--register-claude-code",
            Client::Codex => "--register-chatgpt",
        }
    }

    /// Is this client actually on the box? Best effort, and deliberately cheap:
    /// a false negative costs a skipped registration the user can redo by name,
    /// and nothing here is load-bearing for the server itself.
    pub fn installed(self) -> bool {
        match self {
            Client::ClaudeDesktop => claude_desktop::installed(),
            Client::ClaudeCode => claude_code::installed(),
            Client::Codex => codex::installed(),
        }
    }

    /// `named` is true when the user asked for this client by flag rather than
    /// letting us detect it, which is what licenses creating a config that is
    /// not there yet.
    fn register(self, exe: &Path, named: bool) -> Result<()> {
        match self {
            Client::ClaudeDesktop => claude_desktop::register(exe),
            Client::ClaudeCode => claude_code::register(exe),
            Client::Codex => codex::register(exe, named),
        }
    }

    fn unregister(self) -> Result<()> {
        match self {
            Client::ClaudeDesktop => claude_desktop::unregister(),
            Client::ClaudeCode => claude_code::unregister(),
            Client::Codex => codex::unregister(),
        }
    }
}

/// Which clients an invocation applies to.
enum Scope {
    /// Bare `--register`: whichever clients are installed.
    Detected,
    /// `--register-chatgpt`, `--register-claude-desktop`, or both: exactly these.
    Named(Vec<Client>),
}

/// A registration run parsed off the command line.
pub struct Action {
    register: bool,
    scope: Scope,
}

impl Action {
    /// Pick the registration flags out of argv. `None` means this is an
    /// ordinary server launch and main should carry on.
    ///
    /// Naming clients wins over the bare flag, and naming both is how you say
    /// "Claude and ChatGPT" in one run.
    pub fn from_args(args: &[String]) -> Option<Result<Action>> {
        let mut register: Option<bool> = None;
        let mut named: Vec<Client> = Vec::new();
        let mut conflict = false;

        for arg in args.iter().skip(1) {
            let (verb, client) = match arg.as_str() {
                "--register" => (true, None),
                "--register-claude-desktop" | "--register-claude" => {
                    (true, Some(Client::ClaudeDesktop))
                }
                "--register-claude-code" => (true, Some(Client::ClaudeCode)),
                "--register-chatgpt" | "--register-codex" => (true, Some(Client::Codex)),
                "--unregister" => (false, None),
                "--unregister-claude-desktop" | "--unregister-claude" => {
                    (false, Some(Client::ClaudeDesktop))
                }
                "--unregister-claude-code" => (false, Some(Client::ClaudeCode)),
                "--unregister-chatgpt" | "--unregister-codex" => (false, Some(Client::Codex)),
                _ => continue,
            };

            if register.is_some_and(|previous| previous != verb) {
                conflict = true;
            }
            register = Some(verb);

            if let Some(client) = client {
                if !named.contains(&client) {
                    named.push(client);
                }
            }
        }

        let register = register?;
        if conflict {
            return Some(Err(anyhow::anyhow!(
                "register and unregister flags in the same run; pick one"
            )));
        }

        let scope = if named.is_empty() {
            Scope::Detected
        } else {
            Scope::Named(named)
        };
        Some(Ok(Action { register, scope }))
    }

    pub fn run(self) -> Result<()> {
        let exe = std::env::current_exe()?;
        let named = matches!(self.scope, Scope::Named(_));

        let targets: Vec<Client> = match self.scope {
            Scope::Named(list) => list,
            // Removal sweeps everything. A client that has since been
            // uninstalled can still have our entry sitting in a config file it
            // left behind, and each unregister is a no-op when the file is gone.
            Scope::Detected if !self.register => Client::ALL.to_vec(),
            Scope::Detected => Client::ALL
                .into_iter()
                .filter(|client| client.installed())
                .collect(),
        };

        if self.register && targets.is_empty() {
            println!("No supported MCP client found.");
            println!("Looked for: Claude Desktop, Claude Code, ChatGPT / Codex.");
            println!("Install one and re-run: \"{}\" --register", exe.display());
            return Ok(());
        }

        // One client's mangled config should not cost the other one its
        // registration, so every target gets its turn and the failures are
        // reported together at the end.
        let mut failed: Vec<&str> = Vec::new();
        for &client in &targets {
            println!("\n[{}]", client.label());
            let outcome = if self.register {
                client.register(&exe, named)
            } else {
                client.unregister()
            };
            if let Err(e) = outcome {
                println!("failed: {e:#}");
                failed.push(client.label());
            }
        }

        // Say what we passed over. Detection deciding on its own that a
        // supported client does not exist is exactly the sort of thing to print
        // rather than assume, and the flag that overrides it goes on the line
        // with it.
        if self.register && !named {
            for client in Client::ALL
                .into_iter()
                .filter(|client| !targets.contains(client))
            {
                println!(
                    "\n[{}]\nnot found, skipped. Register anyway with: {}",
                    client.label(),
                    client.flag()
                );
            }
        }

        if !failed.is_empty() {
            anyhow::bail!("failed for: {}", failed.join(", "));
        }
        Ok(())
    }
}
