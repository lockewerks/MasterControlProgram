//! # Installer support subcommands
//!
//! Things the Forge installer needs done that it cannot do itself. A Forge hook
//! runs a payload member as argv with no shell and no interpreter, so anything
//! an install needs to execute has to be a mode of this binary.

use anyhow::Result;

/// Terminate every other copy of this server on the box.
pub const KILL_FLAG: &str = "--kill-stale";

const EXE_NAME: &str = "MasterControlProgram.exe";

/// Kill every running instance except this one.
///
/// An upgrade does not need this to succeed. Forge renames the existing file
/// aside before writing the new one, which Windows permits even while the image
/// is mapped, so the install lands with old servers still running. What it does
/// need is for those servers to stop, because each one keeps serving the old
/// image out of the renamed file until its client happens to restart it, and
/// the user who just installed a new version would be talking to the old one
/// with nothing on screen to say so.
///
/// Killing them is safe: this is a headless stdio server that its MCP client
/// owns and respawns on demand. There is no unsaved state to lose, and a client
/// that wants one back starts a fresh process against the new binary.
///
/// Runs elevated, as the installer, on purpose. The servers elevate themselves,
/// so a medium-integrity token cannot terminate them.
///
/// Never fails the install. A process we could not kill is a stale server, not
/// a broken installation, and the client restarts it against the new binary
/// soon enough anyway.
pub fn kill_stale() -> Result<()> {
    let me = std::process::id();
    let mut killed = 0usize;
    let mut failed = 0usize;

    for (pid, name) in crate::win32::process::snapshot_name_cache() {
        if pid == me || !name.eq_ignore_ascii_case(EXE_NAME) {
            continue;
        }
        match crate::win32::process::kill(pid) {
            Ok(_) => {
                println!("terminated pid {pid}");
                killed += 1;
            }
            Err(e) => {
                // Most likely it exited between the snapshot and the kill,
                // which is the outcome we wanted anyway.
                println!("could not terminate pid {pid}: {e:#}");
                failed += 1;
            }
        }
    }

    match (killed, failed) {
        (0, 0) => println!("no other instances were running"),
        (k, 0) => println!("stopped {k} running instance(s)"),
        (k, f) => println!("stopped {k}, could not stop {f}"),
    }
    Ok(())
}
