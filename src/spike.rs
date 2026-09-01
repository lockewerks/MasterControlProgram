//! # Activity glow spike
//!
//! `MasterControlProgram.exe --glow-spike`
//!
//! Runs the real overlay against a human's eyes. Every software instrument we
//! have says the glow works: the window flips visible, `UpdateLayeredWindow`
//! returns Ok, the envelope timing matches to within a frame. None of that is
//! proof, because a window can be shown, report visible, and still put nothing
//! on the glass. Capture exclusion makes it worse: it is designed to hide the
//! window from every screenshot on the machine, so "not rendering" and
//! "rendering, correctly hidden" are indistinguishable from software.
//!
//! So this drives `overlay::init` and `overlay::pulse`, the same two functions
//! the tool handlers call, and narrates each step so a person can say whether
//! they saw it. No reimplementation: a copy of the drawing code that worked
//! would prove nothing about the code that ships.

use std::time::Duration;

use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};

use crate::overlay;

pub const FLAG: &str = "--glow-spike";

fn beat(secs: f32) {
    std::thread::sleep(Duration::from_secs_f32(secs));
}

pub fn run() -> anyhow::Result<()> {
    // Same call main() makes, for the same reason: the window is sized from
    // virtual-screen metrics and has to land on physical pixels.
    let _ = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };

    let excluded = std::env::var("MCP_OVERLAY_AFFINITY").as_deref() == Ok("exclude");

    println!();
    println!("  Activity glow spike");
    println!("  ───────────────────");
    println!();
    println!("  Watch the edges of your screen, not this window.");
    if excluded {
        println!("  MCP_OVERLAY_AFFINITY=exclude is set. On a virtual or indirect");
        println!("  display that hides the glow from you as well as from capture,");
        println!("  so seeing nothing at all here is the expected failure.");
    } else {
        println!("  Capture exclusion is off, which is the default now.");
    }
    println!();

    overlay::init();
    beat(0.4);

    println!("  [1/4] One pulse. Expect a red band to bloom over about a quarter");
    println!("        second, sit for a second, then fade out over three.");
    overlay::pulse();
    beat(6.0);

    println!("  [2/4] Nothing for four seconds. Expect the screen to stay clean.");
    beat(4.0);

    println!("  [3/4] Four pulses, 1.2s apart. Expect one continuous glow that");
    println!("        dips and recovers, never blinking fully off between them.");
    for _ in 0..4 {
        overlay::pulse();
        beat(1.2);
    }
    beat(5.0);

    println!("  [4/4] A pulse every 300ms for four seconds, the way a real");
    println!("        computer-use loop drives it. Expect a steady glow.");
    for _ in 0..13 {
        overlay::pulse();
        beat(0.3);
    }
    beat(5.0);

    println!();
    println!("  Done. If you saw nothing at all, the overlay is not reaching the");
    println!("  glass and the problem is in rendering, not in the trigger path.");
    println!();
    println!("  Knobs worth trying:");
    println!("    set MCP_OVERLAY_INTENSITY=255     brightest possible");
    println!("    set MCP_OVERLAY_AFFINITY=exclude  the old behaviour, likely invisible");
    println!();
    Ok(())
}
