//! Mouse and keyboard input through SendInput in virtual-desktop coordinates.

use super::pretty;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::mem::size_of;
use std::time::Duration;
use windows::Win32::Foundation::{GetLastError, SetLastError, POINT, WIN32_ERROR};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

const GLIDE_MAX_MS: f64 = 600.0;
const GLIDE_MIN_MS: f64 = 60.0;
const GLIDE_STEP_MS: u64 = 5;
const SCREEN_DIAG: f64 = 2203.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Button {
    Left,
    Right,
    Middle,
}

impl Button {
    fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "right" => Self::Right,
            "middle" => Self::Middle,
            _ => Self::Left,
        }
    }

    fn virtual_key(self) -> u16 {
        match self {
            Self::Left => VK_LBUTTON.0,
            Self::Right => VK_RBUTTON.0,
            Self::Middle => VK_MBUTTON.0,
        }
    }

    fn flags(self, up: bool) -> MOUSE_EVENT_FLAGS {
        match (self, up) {
            (Self::Left, false) => MOUSEEVENTF_LEFTDOWN,
            (Self::Left, true) => MOUSEEVENTF_LEFTUP,
            (Self::Right, false) => MOUSEEVENTF_RIGHTDOWN,
            (Self::Right, true) => MOUSEEVENTF_RIGHTUP,
            (Self::Middle, false) => MOUSEEVENTF_MIDDLEDOWN,
            (Self::Middle, true) => MOUSEEVENTF_MIDDLEUP,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeldInput {
    Key(u16),
    Unicode(u16),
    Mouse(Button),
}

impl HeldInput {
    fn input(self, up: bool) -> INPUT {
        match self {
            Self::Key(vk) => key_input(vk, up),
            Self::Unicode(ch) => INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: ch,
                        dwFlags: KEYEVENTF_UNICODE
                            | if up {
                                KEYEVENTF_KEYUP
                            } else {
                                KEYBD_EVENT_FLAGS(0)
                            },
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            },
            Self::Mouse(button) => mouse_input(button.flags(up)),
        }
    }
}

#[derive(Clone, Copy)]
enum Event {
    Plain(INPUT),
    Down(HeldInput),
    Up(HeldInput),
}

impl Event {
    fn input(self) -> INPUT {
        match self {
            Self::Plain(input) => input,
            Self::Down(held) => held.input(false),
            Self::Up(held) => held.input(true),
        }
    }
}

struct Insertion {
    accepted: usize,
    error: u32,
}

trait InputSender {
    fn send(&mut self, inputs: &[INPUT]) -> Insertion;
    fn is_down(&mut self, vk: u16) -> bool;
    fn cursor(&mut self) -> Result<POINT>;
    fn geometry(&mut self) -> (i32, i32, i32, i32);
    fn checkpoint(&mut self) -> Result<()> {
        crate::runtime::checkpoint()
    }
    fn sleep(&mut self, duration: Duration) -> Result<()> {
        crate::runtime::sleep(duration)
    }
}

struct WindowsInput;

impl InputSender for WindowsInput {
    fn send(&mut self, inputs: &[INPUT]) -> Insertion {
        unsafe {
            SetLastError(WIN32_ERROR(0));
            let accepted = SendInput(inputs, size_of::<INPUT>() as i32) as usize;
            Insertion {
                accepted,
                error: GetLastError().0,
            }
        }
    }

    fn is_down(&mut self, vk: u16) -> bool {
        unsafe { GetAsyncKeyState(i32::from(vk)) < 0 }
    }

    fn cursor(&mut self) -> Result<POINT> {
        let mut point = POINT::default();
        unsafe {
            GetCursorPos(&mut point)?;
        }
        Ok(point)
    }

    fn geometry(&mut self) -> (i32, i32, i32, i32) {
        unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        }
    }
}

struct InputOperation<'a, S: InputSender> {
    sender: &'a mut S,
    held: Vec<HeldInput>,
    accepted: usize,
    requested: usize,
    cleanup_attempted: bool,
}

impl<S: InputSender> InputOperation<'_, S> {
    fn send(&mut self, events: &[Event]) -> Result<()> {
        self.sender.checkpoint()?;
        if events.is_empty() {
            return Ok(());
        }
        let inputs: Vec<_> = events.iter().map(|event| event.input()).collect();
        let Insertion { accepted, error } = self.sender.send(&inputs);
        self.requested += events.len();
        if accepted > events.len() {
            bail!(
                "SendInput returned an invalid count: {accepted} for {} events",
                events.len()
            );
        }
        self.accepted += accepted;
        // Only the accepted prefix changes ownership. A cancelled future may
        // stop between any two batches, including immediately after key-down.
        for event in &events[..accepted] {
            match event {
                Event::Down(held) => {
                    if !self.held.contains(held) {
                        self.held.push(*held);
                    }
                }
                Event::Up(held) => self.held.retain(|current| current != held),
                Event::Plain(_) => {}
            }
        }
        if accepted != events.len() {
            bail!("SendInput accepted {accepted} of {} events (Win32 error {error}; Windows may block input across privilege or desktop boundaries)", events.len());
        }
        self.sender.checkpoint()
    }

    fn release_owned(&mut self) -> Result<()> {
        self.cleanup_attempted = true;
        let mut failures = Vec::new();
        // Cleanup deliberately ignores cancellation and attempts every owned
        // release even if another release fails. User-held keys are absent.
        for held in self.held.clone().into_iter().rev() {
            let Insertion { accepted, error } = self.sender.send(&[held.input(true)]);
            if accepted == 1 {
                self.held.retain(|current| *current != held);
            } else {
                failures.push(format!(
                    "{held:?}: accepted {accepted} of 1 release events, Win32 error {error}"
                ));
            }
        }
        if !failures.is_empty() {
            bail!(
                "Input cleanup failed; these owned inputs may remain down: {}",
                failures.join("; ")
            );
        }
        Ok(())
    }

    fn absolute(&mut self, x: i32, y: i32) -> Result<()> {
        let (origin_x, origin_y, width, height) = self.sender.geometry();
        let dx = normalize_axis(x, origin_x, width)?;
        let dy = normalize_axis(y, origin_y, height)?;
        self.send(&[Event::Plain(INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_MOVE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })])
    }

    fn glide_to(&mut self, x: i32, y: i32) -> Result<()> {
        self.sender.checkpoint()?;
        let start = self.sender.cursor()?;
        let distance = (f64::from(x) - f64::from(start.x)).hypot(f64::from(y) - f64::from(start.y));
        if distance < 2.0 {
            return self.absolute(x, y);
        }
        let duration_ms =
            GLIDE_MIN_MS + (distance / SCREEN_DIAG).min(1.0) * (GLIDE_MAX_MS - GLIDE_MIN_MS);
        let steps = (duration_ms / GLIDE_STEP_MS as f64).ceil() as u32;
        for step in 1..=steps {
            let t = ease_in_out(f64::from(step) / f64::from(steps));
            self.absolute(interpolate(start.x, x, t), interpolate(start.y, y, t))?;
            self.sender.sleep(Duration::from_millis(GLIDE_STEP_MS))?;
        }
        self.absolute(x, y)
    }

    fn position_if_requested(&mut self, position: Option<(i32, i32)>) -> Result<()> {
        if let Some((x, y)) = position {
            self.glide_to(x, y)?;
            self.sender.sleep(Duration::from_millis(5))?;
        }
        Ok(())
    }

    fn require_unheld_button(&mut self, button: Button) -> Result<()> {
        if self.sender.is_down(button.virtual_key()) {
            bail!("Mouse button {button:?} is already held; refusing to release user-owned input");
        }
        Ok(())
    }
}

impl<S: InputSender> Drop for InputOperation<'_, S> {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            if let Err(error) = self.release_owned() {
                tracing::error!(%error, "input cleanup during unwinding failed");
            }
        }
    }
}

fn operate<S, T>(
    sender: &mut S,
    work: impl FnOnce(&mut InputOperation<'_, S>) -> Result<T>,
) -> Result<T>
where
    S: InputSender,
{
    let mut operation = InputOperation {
        sender,
        held: Vec::new(),
        accepted: 0,
        requested: 0,
        cleanup_attempted: false,
    };
    let result = work(&mut operation);
    let cleanup = operation.release_owned();
    let result = match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{cleanup:#}"))),
    };
    result.with_context(|| format!(
        "Input operation failed after Windows accepted {} of {} requested events; application outcome is not observed",
        operation.accepted, operation.requested
    ))
}

fn normalize_axis(position: i32, origin: i32, dimension: i32) -> Result<i32> {
    if dimension <= 1 {
        bail!("Virtual screen dimension is too small to normalize: {dimension}");
    }
    let extent = i64::from(dimension) - 1;
    let relative = (i64::from(position) - i64::from(origin)).clamp(0, extent);
    Ok((relative * 65535 / extent) as i32)
}

fn interpolate(start: i32, end: i32, t: f64) -> i32 {
    (f64::from(start) + (f64::from(end) - f64::from(start)) * t).round() as i32
}

fn ease_in_out(t: f64) -> f64 {
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

fn paired_position(x: Option<i32>, y: Option<i32>) -> Result<Option<(i32, i32)>> {
    match (x, y) {
        (Some(x), Some(y)) => Ok(Some((x, y))),
        (None, None) => Ok(None),
        _ => bail!("x and y must be supplied together; no input was sent"),
    }
}

pub fn cursor_position() -> Result<String> {
    let point = WindowsInput.cursor()?;
    Ok(pretty(&json!({ "X": point.x, "Y": point.y })))
}

pub fn mouse_move(x: i32, y: i32) -> Result<String> {
    move_with(&mut WindowsInput, x, y)
}

fn move_with(sender: &mut impl InputSender, x: i32, y: i32) -> Result<String> {
    operate(sender, |operation| {
        operation.glide_to(x, y)?;
        let observed = operation.sender.cursor()?;
        Ok(pretty(&json!({
            "Status": "Moved", "X": x, "Y": y,
            "Accepted": true, "EventsSent": operation.accepted,
            "Observed": { "CursorPosition": { "X": observed.x, "Y": observed.y } },
            "ApplicationActionObserved": false,
        })))
    })
}

pub fn mouse_click(x: Option<i32>, y: Option<i32>, button: &str, count: u32) -> Result<String> {
    click_with(&mut WindowsInput, x, y, button, count)
}

fn click_with(
    sender: &mut impl InputSender,
    x: Option<i32>,
    y: Option<i32>,
    button: &str,
    count: u32,
) -> Result<String> {
    let position = paired_position(x, y)?;
    let selected = Button::from_name(button);
    operate(sender, |operation| {
        operation.require_unheld_button(selected)?;
        operation.position_if_requested(position)?;
        let click_count = count.clamp(1, 5);
        let held = HeldInput::Mouse(selected);
        for _ in 0..click_count {
            operation.require_unheld_button(selected)?;
            operation.send(&[Event::Down(held), Event::Up(held)])?;
            if click_count > 1 {
                operation.sender.sleep(Duration::from_millis(30))?;
            }
        }
        let observed = operation.sender.cursor()?;
        Ok(pretty(&json!({
            "Status": "Clicked", "Button": button, "Count": click_count,
            "X": observed.x, "Y": observed.y,
            "Accepted": true, "EventsSent": operation.accepted,
            "Observed": { "CursorPosition": { "X": observed.x, "Y": observed.y } },
            "ApplicationActionObserved": false,
        })))
    })
}

pub fn mouse_scroll(x: Option<i32>, y: Option<i32>, clicks: i32) -> Result<String> {
    scroll_with(&mut WindowsInput, x, y, clicks)
}

fn scroll_with(
    sender: &mut impl InputSender,
    x: Option<i32>,
    y: Option<i32>,
    clicks: i32,
) -> Result<String> {
    let position = paired_position(x, y)?;
    let amount = clicks
        .checked_mul(120)
        .context("Mouse wheel delta overflow; no input was sent")?;
    operate(sender, |operation| {
        operation.position_if_requested(position)?;
        operation.send(&[Event::Plain(INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: amount as u32,
                    dwFlags: MOUSEEVENTF_WHEEL,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })])?;
        Ok(pretty(&json!({
            "Status": "Scrolled", "Clicks": clicks,
            "Direction": if clicks > 0 { "Up" } else { "Down" },
            "Accepted": true, "EventsSent": operation.accepted,
            "Observed": null, "ApplicationActionObserved": false,
        })))
    })
}

pub fn mouse_drag(
    start_x: i32,
    start_y: i32,
    end_x: i32,
    end_y: i32,
    button: &str,
) -> Result<String> {
    drag_with(&mut WindowsInput, start_x, start_y, end_x, end_y, button)
}

fn drag_with(
    sender: &mut impl InputSender,
    start_x: i32,
    start_y: i32,
    end_x: i32,
    end_y: i32,
    button: &str,
) -> Result<String> {
    let selected = Button::from_name(button);
    operate(sender, |operation| {
        operation.require_unheld_button(selected)?;
        operation.glide_to(start_x, start_y)?;
        operation.sender.sleep(Duration::from_millis(15))?;
        operation.require_unheld_button(selected)?;
        let held = HeldInput::Mouse(selected);
        operation.send(&[Event::Down(held)])?;
        operation.sender.sleep(Duration::from_millis(30))?;
        operation.glide_to(end_x, end_y)?;
        operation.sender.sleep(Duration::from_millis(15))?;
        operation.send(&[Event::Up(held)])?;
        let observed = operation.sender.cursor()?;
        Ok(pretty(&json!({
            "Status": "Dragged", "Button": button,
            "From": { "X": start_x, "Y": start_y }, "To": { "X": end_x, "Y": end_y },
            "Accepted": true, "EventsSent": operation.accepted,
            "Observed": { "CursorPosition": { "X": observed.x, "Y": observed.y } },
            "ApplicationActionObserved": false,
        })))
    })
}

pub fn keyboard_type(text: &str) -> Result<String> {
    type_with(&mut WindowsInput, text)
}

fn type_with(sender: &mut impl InputSender, text: &str) -> Result<String> {
    let count = u32::try_from(text.encode_utf16().count())
        .context("Text is too long to count UTF-16 units")?;
    operate(sender, |operation| {
        for ch in text.encode_utf16() {
            let held = HeldInput::Unicode(ch);
            operation.send(&[Event::Down(held), Event::Up(held)])?;
        }
        Ok(pretty(&json!({
            "Status": "Typed", "Characters": count,
            "Accepted": true, "EventsSent": operation.accepted,
            "Observed": null, "ApplicationActionObserved": false,
        })))
    })
}

pub fn keyboard_key(keys: &str) -> Result<String> {
    key_with(&mut WindowsInput, keys)
}

fn key_with(sender: &mut impl InputSender, keys: &str) -> Result<String> {
    let mut vks = Vec::new();
    for part in keys.split('+').map(str::trim) {
        let vk = vk_from_name(part).with_context(|| format!("Unknown key name: '{part}'"))?;
        if !vks.contains(&vk) {
            vks.push(vk);
        }
    }
    operate(sender, |operation| {
        let mut already_held = Vec::new();
        vks.retain(|vk| {
            if operation.sender.is_down(*vk) {
                already_held.push(*vk);
                false
            } else {
                true
            }
        });
        if vks.is_empty() {
            bail!("All requested keys are already held; no input was sent");
        }
        let events: Vec<_> = vks
            .iter()
            .map(|vk| Event::Down(HeldInput::Key(*vk)))
            .chain(vks.iter().rev().map(|vk| Event::Up(HeldInput::Key(*vk))))
            .collect();
        operation.send(&events)?;
        Ok(pretty(&json!({
            "Status": "Pressed", "Keys": keys, "EventsSent": operation.accepted,
            "Accepted": true, "Observed": { "AlreadyHeldVirtualKeys": already_held },
            "ApplicationActionObserved": false,
        })))
    })
}

fn vk_from_name(name: &str) -> Option<u16> {
    let lower = name.to_lowercase();
    if lower.starts_with('f') && lower.len() >= 2 {
        if let Ok(n) = lower[1..].parse::<u16>() {
            if (1..=24).contains(&n) {
                return Some(0x6F + n);
            }
        }
    }
    match lower.as_str() {
        "ctrl" | "control" => Some(0x11),
        "shift" => Some(0x10),
        "alt" | "menu" => Some(0x12),
        "win" | "windows" | "super" | "meta" | "cmd" => Some(0x5B),
        "up" => Some(0x26),
        "down" => Some(0x28),
        "left" => Some(0x25),
        "right" => Some(0x27),
        "home" => Some(0x24),
        "end" => Some(0x23),
        "pageup" | "pgup" => Some(0x21),
        "pagedown" | "pgdn" => Some(0x22),
        "enter" | "return" => Some(0x0D),
        "tab" => Some(0x09),
        "escape" | "esc" => Some(0x1B),
        "backspace" | "back" => Some(0x08),
        "delete" | "del" => Some(0x2E),
        "insert" | "ins" => Some(0x2D),
        "space" => Some(0x20),
        "capslock" | "caps" => Some(0x14),
        "numlock" => Some(0x90),
        "scrolllock" => Some(0x91),
        "printscreen" | "prtsc" | "print" => Some(0x2C),
        "pause" | "break" => Some(0x13),
        "apps" | "contextmenu" => Some(0x5D),
        s if s.len() == 1 => {
            let ch = s.chars().next()?;
            if ch.is_ascii_alphanumeric() {
                Some(ch.to_ascii_uppercase() as u16)
            } else {
                match ch {
                    ';' | ':' => Some(0xBA),
                    '=' | '+' => Some(0xBB),
                    ',' | '<' => Some(0xBC),
                    '-' | '_' => Some(0xBD),
                    '.' | '>' => Some(0xBE),
                    '/' | '?' => Some(0xBF),
                    '`' | '~' => Some(0xC0),
                    '[' | '{' => Some(0xDB),
                    '\\' | '|' => Some(0xDC),
                    ']' | '}' => Some(0xDD),
                    '\'' | '"' => Some(0xDE),
                    _ => None,
                }
            }
        }
        _ => None,
    }
}

fn mouse_input(flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn key_input(vk: u16, key_up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: if key_up {
                    KEYEVENTF_KEYUP
                } else {
                    KEYBD_EVENT_FLAGS(0)
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SentEvent {
        Down(HeldInput),
        Up(HeldInput),
        Move(i32, i32, u32),
        Wheel(i32),
    }

    fn describe(input: &INPUT) -> SentEvent {
        unsafe {
            if input.r#type == INPUT_KEYBOARD {
                let key = input.Anonymous.ki;
                let held = if key.dwFlags.contains(KEYEVENTF_UNICODE) {
                    HeldInput::Unicode(key.wScan)
                } else {
                    HeldInput::Key(key.wVk.0)
                };
                return if key.dwFlags.contains(KEYEVENTF_KEYUP) {
                    SentEvent::Up(held)
                } else {
                    SentEvent::Down(held)
                };
            }
            let mouse = input.Anonymous.mi;
            for button in [Button::Left, Button::Right, Button::Middle] {
                if mouse.dwFlags.contains(button.flags(false)) {
                    return SentEvent::Down(HeldInput::Mouse(button));
                }
                if mouse.dwFlags.contains(button.flags(true)) {
                    return SentEvent::Up(HeldInput::Mouse(button));
                }
            }
            if mouse.dwFlags.contains(MOUSEEVENTF_WHEEL) {
                SentEvent::Wheel(mouse.mouseData as i32)
            } else {
                SentEvent::Move(mouse.dx, mouse.dy, mouse.dwFlags.0)
            }
        }
    }

    struct FakeInput {
        counts: VecDeque<usize>,
        batches: Vec<Vec<SentEvent>>,
        held: Vec<HeldInput>,
        user_held: Vec<u16>,
        point: POINT,
        geometry: (i32, i32, i32, i32),
        checks: usize,
        fail_check: Option<usize>,
        fail_sleep: Option<usize>,
        sleeps: usize,
        user_hold_on_sleep: Option<u16>,
        fail_cursor_after_send: bool,
    }

    impl Default for FakeInput {
        fn default() -> Self {
            Self {
                counts: VecDeque::new(),
                batches: Vec::new(),
                held: Vec::new(),
                user_held: Vec::new(),
                point: POINT { x: 0, y: 0 },
                geometry: (-1920, -1080, 3840, 2160),
                checks: 0,
                fail_check: None,
                fail_sleep: None,
                sleeps: 0,
                user_hold_on_sleep: None,
                fail_cursor_after_send: false,
            }
        }
    }

    impl InputSender for FakeInput {
        fn send(&mut self, inputs: &[INPUT]) -> Insertion {
            let events: Vec<_> = inputs.iter().map(describe).collect();
            let accepted = self.counts.pop_front().unwrap_or(inputs.len());
            assert!(accepted <= events.len());
            for event in &events[..accepted] {
                match event {
                    SentEvent::Down(held) => {
                        if !self.held.contains(held) {
                            self.held.push(*held);
                        }
                    }
                    SentEvent::Up(held) => self.held.retain(|current| current != held),
                    _ => {}
                }
            }
            self.batches.push(events);
            Insertion {
                accepted,
                error: if accepted == inputs.len() { 0 } else { 5 },
            }
        }

        fn is_down(&mut self, vk: u16) -> bool {
            self.user_held.contains(&vk)
        }
        fn cursor(&mut self) -> Result<POINT> {
            if self.fail_cursor_after_send && !self.batches.is_empty() {
                bail!("GetCursorPos failed");
            }
            Ok(self.point)
        }
        fn geometry(&mut self) -> (i32, i32, i32, i32) {
            self.geometry
        }
        fn checkpoint(&mut self) -> Result<()> {
            self.checks += 1;
            if self.fail_check == Some(self.checks) {
                bail!("Operation cancelled");
            }
            crate::runtime::checkpoint()
        }
        fn sleep(&mut self, _duration: Duration) -> Result<()> {
            self.sleeps += 1;
            if let Some(vk) = self.user_hold_on_sleep.take() {
                self.user_held.push(vk);
            }
            if self.fail_sleep == Some(self.sleeps) {
                bail!("Operation deadline exceeded");
            }
            self.checkpoint()
        }
    }

    #[test]
    fn every_combo_prefix_releases_only_accepted_down_events() {
        let ctrl = HeldInput::Key(VK_CONTROL.0);
        let shift = HeldInput::Key(VK_SHIFT.0);
        let c = HeldInput::Key(0x43);
        let sequence = [
            SentEvent::Down(ctrl),
            SentEvent::Down(shift),
            SentEvent::Down(c),
            SentEvent::Up(c),
            SentEvent::Up(shift),
            SentEvent::Up(ctrl),
        ];
        for prefix in 0..=sequence.len() {
            let mut sender = FakeInput {
                counts: [prefix].into(),
                ..Default::default()
            };
            let result = key_with(&mut sender, "ctrl+shift+c");
            assert_eq!(result.is_ok(), prefix == sequence.len(), "prefix {prefix}");
            assert_eq!(sender.batches[0], sequence);
            let mut owned = Vec::new();
            for event in &sequence[..prefix] {
                match event {
                    SentEvent::Down(key) => owned.push(*key),
                    SentEvent::Up(key) => owned.retain(|held| held != key),
                    _ => unreachable!(),
                }
            }
            let cleanup: Vec<_> = sender.batches[1..].iter().flatten().copied().collect();
            let expected: Vec<_> = owned.into_iter().rev().map(SentEvent::Up).collect();
            assert_eq!(cleanup, expected, "prefix {prefix}");
            assert!(sender.held.is_empty(), "prefix {prefix}");
        }
    }

    #[test]
    fn every_click_and_unicode_prefix_checks_counts_and_releases() {
        for prefix in 0..=2 {
            for text in [false, true] {
                let mut sender = FakeInput {
                    counts: [prefix].into(),
                    ..Default::default()
                };
                let result = if text {
                    type_with(&mut sender, "A")
                } else {
                    click_with(&mut sender, None, None, "left", 1)
                };
                assert_eq!(result.is_ok(), prefix == 2);
                assert_eq!(sender.batches.len(), if prefix == 1 { 2 } else { 1 });
                assert!(sender.held.is_empty());
            }
        }
    }

    #[test]
    fn cleanup_attempts_all_releases_and_reports_each_failure() {
        let mut sender = FakeInput {
            counts: [3, 0, 0, 1].into(),
            ..Default::default()
        };
        let result = key_with(&mut sender, "ctrl+shift+c").unwrap_err();
        let message = format!("{result:#}");
        assert!(message.contains("cleanup failed"));
        assert!(message.contains("Key(67)"));
        assert!(message.contains("Key(16)"));
        assert_eq!(sender.batches.len(), 4);
        assert_eq!(sender.held, [HeldInput::Key(0x10), HeldInput::Key(0x43)]);
    }

    #[test]
    fn already_held_keys_are_never_pressed_or_released() {
        for prefix in 0..=2 {
            let mut sender = FakeInput {
                user_held: vec![VK_CONTROL.0],
                counts: [prefix].into(),
                ..Default::default()
            };
            let _ = key_with(&mut sender, "ctrl+c");
            assert!(!sender.batches.iter().flatten().any(|event| matches!(
                event,
                SentEvent::Down(HeldInput::Key(0x11)) | SentEvent::Up(HeldInput::Key(0x11))
            )));
            assert!(sender.held.is_empty());
        }
        let mut sender = FakeInput {
            user_held: vec![VK_RETURN.0],
            ..Default::default()
        };
        assert!(key_with(&mut sender, "enter").is_err());
        assert!(sender.batches.is_empty());
        let mut sender = FakeInput {
            user_held: vec![VK_LBUTTON.0],
            ..Default::default()
        };
        assert!(click_with(&mut sender, Some(20), Some(10), "left", 1).is_err());
        assert!(drag_with(&mut sender, 0, 0, 20, 10, "left").is_err());
        assert!(sender.batches.is_empty());
    }

    #[test]
    fn user_holding_button_between_clicks_is_not_released() {
        let mut sender = FakeInput {
            user_hold_on_sleep: Some(VK_LBUTTON.0),
            ..Default::default()
        };
        assert!(click_with(&mut sender, None, None, "left", 2).is_err());
        assert_eq!(sender.batches.len(), 1);
        assert_eq!(sender.user_held, [VK_LBUTTON.0]);
        assert!(sender.held.is_empty());
    }

    #[test]
    fn scroll_and_absolute_move_check_the_single_event_count() {
        let mut sender = FakeInput {
            counts: [0].into(),
            ..Default::default()
        };
        assert!(scroll_with(&mut sender, None, None, -2).is_err());
        assert_eq!(sender.batches, [vec![SentEvent::Wheel(-240)]]);
        let mut sender = FakeInput {
            counts: [0].into(),
            ..Default::default()
        };
        assert!(move_with(&mut sender, 0, 0).is_err());
        assert_eq!(sender.batches.len(), 1);
    }

    #[test]
    fn drag_down_move_and_up_failures_release_only_owned_button() {
        // Start and destination equal the fake cursor, so each glide sends
        // exactly one absolute movement event.
        for (counts, expected_releases) in
            [(vec![1, 0], 0), (vec![1, 1, 0], 1), (vec![1, 1, 1, 0], 2)]
        {
            let mut sender = FakeInput {
                counts: counts.into(),
                ..Default::default()
            };
            assert!(drag_with(&mut sender, 0, 0, 0, 0, "right").is_err());
            assert!(sender.held.is_empty());
            let releases = sender
                .batches
                .iter()
                .flatten()
                .filter(|event| matches!(event, SentEvent::Up(HeldInput::Mouse(Button::Right))))
                .count();
            assert_eq!(releases, expected_releases);
        }
    }

    #[test]
    fn cancellation_and_deadline_release_accepted_drag_down() {
        let mut sender = FakeInput {
            fail_sleep: Some(2),
            ..Default::default()
        };
        let error = drag_with(&mut sender, 0, 0, 0, 0, "left").unwrap_err();
        assert!(format!("{error:#}").contains("deadline exceeded"));
        assert!(sender.held.is_empty());
        assert_eq!(
            sender.batches.last().unwrap(),
            &[SentEvent::Up(HeldInput::Mouse(Button::Left))]
        );

        let mut sender = FakeInput {
            fail_check: Some(2),
            ..Default::default()
        };
        let result = operate(&mut sender, |operation| {
            operation.send(&[Event::Down(HeldInput::Key(VK_CONTROL.0))])
        });
        assert!(result.is_err());
        assert!(sender.held.is_empty());
        assert_eq!(sender.batches.len(), 2);
    }

    #[test]
    fn unwinding_also_releases_owned_input() {
        let mut sender = FakeInput::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<()> = operate(&mut sender, |operation| {
                operation.send(&[Event::Down(HeldInput::Key(VK_SHIFT.0))])?;
                panic!("injected operation failure");
            });
        }));
        assert!(result.is_err());
        assert!(sender.held.is_empty());
        assert_eq!(
            sender.batches.last().unwrap(),
            &[SentEvent::Up(HeldInput::Key(VK_SHIFT.0))]
        );
    }

    #[test]
    fn negative_and_extreme_coordinates_normalize_without_overflow() {
        assert_eq!(normalize_axis(-1920, -1920, 3840).unwrap(), 0);
        assert_eq!(normalize_axis(1919, -1920, 3840).unwrap(), 65535);
        assert_eq!(normalize_axis(i32::MIN, i32::MAX, i32::MAX).unwrap(), 0);
        assert_eq!(normalize_axis(i32::MAX, i32::MIN, i32::MAX).unwrap(), 65535);
        for size in [i32::MIN, -1, 0, 1] {
            assert!(normalize_axis(0, 0, size).is_err());
        }
        assert_eq!(interpolate(i32::MIN, i32::MAX, 0.0), i32::MIN);
        assert_eq!(interpolate(i32::MIN, i32::MAX, 1.0), i32::MAX);
        assert_eq!(interpolate(i32::MAX, i32::MIN, 1.0), i32::MIN);
        for target in [(i32::MIN, i32::MAX), (i32::MAX, i32::MIN)] {
            let mut sender = FakeInput::default();
            assert!(move_with(&mut sender, target.0, target.1).is_ok());
            assert!(sender.batches.len() <= 121);
            for event in sender.batches.iter().flatten() {
                if let SentEvent::Move(x, y, flags) = event {
                    assert!((0..=65535).contains(x) && (0..=65535).contains(y));
                    assert_eq!(
                        *flags,
                        (MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_MOVE).0
                    );
                } else {
                    panic!("unexpected event");
                }
            }
        }
    }

    #[test]
    fn malformed_coordinates_and_wheel_overflow_do_not_mutate_input() {
        let mut sender = FakeInput::default();
        assert!(click_with(&mut sender, Some(1), None, "left", 1).is_err());
        assert!(scroll_with(&mut sender, None, Some(1), 1).is_err());
        for clicks in [i32::MIN, i32::MAX] {
            assert!(scroll_with(&mut sender, Some(0), Some(0), clicks).is_err());
        }
        assert!(sender.batches.is_empty());
    }

    #[test]
    fn preserves_button_count_unicode_and_result_shapes() {
        for (count, expected) in [(0, 1), (1, 1), (2, 2), (u32::MAX, 5)] {
            let mut sender = FakeInput::default();
            let value: serde_json::Value = serde_json::from_str(
                &click_with(&mut sender, None, None, "unknown", count).unwrap(),
            )
            .unwrap();
            assert_eq!(value["Count"], expected);
            assert_eq!(value["Status"], "Clicked");
            assert_eq!(value["Accepted"], true);
            assert_eq!(value["ApplicationActionObserved"], false);
            assert!(sender.batches.iter().flatten().all(|event| matches!(
                event,
                SentEvent::Down(HeldInput::Mouse(Button::Left))
                    | SentEvent::Up(HeldInput::Mouse(Button::Left))
            )));
        }
        let mut sender = FakeInput::default();
        let value: serde_json::Value =
            serde_json::from_str(&type_with(&mut sender, "\u{1f600}").unwrap()).unwrap();
        assert_eq!(value["Characters"], 2);
        assert_eq!(value["EventsSent"], 4);
        assert_eq!(value["Observed"], serde_json::Value::Null);
        assert!(sender.held.is_empty());
        assert_eq!(ease_in_out(0.0), 0.0);
        assert_eq!(ease_in_out(0.5), 0.5);
        assert_eq!(ease_in_out(1.0), 1.0);
    }

    #[test]
    fn observation_failure_does_not_claim_click_completed() {
        let mut sender = FakeInput {
            fail_cursor_after_send: true,
            ..Default::default()
        };
        let error = click_with(&mut sender, None, None, "left", 1).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("accepted 2 of 2"));
        assert!(message.contains("GetCursorPos failed"));
        assert!(sender.held.is_empty());
    }

    #[test]
    fn failed_mouse_cleanup_and_partial_surrogate_are_explicit() {
        let mut sender = FakeInput {
            counts: [1, 0].into(),
            ..Default::default()
        };
        let error = click_with(&mut sender, None, None, "middle", 1).unwrap_err();
        assert!(format!("{error:#}").contains("Mouse(Middle)"));
        assert_eq!(sender.held, [HeldInput::Mouse(Button::Middle)]);

        for prefix in 0..=2 {
            let mut sender = FakeInput {
                counts: [2, prefix].into(),
                ..Default::default()
            };
            let result = type_with(&mut sender, "\u{1f600}");
            assert_eq!(result.is_ok(), prefix == 2);
            assert!(sender.held.is_empty());
        }
    }

    #[tokio::test]
    async fn runtime_deadline_releases_fake_input_before_work_exits() {
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let result = crate::runtime::blocking_with_timeout(30, move || {
            let mut sender = FakeInput::default();
            let result = operate(&mut sender, |operation| {
                operation.send(&[Event::Down(HeldInput::Key(VK_CONTROL.0))])?;
                crate::runtime::sleep(Duration::from_secs(10))
            });
            finished_tx
                .send((sender.held.is_empty(), sender.batches))
                .unwrap();
            result
        })
        .await;
        assert!(result.is_err());
        let (released, batches) = tokio::time::timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(released);
        assert_eq!(
            batches.last().unwrap(),
            &[SentEvent::Up(HeldInput::Key(VK_CONTROL.0))]
        );
    }
}
