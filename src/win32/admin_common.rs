use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub const MAX_RESULTS: u32 = 1024;
pub const MAX_NATIVE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct AdminContext {
    deadline: Instant,
    cancelled: CancellationToken,
    mutation_started: Arc<AtomicBool>,
}

impl AdminContext {
    pub fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
            cancelled: CancellationToken::new(),
            mutation_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn check(&self) -> Result<()> {
        if self.cancelled.is_cancelled() {
            bail!(
                "Administration request cancelled; an in-flight native operation may still finish"
            );
        }
        if Instant::now() >= self.deadline {
            bail!(
                "Administration deadline exceeded; an in-flight native operation may still finish"
            );
        }
        Ok(())
    }

    pub fn begin_mutation(&self) -> Result<()> {
        self.check()?;
        self.mutation_started.store(true, Ordering::Release);
        Ok(())
    }

    pub fn cancel(&self) {
        self.cancelled.cancel();
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancelled.clone()
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn mutation_started(&self) -> bool {
        self.mutation_started.load(Ordering::Acquire)
    }
}

#[derive(Debug, Serialize)]
pub struct NativeError {
    pub api: String,
    pub domain: String,
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} code {} (0x{:08X}): {}",
            self.api, self.domain, self.code, self.code, self.message
        )
    }
}

impl std::error::Error for NativeError {}

pub fn win32_error(api: &str, code: u32) -> anyhow::Error {
    NativeError {
        api: api.into(),
        domain: "win32".into(),
        code,
        message: windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(code))
            .message(),
    }
    .into()
}

pub fn check_win32(api: &str, code: u32) -> Result<()> {
    if code != 0 {
        return Err(win32_error(api, code));
    }
    Ok(())
}

pub fn hresult_error(api: &str, error: windows::core::Error) -> anyhow::Error {
    NativeError {
        api: api.into(),
        domain: "hresult".into(),
        code: error.code().0 as u32,
        message: error.message(),
    }
    .into()
}

pub fn failure(error: &anyhow::Error, context: &AdminContext) -> Value {
    json!({
        "error": format!("{error:#}"),
        "native_error": error.downcast_ref::<NativeError>(),
        "mutation_may_have_completed": context.mutation_started(),
        "automatically_retried": false,
    })
}

pub fn timeout_duration(timeout_ms: Option<u64>) -> Result<Duration> {
    let ms = timeout_ms.unwrap_or(15_000);
    if !(100..=300_000).contains(&ms) {
        bail!("timeout_ms must be between 100 and 300000");
    }
    Ok(Duration::from_millis(ms))
}

pub fn result_limit(limit: Option<u32>) -> Result<usize> {
    let limit = limit.unwrap_or(128);
    if !(1..=MAX_RESULTS).contains(&limit) {
        bail!("limit must be between 1 and {MAX_RESULTS}");
    }
    Ok(limit as usize)
}

pub fn text(value: &str, field: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.encode_utf16().count() > max || value.contains('\0') {
        bail!("{field} must contain 1..={max} UTF-16 code units and no NUL");
    }
    Ok(())
}

pub fn wide(value: &str, field: &str, max: usize) -> Result<Vec<u16>> {
    text(value, field, max)?;
    Ok(super::to_wide(value))
}

pub fn absolute_path(value: &str, field: &str) -> Result<PathBuf> {
    text(value, field, 32_000)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("{field} must be a fully qualified path with no parent traversal");
    }
    Ok(path.to_owned())
}

pub fn guid(value: &str, field: &str) -> Result<windows::core::GUID> {
    text(value, field, 38)?;
    let value = value
        .strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .unwrap_or(value);
    if value.len() != 36
        || ![8, 13, 18, 23]
            .iter()
            .all(|&index| value.as_bytes()[index] == b'-')
    {
        bail!("{field} must be an exact GUID");
    }
    let parsed = uuid::Uuid::parse_str(value)?;
    Ok(windows::core::GUID::from_u128(parsed.as_u128()))
}

pub fn guid_string(value: windows::core::GUID) -> String {
    uuid::Uuid::from_u128(value.to_u128())
        .hyphenated()
        .to_string()
}

pub fn ps_quote(value: &str) -> Result<String> {
    text(value, "PowerShell argument", 32_000)?;
    Ok(format!("'{}'", value.replace('\'', "''")))
}

pub fn current_user_sid() -> Result<String> {
    Ok(crate::context::TokenContext::current()?.user_sid)
}

pub fn require_user(expected: Option<&str>) -> Result<String> {
    let current = current_user_sid()?;
    if expected != Some(current.as_str()) {
        bail!(
            "Per-user operation requires expected_user_sid matching the executing token ({current}); \
             elevation does not imply the intended desktop user"
        );
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administration_bounds_and_cancellation() {
        assert!(result_limit(Some(0)).is_err());
        assert!(result_limit(Some(1025)).is_err());
        assert!(timeout_duration(Some(99)).is_err());
        let context = AdminContext::new(Duration::from_secs(1));
        context.cancel();
        assert!(context.begin_mutation().is_err());
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_exact_identity_and_paths() {
        assert!(guid("00000000-0000-0000-0000-000000000001", "id").is_ok());
        assert!(guid("00000000000000000000000000000001", "id").is_err());
        assert!(absolute_path(r"C:relative.vhdx", "path").is_err());
        assert!(absolute_path(r"C:\images\..\system.vhdx", "path").is_err());
        assert!(wide("value\0suffix", "value", 128).is_err());
        assert_eq!(ps_quote("O'Brien $x").unwrap(), "'O''Brien $x'");
    }

    #[test]
    fn administration_windows_error_keeps_native_code() {
        let context = AdminContext::new(Duration::from_secs(1));
        let error = win32_error("Example", 5);
        let value = failure(&error, &context);
        assert_eq!(value["native_error"]["code"], 5);
        assert_eq!(value["native_error"]["domain"], "win32");
        assert_eq!(value["mutation_may_have_completed"], false);
        context.begin_mutation().unwrap();
        assert_eq!(
            failure(&error, &context)["mutation_may_have_completed"],
            true
        );
    }
}
