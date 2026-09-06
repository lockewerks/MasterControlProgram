use super::admin_common::*;
use anyhow::{ensure, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use windows::core::{w, PWSTR};
use windows::Win32::Foundation::{GlobalFree, ERROR_FILE_NOT_FOUND, HGLOBAL};
use windows::Win32::Networking::{WinHttp::*, WinInet::*};
use windows::Win32::System::Registry::*;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyScope {
    WinhttpMachine,
    WininetCurrentUser,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyInput {
    pub scope: ProxyScope,
    /// Required for current-user changes; obtain the SID from a read call.
    pub expected_user_sid: Option<String>,
    /// Omit all setting fields to query. Only provided settings change.
    pub enabled: Option<bool>,
    /// WinHTTP/WinINet proxy format, for example proxy.example:8080. No credentials.
    pub proxy_server: Option<String>,
    /// Semicolon-separated bypass entries. Empty clears only this setting.
    pub bypass: Option<String>,
    /// WinINet only. Empty disables the automatic configuration URL.
    pub pac_url: Option<String>,
    /// WinINet only. Leaves the static proxy and PAC settings unchanged.
    pub auto_detect: Option<bool>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

impl ProxyInput {
    pub fn mutates(&self) -> bool {
        self.enabled.is_some()
            || self.proxy_server.is_some()
            || self.bypass.is_some()
            || self.pac_url.is_some()
            || self.auto_detect.is_some()
    }

    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("proxy_server", &self.proxy_server),
            ("bypass", &self.bypass),
            ("pac_url", &self.pac_url),
        ] {
            if let Some(value) = value {
                ensure!(
                    value.len() <= 8192 && !value.contains(['\0', '\r', '\n']),
                    "{field} must be at most 8192 bytes with no NUL or line breaks"
                );
            }
        }
        if let Some(proxy) = &self.proxy_server {
            ensure!(
                !proxy.contains('@'),
                "Proxy credentials are not accepted in proxy_server"
            );
        }
        if let Some(pac) = &self.pac_url {
            ensure!(
                pac.is_empty()
                    || ((pac.starts_with("http://") || pac.starts_with("https://"))
                        && !pac.contains('@')),
                "pac_url must be an HTTP(S) URL without credentials, or empty"
            );
        }
        if matches!(self.scope, ProxyScope::WinhttpMachine) {
            ensure!(self.pac_url.is_none() && self.auto_detect.is_none(), "Machine WinHTTP default configuration supports a static proxy, not PAC or auto-detection");
            ensure!(
                self.expected_user_sid.is_none(),
                "Machine WinHTTP settings do not target a user SID"
            );
        }
        Ok(())
    }
}

struct GlobalString(PWSTR);

impl Drop for GlobalString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            if let Err(error) = unsafe { GlobalFree(Some(HGLOBAL(self.0 .0.cast()))) } {
                tracing::warn!(%error, "Freeing proxy string failed");
            }
        }
    }
}

#[derive(Serialize)]
struct ProxySettings {
    flags: u32,
    enabled: bool,
    proxy_server: String,
    bypass: String,
    pac_url: Option<String>,
    auto_detect: Option<bool>,
}

fn winhttp_get() -> Result<ProxySettings> {
    unsafe {
        let mut settings = WINHTTP_PROXY_INFO::default();
        WinHttpGetDefaultProxyConfiguration(&mut settings)
            .map_err(|error| hresult_error("WinHttpGetDefaultProxyConfiguration", error))?;
        let proxy = GlobalString(settings.lpszProxy);
        let bypass = GlobalString(settings.lpszProxyBypass);
        Ok(ProxySettings {
            flags: settings.dwAccessType.0,
            enabled: settings.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            proxy_server: super::from_wide(proxy.0 .0),
            bypass: super::from_wide(bypass.0 .0),
            pac_url: None,
            auto_detect: None,
        })
    }
}

fn winhttp_set(input: &ProxyInput, before: &ProxySettings, context: &AdminContext) -> Result<()> {
    let enabled = input.enabled.unwrap_or(before.enabled);
    let proxy = input
        .proxy_server
        .as_deref()
        .unwrap_or(&before.proxy_server);
    let bypass = input.bypass.as_deref().unwrap_or(&before.bypass);
    ensure!(
        !enabled || !proxy.is_empty(),
        "An enabled static proxy requires proxy_server"
    );
    let mut proxy = super::to_wide(proxy);
    let mut bypass = super::to_wide(bypass);
    let mut settings = WINHTTP_PROXY_INFO {
        dwAccessType: if enabled {
            WINHTTP_ACCESS_TYPE_NAMED_PROXY
        } else {
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
        },
        lpszProxy: if enabled {
            PWSTR(proxy.as_mut_ptr())
        } else {
            PWSTR::null()
        },
        lpszProxyBypass: if enabled {
            PWSTR(bypass.as_mut_ptr())
        } else {
            PWSTR::null()
        },
    };
    context.begin_mutation()?;
    unsafe {
        WinHttpSetDefaultProxyConfiguration(&mut settings)
            .map_err(|error| hresult_error("WinHttpSetDefaultProxyConfiguration", error))
    }
}

fn user_scoped_policy() -> Result<bool> {
    unsafe {
        let mut setting: u32 = 1;
        let mut size = std::mem::size_of_val(&setting) as u32;
        let code = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
            w!("ProxySettingsPerUser"),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            None,
            Some((&mut setting as *mut u32).cast()),
            Some(&mut size),
        );
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(true);
        }
        check_win32("RegGetValueW (ProxySettingsPerUser policy)", code.0)?;
        ensure!(size == 4, "Unexpected ProxySettingsPerUser registry data");
        Ok(setting != 0)
    }
}

fn wininet_get() -> Result<ProxySettings> {
    unsafe {
        let mut options = [
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_FLAGS,
                ..Default::default()
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                ..Default::default()
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                ..Default::default()
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
                ..Default::default()
            },
        ];
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            dwOptionCount: options.len() as u32,
            pOptions: options.as_mut_ptr(),
            ..Default::default()
        };
        let mut size = list.dwSize;
        let result = InternetQueryOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some((&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast()),
            &mut size,
        );
        let proxy = GlobalString(options[1].Value.pszValue);
        let bypass = GlobalString(options[2].Value.pszValue);
        let pac = GlobalString(options[3].Value.pszValue);
        result.map_err(|error| hresult_error("InternetQueryOptionW (LAN proxy)", error))?;
        let flags = options[0].Value.dwValue;
        Ok(ProxySettings {
            flags,
            enabled: flags & PROXY_TYPE_PROXY != 0,
            proxy_server: super::from_wide(proxy.0 .0),
            bypass: super::from_wide(bypass.0 .0),
            pac_url: Some(super::from_wide(pac.0 .0)),
            auto_detect: Some(flags & PROXY_TYPE_AUTO_DETECT != 0),
        })
    }
}

fn changed_flags(input: &ProxyInput, previous: u32) -> u32 {
    let mut flags = previous;
    for (flag, enabled) in [
        (PROXY_TYPE_PROXY, input.enabled),
        (PROXY_TYPE_AUTO_DETECT, input.auto_detect),
        (
            PROXY_TYPE_AUTO_PROXY_URL,
            input.pac_url.as_ref().map(|url| !url.is_empty()),
        ),
    ] {
        if let Some(enabled) = enabled {
            if enabled {
                flags |= flag;
            } else {
                flags &= !flag;
            }
        }
    }
    flags
}

fn wininet_set(input: &ProxyInput, before: &ProxySettings, context: &AdminContext) -> Result<()> {
    let proxy = input
        .proxy_server
        .as_deref()
        .unwrap_or(&before.proxy_server);
    let flags = changed_flags(input, before.flags);
    ensure!(
        flags & PROXY_TYPE_PROXY == 0 || !proxy.is_empty(),
        "An enabled static proxy requires proxy_server"
    );
    let mut options = Vec::new();
    if flags != before.flags {
        options.push(INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
        });
    }
    // The owned strings outlive the single native call; untouched options are not sent.
    let mut strings: Vec<(INTERNET_PER_CONN, Vec<u16>)> = [
        (INTERNET_PER_CONN_PROXY_SERVER, &input.proxy_server),
        (INTERNET_PER_CONN_PROXY_BYPASS, &input.bypass),
        (INTERNET_PER_CONN_AUTOCONFIG_URL, &input.pac_url),
    ]
    .into_iter()
    .filter_map(|(option, value)| value.as_ref().map(|value| (option, super::to_wide(value))))
    .collect();
    for (option, value) in &mut strings {
        options.push(INTERNET_PER_CONN_OPTIONW {
            dwOption: *option,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: PWSTR(value.as_mut_ptr()),
            },
        });
    }
    if options.is_empty() {
        return Ok(());
    }
    let list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        dwOptionCount: options.len() as u32,
        pOptions: options.as_mut_ptr(),
        ..Default::default()
    };
    ensure!(
        user_scoped_policy()?,
        "Proxy policy changed to machine-wide; no user-scoped mutation was attempted"
    );
    context.begin_mutation()?;
    unsafe {
        InternetSetOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some((&list as *const INTERNET_PER_CONN_OPTION_LISTW).cast()),
            list.dwSize,
        )
        .map_err(|error| hresult_error("InternetSetOptionW (LAN proxy)", error))?;
        InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0).map_err(|error| {
            hresult_error(
                "InternetSetOptionW (notify settings changed after applying proxy)",
                error,
            )
        })?;
        InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0).map_err(|error| {
            hresult_error("InternetSetOptionW (refresh after applying proxy)", error)
        })?;
    }
    Ok(())
}

pub fn configure(input: &ProxyInput, context: &AdminContext) -> Result<Value> {
    input.validate()?;
    context.check()?;
    let current_user = match input.scope {
        ProxyScope::WinhttpMachine => None,
        ProxyScope::WininetCurrentUser if input.mutates() => {
            Some(require_user(input.expected_user_sid.as_deref())?)
        }
        ProxyScope::WininetCurrentUser => Some(current_user_sid()?),
    };
    let user_scope = match input.scope {
        ProxyScope::WinhttpMachine => false,
        ProxyScope::WininetCurrentUser => user_scoped_policy()?,
    };
    if input.mutates() && matches!(input.scope, ProxyScope::WininetCurrentUser) {
        ensure!(user_scope, "WinINet proxy is machine-wide by policy; this tool will not modify machine settings through a current-user scope");
    }
    let before = match input.scope {
        ProxyScope::WinhttpMachine => winhttp_get()?,
        ProxyScope::WininetCurrentUser => wininet_get()?,
    };
    if !input.mutates() {
        return Ok(json!({
            "scope": input.scope, "user_sid": current_user, "settings": before,
            "wininet_policy_per_user": user_scope,
            "coverage": if matches!(input.scope, ProxyScope::WinhttpMachine) {
                "Legacy static WinHTTP defaults; automatic/per-session proxy settings are not changed."
            } else { "WinINet LAN settings for the executing token." },
        }));
    }
    match input.scope {
        ProxyScope::WinhttpMachine => winhttp_set(input, &before, context)?,
        ProxyScope::WininetCurrentUser => wininet_set(input, &before, context)?,
    }
    let after = match input.scope {
        ProxyScope::WinhttpMachine => winhttp_get()?,
        ProxyScope::WininetCurrentUser => wininet_get()?,
    };
    Ok(json!({
        "scope": input.scope, "user_sid": current_user, "before": before, "after": after,
        "accepted": true, "windows_code": 0, "reboot_required": false,
        "application_refresh_may_be_required": true,
        "note": "Applications may cache settings or use their own proxy configuration.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn query() -> ProxyInput {
        ProxyInput {
            scope: ProxyScope::WininetCurrentUser,
            expected_user_sid: None,
            enabled: None,
            proxy_server: None,
            bypass: None,
            pac_url: None,
            auto_detect: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn administration_proxy_changes_preserve_unrelated_flags() {
        let mut input = query();
        input.enabled = Some(false);
        let old = PROXY_TYPE_DIRECT
            | PROXY_TYPE_PROXY
            | PROXY_TYPE_AUTO_PROXY_URL
            | PROXY_TYPE_AUTO_DETECT
            | 0x1000;
        assert_eq!(changed_flags(&input, old), old & !PROXY_TYPE_PROXY);
        input.pac_url = Some(String::new());
        assert_eq!(
            changed_flags(&input, old),
            old & !(PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL)
        );
    }

    #[test]
    fn administration_proxy_rejects_mixed_scope_and_credentials() {
        let mut input = query();
        input.scope = ProxyScope::WinhttpMachine;
        input.auto_detect = Some(true);
        assert!(input.validate().is_err());
        input.auto_detect = None;
        input.proxy_server = Some("user:password@proxy:8080".into());
        assert!(input.validate().is_err());
    }

    #[test]
    fn administration_proxy_read_only_inventory() {
        let input = query();
        let context = AdminContext::new(Duration::from_secs(10));
        let output = configure(&input, &context).unwrap();
        assert!(output["settings"]["enabled"].is_boolean());
        assert!(output["user_sid"].as_str().unwrap().starts_with("S-1-"));
        assert!(!context.mutation_started());
    }
}
