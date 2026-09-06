use super::admin_common::*;
use super::network_admin::{resolve, InterfaceTarget};
use anyhow::{ensure, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_INVALID_STATE, HANDLE};
use windows::Win32::NetworkManagement::WiFi::*;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WifiQuery {
    pub target: Option<InterfaceTarget>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfileScope {
    CurrentUser,
    AllUsers,
    GroupPolicy,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WifiAction {
    Connect {
        /// Exact profile_id from network_wifi_profiles, never an SSID search.
        profile_id: String,
        profile_scope: ProfileScope,
    },
    Disconnect,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WifiInput {
    pub target: InterfaceTarget,
    #[serde(flatten)]
    pub operation: WifiAction,
    /// Required when connecting a current_user profile. Read profiles to obtain it.
    pub expected_user_sid: Option<String>,
    /// How long to observe state after acceptance, 0..120000. Default 5000.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub wait_ms: Option<u64>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

struct WlanClient(HANDLE);

impl WlanClient {
    fn open() -> Result<Self> {
        let mut version = 0;
        let mut handle = HANDLE::default();
        unsafe {
            check_win32(
                "WlanOpenHandle (requires WLAN AutoConfig and a supported Wi-Fi adapter)",
                WlanOpenHandle(2, None, &mut version, &mut handle),
            )?;
        }
        Ok(Self(handle))
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        let code = unsafe { WlanCloseHandle(self.0, None) };
        if code != 0 {
            tracing::warn!(code, "Closing WLAN client handle failed");
        }
    }
}

struct WlanAllocation(*mut std::ffi::c_void);

impl Drop for WlanAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WlanFreeMemory(self.0) };
        }
    }
}

#[derive(Serialize)]
struct Profile {
    profile_id: String,
    scope: ProfileScope,
    flags: u32,
}

fn scope(flags: u32) -> ProfileScope {
    if flags & WLAN_PROFILE_GROUP_POLICY != 0 {
        ProfileScope::GroupPolicy
    } else if flags & WLAN_PROFILE_USER != 0 {
        ProfileScope::CurrentUser
    } else {
        ProfileScope::AllUsers
    }
}

fn profiles(client: &WlanClient, id: &GUID, limit: usize) -> Result<(Vec<Profile>, bool)> {
    unsafe {
        let mut list = std::ptr::null_mut();
        check_win32(
            "WlanGetProfileList",
            WlanGetProfileList(client.0, id, None, &mut list),
        )?;
        let _memory = WlanAllocation(list.cast());
        ensure!(!list.is_null(), "WlanGetProfileList returned no list");
        let count = (*list).dwNumberOfItems as usize;
        ensure!(
            count <= MAX_NATIVE_BYTES / std::mem::size_of::<WLAN_PROFILE_INFO>(),
            "WLAN profile list exceeds bound"
        );
        let entries = std::slice::from_raw_parts((*list).ProfileInfo.as_ptr(), count.min(limit));
        Ok((
            entries
                .iter()
                .map(|entry| Profile {
                    profile_id: super::wchar_to_string(&entry.strProfileName),
                    scope: scope(entry.dwFlags),
                    flags: entry.dwFlags,
                })
                .collect(),
            count > limit,
        ))
    }
}

fn connection(client: &WlanClient, id: &GUID) -> Result<Value> {
    unsafe {
        let mut data = std::ptr::null_mut();
        let mut size = 0;
        let code = WlanQueryInterface(
            client.0,
            id,
            wlan_intf_opcode_current_connection,
            None,
            &mut size,
            &mut data,
            None,
        );
        let _memory = WlanAllocation(data);
        if code == ERROR_INVALID_STATE.0 {
            return Ok(json!({"connected": false, "windows_code": code}));
        }
        check_win32(
            "WlanQueryInterface (Windows location permission or WLAN service may be required)",
            code,
        )?;
        ensure!(
            !data.is_null() && size as usize >= std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>(),
            "Invalid WLAN connection result"
        );
        let info = &*data.cast::<WLAN_CONNECTION_ATTRIBUTES>();
        let association = &info.wlanAssociationAttributes;
        let ssid_len = association.dot11Ssid.uSSIDLength as usize;
        ensure!(
            ssid_len <= association.dot11Ssid.ucSSID.len(),
            "Invalid native SSID length"
        );
        let ssid = &association.dot11Ssid.ucSSID[..ssid_len];
        Ok(json!({
            "connected": info.isState == wlan_interface_state_connected,
            "state": info.isState.0,
            "profile_id": super::wchar_to_string(&info.strProfileName),
            "ssid_utf8": std::str::from_utf8(ssid).ok(),
            "ssid_hex": ssid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "signal_quality": association.wlanSignalQuality,
            "receive_rate": association.ulRxRate,
            "transmit_rate": association.ulTxRate,
            "security_enabled": info.wlanSecurityAttributes.bSecurityEnabled.as_bool(),
            "authentication": info.wlanSecurityAttributes.dot11AuthAlgorithm.0,
            "cipher": info.wlanSecurityAttributes.dot11CipherAlgorithm.0,
        }))
    }
}

pub fn inventory(input: &WifiQuery, context: &AdminContext) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    context.check()?;
    let filter = input.target.as_ref().map(resolve).transpose()?;
    let client = WlanClient::open()?;
    unsafe {
        let mut list = std::ptr::null_mut();
        check_win32(
            "WlanEnumInterfaces",
            WlanEnumInterfaces(client.0, None, &mut list),
        )?;
        let _memory = WlanAllocation(list.cast());
        ensure!(!list.is_null(), "WlanEnumInterfaces returned no list");
        let count = (*list).dwNumberOfItems as usize;
        ensure!(
            count <= MAX_NATIVE_BYTES / std::mem::size_of::<WLAN_INTERFACE_INFO>(),
            "WLAN interface list exceeds bound"
        );
        let entries = std::slice::from_raw_parts((*list).InterfaceInfo.as_ptr(), count);
        let mut output = Vec::new();
        let mut matched = 0;
        let mut profile_count = 0;
        for entry in entries {
            context.check()?;
            if filter
                .as_ref()
                .is_some_and(|filter| filter.guid != entry.InterfaceGuid)
            {
                continue;
            }
            matched += 1;
            if output.len() == limit {
                continue;
            }
            let (profiles, truncated) =
                profiles(&client, &entry.InterfaceGuid, limit - profile_count)?;
            profile_count += profiles.len();
            let observed = match connection(&client, &entry.InterfaceGuid) {
                Ok(value) => value,
                Err(error) => failure(&error, context),
            };
            output.push(json!({
                "guid": guid_string(entry.InterfaceGuid),
                "description": super::wchar_to_string(&entry.strInterfaceDescription),
                "state": entry.isState.0,
                "profiles": profiles,
                "profiles_truncated": truncated,
                "connection": observed,
            }));
        }
        ensure!(
            filter.is_none() || matched == 1,
            "Requested interface is not a WLAN interface"
        );
        Ok(json!({
            "interfaces": output, "truncated": matched > limit, "user_sid": current_user_sid()?,
            "profile_result_limit": limit,
            "credentials_included": false,
            "available": count > 0,
            "prerequisite": if count == 0 { Some("An installed WLAN adapter and WLAN AutoConfig service") } else { None },
        }))
    }
}

fn matched_profile<'a>(
    profiles: &'a [Profile],
    id: &str,
    expected_scope: ProfileScope,
) -> Result<&'a Profile> {
    text(id, "profile_id", 255)?;
    let matching: Vec<_> = profiles
        .iter()
        .filter(|profile| profile.profile_id == id)
        .collect();
    ensure!(
        matching.len() == 1,
        "Exactly one profile must match the case-sensitive profile_id"
    );
    ensure!(
        matching[0].scope == expected_scope,
        "Profile scope changed; no connection was requested"
    );
    Ok(matching[0])
}

pub fn change(input: &WifiInput, context: &AdminContext) -> Result<Value> {
    let wait_ms = input.wait_ms.unwrap_or(5000);
    ensure!(wait_ms <= 120_000, "wait_ms must be 0..=120000");
    context.check()?;
    if input.expected_user_sid.is_some() {
        require_user(input.expected_user_sid.as_deref())?;
    }
    let target = resolve(&input.target)?;
    let client = WlanClient::open()?;
    let (available, truncated) = profiles(&client, &target.guid, MAX_RESULTS as usize)?;
    ensure!(
        !truncated,
        "Too many profiles to resolve this target safely"
    );
    let profile_wide = match &input.operation {
        WifiAction::Connect {
            profile_id,
            profile_scope,
        } => {
            matched_profile(&available, profile_id, *profile_scope)?;
            if *profile_scope == ProfileScope::CurrentUser {
                require_user(input.expected_user_sid.as_deref())?;
            }
            Some(wide(profile_id, "profile_id", 255)?)
        }
        WifiAction::Disconnect => None,
    };
    let before = connection(&client, &target.guid)?;
    context.begin_mutation()?;
    unsafe {
        if let Some(profile) = &profile_wide {
            let params = WLAN_CONNECTION_PARAMETERS {
                wlanConnectionMode: wlan_connection_mode_profile,
                strProfile: PCWSTR(profile.as_ptr()),
                dot11BssType: dot11_BSS_type_infrastructure,
                ..Default::default()
            };
            check_win32(
                "WlanConnect",
                WlanConnect(client.0, &target.guid, &params, None),
            )?;
        } else {
            check_win32(
                "WlanDisconnect",
                WlanDisconnect(client.0, &target.guid, None),
            )?;
        }
    }
    let until = Instant::now() + Duration::from_millis(wait_ms);
    loop {
        context.check()?;
        let after = connection(&client, &target.guid)?;
        let satisfied = match &input.operation {
            WifiAction::Connect { profile_id, .. } => {
                after["connected"] == true
                    && after["profile_id"].as_str() == Some(profile_id.as_str())
            }
            WifiAction::Disconnect => after["connected"] == false,
        };
        if satisfied || Instant::now() >= until {
            return Ok(json!({
                "interface_guid": guid_string(target.guid), "accepted": true, "windows_code": 0,
                "before": before, "after": after, "postcondition_satisfied": satisfied,
                "observation": if satisfied { "satisfied" } else { "timed_out" },
                "reboot_required": false, "credentials_included": false,
                "internet_connectivity_verified": false,
            }));
        }
        std::thread::sleep(Duration::from_millis(100).min(context.remaining()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administration_wifi_exact_profile_and_scope() {
        let profiles = [Profile {
            profile_id: "Office".into(),
            scope: ProfileScope::AllUsers,
            flags: 0,
        }];
        assert!(matched_profile(&profiles, "office", ProfileScope::AllUsers).is_err());
        assert!(matched_profile(&profiles, "Office", ProfileScope::CurrentUser).is_err());
        assert!(matched_profile(&profiles, "Office", ProfileScope::AllUsers).is_ok());
        assert_eq!(scope(WLAN_PROFILE_USER), ProfileScope::CurrentUser);
        assert_eq!(scope(WLAN_PROFILE_GROUP_POLICY), ProfileScope::GroupPolicy);
    }

    #[test]
    fn administration_wifi_coercion_and_no_credentials_schema() {
        let value = json!({
            "target": {"guid": "00000000-0000-0000-0000-000000000001"},
            "action": "connect", "profile_id": "Office", "profile_scope": "all_users",
            "wait_ms": "0", "timeout_ms": "1000"
        });
        let input: WifiInput = serde_json::from_value(value).unwrap();
        assert_eq!(input.wait_ms, Some(0));
        let schema = serde_json::to_string(&schemars::schema_for!(WifiInput)).unwrap();
        assert!(!schema.contains("\"password\""));
    }
}
