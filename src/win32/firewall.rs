use std::{cmp::Ordering, marker::PhantomData, rc::Rc};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use windows::{
    core::{IUnknown, Interface, BSTR, PCWSTR},
    Win32::{
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, S_FALSE,
            S_OK,
        },
        Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN},
        NetworkManagement::WindowsFirewall::*,
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED,
            },
            Ole::IEnumVARIANT,
            Registry::{
                RegGetValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
                RRF_NOEXPAND, RRF_RT_ANY, RRF_SUBKEY_WOW6464KEY,
            },
            Variant::{VARIANT, VT_DISPATCH, VT_UNKNOWN},
        },
        UI::Shell::SHLoadIndirectString,
    },
};

use super::{pretty, to_wide};

const LIST_LIMIT: usize = 100;
const MAX_ENUMERATED_RULES: usize = 32_768;
const MAX_MATCHES: usize = 128;
const MAX_REPORTED_NAME_ERRORS: usize = 8;
const MAX_TEXT_UNITS: usize = 32_767;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGISTRY_BYTES: usize = 64 * 1024;
const MATCH_MODE: &str =
    "All exact display-name matches, ordinal case-insensitive; wildcards are literal";
const MUTATION_SCOPE: &str = "Preflight snapshot, not a transaction. Concurrent policy changes are not locked. No elevation or policy override is attempted.";

struct Apartment(PhantomData<Rc<()>>);

impl Apartment {
    fn new() -> Result<Self> {
        native("CoInitializeEx(COINIT_MULTITHREADED)", unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()
        })?;
        Ok(Self(PhantomData))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn native<T>(operation: &str, result: windows::core::Result<T>) -> Result<T> {
    result.map_err(|error| {
        let hint = match error.code().0 as u32 {
            0x80070005 | 0x800702E4 => " An elevated administrator token may be required. Group Policy or MDM may also prohibit local changes. No elevation was attempted.",
            0x80010106 => " The caller must use a blocking thread that can initialize a multithreaded COM apartment; its existing apartment was not uninitialized.",
            0x80070422 | 0x800706D9 => " Windows Defender Firewall or Base Filtering Engine may be unavailable or disabled.",
            _ => "",
        };
        anyhow!(
            "{operation}: HRESULT 0x{:08X}: {}{hint}",
            error.code().0 as u32,
            error.message()
        )
    })
}

fn with_policy(operation: impl FnOnce(&INetFwPolicy2) -> Result<Value>) -> Result<String> {
    let _apartment = Apartment::new()?;
    // The closure cannot return an interface. All COM objects drop before the apartment.
    let policy: INetFwPolicy2 = native("CoCreateInstance(NetFwPolicy2)", unsafe {
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
    })?;
    let result = operation(&policy)?;
    Ok(pretty(&result))
}

fn bounded_bstr(value: BSTR, property: &str) -> Result<String> {
    if value.len() > MAX_TEXT_UNITS {
        bail!("{property} exceeds the {MAX_TEXT_UNITS} UTF-16-unit read bound");
    }
    let text = String::from_utf16(&value)
        .with_context(|| format!("{property} contains invalid UTF-16"))?;
    if text.contains('\0') {
        bail!("{property} contains an embedded NUL");
    }
    Ok(text)
}

fn compare_names(left: &str, right: &str) -> Result<Ordering> {
    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    match unsafe { CompareStringOrdinal(&left, &right, true) } {
        CSTR_LESS_THAN => Ok(Ordering::Less),
        CSTR_EQUAL => Ok(Ordering::Equal),
        CSTR_GREATER_THAN => Ok(Ordering::Greater),
        _ => Err(anyhow!(
            "CompareStringOrdinal: {}",
            windows::core::Error::from_thread()
        )),
    }
}

fn same_name(left: &str, right: &str) -> Result<bool> {
    Ok(compare_names(left, right)? == Ordering::Equal)
}

#[derive(Clone, Debug)]
struct RuleName {
    native: String,
    display: Option<String>,
    unavailable: Option<String>,
}

fn resolve_display_name(name: &str) -> Result<String> {
    if !name.starts_with('@') {
        return Ok(name.to_owned());
    }
    let source = to_wide(name);
    let mut buffer = vec![0u16; MAX_TEXT_UNITS + 1];
    native("SHLoadIndirectString(firewall display name)", unsafe {
        SHLoadIndirectString(PCWSTR(source.as_ptr()), &mut buffer, None)
    })?;
    let length = buffer
        .iter()
        .position(|&unit| unit == 0)
        .context("SHLoadIndirectString returned an unterminated display name")?;
    if length >= MAX_TEXT_UNITS {
        bail!("Localized firewall display name reached the {MAX_TEXT_UNITS}-unit buffer bound");
    }
    String::from_utf16(&buffer[..length])
        .context("Localized firewall display name contains invalid UTF-16")
}

fn rule_name(rule: &INetFwRule) -> Result<RuleName> {
    let name = bounded_bstr(native("INetFwRule::Name", unsafe { rule.Name() })?, "Name")?;
    Ok(match resolve_display_name(&name) {
        Ok(display) => RuleName {
            native: name,
            display: Some(display),
            unavailable: None,
        },
        Err(error) => RuleName {
            native: name,
            display: None,
            unavailable: Some(format!("{error:#}")),
        },
    })
}

fn matches_display(name: &RuleName, requested: &str) -> Result<bool> {
    let display = name.display.as_deref().ok_or_else(|| anyhow!(
        "Cannot guarantee all display-name matches: native rule {:?} has an unavailable display name: {}",
        name.native,
        name.unavailable.as_deref().unwrap_or("no display name returned")
    ))?;
    same_name(display, requested)
}

#[derive(Debug)]
pub(crate) struct RequiresDistinctRuleIdentity;

impl std::fmt::Display for RequiresDistinctRuleIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "An existing firewall display/native name requires a distinct rule identifier; no write was attempted",
        )
    }
}

impl std::error::Error for RequiresDistinctRuleIdentity {}

fn require_unique_create_name(existing: &RuleName, requested: &str) -> Result<()> {
    if same_name(&existing.native, requested)? || matches_display(existing, requested)? {
        return Err(RequiresDistinctRuleIdentity.into());
    }
    Ok(())
}

fn rule_from_variant(value: &VARIANT) -> Result<INetFwRule> {
    // TryFrom borrows and AddRefs the interface. VARIANT owns and releases the original.
    match value.vt() {
        VT_DISPATCH => native(
            "QueryInterface(INetFwRule)",
            native("Read firewall VT_DISPATCH", IDispatch::try_from(value))?.cast(),
        ),
        VT_UNKNOWN => native(
            "QueryInterface(INetFwRule)",
            native("Read firewall VT_UNKNOWN", IUnknown::try_from(value))?.cast(),
        ),
        other => bail!(
            "Firewall enumerator returned unexpected VARIANT type {}",
            other.0
        ),
    }
}

fn visit_rules(
    rules: &INetFwRules,
    mut visit: impl FnMut(INetFwRule, usize) -> Result<()>,
) -> Result<(usize, usize)> {
    let reported = native("INetFwRules::Count", unsafe { rules.Count() })?;
    if reported < 0 || reported as usize > MAX_ENUMERATED_RULES {
        bail!("Firewall rule count {reported} exceeds the enumeration bound {MAX_ENUMERATED_RULES}; no partial enumeration is used for mutations");
    }
    let unknown = native("INetFwRules::_NewEnum", unsafe { rules._NewEnum() })?;
    let enumerator: IEnumVARIANT = native("QueryInterface(IEnumVARIANT)", unknown.cast())?;
    let mut count = 0;
    loop {
        let mut values = [VARIANT::default()];
        let mut fetched = 0;
        let result = unsafe { enumerator.Next(&mut values, &mut fetched) };
        native("IEnumVARIANT::Next(firewall rules)", result.ok())?;
        if result == S_FALSE && fetched == 0 {
            return Ok((reported as usize, count));
        }
        if result != S_OK || fetched != 1 {
            bail!("Firewall enumerator violated the one-item contract: HRESULT 0x{:08X}, fetched {fetched}", result.0 as u32);
        }
        if count >= MAX_ENUMERATED_RULES {
            bail!("Firewall enumeration exceeded {MAX_ENUMERATED_RULES} rules; the collection may have changed");
        }
        let rule = rule_from_variant(&values[0])?;
        visit(rule, count)?;
        count += 1;
    }
}

fn direction(value: NET_FW_RULE_DIRECTION) -> String {
    match value {
        NET_FW_RULE_DIR_IN => "Inbound".to_owned(),
        NET_FW_RULE_DIR_OUT => "Outbound".to_owned(),
        other => format!("Unknown({})", other.0),
    }
}

fn action(value: NET_FW_ACTION) -> String {
    match value {
        NET_FW_ACTION_ALLOW => "Allow".to_owned(),
        NET_FW_ACTION_BLOCK => "Block".to_owned(),
        other => format!("Unknown({})", other.0),
    }
}

fn profiles(mask: i32) -> String {
    if mask == NET_FW_PROFILE2_ALL.0 {
        return "Any".to_owned();
    }
    let mut names = Vec::new();
    for (flag, name) in [(1, "Domain"), (2, "Private"), (4, "Public")] {
        if mask & flag != 0 {
            names.push(name.to_owned());
        }
    }
    if mask & !7 != 0 {
        names.push(format!("UnknownBits(0x{:08X})", mask & !7));
    }
    if names.is_empty() {
        "None".to_owned()
    } else {
        names.join(", ")
    }
}

fn protocol_name(protocol: i32) -> String {
    match protocol {
        6 => "TCP".to_owned(),
        17 => "UDP".to_owned(),
        256 => "Any".to_owned(),
        1 => "ICMPv4".to_owned(),
        58 => "ICMPv6".to_owned(),
        other => other.to_string(),
    }
}

fn snapshot(rule: &INetFwRule, name: &RuleName) -> Result<Value> {
    let protocol = native("INetFwRule::Protocol", unsafe { rule.Protocol() })?;
    let local_ports = if matches!(protocol, 6 | 17) {
        Some(bounded_bstr(
            native("INetFwRule::LocalPorts", unsafe { rule.LocalPorts() })?,
            "LocalPorts",
        )?)
    } else {
        None
    };
    let profile_mask = native("INetFwRule::Profiles", unsafe { rule.Profiles() })?;
    Ok(json!({
        "DisplayName": name.display,
        "Direction": direction(native("INetFwRule::Direction", unsafe { rule.Direction() })?),
        "Action": action(native("INetFwRule::Action", unsafe { rule.Action() })?),
        "Enabled": native("INetFwRule::Enabled", unsafe { rule.Enabled() })?.as_bool(),
        "Profile": profiles(profile_mask),
        "NativeName": name.native,
        "DisplayNameSource": if name.native.starts_with('@') { "SHLoadIndirectString(INetFwRule::Name)" } else { "INetFwRule::Name" },
        "DisplayNameUnavailable": name.unavailable,
        "Protocol": protocol_name(protocol),
        "ProtocolNumber": protocol,
        "LocalPort": local_ports,
        "LocalPortNotApplicable": !matches!(protocol, 6 | 17),
        "RemoteAddress": bounded_bstr(native("INetFwRule::RemoteAddresses", unsafe { rule.RemoteAddresses() })?, "RemoteAddresses")?,
        "Program": bounded_bstr(native("INetFwRule::ApplicationName", unsafe { rule.ApplicationName() })?, "ApplicationName")?,
        "Description": bounded_bstr(native("INetFwRule::Description", unsafe { rule.Description() })?, "Description")?,
        "ServiceName": bounded_bstr(native("INetFwRule::ServiceName", unsafe { rule.ServiceName() })?, "ServiceName")?,
        "ProfileMask": profile_mask,
        "Source": "INetFwPolicy2::Rules / INetFwRule"
    }))
}

fn add_snapshot_size(total: &mut usize, value: &Value) -> Result<()> {
    *total = total
        .checked_add(serde_json::to_vec(value)?.len())
        .context("Firewall snapshot size overflow")?;
    if *total > MAX_SNAPSHOT_BYTES {
        bail!("Firewall snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes; no partial snapshot is used for mutations");
    }
    Ok(())
}

pub fn list() -> Result<String> {
    with_policy(|policy| {
        let rules = native("INetFwPolicy2::Rules", unsafe { policy.Rules() })?;
        let mut selected: Vec<(RuleName, INetFwRule)> = Vec::new();
        let mut unavailable_names = 0;
        let mut name_errors = Vec::new();
        let (reported, enumerated) = visit_rules(&rules, |rule, _| {
            let name = rule_name(&rule)?;
            if name.display.is_none() {
                unavailable_names += 1;
                if name_errors.len() < MAX_REPORTED_NAME_ERRORS {
                    name_errors.push(json!({
                        "NativeName": name.native,
                        "Error": name.unavailable
                    }));
                }
            }
            let mut position = selected.len();
            for (index, (other, _)) in selected.iter().enumerate() {
                let ordering = match (&name.display, &other.display) {
                    (Some(left), Some(right)) => compare_names(left, right)?,
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => compare_names(&name.native, &other.native)?,
                };
                if ordering == Ordering::Less {
                    position = index;
                    break;
                }
            }
            if position < LIST_LIMIT {
                selected.insert(position, (name, rule));
                if selected.len() > LIST_LIMIT {
                    selected.pop();
                }
            }
            Ok(())
        })?;
        let mut bytes = 0;
        let mut output = Vec::with_capacity(selected.len());
        for (name, rule) in selected {
            let value = snapshot(&rule, &name)?;
            add_snapshot_size(&mut bytes, &value)?;
            output.push(value);
        }
        Ok(json!({
            "Rules": output,
            "Returned": output.len(),
            "TotalEnumerated": enumerated,
            "CountBeforeEnumeration": reported,
            "Limit": LIST_LIMIT,
            "Truncated": enumerated > LIST_LIMIT,
            "Sort": "DisplayName, ordinal case-insensitive; unavailable display names last",
            "UnavailableDisplayNames": unavailable_names,
            "DisplayNameErrors": name_errors,
            "DisplayNameErrorLimit": MAX_REPORTED_NAME_ERRORS,
            "DisplayNameErrorsTruncated": unavailable_names > name_errors.len(),
            "SnapshotAtomic": false,
            "Source": "INetFwPolicy2::Rules"
        }))
    })
}

struct Target {
    rule: INetFwRule,
    name: RuleName,
    before: Value,
}

fn find_matches(
    rules: &INetFwRules,
    requested: &str,
    include_native_name: bool,
) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let mut bytes = 0;
    visit_rules(rules, |rule, _| {
        let name = rule_name(&rule)?;
        let display_match = matches_display(&name, requested)?;
        if display_match || (include_native_name && same_name(&name.native, requested)?) {
            if targets.len() >= MAX_MATCHES {
                bail!("More than {MAX_MATCHES} firewall rules match {requested:?}; a complete bounded snapshot is unavailable");
            }
            let before = snapshot(&rule, &name)?;
            add_snapshot_size(&mut bytes, &before)?;
            targets.push(Target { rule, name, before });
        }
        Ok(())
    })?;
    Ok(targets)
}

fn validate_text(value: &str, field: &str, max_units: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    if value.contains('\0') {
        bail!("{field} must not contain NUL");
    }
    if value.encode_utf16().count() > max_units {
        bail!("{field} exceeds {max_units} UTF-16 units");
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    validate_text(name, "name", 256)?;
    if name.contains('|') {
        bail!("A firewall rule name must not contain '|'");
    }
    Ok(())
}

#[derive(Debug)]
struct ValidatedCreate {
    direction: NET_FW_RULE_DIRECTION,
    action: NET_FW_ACTION,
    protocol: i32,
    ports: Option<String>,
    addresses: Option<String>,
    program: Option<String>,
}

fn normalize_list(value: &str, field: &str) -> Result<String> {
    validate_text(value, field, MAX_TEXT_UNITS)?;
    let parts: Vec<&str> = value.split(',').map(str::trim).take(257).collect();
    if parts.len() > 256 || parts.iter().any(|part| part.is_empty()) {
        bail!("{field} must contain 1..256 nonempty comma-separated entries");
    }
    if parts.len() == 1 && (parts[0].eq_ignore_ascii_case("Any") || parts[0] == "*") {
        return Ok("*".to_owned());
    }
    if parts
        .iter()
        .any(|part| *part == "*" || part.eq_ignore_ascii_case("Any"))
    {
        bail!("{field}: Any must appear alone");
    }
    Ok(parts.join(","))
}

fn validate_ports(value: &str, protocol: i32) -> Result<Option<String>> {
    let ports = normalize_list(value, "local_port")?;
    if ports == "*" {
        return Ok(None);
    }
    if !matches!(protocol, 6 | 17) {
        bail!("local_port requires an explicit TCP or UDP protocol; protocol Any cannot restrict ports");
    }
    for part in ports.split(',') {
        // Leave documented dynamic-port keywords to the native rule validator.
        if [
            "RPC",
            "RPC-EPMap",
            "Teredo",
            "IPHTTPSIn",
            "IPHTTPSOut",
            "Ply2Disc",
            "mDNS",
            "DHCP",
        ]
        .iter()
        .any(|keyword| part.eq_ignore_ascii_case(keyword))
        {
            continue;
        }
        let parse = |text: &str| -> Result<u16> {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("Invalid local_port {part:?}: use ports 0..65535, ascending ranges, or a native dynamic-port keyword");
            }
            text.parse::<u16>()
                .with_context(|| format!("local_port {part:?} is outside 0..65535"))
        };
        if let Some((first, last)) = part.split_once('-') {
            if parse(first)? > parse(last)? {
                bail!("local_port range {part:?} is descending");
            }
        } else {
            parse(part)?;
        }
    }
    Ok(Some(ports))
}

fn validate_create(input: &crate::server::FirewallRuleCreateInput) -> Result<ValidatedCreate> {
    validate_name(&input.name)?;
    let direction = if input.direction.trim().eq_ignore_ascii_case("Inbound") {
        NET_FW_RULE_DIR_IN
    } else if input.direction.trim().eq_ignore_ascii_case("Outbound") {
        NET_FW_RULE_DIR_OUT
    } else {
        bail!("direction must be Inbound or Outbound")
    };
    let action = if input.action.trim().eq_ignore_ascii_case("Allow") {
        NET_FW_ACTION_ALLOW
    } else if input.action.trim().eq_ignore_ascii_case("Block") {
        NET_FW_ACTION_BLOCK
    } else {
        bail!("action must be Allow or Block")
    };
    let protocol_text = input.protocol.as_deref().unwrap_or("Any").trim();
    let protocol = if protocol_text.eq_ignore_ascii_case("TCP") {
        NET_FW_IP_PROTOCOL_TCP.0
    } else if protocol_text.eq_ignore_ascii_case("UDP") {
        NET_FW_IP_PROTOCOL_UDP.0
    } else if protocol_text.eq_ignore_ascii_case("Any") {
        NET_FW_IP_PROTOCOL_ANY.0
    } else {
        bail!("protocol must be TCP, UDP, or Any")
    };
    let ports = input
        .local_port
        .as_deref()
        .map(|value| validate_ports(value, protocol))
        .transpose()?
        .flatten();
    let addresses = input
        .remote_address
        .as_deref()
        .map(|value| normalize_list(value, "remote_address"))
        .transpose()?;
    let program = input
        .program
        .as_deref()
        .map(|value| {
            validate_text(value, "program", MAX_TEXT_UNITS)?;
            Ok::<_, anyhow::Error>(if value.eq_ignore_ascii_case("Any") || value == "*" {
                None
            } else {
                Some(value.to_owned())
            })
        })
        .transpose()?
        .flatten();
    Ok(ValidatedCreate {
        direction,
        action,
        protocol,
        ports,
        addresses,
        program,
    })
}

pub fn create(input: &crate::server::FirewallRuleCreateInput) -> Result<String> {
    let validated = validate_create(input)?;
    with_policy(|policy| {
        let rules = native("INetFwPolicy2::Rules", unsafe { policy.Rules() })?;
        // INetFwRules::Add can replace a matching identifier. Select the CIM
        // provider before touching a rule when a distinct identifier is needed.
        visit_rules(&rules, |rule, _| {
            require_unique_create_name(&rule_name(&rule)?, &input.name)
        })?;
        let rule: INetFwRule = native("CoCreateInstance(NetFwRule)", unsafe {
            CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
        })?;
        // Validate every property on a detached rule before the only persistent write, Add.
        unsafe {
            native(
                "INetFwRule::SetName",
                rule.SetName(&BSTR::from(input.name.as_str())),
            )?;
            native(
                "INetFwRule::SetProtocol",
                rule.SetProtocol(validated.protocol),
            )?;
            if let Some(ports) = &validated.ports {
                native(
                    "INetFwRule::SetLocalPorts",
                    rule.SetLocalPorts(&BSTR::from(ports.as_str())),
                )?;
            }
            if let Some(addresses) = &validated.addresses {
                native(
                    "INetFwRule::SetRemoteAddresses",
                    rule.SetRemoteAddresses(&BSTR::from(addresses.as_str())),
                )?;
            }
            if let Some(program) = &validated.program {
                native(
                    "INetFwRule::SetApplicationName",
                    rule.SetApplicationName(&BSTR::from(program.as_str())),
                )?;
            }
            native(
                "INetFwRule::SetDirection",
                rule.SetDirection(validated.direction),
            )?;
            native(
                "INetFwRule::SetProfiles",
                rule.SetProfiles(NET_FW_PROFILE2_ALL.0),
            )?;
            native("INetFwRule::SetAction", rule.SetAction(validated.action))?;
            native("INetFwRule::SetEnabled", rule.SetEnabled(true.into()))?;
        }
        if let Err(error) = native("INetFwRules::Add", unsafe { rules.Add(&rule) }) {
            bail!(
                "{}",
                pretty(&json!({
                    "DisplayName": input.name, "Status": "Failed",
                    "WriteAttempted": true, "WriteSucceeded": false, "Verified": false,
                    "Error": format!("{error:#}"), "Scope": MUTATION_SCOPE
                }))
            );
        }
        let readback = (|| -> Result<Value> {
            let found = find_matches(&rules, &input.name, true)?;
            if found.len() != 1 {
                bail!("Expected one rule after Add, found {}. Native COM does not expose a stable identifier to disambiguate this read-back.", found.len());
            }
            let value = found
                .into_iter()
                .next()
                .context("Missing created firewall rule")?
                .before;
            if value["Direction"] != direction(validated.direction)
                || value["Action"] != action(validated.action)
                || value["Enabled"] != true
                || value["ProtocolNumber"] != validated.protocol
                || value["ProfileMask"] != NET_FW_PROFILE2_ALL.0
            {
                bail!(
                    "Created rule read-back differs from requested properties: {}",
                    pretty(&value)
                );
            }
            Ok(value)
        })();
        match readback {
            Ok(mut value) => {
                value["Status"] = json!("Created");
                value["WriteSucceeded"] = json!(true);
                value["Verified"] = json!(true);
                value["Scope"] = json!(MUTATION_SCOPE);
                value["Defaults"] = json!({ "Enabled": true, "Profile": "Any" });
                Ok(value)
            }
            Err(error) => bail!(
                "{}",
                pretty(&json!({
                    "DisplayName": input.name, "Status": "ReadBackFailed",
                    "WriteSucceeded": true, "Verified": false,
                    "Error": format!("{error:#}"), "Scope": MUTATION_SCOPE,
                    "RollbackAttempted": false
                }))
            ),
        }
    })
}

trait ToggleTarget {
    fn before(&self) -> &Value;
    fn set_enabled(&self, enabled: bool) -> Result<()>;
    fn read_back(&self) -> Result<Value>;
}

impl ToggleTarget for Target {
    fn before(&self) -> &Value {
        &self.before
    }

    fn set_enabled(&self, enabled: bool) -> Result<()> {
        native("INetFwRule::SetEnabled", unsafe {
            self.rule.SetEnabled(enabled.into())
        })
    }

    fn read_back(&self) -> Result<Value> {
        let current_name = rule_name(&self.rule)?;
        if !same_name(&self.name.native, &current_name.native)? {
            bail!("Rule name changed during the operation");
        }
        snapshot(&self.rule, &current_name)
    }
}

fn finish_mutation(
    mut report: Value,
    results: Vec<Value>,
    errors: Vec<String>,
    success: &str,
) -> Result<Value> {
    let succeeded = results
        .iter()
        .filter(|result| result["Verified"] == true)
        .count();
    let failed = results.len() - succeeded;
    let any_write = results.iter().any(|result| {
        result["WriteSucceeded"] == true
            || result["Status"] == "Removed"
            || result["SuccessfulCallsForNativeName"]
                .as_u64()
                .is_some_and(|count| count != 0)
    });
    report["Results"] = json!(results);
    report["Succeeded"] = json!(succeeded);
    report["Failed"] = json!(failed);
    report["Errors"] = json!(errors);
    report["MatchMode"] = json!(MATCH_MODE);
    report["Scope"] = json!(MUTATION_SCOPE);
    if failed != 0 || !errors.is_empty() {
        report["Status"] = json!(if any_write {
            "PartialFailure"
        } else {
            "Failed"
        });
        bail!("{}", pretty(&report));
    }
    report["Status"] = json!(success);
    Ok(report)
}

fn toggle_targets<T: ToggleTarget>(name: &str, enabled: bool, targets: &[T]) -> Result<Value> {
    let mut results = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let write = target.set_enabled(enabled);
        let readback = target.read_back();
        let verified = write.is_ok()
            && readback
                .as_ref()
                .is_ok_and(|value| value["Enabled"] == enabled);
        let mut result = match &readback {
            Ok(value) => value.clone(),
            Err(_) => json!({
                "DisplayName": target.before()["DisplayName"],
                "NativeName": target.before()["NativeName"],
                "Enabled": null,
                "Direction": null,
                "Action": null
            }),
        };
        result["Before"] = target.before().clone();
        result["SnapshotIndex"] = json!(index);
        result["ReadBackSource"] = json!("Retained INetFwRule properties; native operations also verify collection membership before reporting overall success");
        result["WriteSucceeded"] = json!(write.is_ok());
        result["Verified"] = json!(verified);
        result["Status"] = json!(if verified {
            "Updated"
        } else if write.is_ok() {
            "ReadBackFailed"
        } else {
            "Failed"
        });
        let mut errors = Vec::new();
        if let Err(error) = write {
            errors.push(format!("{error:#}"));
        }
        match readback {
            Err(error) => errors.push(format!("Read-back: {error:#}")),
            Ok(value) if value["Enabled"] != enabled => errors.push(format!(
                "Read-back Enabled={} differs from requested {enabled}",
                value["Enabled"]
            )),
            _ => {}
        }
        result["Errors"] = json!(errors);
        results.push(result);
    }
    finish_mutation(
        json!({ "DisplayName": name, "Enabled": enabled, "Matched": targets.len() }),
        results,
        Vec::new(),
        "Updated",
    )
}

pub fn toggle(name: &str, enabled: bool) -> Result<String> {
    validate_text(name, "name", MAX_TEXT_UNITS)?;
    with_policy(|policy| {
        let rules = native("INetFwPolicy2::Rules", unsafe { policy.Rules() })?;
        let targets = find_matches(&rules, name, false)?;
        if targets.is_empty() {
            bail!("No firewall rules have the exact display name {name:?}; no changes were made");
        }
        let mut report = toggle_targets(name, enabled, &targets)?;
        let verify = (|| -> Result<()> {
            let found = find_matches(&rules, name, false)?;
            if found.len() != targets.len() {
                bail!(
                    "Matching rule count changed from {} to {} during toggle",
                    targets.len(),
                    found.len()
                );
            }
            let expected: Vec<Value> = targets
                .iter()
                .map(|target| {
                    let mut value = target.before.clone();
                    value["Enabled"] = json!(enabled);
                    value
                })
                .collect();
            let current: Vec<Value> = found.into_iter().map(|target| target.before).collect();
            correlate_remaining(&expected, &current)
                .context("Fresh collection read-back did not match the toggled rules")?;
            Ok(())
        })();
        match verify {
            Ok(()) => {
                report["ReadBackSource"] = json!("Fresh INetFwRules enumeration; all preflight rules and requested Enabled states observed");
                Ok(report)
            }
            Err(error) => {
                report["Status"] = json!("PartialFailure");
                report["Verified"] = json!(false);
                report["Error"] = json!(format!(
                    "Writes were attempted, but fresh collection verification failed: {error:#}"
                ));
                report["Succeeded"] = json!(0);
                report["Failed"] = json!(targets.len());
                if let Some(results) = report["Results"].as_array_mut() {
                    for result in results {
                        result["Verified"] = json!(false);
                        result["Status"] = json!("ReadBackFailed");
                    }
                }
                bail!("{}", pretty(&report))
            }
        }
    })
}

trait RemovalBackend {
    fn remove(&mut self, native_name: &str) -> Result<()>;
    fn remaining(&mut self, native_name: &str) -> Result<Vec<Value>>;
}

struct NativeRemoval<'a>(&'a INetFwRules);

impl RemovalBackend for NativeRemoval<'_> {
    fn remove(&mut self, native_name: &str) -> Result<()> {
        native("INetFwRules::Remove", unsafe {
            self.0.Remove(&BSTR::from(native_name))
        })
    }

    fn remaining(&mut self, native_name: &str) -> Result<Vec<Value>> {
        let mut values = Vec::new();
        let mut bytes = 0;
        visit_rules(self.0, |rule, _| {
            let name = rule_name(&rule)?;
            if same_name(&name.native, native_name)? {
                if values.len() >= MAX_MATCHES {
                    bail!("Read-back exceeds {MAX_MATCHES} matching firewall rules");
                }
                let value = snapshot(&rule, &name)?;
                add_snapshot_size(&mut bytes, &value)?;
                values.push(value);
            }
            Ok(())
        })?;
        Ok(values)
    }
}

fn correlate_remaining(before: &[Value], remaining: &[Value]) -> Result<Vec<bool>> {
    let mut present = vec![false; before.len()];
    for current in remaining {
        let index = before.iter().enumerate()
            .position(|(index, original)| !present[index] && original == current)
            .context("Read-back contains a new or changed same-name rule and cannot be correlated to the preflight snapshot.")?;
        present[index] = true;
    }
    Ok(present)
}

fn remove_group(
    backend: &mut impl RemovalBackend,
    native_name: &str,
    before: &[Value],
) -> (Vec<Value>, Vec<String>) {
    let mut remaining = Some(before.to_vec());
    let mut errors = Vec::new();
    let mut calls = 0;
    let mut successful_calls = 0;
    let mut previous_count = before.len();
    for _ in 0..before.len() {
        let removal_name = remaining
            .as_ref()
            .and_then(|values| values.first())
            .and_then(|value| value["NativeName"].as_str());
        let Some(removal_name) = removal_name else {
            errors.push(format!(
                "{native_name:?}: no native name is available for the remaining rules"
            ));
            break;
        };
        calls += 1;
        // Preserve the remaining rule's spelling even if Remove compares names case-sensitively.
        let write = backend.remove(removal_name);
        let write_failed = write.is_err();
        match write {
            Ok(()) => successful_calls += 1,
            Err(error) => errors.push(format!("{native_name:?}: {error:#}")),
        }
        match backend.remaining(native_name) {
            Ok(current) => {
                if let Err(error) = correlate_remaining(before, &current) {
                    errors.push(format!("{native_name:?}: {error:#}"));
                    remaining = None;
                    break;
                }
                let count = current.len();
                remaining = Some(current);
                if count == 0 || write_failed {
                    break;
                }
                if count >= previous_count {
                    errors.push(format!("{native_name:?}: Remove returned success without reducing the matching rule count ({count}). Rules may be controlled by policy or have changed concurrently."));
                    break;
                }
                previous_count = count;
            }
            Err(error) => {
                errors.push(format!(
                    "{native_name:?}: removal read-back unavailable: {error:#}"
                ));
                remaining = None;
                break;
            }
        }
    }
    let present = match remaining {
        Some(current) => match correlate_remaining(before, &current) {
            Ok(present) => Some(present),
            Err(error) => {
                errors.push(format!("{native_name:?}: {error:#}"));
                None
            }
        },
        None => None,
    };
    let mut results = Vec::with_capacity(before.len());
    for (index, original) in before.iter().enumerate() {
        let mut result = original.clone();
        let removed = present.as_ref().is_some_and(|flags| !flags[index]);
        result["SnapshotOccurrence"] = json!(index);
        result["Status"] = json!(if removed {
            "Removed"
        } else if present.is_some() {
            "Failed"
        } else {
            "Unverified"
        });
        result["Verified"] = json!(removed);
        result["RemovalCallsForNativeName"] = json!(calls);
        result["SuccessfulCallsForNativeName"] = json!(successful_calls);
        result["Correlation"] = json!("Snapshot attributes and multiplicity, not persistent rule IDs. Identical duplicates are indistinguishable.");
        if !removed {
            result["Error"] = json!(if present.is_some() {
                "The matching rule remains after removal attempts"
            } else {
                "Removal could not be verified or correlated"
            });
        }
        results.push(result);
    }
    (results, errors)
}

pub fn delete(name: &str) -> Result<String> {
    validate_text(name, "name", MAX_TEXT_UNITS)?;
    with_policy(|policy| {
        let rules = native("INetFwPolicy2::Rules", unsafe { policy.Rules() })?;
        let targets = find_matches(&rules, name, false)?;
        if targets.is_empty() {
            bail!("No firewall rules have the exact display name {name:?}; no changes were made");
        }
        let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
        for target in &targets {
            let mut found = None;
            for (index, (native_name, _)) in groups.iter().enumerate() {
                if same_name(native_name, &target.name.native)? {
                    found = Some(index);
                    break;
                }
            }
            if let Some(index) = found {
                groups[index].1.push(target.before.clone());
            } else {
                groups.push((target.name.native.clone(), vec![target.before.clone()]));
            }
        }
        let mut backend = NativeRemoval(&rules);
        let mut results = Vec::new();
        let mut errors = Vec::new();
        for (native_name, before) in groups {
            let (group_results, group_errors) = remove_group(&mut backend, &native_name, &before);
            results.extend(group_results);
            errors.extend(group_errors);
        }
        finish_mutation(
            json!({ "Deleted": name, "Matched": targets.len() }),
            results,
            errors,
            "Removed",
        )
    })
}

#[derive(Clone, Debug)]
enum Observation {
    Present(Value),
    Missing(String),
    Unavailable(String),
}

fn registry_error(operation: &str, code: windows::Win32::Foundation::WIN32_ERROR) -> anyhow::Error {
    anyhow!(
        "{operation}: Win32 {}: {}",
        code.0,
        std::io::Error::from_raw_os_error(code.0 as i32)
    )
}

fn decode_registry(kind: REG_VALUE_TYPE, bytes: &[u8], boolean: bool) -> Result<Value> {
    if boolean {
        if kind != REG_DWORD || bytes.len() != 4 {
            bail!(
                "Expected a four-byte REG_DWORD logging flag, received type {} and {} bytes",
                kind.0,
                bytes.len()
            );
        }
        return match u32::from_le_bytes(bytes.try_into().expect("length checked")) {
            0 => Ok(json!(false)),
            1 => Ok(json!(true)),
            other => bail!("Logging flag is {other}, not 0 or 1"),
        };
    }
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ) || !bytes.len().is_multiple_of(2) {
        bail!(
            "Expected UTF-16 REG_SZ or REG_EXPAND_SZ logging path, received type {} and {} bytes",
            kind.0,
            bytes.len()
        );
    }
    let mut units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    if units.last() != Some(&0) {
        bail!("Registry logging path is not NUL-terminated");
    }
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.contains(&0) {
        bail!("Registry logging path contains an embedded NUL");
    }
    Ok(json!(String::from_utf16(&units).context(
        "Registry logging path contains invalid UTF-16"
    )?))
}

fn observe_registry(subkey: &str, value: &str, boolean: bool) -> Observation {
    let read = || -> Result<Option<Value>> {
        let subkey_wide = to_wide(subkey);
        let value_wide = to_wide(value);
        let flags = RRF_RT_ANY | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY;
        let mut kind = REG_VALUE_TYPE::default();
        let mut length = 0;
        let initial = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_wide.as_ptr()),
                PCWSTR(value_wide.as_ptr()),
                flags,
                Some(&mut kind),
                None,
                Some(&mut length),
            )
        };
        if initial == ERROR_FILE_NOT_FOUND || initial == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        if initial != ERROR_SUCCESS {
            return Err(registry_error("RegGetValueW(size)", initial));
        }
        for _ in 0..3 {
            if length as usize > MAX_REGISTRY_BYTES {
                bail!("Logging registry value exceeds {MAX_REGISTRY_BYTES} bytes");
            }
            let mut bytes = vec![0u8; length as usize];
            let result = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(subkey_wide.as_ptr()),
                    PCWSTR(value_wide.as_ptr()),
                    flags,
                    Some(&mut kind),
                    Some(bytes.as_mut_ptr().cast()),
                    Some(&mut length),
                )
            };
            if result == ERROR_MORE_DATA {
                continue;
            }
            if result != ERROR_SUCCESS {
                return Err(registry_error("RegGetValueW(data)", result));
            }
            if length as usize > bytes.len() {
                bail!("Registry returned an oversized logging value");
            }
            return Ok(Some(decode_registry(
                kind,
                &bytes[..length as usize],
                boolean,
            )?));
        }
        bail!("Logging registry value kept changing during the bounded read")
    };
    match read() {
        Ok(Some(value)) => Observation::Present(value),
        Ok(None) => Observation::Missing(
            "Value or key is not configured at this registry location".to_owned(),
        ),
        Err(error) => Observation::Unavailable(format!("{error:#}")),
    }
}

fn observation_json(observation: &Observation, path: &str) -> Value {
    match observation {
        Observation::Present(value) => {
            json!({ "Value": value, "Source": path, "Status": "Observed" })
        }
        Observation::Missing(reason) => {
            json!({ "Value": null, "Source": path, "Status": "NotConfigured", "Unavailable": reason })
        }
        Observation::Unavailable(reason) => {
            json!({ "Value": null, "Source": path, "Status": "Unavailable", "Unavailable": reason })
        }
    }
}

fn select_logging_observation(
    local: &Observation,
    policy: &Observation,
) -> (Value, &'static str, Option<String>) {
    match policy {
        Observation::Present(value) => (value.clone(), "GroupPolicyRegistry", None),
        Observation::Unavailable(reason) => (Value::Null, "Unavailable", Some(format!("Group Policy observation failed, so no local fallback is asserted: {reason}"))),
        Observation::Missing(_) => match local {
            Observation::Present(value) => (value.clone(), "LocalRegistry", None),
            Observation::Missing(_) => (Value::Null, "Unavailable", Some("No configured value was observed. INetFwPolicy2 does not expose the effective logging default.".to_owned())),
            Observation::Unavailable(reason) => (Value::Null, "Unavailable", Some(reason.clone())),
        },
    }
}

fn logging(profile: &str, local_profile: &str) -> (Value, Value, Value, Value) {
    let local_key = format!(
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{local_profile}\Logging"
    );
    let policy_key =
        format!(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\{profile}Profile\Logging");
    let mut values = Vec::new();
    let mut detail = json!({
        "EffectivePolicyAvailable": false,
        "Source": "Read-only 64-bit HKLM registry observations",
        "Selection": "Configured Group Policy registry value, otherwise configured local value; a failed policy read does not fall back",
        "Unavailable": "INetFwPolicy2 does not expose logging properties. These observations are not the effective CIM policy; MDM, policy merging, and unconfigured defaults are not inferred. Environment variables in log paths are preserved."
    });
    for (field, registry_name, boolean) in [
        ("LogFileName", "LogFilePath", false),
        ("LogAllowed", "LogSuccessfulConnections", true),
        ("LogBlocked", "LogDroppedPackets", true),
    ] {
        let local = observe_registry(&local_key, registry_name, boolean);
        let policy = observe_registry(&policy_key, registry_name, boolean);
        let (value, source, unavailable) = select_logging_observation(&local, &policy);
        detail[field] = json!({
            "SelectedSource": source,
            "Unavailable": unavailable,
            "Local": observation_json(&local, &format!(r"HKLM\{local_key}\{registry_name}")),
            "GroupPolicy": observation_json(&policy, &format!(r"HKLM\{policy_key}\{registry_name}"))
        });
        values.push(value);
    }
    (
        values[0].clone(),
        values[1].clone(),
        values[2].clone(),
        detail,
    )
}

pub fn status() -> Result<String> {
    with_policy(|policy| {
        let active = native("INetFwPolicy2::CurrentProfileTypes", unsafe {
            policy.CurrentProfileTypes()
        })?;
        let modify_state = native("INetFwPolicy2::LocalPolicyModifyState", unsafe {
            policy.LocalPolicyModifyState()
        })?;
        let mut output = Vec::new();
        for (name, local_name, profile) in [
            ("Domain", "DomainProfile", NET_FW_PROFILE2_DOMAIN),
            ("Private", "StandardProfile", NET_FW_PROFILE2_PRIVATE),
            ("Public", "PublicProfile", NET_FW_PROFILE2_PUBLIC),
        ] {
            let (log_file, log_allowed, log_blocked, logging_details) = logging(name, local_name);
            output.push(json!({
                "Name": name,
                "Enabled": native(&format!("INetFwPolicy2::get_FirewallEnabled({name})"), unsafe { policy.get_FirewallEnabled(profile) })?.as_bool(),
                "DefaultInboundAction": action(native(&format!("INetFwPolicy2::get_DefaultInboundAction({name})"), unsafe { policy.get_DefaultInboundAction(profile) })?),
                "DefaultOutboundAction": action(native(&format!("INetFwPolicy2::get_DefaultOutboundAction({name})"), unsafe { policy.get_DefaultOutboundAction(profile) })?),
                "LogFileName": log_file,
                "LogAllowed": log_allowed,
                "LogBlocked": log_blocked,
                "Logging": logging_details,
                "Active": active & profile.0 != 0,
                "ProfileMask": profile.0,
                "BlockAllInboundTraffic": native(&format!("INetFwPolicy2::get_BlockAllInboundTraffic({name})"), unsafe { policy.get_BlockAllInboundTraffic(profile) })?.as_bool(),
                "LocalPolicyModifyState": match modify_state {
                    NET_FW_MODIFY_STATE_OK => "OK".to_owned(),
                    NET_FW_MODIFY_STATE_GP_OVERRIDE => "GroupPolicyOverride".to_owned(),
                    NET_FW_MODIFY_STATE_INBOUND_BLOCKED => "InboundBlocked".to_owned(),
                    other => format!("Unknown({})", other.0),
                },
                "Source": "INetFwPolicy2; logging fields are labeled registry observations"
            }));
        }
        Ok(json!(output))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        ffi::c_void,
        sync::{
            atomic::{AtomicU32, AtomicUsize, Ordering as AtomicOrdering},
            Arc,
        },
    };
    use windows::{
        core::{IUnknown_Vtbl, GUID, HRESULT},
        Win32::Foundation::{E_ACCESSDENIED, E_NOINTERFACE, E_POINTER},
    };

    fn input() -> crate::server::FirewallRuleCreateInput {
        crate::server::FirewallRuleCreateInput {
            name: "Example rule".to_owned(),
            direction: "Inbound".to_owned(),
            action: "Allow".to_owned(),
            protocol: None,
            local_port: None,
            remote_address: None,
            program: None,
        }
    }

    fn fake_rule(name: &str, enabled: bool, port: &str) -> Value {
        json!({ "DisplayName": name, "NativeName": name, "Enabled": enabled, "Direction": "Inbound", "Action": "Allow", "LocalPort": port })
    }

    #[test]
    fn provider_compat_collision_signal_precedes_all_writes() {
        let writes = Cell::new(0);
        let create = |names: &[RuleName]| -> Result<()> {
            for name in names {
                require_unique_create_name(name, "Example")?;
            }
            writes.set(writes.get() + 1);
            Ok(())
        };
        let ordinary = RuleName {
            native: "different native name".into(),
            display: Some("Other".into()),
            unavailable: None,
        };
        create(std::slice::from_ref(&ordinary)).unwrap();
        assert_eq!(writes.get(), 1);
        for collision in [
            RuleName {
                native: "different native name".into(),
                display: Some("eXaMpLe".into()),
                unavailable: None,
            },
            RuleName {
                native: "EXAMPLE".into(),
                display: Some("Other display name".into()),
                unavailable: None,
            },
        ] {
            let error = create(&[ordinary.clone(), collision.clone(), collision]).unwrap_err();
            assert!(error.is::<RequiresDistinctRuleIdentity>());
            assert_eq!(writes.get(), 1);
        }
        let unavailable = RuleName {
            native: "@missing,-1".into(),
            display: None,
            unavailable: Some("resource absent".into()),
        };
        let error = create(&[unavailable]).unwrap_err();
        assert!(!error.is::<RequiresDistinctRuleIdentity>());
        assert_eq!(writes.get(), 1);
        let access_denied = native::<()>(
            "INetFwRules::Add",
            Err(windows::core::Error::from_hresult(E_ACCESSDENIED)),
        )
        .unwrap_err();
        assert!(!access_denied.is::<RequiresDistinctRuleIdentity>());
    }

    #[test]
    fn matches_all_literal_display_names_including_unicode_and_not_native_ids() {
        let names = [
            RuleName {
                native: "@first,-1".into(),
                display: Some("R\u{e8}gle".into()),
                unavailable: None,
            },
            RuleName {
                native: "@second,-2".into(),
                display: Some("R\u{c8}GLE".into()),
                unavailable: None,
            },
            RuleName {
                native: "R\u{e8}gle".into(),
                display: Some("Other display".into()),
                unavailable: None,
            },
        ];
        let matching: Vec<_> = names
            .iter()
            .enumerate()
            .filter(|(_, name)| matches_display(name, "r\u{e8}gle").unwrap())
            .map(|(index, _)| index)
            .collect();
        assert_eq!(matching, vec![0, 1]);
        assert!(!matches_display(&names[0], "*").unwrap());
        assert!(!matches_display(&names[0], "@first,-1").unwrap());
        let unresolved = RuleName {
            native: "@missing,-1".into(),
            display: None,
            unavailable: Some("resource absent".into()),
        };
        assert!(matches_display(&unresolved, "Anything")
            .unwrap_err()
            .to_string()
            .contains("Cannot guarantee all"));
    }

    #[test]
    fn validates_before_com_without_broadening_port_restrictions() {
        let mut value = input();
        assert_eq!(validate_create(&value).unwrap().protocol, 256);
        value.local_port = Some("443".into());
        assert!(validate_create(&value).is_err());
        value.protocol = Some("tcp".into());
        value.local_port = Some("80, 443,1000-2000".into());
        assert_eq!(
            validate_create(&value).unwrap().ports.as_deref(),
            Some("80,443,1000-2000")
        );
        for invalid in [
            "65536", "200-100", "80,,443", "-1", "80,Any", "1-2-3", "80\0",
        ] {
            value.local_port = Some(invalid.into());
            assert!(validate_create(&value).is_err(), "{invalid:?}");
        }
        value.local_port = Some("Any".into());
        value.protocol = None;
        assert!(validate_create(&value).unwrap().ports.is_none());
        value.direction = "Both".into();
        assert!(validate_create(&value).is_err());
        value.direction = "Inbound".into();
        value.action = "Permit".into();
        assert!(validate_create(&value).is_err());
        assert!(validate_name(" ").is_err());
        assert!(validate_name("A|B").is_err());
        assert!(validate_name(&"x".repeat(257)).is_err());
        assert!(normalize_list("192.0.2.1,,192.0.2.2", "remote_address").is_err());
        assert!(normalize_list(&vec!["1"; 257].join(","), "remote_address").is_err());
    }

    struct MockToggle {
        before: Value,
        enabled: Cell<bool>,
        called: Cell<usize>,
        fail_write: bool,
        fail_read: bool,
    }

    impl ToggleTarget for MockToggle {
        fn before(&self) -> &Value {
            &self.before
        }
        fn set_enabled(&self, enabled: bool) -> Result<()> {
            self.called.set(self.called.get() + 1);
            if self.fail_write {
                return native(
                    "mock SetEnabled",
                    Err(windows::core::Error::from_hresult(E_ACCESSDENIED)),
                );
            }
            self.enabled.set(enabled);
            Ok(())
        }
        fn read_back(&self) -> Result<Value> {
            if self.fail_read {
                bail!("mock read-back unavailable");
            }
            let mut value = self.before.clone();
            value["Enabled"] = json!(self.enabled.get());
            Ok(value)
        }
    }

    #[test]
    fn toggle_attempts_every_duplicate_and_errors_after_partial_changes() {
        let targets: Vec<_> = (0..3)
            .map(|index| MockToggle {
                before: fake_rule("Duplicate", false, &index.to_string()),
                enabled: Cell::new(false),
                called: Cell::new(0),
                fail_write: index == 1,
                fail_read: false,
            })
            .collect();
        let error = toggle_targets("Duplicate", true, &targets).unwrap_err();
        let report: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(report["Status"], "PartialFailure");
        assert_eq!(report["Succeeded"], 2);
        assert_eq!(report["Failed"], 1);
        assert!(report["Results"][1]["Errors"][0]
            .as_str()
            .unwrap()
            .contains("0x80070005"));
        assert!(targets.iter().all(|target| target.called.get() == 1));
        assert!(targets[0].enabled.get() && targets[2].enabled.get());
    }

    #[test]
    fn successful_write_without_readback_is_an_error_not_success() {
        let target = MockToggle {
            before: fake_rule("Example", false, "443"),
            enabled: Cell::new(false),
            called: Cell::new(0),
            fail_write: false,
            fail_read: true,
        };
        let error = toggle_targets("Example", true, &[target]).unwrap_err();
        let report: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert_eq!(report["Status"], "PartialFailure");
        assert_eq!(report["Results"][0]["WriteSucceeded"], true);
        assert_eq!(report["Results"][0]["Verified"], false);
        assert_eq!(report["Results"][0]["Enabled"], Value::Null);
    }

    struct MockRemoval {
        rules: Vec<Value>,
        calls: usize,
        fail_at: Option<usize>,
        no_op: bool,
        fail_read: bool,
    }

    impl RemovalBackend for MockRemoval {
        fn remove(&mut self, native_name: &str) -> Result<()> {
            self.calls += 1;
            if self.fail_at == Some(self.calls) {
                bail!("mock access denied");
            }
            if !self.no_op {
                if let Some(index) = self
                    .rules
                    .iter()
                    .position(|value| value["NativeName"] == native_name)
                {
                    self.rules.remove(index);
                }
            }
            Ok(())
        }
        fn remaining(&mut self, _: &str) -> Result<Vec<Value>> {
            if self.fail_read {
                bail!("mock enumeration failed");
            }
            Ok(self.rules.clone())
        }
    }

    #[test]
    fn removes_all_duplicates_and_reports_individual_partial_outcomes() {
        let before = vec![
            fake_rule("Duplicate", true, "80"),
            fake_rule("Duplicate", true, "443"),
        ];
        let mut backend = MockRemoval {
            rules: before.clone(),
            calls: 0,
            fail_at: None,
            no_op: false,
            fail_read: false,
        };
        let (results, errors) = remove_group(&mut backend, "Duplicate", &before);
        assert_eq!(backend.calls, 2);
        assert!(results.iter().all(|value| value["Status"] == "Removed"));
        assert!(errors.is_empty());
        backend = MockRemoval {
            rules: before.clone(),
            calls: 0,
            fail_at: Some(2),
            no_op: false,
            fail_read: false,
        };
        let (results, errors) = remove_group(&mut backend, "Duplicate", &before);
        assert_eq!(results[0]["Status"], "Removed");
        assert_eq!(results[1]["Status"], "Failed");
        let error = finish_mutation(
            json!({ "Deleted": "Duplicate" }),
            results,
            errors,
            "Removed",
        )
        .unwrap_err();
        assert!(error.to_string().contains("PartialFailure"));
    }

    #[test]
    fn deletion_uses_each_remaining_native_name_spelling() {
        let before = vec![
            fake_rule("Duplicate", true, "80"),
            fake_rule("DUPLICATE", true, "443"),
        ];
        let mut backend = MockRemoval {
            rules: before.clone(),
            calls: 0,
            fail_at: None,
            no_op: false,
            fail_read: false,
        };
        let (results, errors) = remove_group(&mut backend, "Duplicate", &before);
        assert_eq!(backend.calls, 2);
        assert!(backend.rules.is_empty());
        assert!(errors.is_empty());
        assert!(results.iter().all(|value| value["Verified"] == true));
    }

    #[test]
    fn delete_requires_observed_removal_and_bounds_no_progress() {
        let before = vec![fake_rule("Example", true, "443"); 2];
        assert_eq!(
            correlate_remaining(&before, &before[..1]).unwrap(),
            vec![true, false]
        );
        assert!(correlate_remaining(&before[..1], &before).is_err());
        let mut backend = MockRemoval {
            rules: before.clone(),
            calls: 0,
            fail_at: None,
            no_op: true,
            fail_read: false,
        };
        let (results, errors) = remove_group(&mut backend, "Example", &before);
        assert_eq!(backend.calls, 1);
        assert!(results.iter().all(|value| value["Verified"] == false));
        assert!(errors[0].contains("without reducing"));
        backend.fail_read = true;
        let (results, errors) = remove_group(&mut backend, "Example", &before);
        assert!(results.iter().all(|value| value["Status"] == "Unverified"));
        assert!(errors[0].contains("read-back unavailable"));
    }

    #[test]
    fn registry_logging_does_not_invent_defaults_or_hide_failed_policy_reads() {
        let missing = Observation::Missing("not configured".into());
        let enabled = Observation::Present(json!(true));
        assert_eq!(
            select_logging_observation(&missing, &missing).0,
            Value::Null
        );
        assert_eq!(select_logging_observation(&enabled, &missing).0, true);
        assert_eq!(
            select_logging_observation(&enabled, &Observation::Unavailable("access denied".into()))
                .0,
            Value::Null
        );
        assert_eq!(
            decode_registry(REG_DWORD, &1u32.to_le_bytes(), true).unwrap(),
            true
        );
        assert!(decode_registry(REG_DWORD, &2u32.to_le_bytes(), true).is_err());
        assert!(decode_registry(REG_SZ, &[1, 0, 0], false).is_err());
        let path = r"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log";
        let bytes: Vec<u8> = to_wide(path)
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_registry(REG_EXPAND_SZ, &bytes, false).unwrap(), path);
    }

    #[repr(C)]
    struct OwnedComProbe {
        vtable: *const IUnknown_Vtbl,
        references: AtomicU32,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for OwnedComProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    unsafe extern "system" fn probe_query(
        this: *mut c_void,
        iid: *const GUID,
        output: *mut *mut c_void,
    ) -> HRESULT {
        if iid.is_null() || output.is_null() {
            return E_POINTER;
        }
        unsafe {
            *output = std::ptr::null_mut();
            if *iid != IUnknown::IID {
                return E_NOINTERFACE;
            }
            probe_add_ref(this);
            *output = this;
        }
        S_OK
    }

    unsafe extern "system" fn probe_add_ref(this: *mut c_void) -> u32 {
        unsafe { &*this.cast::<OwnedComProbe>() }
            .references
            .fetch_add(1, AtomicOrdering::Relaxed)
            + 1
    }

    unsafe extern "system" fn probe_release(this: *mut c_void) -> u32 {
        let count = unsafe { &*this.cast::<OwnedComProbe>() }
            .references
            .fetch_sub(1, AtomicOrdering::AcqRel)
            - 1;
        if count == 0 {
            unsafe { drop(Box::from_raw(this.cast::<OwnedComProbe>())) };
        }
        count
    }

    static PROBE_VTABLE: IUnknown_Vtbl = IUnknown_Vtbl {
        QueryInterface: probe_query,
        AddRef: probe_add_ref,
        Release: probe_release,
    };

    #[test]
    fn variant_bstr_and_interface_ownership_survive_borrowed_extraction() {
        let value = VARIANT::from(BSTR::from("Owned UTF-16 text"));
        let copied = BSTR::try_from(&value).unwrap();
        drop(value);
        assert_eq!(String::from_utf16(&copied).unwrap(), "Owned UTF-16 text");
        let drops = Arc::new(AtomicUsize::new(0));
        let raw = Box::into_raw(Box::new(OwnedComProbe {
            vtable: &PROBE_VTABLE,
            references: AtomicU32::new(1),
            drops: drops.clone(),
        }));
        let probe = unsafe { IUnknown::from_raw(raw.cast()) };
        let value = VARIANT::from(probe.clone());
        let extracted = IUnknown::try_from(&value).unwrap();
        assert!(rule_from_variant(&value).is_err());
        drop(probe);
        drop(value);
        assert_eq!(drops.load(AtomicOrdering::SeqCst), 0);
        drop(extracted);
        assert_eq!(drops.load(AtomicOrdering::SeqCst), 1);
        assert!(rule_from_variant(&VARIANT::from("not a rule")).is_err());
    }

    #[test]
    fn native_firewall_read_only_probe_reports_unavailable_reasons() {
        std::thread::spawn(|| {
            for (operation, result) in [("list", list()), ("status", status())] {
                match result {
                    Ok(text) => {
                        let value: Value = serde_json::from_str(&text).unwrap();
                        if operation == "list" {
                            assert!(value["Rules"].is_array());
                            assert!(value["Rules"].as_array().unwrap().len() <= LIST_LIMIT);
                        } else {
                            let profiles = value.as_array().unwrap();
                            assert_eq!(profiles.len(), 3);
                            assert_eq!(profiles[0]["Name"], "Domain");
                            assert_eq!(profiles[1]["Name"], "Private");
                            assert_eq!(profiles[2]["Name"], "Public");
                            assert!(profiles
                                .iter()
                                .all(|profile| profile["Enabled"].is_boolean()));
                        }
                        eprintln!("Native firewall {operation}: available");
                    }
                    Err(error) => {
                        assert!(!error.to_string().is_empty());
                        eprintln!("Native firewall {operation}: unavailable: {error:#}");
                    }
                }
            }
        })
        .join()
        .expect("read-only firewall probe thread panicked");
    }
}
