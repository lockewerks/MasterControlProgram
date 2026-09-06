use super::admin_common::*;
use anyhow::{bail, ensure, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::core::{GUID, PWSTR};
use windows::Win32::NetworkManagement::{IpHelper::*, Ndis::*};
use windows::Win32::Networking::WinSock::*;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InterfaceTarget {
    /// Exact interface GUID returned by network_interfaces. Names are not identities.
    pub guid: String,
    /// Optional consistency guard against an interface index being reused.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub index: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub luid: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn native(self) -> ADDRESS_FAMILY {
        match self {
            Self::Ipv4 => AF_INET,
            Self::Ipv6 => AF_INET6,
        }
    }

    fn validate(self, ip: IpAddr) -> Result<()> {
        ensure!(
            matches!(
                (self, ip),
                (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
            ),
            "Address family does not match the requested networking stack"
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkQuery {
    pub target: Option<InterfaceTarget>,
    pub family: Option<AddressFamily>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub limit: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntryAction {
    Add,
    Update,
    Remove,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressInput {
    pub target: InterfaceTarget,
    pub action: EntryAction,
    pub family: AddressFamily,
    pub address: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub prefix_length: u8,
    /// Required for update/remove: compare with the existing prefix before changing it.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub expected_prefix_length: Option<u8>,
    /// Omitted updates preserve this setting. Remove must omit it.
    pub skip_as_source: Option<bool>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteInput {
    pub target: InterfaceTarget,
    pub action: EntryAction,
    pub family: AddressFamily,
    /// Network address with host bits zero. Use 0.0.0.0 or :: and prefix 0 for a gateway.
    pub destination: String,
    #[serde(deserialize_with = "crate::coerce::num")]
    pub prefix_length: u8,
    /// Use 0.0.0.0 or :: for an on-link route.
    pub next_hop: String,
    /// Required for add/update, omitted for remove. Excludes the interface metric.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub metric: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsInput {
    pub target: InterfaceTarget,
    pub family: AddressFamily,
    /// Omit to query. Replaces only this interface/family's static DNS server list.
    /// An empty list clears the static override, allowing automatic DNS.
    pub servers: Option<Vec<String>>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterStateInput {
    pub target: InterfaceTarget,
    /// IP Helper administrative state. This does not disable the PnP device.
    pub enabled: bool,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStore {
    Active,
    Persistent,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DhcpInput {
    pub target: InterfaceTarget,
    pub family: AddressFamily,
    pub store: PolicyStore,
    /// Omit to read. DHCP is provider-managed; manual address tools do not toggle it.
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u64>,
}

pub fn dhcp_script(input: &DhcpInput, context: &AdminContext) -> Result<String> {
    context.check()?;
    let target = resolve(&input.target)?;
    let family = match input.family {
        AddressFamily::Ipv4 => "IPv4",
        AddressFamily::Ipv6 => "IPv6",
    };
    let store = match input.store {
        PolicyStore::Active => "ActiveStore",
        PolicyStore::Persistent => "PersistentStore",
    };
    let id = ps_quote(&guid_string(target.guid))?;
    let update = input
        .enabled
        .map(|enabled| {
            format!(
                "Set-NetIPInterface -InputObject $iface[0] -Dhcp {} -ErrorAction Stop; ",
                if enabled { "Enabled" } else { "Disabled" },
            )
        })
        .unwrap_or_default();
    Ok(format!(
        "$ErrorActionPreference='Stop'; \
         Import-Module NetTCPIP -ErrorAction Stop; Import-Module NetAdapter -ErrorAction Stop; \
         $adapter=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {{ ([Guid]$_.InterfaceGuid) -eq ([Guid]{id}) }}); \
         if($adapter.Count -ne 1 -or $adapter[0].ifIndex -ne {index}) {{ throw 'Interface GUID/index changed; no DHCP change was attempted' }}; \
         $iface=@(Get-NetIPInterface -InterfaceIndex {index} -AddressFamily {family} -PolicyStore {store} -ErrorAction Stop); \
         if($iface.Count -ne 1) {{ throw 'An exact IP interface could not be resolved; no DHCP change was attempted' }}; \
         $before=$iface[0] | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,Dhcp,ConnectionState,PolicyStore; \
         {update} \
         $after=Get-NetIPInterface -InterfaceIndex {index} -AddressFamily {family} -PolicyStore {store} -ErrorAction Stop | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,Dhcp,ConnectionState,PolicyStore; \
         $active=Get-NetIPInterface -InterfaceIndex {index} -AddressFamily {family} -PolicyStore ActiveStore -ErrorAction Stop | Select-Object InterfaceIndex,AddressFamily,Dhcp,ConnectionState; \
         [pscustomobject]@{{interface_guid={id}; scope='per_interface'; store='{store}'; mutation_requested={mutated}; before=$before; after=$after; active=$active; activation_pending=($after.Dhcp -ne $active.Dhcp); reboot_required=$null; restart_requirement='Persistent-store changes may need interface reactivation or reboot; live state is returned separately'; address_readiness_verified=$false}}",
        index = target.index,
        mutated = if input.enabled.is_some() { "$true" } else { "$false" },
    ))
}

pub struct ResolvedInterface {
    pub guid: GUID,
    pub luid: NET_LUID_LH,
    pub index: u32,
    pub row: MIB_IF_ROW2,
}

pub fn resolve(target: &InterfaceTarget) -> Result<ResolvedInterface> {
    let id = guid(&target.guid, "interface GUID")?;
    ensure!(id != GUID::zeroed(), "Interface GUID must not be zero");
    let mut luid = NET_LUID_LH::default();
    unsafe {
        check_win32(
            "ConvertInterfaceGuidToLuid",
            ConvertInterfaceGuidToLuid(&id, &mut luid).0,
        )?;
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: luid,
            ..Default::default()
        };
        check_win32("GetIfEntry2", GetIfEntry2(&mut row).0)?;
        validate_identity(target, id, &row)?;
        Ok(ResolvedInterface {
            guid: id,
            luid,
            index: row.InterfaceIndex,
            row,
        })
    }
}

fn validate_identity(target: &InterfaceTarget, id: GUID, row: &MIB_IF_ROW2) -> Result<()> {
    ensure!(
        row.InterfaceGuid == id,
        "Interface identity changed while resolving it"
    );
    ensure!(
        target.index.is_none_or(|index| index == row.InterfaceIndex),
        "Interface index does not match the supplied GUID"
    );
    ensure!(
        target
            .luid
            .is_none_or(|luid| luid == unsafe { row.InterfaceLuid.Value }),
        "Interface LUID does not match the supplied GUID"
    );
    Ok(())
}

fn interface_json(row: &MIB_IF_ROW2) -> Result<Value> {
    let length = row.PhysicalAddressLength as usize;
    ensure!(
        length <= row.PhysicalAddress.len(),
        "Invalid native MAC address length"
    );
    Ok(json!({
        "guid": guid_string(row.InterfaceGuid),
        "index": row.InterfaceIndex,
        "luid": unsafe { row.InterfaceLuid.Value }.to_string(),
        "alias": super::wchar_to_string(&row.Alias),
        "description": super::wchar_to_string(&row.Description),
        "admin_status": row.AdminStatus.0,
        "oper_status": row.OperStatus.0,
        "media_connect_state": row.MediaConnectState.0,
        "mtu": row.Mtu,
        "type": row.Type,
        "physical_address": row.PhysicalAddress[..length].iter()
            .map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-"),
        "receive_link_speed": row.ReceiveLinkSpeed,
        "transmit_link_speed": row.TransmitLinkSpeed,
    }))
}

struct MibAllocation(*mut std::ffi::c_void);

impl Drop for MibAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0) };
        }
    }
}

fn bounded_count<T>(count: u32) -> Result<usize> {
    let count = count as usize;
    ensure!(
        count <= MAX_NATIVE_BYTES / std::mem::size_of::<T>(),
        "Native IP table exceeds the allocation bound"
    );
    Ok(count)
}

pub fn interfaces(input: &NetworkQuery, context: &AdminContext) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    context.check()?;
    if let Some(target) = &input.target {
        let resolved = resolve(target)?;
        return Ok(json!({"interfaces": [interface_json(&resolved.row)?], "truncated": false}));
    }
    unsafe {
        let mut table = std::ptr::null_mut();
        check_win32("GetIfTable2", GetIfTable2(&mut table).0)?;
        let _allocation = MibAllocation(table.cast());
        ensure!(!table.is_null(), "GetIfTable2 returned no table");
        let count = bounded_count::<MIB_IF_ROW2>((*table).NumEntries)?;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut output = Vec::new();
        for row in rows.iter().take(limit) {
            context.check()?;
            output.push(interface_json(row)?);
        }
        Ok(json!({"interfaces": output, "total": count, "truncated": count > limit}))
    }
}

fn parsed_ip(value: &str, family: AddressFamily) -> Result<IpAddr> {
    text(value, "IP address", 64)?;
    let ip: IpAddr = value.parse()?;
    family.validate(ip)?;
    Ok(ip)
}

fn prefix_valid(ip: IpAddr, prefix: u8) -> Result<()> {
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    ensure!(prefix <= bits, "Prefix length exceeds address family width");
    Ok(())
}

fn sockaddr(ip: IpAddr, interface_index: u32) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => {
            let mut address = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            address.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            SOCKADDR_INET { Ipv4: address }
        }
        IpAddr::V6(ip) => {
            let mut address = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            address.sin6_addr.u.Byte = ip.octets();
            if ip.is_unicast_link_local() {
                address.Anonymous.sin6_scope_id = interface_index;
            }
            SOCKADDR_INET { Ipv6: address }
        }
    }
}

fn sockaddr_json(address: &SOCKADDR_INET) -> Result<Value> {
    unsafe {
        if address.si_family == AF_INET {
            return Ok(json!({
                "address": Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).to_string(),
                "family": "ipv4",
                "scope_id": 0,
            }));
        }
        if address.si_family == AF_INET6 {
            return Ok(json!({
                "address": Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte).to_string(),
                "family": "ipv6",
                "scope_id": address.Ipv6.Anonymous.sin6_scope_id,
            }));
        }
        bail!("Unexpected socket address family {}", address.si_family.0);
    }
}

fn address_json(row: &MIB_UNICASTIPADDRESS_ROW) -> Result<Value> {
    Ok(json!({
        "interface_index": row.InterfaceIndex,
        "interface_luid": unsafe { row.InterfaceLuid.Value }.to_string(),
        "ip": sockaddr_json(&row.Address)?,
        "prefix_length": row.OnLinkPrefixLength,
        "prefix_origin": row.PrefixOrigin.0,
        "suffix_origin": row.SuffixOrigin.0,
        "dad_state": row.DadState.0,
        "skip_as_source": row.SkipAsSource,
        "valid_lifetime_seconds": row.ValidLifetime,
        "preferred_lifetime_seconds": row.PreferredLifetime,
    }))
}

pub fn addresses(input: &NetworkQuery, context: &AdminContext) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    context.check()?;
    let target = input.target.as_ref().map(resolve).transpose()?;
    unsafe {
        let mut table = std::ptr::null_mut();
        check_win32(
            "GetUnicastIpAddressTable",
            GetUnicastIpAddressTable(
                input.family.map_or(AF_UNSPEC, AddressFamily::native),
                &mut table,
            )
            .0,
        )?;
        let _allocation = MibAllocation(table.cast());
        ensure!(
            !table.is_null(),
            "GetUnicastIpAddressTable returned no table"
        );
        let count = bounded_count::<MIB_UNICASTIPADDRESS_ROW>((*table).NumEntries)?;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut output = Vec::new();
        let mut matched = 0;
        for row in rows {
            context.check()?;
            if target
                .as_ref()
                .is_some_and(|target| target.luid.Value != row.InterfaceLuid.Value)
            {
                continue;
            }
            matched += 1;
            if output.len() < limit {
                output.push(address_json(row)?);
            }
        }
        Ok(
            json!({"addresses": output, "matching": matched, "truncated": matched > limit, "scope": "active_store"}),
        )
    }
}

fn validate_address(input: &AddressInput) -> Result<IpAddr> {
    let ip = parsed_ip(&input.address, input.family)?;
    prefix_valid(ip, input.prefix_length)?;
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast(),
        "A unicast address must be specified"
    );
    match input.action {
        EntryAction::Add => ensure!(
            input.expected_prefix_length.is_none(),
            "Add must omit expected_prefix_length"
        ),
        EntryAction::Update | EntryAction::Remove => {
            let expected = input
                .expected_prefix_length
                .ok_or_else(|| anyhow::anyhow!("Update/remove requires expected_prefix_length"))?;
            prefix_valid(ip, expected)?;
        }
    }
    if matches!(input.action, EntryAction::Remove) {
        ensure!(
            input.skip_as_source.is_none(),
            "Remove must omit skip_as_source"
        );
        ensure!(
            input.expected_prefix_length == Some(input.prefix_length),
            "Remove prefix must match expected_prefix_length"
        );
    }
    Ok(ip)
}

pub fn set_address(input: &AddressInput, context: &AdminContext) -> Result<Value> {
    let ip = validate_address(input)?;
    context.check()?;
    let target = resolve(&input.target)?;
    unsafe {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceLuid = target.luid;
        row.InterfaceIndex = target.index;
        row.Address = sockaddr(ip, target.index);
        if !matches!(input.action, EntryAction::Add) {
            check_win32(
                "GetUnicastIpAddressEntry",
                GetUnicastIpAddressEntry(&mut row).0,
            )?;
            ensure!(
                Some(row.OnLinkPrefixLength) == input.expected_prefix_length,
                "Address prefix changed; no mutation was attempted"
            );
            ensure!(
                row.PrefixOrigin == IpPrefixOriginManual && row.SuffixOrigin == IpSuffixOriginManual,
                "This address is provider-managed (DHCP/autoconfiguration); configure its provider instead"
            );
        }
        let before = if matches!(input.action, EntryAction::Add) {
            None
        } else {
            Some(address_json(&row)?)
        };
        row.OnLinkPrefixLength = input.prefix_length;
        if matches!(input.action, EntryAction::Add) {
            row.PrefixOrigin = IpPrefixOriginManual;
            row.SuffixOrigin = IpSuffixOriginManual;
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
        }
        if let Some(skip) = input.skip_as_source {
            row.SkipAsSource = skip;
        }
        context.begin_mutation()?;
        let (api, result) = match input.action {
            EntryAction::Add => (
                "CreateUnicastIpAddressEntry",
                CreateUnicastIpAddressEntry(&row),
            ),
            EntryAction::Update => ("SetUnicastIpAddressEntry", SetUnicastIpAddressEntry(&row)),
            EntryAction::Remove => (
                "DeleteUnicastIpAddressEntry",
                DeleteUnicastIpAddressEntry(&row),
            ),
        };
        check_win32(api, result.0)?;
        let queried = GetUnicastIpAddressEntry(&mut row);
        let removed = matches!(input.action, EntryAction::Remove);
        if removed && queried.0 == windows::Win32::Foundation::ERROR_NOT_FOUND.0 {
            return Ok(json!({
                "accepted": true, "removed": true, "before": before, "after": null,
                "scope": "active_store", "persists_across_reboot": false, "reboot_required": false,
                "windows_code": 0,
            }));
        }
        check_win32("GetUnicastIpAddressEntry (after mutation)", queried.0)?;
        Ok(json!({
            "accepted": true, "removed": false, "before": before, "after": address_json(&row)?,
            "scope": "active_store", "persists_across_reboot": false, "reboot_required": false,
            "windows_code": 0, "postcondition_satisfied": !removed
                && row.OnLinkPrefixLength == input.prefix_length
                && input.skip_as_source.is_none_or(|skip| skip == row.SkipAsSource),
            "address_usable": row.DadState == IpDadStatePreferred,
        }))
    }
}

fn route_json(row: &MIB_IPFORWARD_ROW2) -> Result<Value> {
    Ok(json!({
        "interface_index": row.InterfaceIndex,
        "interface_luid": unsafe { row.InterfaceLuid.Value }.to_string(),
        "destination": sockaddr_json(&row.DestinationPrefix.Prefix)?,
        "prefix_length": row.DestinationPrefix.PrefixLength,
        "next_hop": sockaddr_json(&row.NextHop)?,
        "metric": row.Metric,
        "protocol": row.Protocol.0,
        "origin": row.Origin.0,
        "valid_lifetime_seconds": row.ValidLifetime,
        "preferred_lifetime_seconds": row.PreferredLifetime,
    }))
}

pub fn routes(input: &NetworkQuery, context: &AdminContext) -> Result<Value> {
    let limit = result_limit(input.limit)?;
    context.check()?;
    let target = input.target.as_ref().map(resolve).transpose()?;
    unsafe {
        let mut table = std::ptr::null_mut();
        check_win32(
            "GetIpForwardTable2",
            GetIpForwardTable2(
                input.family.map_or(AF_UNSPEC, AddressFamily::native),
                &mut table,
            )
            .0,
        )?;
        let _allocation = MibAllocation(table.cast());
        ensure!(!table.is_null(), "GetIpForwardTable2 returned no table");
        let count = bounded_count::<MIB_IPFORWARD_ROW2>((*table).NumEntries)?;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut output = Vec::new();
        let mut matched = 0;
        for row in rows {
            context.check()?;
            if target
                .as_ref()
                .is_some_and(|target| target.luid.Value != row.InterfaceLuid.Value)
            {
                continue;
            }
            matched += 1;
            if output.len() < limit {
                output.push(route_json(row)?);
            }
        }
        Ok(
            json!({"routes": output, "matching": matched, "truncated": matched > limit, "scope": "active_store"}),
        )
    }
}

fn validate_route(input: &RouteInput) -> Result<(IpAddr, IpAddr)> {
    let destination = parsed_ip(&input.destination, input.family)?;
    let next_hop = parsed_ip(&input.next_hop, input.family)?;
    prefix_valid(destination, input.prefix_length)?;
    let host_bits_zero = match destination {
        IpAddr::V4(ip) => {
            u32::from(ip)
                & (u32::MAX
                    .checked_shr(input.prefix_length as u32)
                    .unwrap_or(0))
                == 0
        }
        IpAddr::V6(ip) => {
            u128::from(ip)
                & (u128::MAX
                    .checked_shr(input.prefix_length as u32)
                    .unwrap_or(0))
                == 0
        }
    };
    ensure!(host_bits_zero, "Route destination has nonzero host bits");
    ensure!(
        !next_hop.is_multicast(),
        "Next hop must be unicast or the unspecified on-link address"
    );
    match input.action {
        EntryAction::Remove => ensure!(
            input.metric.is_none(),
            "Remove identifies a route by interface, prefix and next hop; omit metric"
        ),
        _ => ensure!(
            input.metric.is_some_and(|metric| metric <= 9999),
            "Add/update metric must be 0..=9999"
        ),
    }
    Ok((destination, next_hop))
}

pub fn set_route(input: &RouteInput, context: &AdminContext) -> Result<Value> {
    let (destination, next_hop) = validate_route(input)?;
    context.check()?;
    let target = resolve(&input.target)?;
    unsafe {
        let mut row = MIB_IPFORWARD_ROW2::default();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceLuid = target.luid;
        row.InterfaceIndex = target.index;
        row.DestinationPrefix.Prefix = sockaddr(destination, target.index);
        row.DestinationPrefix.PrefixLength = input.prefix_length;
        row.NextHop = sockaddr(next_hop, target.index);
        if !matches!(input.action, EntryAction::Add) {
            check_win32("GetIpForwardEntry2", GetIpForwardEntry2(&mut row).0)?;
        }
        let before = if matches!(input.action, EntryAction::Add) {
            None
        } else {
            Some(route_json(&row)?)
        };
        if let Some(metric) = input.metric {
            row.Metric = metric;
        }
        if matches!(input.action, EntryAction::Add) {
            row.Protocol = MIB_IPPROTO_NETMGMT;
        }
        context.begin_mutation()?;
        let (api, code) = match input.action {
            EntryAction::Add => ("CreateIpForwardEntry2", CreateIpForwardEntry2(&row)),
            EntryAction::Update => ("SetIpForwardEntry2", SetIpForwardEntry2(&row)),
            EntryAction::Remove => ("DeleteIpForwardEntry2", DeleteIpForwardEntry2(&row)),
        };
        check_win32(api, code.0)?;
        let queried = GetIpForwardEntry2(&mut row);
        let removed = matches!(input.action, EntryAction::Remove);
        if removed && queried.0 == windows::Win32::Foundation::ERROR_NOT_FOUND.0 {
            return Ok(json!({
                "accepted": true, "removed": true, "before": before, "after": null,
                "scope": "active_store", "persists_across_reboot": false, "reboot_required": false, "windows_code": 0,
            }));
        }
        check_win32("GetIpForwardEntry2 (after mutation)", queried.0)?;
        Ok(json!({
            "accepted": true, "removed": false, "before": before, "after": route_json(&row)?,
            "scope": "active_store", "persists_across_reboot": false, "reboot_required": false, "windows_code": 0,
            "postcondition_satisfied": !removed && input.metric == Some(row.Metric),
        }))
    }
}

struct DnsSettings(DNS_INTERFACE_SETTINGS);

impl Drop for DnsSettings {
    fn drop(&mut self) {
        unsafe { FreeInterfaceDnsSettings(&mut self.0) };
    }
}

fn dns_settings(id: GUID, family: AddressFamily) -> Result<Value> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: if matches!(family, AddressFamily::Ipv6) {
            DNS_SETTING_IPV6 as u64
        } else {
            0
        },
        ..Default::default()
    };
    unsafe {
        check_win32(
            "GetInterfaceDnsSettings",
            GetInterfaceDnsSettings(id, &mut settings).0,
        )?;
        let settings = DnsSettings(settings);
        Ok(json!({
            "family": family,
            "flags": settings.0.Flags,
            "name_server": super::from_wide(settings.0.NameServer.0),
            "profile_name_server": super::from_wide(settings.0.ProfileNameServer.0),
            "domain": super::from_wide(settings.0.Domain.0),
            "search_list": super::from_wide(settings.0.SearchList.0),
            "registration_enabled": settings.0.RegistrationEnabled != 0,
            "register_adapter_name": settings.0.RegisterAdapterName != 0,
        }))
    }
}

fn dns_server_string(servers: &[String], family: AddressFamily) -> Result<String> {
    ensure!(
        servers.len() <= 16,
        "At most 16 DNS servers may be configured"
    );
    let mut addresses = Vec::new();
    for value in servers {
        let ip = parsed_ip(value, family)?;
        ensure!(
            !ip.is_unspecified() && !ip.is_multicast(),
            "DNS servers must be unicast addresses"
        );
        ensure!(!addresses.contains(&ip), "Duplicate DNS server address");
        addresses.push(ip);
    }
    Ok(addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(","))
}

pub fn dns(input: &DnsInput, context: &AdminContext) -> Result<Value> {
    let configured = input
        .servers
        .as_ref()
        .map(|servers| dns_server_string(servers, input.family))
        .transpose()?;
    context.check()?;
    let target = resolve(&input.target)?;
    let before = dns_settings(target.guid, input.family)?;
    if let Some(configured) = configured {
        let mut names = super::to_wide(&configured);
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: (DNS_SETTING_NAMESERVER
                | if matches!(input.family, AddressFamily::Ipv6) {
                    DNS_SETTING_IPV6
                } else {
                    0
                }) as u64,
            NameServer: PWSTR(names.as_mut_ptr()),
            ..Default::default()
        };
        context.begin_mutation()?;
        unsafe {
            check_win32(
                "SetInterfaceDnsSettings",
                SetInterfaceDnsSettings(target.guid, &settings).0,
            )?;
        }
        let after = dns_settings(target.guid, input.family)?;
        let observed: Vec<_> = after["name_server"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Native DNS snapshot is missing name_server"))?
            .split([',', ' '])
            .filter(|server| !server.is_empty())
            .map(str::parse::<IpAddr>)
            .collect::<std::result::Result<_, _>>()?;
        let expected: Vec<_> = configured
            .split(',')
            .filter(|server| !server.is_empty())
            .map(str::parse::<IpAddr>)
            .collect::<std::result::Result<_, _>>()?;
        return Ok(json!({
            "interface": interface_json(&target.row)?, "scope": "per_interface",
            "before": before, "after": after, "accepted": true, "windows_code": 0,
            "reboot_required": false, "persists_across_reboot": true,
            "automatic_dns_requested": configured.is_empty(),
            "postcondition_satisfied": observed == expected,
            "effective_resolver_use_verified": false,
        }));
    }
    Ok(
        json!({"interface": interface_json(&target.row)?, "scope": "per_interface", "settings": before}),
    )
}

pub fn set_adapter_state(input: &AdapterStateInput, context: &AdminContext) -> Result<Value> {
    context.check()?;
    let target = resolve(&input.target)?;
    let before = interface_json(&target.row)?;
    unsafe {
        let mut row = MIB_IFROW {
            dwIndex: target.index,
            ..Default::default()
        };
        check_win32("GetIfEntry", GetIfEntry(&mut row))?;
        let expected = if input.enabled {
            MIB_IF_ADMIN_STATUS_UP
        } else {
            MIB_IF_ADMIN_STATUS_DOWN
        };
        row.dwAdminStatus = expected;
        resolve(&input.target)?;
        context.begin_mutation()?;
        check_win32("SetIfEntry", SetIfEntry(&row))?;
        let after = resolve(&input.target)?;
        Ok(json!({
            "accepted": true, "windows_code": 0, "before": before,
            "after": interface_json(&after.row)?,
            "postcondition_satisfied": after.row.AdminStatus.0 as u32 == expected,
            "scope": "interface_administrative_state", "reboot_required": false,
            "note": "Administrative up does not establish link, address readiness or Internet connectivity.",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn target() -> InterfaceTarget {
        InterfaceTarget {
            guid: "00000000-0000-0000-0000-000000000001".into(),
            index: Some(5),
            luid: Some(10),
        }
    }

    #[test]
    fn administration_network_coercion_and_schema() {
        let input: AddressInput = serde_json::from_value(json!({
            "target": {"guid": target().guid, "index": "5", "luid": "10"},
            "action": "add", "family": "ipv4", "address": "192.0.2.10",
            "prefix_length": "24", "timeout_ms": "1000"
        }))
        .unwrap();
        assert_eq!(input.prefix_length, 24);
        assert_eq!(input.target.luid, Some(10));
        assert!(validate_address(&input).is_ok());
        let schema = serde_json::to_value(schemars::schema_for!(AddressInput)).unwrap();
        assert!(schema["properties"]["prefix_length"].is_object());
    }

    #[test]
    fn administration_network_identity_rejects_mismatch() {
        let mut row = MIB_IF_ROW2 {
            InterfaceGuid: guid(&target().guid, "guid").unwrap(),
            InterfaceIndex: 6,
            ..Default::default()
        };
        row.InterfaceLuid.Value = 10;
        assert!(validate_identity(&target(), row.InterfaceGuid, &row).is_err());
        row.InterfaceIndex = 5;
        assert!(validate_identity(&target(), row.InterfaceGuid, &row).is_ok());
    }

    #[test]
    fn administration_network_ip_families_and_socket_byte_order() {
        assert!(parsed_ip("2001:db8::1", AddressFamily::Ipv4).is_err());
        assert!(prefix_valid("192.0.2.1".parse().unwrap(), 33).is_err());
        for ip in ["192.0.2.1", "2001:db8::1", "fe80::1"] {
            let socket = sockaddr(ip.parse().unwrap(), 12);
            assert_eq!(sockaddr_json(&socket).unwrap()["address"], ip);
        }
        assert_eq!(
            sockaddr_json(&sockaddr("fe80::1".parse().unwrap(), 12)).unwrap()["scope_id"],
            12
        );
        assert!(
            dns_server_string(&["1.1.1.1".into(), "1.1.1.1".into()], AddressFamily::Ipv4).is_err()
        );
    }

    #[test]
    fn administration_network_route_validation() {
        let mut input = RouteInput {
            target: target(),
            action: EntryAction::Add,
            family: AddressFamily::Ipv4,
            destination: "192.0.2.1".into(),
            prefix_length: 24,
            next_hop: "192.0.2.254".into(),
            metric: Some(10),
            timeout_ms: None,
        };
        assert!(validate_route(&input).is_err());
        input.destination = "192.0.2.0".into();
        assert!(validate_route(&input).is_ok());
        input.destination = "0.0.0.0".into();
        input.prefix_length = 0;
        assert!(validate_route(&input).is_ok());
        input.next_hop = "::1".into();
        assert!(validate_route(&input).is_err());
    }

    #[test]
    fn administration_network_invalid_mutations_never_reach_api() {
        let context = AdminContext::new(Duration::from_secs(1));
        let input = AddressInput {
            target: target(),
            action: EntryAction::Update,
            family: AddressFamily::Ipv4,
            address: "192.0.2.5".into(),
            prefix_length: 24,
            expected_prefix_length: None,
            skip_as_source: None,
            timeout_ms: None,
        };
        assert!(set_address(&input, &context).is_err());
        assert!(!context.mutation_started());
        let input = RouteInput {
            target: target(),
            action: EntryAction::Add,
            family: AddressFamily::Ipv4,
            destination: "192.0.2.5".into(),
            prefix_length: 24,
            next_hop: "192.0.2.1".into(),
            metric: Some(5),
            timeout_ms: None,
        };
        assert!(set_route(&input, &context).is_err());
        assert!(!context.mutation_started());
    }

    #[test]
    fn administration_network_read_only_inventory() {
        let context = AdminContext::new(Duration::from_secs(10));
        let input = NetworkQuery {
            target: None,
            family: None,
            limit: Some(2),
            timeout_ms: None,
        };
        let output = interfaces(&input, &context).unwrap();
        assert!(output["interfaces"].as_array().unwrap().len() <= 2);
        let output = addresses(&input, &context).unwrap();
        assert!(output["addresses"].as_array().unwrap().len() <= 2);
        let output = routes(&input, &context).unwrap();
        assert!(output["routes"].as_array().unwrap().len() <= 2);
        assert!(!context.mutation_started());
    }
}
