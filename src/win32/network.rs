//! # Network Info: Where IP Addresses Go to Be Miserable
//!
//! This module wraps Windows networking APIs that were clearly designed by
//! people who peaked during the Winsock 1.1 era and never looked back.
//!
//! GetTcpTable2 uses the beloved "call twice" pattern (get size, then get data).
//! IP addresses are stored as u32 in network byte order because endianness is
//! apparently a permanent tax we all pay for being born after the PDP-11.
//!
//! But the real masterpiece is GetAdaptersAddresses, which returns network
//! adapters as a LINKED LIST. Not an array. Not a Vec. A raw pointer-chasing
//! linked list with nested linked lists for IP addresses, DNS servers, and
//! gateways. Microsoft looked at every data structure ever invented and said
//! "what if we used the worst one?"

use super::pretty;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// Lists all TCP connections on the system. Gets the TCP table (after the
/// mandatory two-call sizing dance), then maps each entry to a JSON object.
/// IP addresses come back as u32s in network byte order, so we have to
/// convert them with `.to_be()` because the IP helper API stores addresses
/// in the opposite endianness of what `Ipv4Addr::from` expects. Port numbers
/// are ALSO in network byte order because consistency is for other platforms.
pub fn connections() -> anyhow::Result<String> {
    unsafe {
        use windows::Win32::NetworkManagement::IpHelper::*;

        // Step 1: Ask how big the buffer needs to be. This "fails" on purpose.
        // The error IS the answer. Only on Windows would a failure be the
        // expected happy path.
        let mut size: u32 = 0;
        let _ = GetTcpTable2(None, &mut size, true);
        let mut buf = vec![0u8; size as usize];
        let ret = GetTcpTable2(Some(buf.as_mut_ptr() as *mut MIB_TCPTABLE2), &mut size, true);
        if ret != 0 {
            anyhow::bail!("GetTcpTable2 failed with error: {ret}");
        }

        // Reinterpret our raw byte buffer as a TCP table struct. Standard Windows
        // "just cast the pointer" energy. Type safety is a suggestion, not a rule.
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE2);
        let entries = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );

        // Build a PID-to-name cache so we don't have to open every process handle
        // individually. The TCP table gives you PIDs but not names because that
        // would be too helpful.
        let procs = crate::win32::process::snapshot_name_cache();

        let mut conns: Vec<serde_json::Value> = entries
            .iter()
            .filter(|e| e.dwState != 2) // Skip MIB_TCP_STATE_LISTEN for brevity... actually keep it
            .map(|e| {
                // IP addresses: stored as u32, network byte order. We call .to_be()
                // which swaps bytes on little-endian (x86), turning the network-order
                // u32 into a host-order u32 that Ipv4Addr::from expects. If this
                // sounds confusing, that's because it is. Endianness: ruining
                // everyone's day since 1980.
                let local_ip = Ipv4Addr::from(e.dwLocalAddr.to_be());
                let remote_ip = Ipv4Addr::from(e.dwRemoteAddr.to_be());
                // Ports are also network byte order. Of course they are.
                let local_port = (e.dwLocalPort as u16).to_be();
                let remote_port = (e.dwRemotePort as u16).to_be();
                // TCP state is a magic number because enums are for languages
                // that respect their developers
                let state = match e.dwState {
                    1 => "Closed",
                    2 => "Listen",
                    3 => "SynSent",
                    4 => "SynReceived",
                    5 => "Established",
                    6 => "FinWait1",
                    7 => "FinWait2",
                    8 => "CloseWait",
                    9 => "Closing",
                    10 => "LastAck",
                    11 => "TimeWait",
                    12 => "DeleteTcb",
                    _ => "Unknown",
                };
                let pid = e.dwOwningPid;
                let proc_name = procs.get(&pid).cloned().unwrap_or_default();

                json!({
                    "LocalAddress": format!("{local_ip}"),
                    "LocalPort": local_port,
                    "RemoteAddress": format!("{remote_ip}"),
                    "RemotePort": remote_port,
                    "State": state,
                    "PID": pid,
                    "ProcessName": proc_name,
                })
            })
            .collect();

        conns.sort_by(|a, b| a["State"].as_str().cmp(&b["State"].as_str()));
        Ok(pretty(&json!(conns)))
    }
}

/// Returns network adapter configuration. This calls GetAdaptersAddresses,
/// which is the crown jewel of unhinged Win32 API design. It returns a
/// LINKED LIST of adapters (traverse via `.Next` pointer), where each adapter
/// contains NESTED linked lists for unicast addresses, DNS servers, and
/// gateways. You traverse this entire horror show by chasing raw pointers
/// through the heap like a bloodhound sniffing through a landfill.
///
/// Oh, and it also uses the two-call pattern to get the buffer size first.
/// Because at this point, why wouldn't it?
pub fn config() -> anyhow::Result<String> {
    unsafe {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
        use windows::Win32::Networking::WinSock::*;

        // Two-call pattern: get size, then get data. I'm so tired.
        let mut size: u32 = 0;
        let _ = GetAdaptersAddresses(AF_UNSPEC.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut size);
        let mut buf = vec![0u8; size as usize];
        let ret = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        );
        if ret != 0 {
            anyhow::bail!("GetAdaptersAddresses failed with error: {ret}");
        }

        let mut adapters = Vec::new();
        // Here we go. Chasing pointers through a linked list like it's 1972
        // and Dijkstra himself wrote this API.
        let mut current = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !current.is_null() {
            let adapter = &*current;
            let name = super::from_wide(adapter.FriendlyName.0);
            let desc = super::from_wide(adapter.Description.0);

            // Collect IP addresses — yet another linked list to traverse.
            // Each unicast address points to the next one via .Next.
            // Arrays? Never heard of 'em.
            let mut ips = Vec::new();
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let addr = &*unicast;
                let sa = addr.Address.lpSockaddr;
                if !sa.is_null() {
                    let family = (*sa).sa_family;
                    if family == AF_INET {
                        // IPv4: cast the sockaddr to SOCKADDR_IN, then extract the
                        // IP from a union field (S_un.S_addr). Unions! In 2026!
                        let sa4 = sa as *const SOCKADDR_IN;
                        let ip = Ipv4Addr::from((*sa4).sin_addr.S_un.S_addr.to_be());
                        ips.push(json!({
                            "Address": ip.to_string(),
                            "PrefixLength": addr.OnLinkPrefixLength,
                            "Family": "IPv4",
                        }));
                    } else if family == AF_INET6 {
                        let sa6 = sa as *const SOCKADDR_IN6;
                        let bytes = (*sa6).sin6_addr.u.Byte;
                        let ip = std::net::Ipv6Addr::from(bytes);
                        ips.push(json!({
                            "Address": ip.to_string(),
                            "PrefixLength": addr.OnLinkPrefixLength,
                            "Family": "IPv6",
                        }));
                    }
                }
                unicast = (*unicast).Next; // Follow the linked list. Like an animal.
            }

            // DNS servers — ANOTHER linked list hanging off the adapter struct.
            // It's linked lists all the way down.
            let mut dns_servers = Vec::new();
            let mut dns = adapter.FirstDnsServerAddress;
            while !dns.is_null() {
                let addr = &*dns;
                let sa = addr.Address.lpSockaddr;
                if !sa.is_null() {
                    let family = (*sa).sa_family;
                    if family == AF_INET {
                        let sa4 = sa as *const SOCKADDR_IN;
                        let ip = Ipv4Addr::from((*sa4).sin_addr.S_un.S_addr.to_be());
                        dns_servers.push(ip.to_string());
                    }
                }
                dns = (*dns).Next;
            }

            // Gateways — oh look, ANOTHER linked list. I'm starting to think
            // the person who designed this data structure only knew one.
            let mut gateways = Vec::new();
            let mut gw = adapter.FirstGatewayAddress;
            while !gw.is_null() {
                let addr = &*gw;
                let sa = addr.Address.lpSockaddr;
                if !sa.is_null() && (*sa).sa_family == AF_INET {
                    let sa4 = sa as *const SOCKADDR_IN;
                    let ip = Ipv4Addr::from((*sa4).sin_addr.S_un.S_addr.to_be());
                    gateways.push(ip.to_string());
                }
                gw = (*gw).Next;
            }

            if !ips.is_empty() {
                adapters.push(json!({
                    "Name": name,
                    "Description": desc,
                    "Status": if adapter.OperStatus == IfOperStatusUp { "Up" } else { "Down" },
                    "IPAddresses": ips,
                    "DNSServers": dns_servers,
                    "Gateways": gateways,
                    "PhysicalAddress": format_mac(&adapter.PhysicalAddress[..adapter.PhysicalAddressLength as usize]),
                }));
            }

            current = adapter.Next; // Advance the outer linked list. Naturally.
        }

        Ok(pretty(&json!(adapters)))
    }
}

/// Formats a MAC address from raw bytes to the "XX-XX-XX-XX-XX-XX" format.
/// One of the few things in this file that isn't a war crime.
fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-")
}

/// Tests TCP connectivity to a host:port. This one actually uses Rust's std
/// library instead of Win32 APIs, which means it's the only function in this
/// module that doesn't make me want to throw my keyboard out the window.
/// TcpStream::connect_timeout does in one call what Windows would require
/// about six API calls and a partridge in a pear tree.
pub fn port_test(host: &str, port: u16) -> anyhow::Result<String> {
    let start = std::time::Instant::now();

    // Parse host as IP or resolve
    let addr: std::net::IpAddr = host.parse().unwrap_or_else(|_| {
        // Simple DNS resolution via std
        use std::net::ToSocketAddrs;
        format!("{host}:0")
            .to_socket_addrs()
            .ok()
            .and_then(|mut iter| iter.next())
            .map(|sa| sa.ip())
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0).into())
    });

    let socket_addr = std::net::SocketAddr::new(addr, port);
    let success = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)).is_ok();
    let ms = start.elapsed().as_millis();

    Ok(pretty(&json!({
        "Host": host,
        "RemoteAddress": addr.to_string(),
        "Port": port,
        "TcpTestSucceeded": success,
        "ResponseTimeMs": ms,
    })))
}
