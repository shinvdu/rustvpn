//! Windows IP Helper (`iphlpapi.dll`) fast path for the cleanup hot path.
//!
//! The command vocabulary and every safety rule (exact destination/prefix,
//! interface index, next hop and metric; never delete unrecorded entries;
//! interface-index reuse detection) stay in [`super::winplan`].  This module
//! only replaces the expensive `Get-Net*`/`Remove-Net*` PowerShell processes
//! for route, unicast-address and interface-metric reads/removal with the
//! equivalent IP Helper MIB calls.
//!
//! Returned text is the same JSON shape as the PowerShell backend, so the
//! planner parses both identically.  Additive install commands (address,
//! route, DNS, NRPT, firewall) stay on PowerShell; this module is read/delete
//! only, which keeps the risk confined to the recovery path.

use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeMibTable, GetIfTable2,
    GetIpForwardTable2, GetIpInterfaceEntry, GetIpInterfaceTable, GetUnicastIpAddressTable,
    InitializeIpInterfaceEntry, SetIpInterfaceEntry, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

use super::winplan::{
    self, format_route_dest, AdapterNameEntry, AddressEntry, InterfaceEntry, RouteEntry,
};

/// Own a table allocated by `GetIp*Table2`; `FreeMibTable` on drop.
struct MibTable<T>(*mut T);

impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
}

fn win_error(code: WIN32_ERROR, what: &str) -> anyhow::Error {
    anyhow!(
        "{what} failed (Windows error {code}: {})",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

/// Read a network-order IPv4 `SOCKADDR_INET`.  Tables queried with `AF_INET`
/// only contain IPv4 sockaddrs.
fn sockaddr_v4(addr: &SOCKADDR_INET) -> Ipv4Addr {
    let bytes = unsafe { addr.Ipv4.sin_addr.S_un.S_un_b };
    Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4)
}

fn ip_forward_rows() -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if rc != NO_ERROR || table.is_null() {
        return Err(win_error(rc, "GetIpForwardTable2"));
    }
    let guard = MibTable(table);
    let table = unsafe { &*guard.0 };
    let rows =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    Ok(rows.to_vec())
}

fn ip_interface_rows() -> Result<Vec<MIB_IPINTERFACE_ROW>> {
    let mut table: *mut MIB_IPINTERFACE_TABLE = std::ptr::null_mut();
    let rc = unsafe { GetIpInterfaceTable(AF_INET, &mut table) };
    if rc != NO_ERROR || table.is_null() {
        return Err(win_error(rc, "GetIpInterfaceTable"));
    }
    let guard = MibTable(table);
    let table = unsafe { &*guard.0 };
    let rows =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    Ok(rows.to_vec())
}

fn if_rows() -> Result<Vec<MIB_IF_ROW2>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIfTable2(&mut table) };
    if rc != NO_ERROR || table.is_null() {
        return Err(win_error(rc, "GetIfTable2"));
    }
    let guard = MibTable(table);
    let table = unsafe { &*guard.0 };
    let rows =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    Ok(rows.to_vec())
}

fn unicast_address_rows() -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let rc = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if rc != NO_ERROR || table.is_null() {
        return Err(win_error(rc, "GetUnicastIpAddressTable"));
    }
    let guard = MibTable(table);
    let table = unsafe { &*guard.0 };
    let rows =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    Ok(rows.to_vec())
}

fn forward_entry(row: &MIB_IPFORWARD_ROW2) -> RouteEntry {
    RouteEntry {
        dest: format_route_dest(
            sockaddr_v4(&row.DestinationPrefix.Prefix),
            row.DestinationPrefix.PrefixLength,
        ),
        ifindex: row.InterfaceIndex,
        next_hop: sockaddr_v4(&row.NextHop),
        metric: row.Metric,
    }
}

/// JSON equivalent of `Get-NetRoute -AddressFamily IPv4`.
pub fn list_routes_json() -> Result<String> {
    let entries: Vec<RouteEntry> = ip_forward_rows()?.iter().map(forward_entry).collect();
    Ok(winplan::render_routes_json(&entries))
}

/// Delete one route only when the live table still carries the exact recorded
/// identity.  Absent is success: the caller already verified the entry, and a
/// concurrent removal must not turn into a stuck state file.
pub fn remove_route(dest: &str, ifindex: u32, next_hop: Ipv4Addr, metric: u32) -> Result<()> {
    for row in ip_forward_rows()? {
        if winplan::route_matches(dest, ifindex, next_hop, metric, &forward_entry(&row))? {
            let rc = unsafe { DeleteIpForwardEntry2(&row) };
            return match rc {
                NO_ERROR | ERROR_NOT_FOUND => Ok(()),
                _ => Err(win_error(rc, "DeleteIpForwardEntry2")),
            };
        }
    }
    Ok(())
}

/// JSON equivalent of `Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex`.
pub fn list_addresses_json(ifindex: u32) -> Result<String> {
    let entries: Vec<AddressEntry> = unicast_address_rows()?
        .iter()
        .filter(|row| row.InterfaceIndex == ifindex)
        .map(|row| AddressEntry {
            address: sockaddr_v4(&row.Address),
            prefix_len: row.OnLinkPrefixLength,
        })
        .collect();
    Ok(winplan::render_addresses_json(&entries))
}

/// Delete one unicast address recorded on this interface.  The prefix check is
/// done by the caller through `GetIpv4Addresses`; Windows only allows one
/// address/prefix identity per interface, so address+index is unambiguous.
pub fn remove_address(ifindex: u32, address: Ipv4Addr) -> Result<()> {
    for row in unicast_address_rows()? {
        if row.InterfaceIndex == ifindex && sockaddr_v4(&row.Address) == address {
            let rc = unsafe { DeleteUnicastIpAddressEntry(&row) };
            return match rc {
                NO_ERROR | ERROR_NOT_FOUND => Ok(()),
                _ => Err(win_error(rc, "DeleteUnicastIpAddressEntry")),
            };
        }
    }
    Ok(())
}

/// JSON equivalent of `Get-NetIPInterface -AddressFamily IPv4`.
pub fn list_interfaces_json() -> Result<String> {
    let entries: Vec<InterfaceEntry> = ip_interface_rows()?
        .iter()
        .map(|row| InterfaceEntry {
            ifindex: row.InterfaceIndex,
            metric: row.Metric,
            automatic: row.UseAutomaticMetric,
            connected: row.Connected,
            mtu: Some(row.NlMtu),
        })
        .collect();
    Ok(winplan::render_interfaces_json(&entries))
}

fn interface_row(ifindex: u32) -> Result<MIB_IPINTERFACE_ROW> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = AF_INET;
    row.InterfaceIndex = ifindex;
    let rc = unsafe { GetIpInterfaceEntry(&mut row) };
    if rc != NO_ERROR {
        return Err(win_error(rc, "GetIpInterfaceEntry"));
    }
    Ok(row)
}

/// Write an interface row using the documented [`InitializeIpInterfaceEntry`]
/// pattern: `SetIpInterfaceEntry` rejects a copy of a `GetIpInterfaceEntry`
/// row (ERROR_INVALID_PARAMETER) because read-only fields are populated.
fn update_interface_entry(ifindex: u32, metric: u32, automatic: bool) -> Result<()> {
    let existing = interface_row(ifindex)?;
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
    }
    row.InterfaceLuid = existing.InterfaceLuid;
    row.InterfaceIndex = ifindex;
    row.Family = AF_INET;
    row.UseAutomaticMetric = automatic;
    row.Metric = metric;
    let rc = unsafe { SetIpInterfaceEntry(&mut row) };
    if rc != NO_ERROR {
        return Err(win_error(rc, "SetIpInterfaceEntry"));
    }
    Ok(())
}

/// Equivalent of `Set-NetIPInterface -InterfaceMetric <metric>`.  A manual
/// metric must disable automatic metric selection, matching the PowerShell
/// cmdlet (and the cleanup check that expects `AutomaticMetric: Disabled`).
pub fn set_interface_metric(ifindex: u32, metric: u32) -> Result<()> {
    update_interface_entry(ifindex, metric, false)
}

/// Equivalent of `Set-NetIPInterface -AutomaticMetric Enabled`.  `Metric` is
/// left at the structure default; Windows recomputes it when automatic
/// selection is enabled.
pub fn set_automatic_metric(ifindex: u32) -> Result<()> {
    update_interface_entry(ifindex, 0, true)
}

/// JSON equivalent of `Get-NetAdapter | Select-Object ifIndex,Name,Status`.
///
/// `GetIfTable2` enumerates every interface (including disconnected/disabled
/// ones) and carries the alias inline, so this matches `Get-NetAdapter` more
/// closely than the IPv4-only interface table.  Interface-index reuse is
/// detected exactly like the PowerShell backend.
pub fn list_adapters_json() -> Result<String> {
    let adapters: Vec<AdapterNameEntry> = if_rows()?
        .iter()
        .map(|row| {
            // IF_MAX_STRING_SIZE (256) plus the terminator; a successful call
            // always NUL-terminates.
            let len = row
                .Alias
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(row.Alias.len());
            AdapterNameEntry {
                ifindex: row.InterfaceIndex,
                name: String::from_utf16_lossy(&row.Alias[..len]),
            }
        })
        .collect();
    Ok(winplan::render_adapters_json(&adapters))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netcfg::winplan::{parse_adapters, parse_addresses, parse_interfaces, parse_routes};

    #[test]
    fn lists_routes_interfaces_addresses_and_adapters() {
        let routes = parse_routes(&list_routes_json().unwrap()).unwrap();
        assert!(!routes.is_empty(), "a Windows host always has IPv4 routes");

        let interfaces = parse_interfaces(&list_interfaces_json().unwrap()).unwrap();
        assert!(
            !interfaces.is_empty(),
            "a Windows host always has IPv4 interfaces"
        );

        let adapters = parse_adapters(&list_adapters_json().unwrap()).unwrap();
        assert!(
            !adapters.is_empty(),
            "a Windows host always has named interfaces"
        );
        assert!(
            adapters
                .iter()
                .any(|adapter| adapter.ifindex == interfaces[0].ifindex),
            "interface indices agree between the two IP Helper reads"
        );
        // Every interface that carries IPv4 state must have a named alias:
        // the cleanup path uses it to detect index reuse.
        let all = if_rows().unwrap();
        for iface in &interfaces {
            assert!(
                all.iter()
                    .any(|row| row.InterfaceIndex == iface.ifindex && row.Alias[0] != 0),
                "no alias for IPv4 interface {}",
                iface.ifindex
            );
        }

        // Read-only: the address list is filtered by an impossible index.
        let addresses = parse_addresses(&list_addresses_json(u32::MAX).unwrap()).unwrap();
        assert!(addresses.is_empty());
    }

    #[test]
    #[ignore = "manual: temporarily changes and restores one disconnected interface metric"]
    fn interface_metric_round_trip_on_disconnected_interface() {
        let rows = ip_interface_rows().unwrap();
        let Some(original) = rows.iter().find(|row| !row.Connected) else {
            eprintln!("skip: no disconnected IPv4 interface on this host");
            return;
        };
        let ifindex = original.InterfaceIndex;
        let prior_metric = original.Metric;
        let prior_automatic = original.UseAutomaticMetric;

        set_interface_metric(ifindex, prior_metric.wrapping_add(1)).unwrap();
        let manual = interface_row(ifindex).unwrap();
        assert_eq!(manual.Metric, prior_metric.wrapping_add(1));
        assert!(!manual.UseAutomaticMetric);

        // Restore exactly the recorded prior state.
        if prior_automatic {
            set_automatic_metric(ifindex).unwrap();
            assert!(interface_row(ifindex).unwrap().UseAutomaticMetric);
        } else {
            set_interface_metric(ifindex, prior_metric).unwrap();
            let restored = interface_row(ifindex).unwrap();
            assert_eq!(restored.Metric, prior_metric);
            assert!(!restored.UseAutomaticMetric);
        }
    }

    #[test]
    fn removal_of_an_unrecorded_identity_is_a_noop() {
        // TEST-NET-3 destination on an impossible interface; if the guard were
        // broken this would delete an unrelated route/address.
        remove_route(
            "192.0.2.123/32",
            u32::MAX,
            Ipv4Addr::new(192, 0, 2, 1),
            u32::MAX - 1,
        )
        .unwrap();
        remove_address(u32::MAX, Ipv4Addr::new(192, 0, 2, 123)).unwrap();
    }
}
