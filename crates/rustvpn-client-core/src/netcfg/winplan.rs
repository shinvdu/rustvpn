//! Platform-neutral Windows network planner.
//!
//! This module is compiled on Windows **and** on Linux for unit tests.  It
//! owns everything that can be expressed without Windows APIs: the command
//! vocabulary, PowerShell script generation, JSON parsing, route conflict
//! rules, DNS/NRPT/IPv6 decisions, and the crash-recovery state file format.
//!
//! The Windows-only executor lives in [`super::windows`] and is deliberately
//! thin: it supplies a [`WinRunner`], a [`StateStore`] with restrictive ACLs
//! and a process liveness probe.
//!
//! Safety rules encoded here:
//!
//! * the outer endpoint gets a `/32` anti-loop route through the **original**
//!   path before any tunnel default route is added;
//! * pre-existing routes are never overwritten; an identical route that is not
//!   recorded as RustVPN-owned is reused but never deleted;
//! * a conflicting route fails the whole install, which then rolls back;
//! * cleanup removes only entries recorded in the state file and verifies they
//!   still exist exactly as recorded;
//! * no value reaches PowerShell unquoted, and only typed IPs, validated
//!   interface names and fixed literals are interpolated.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use rustvpn_client_ipc::ProfileSpec;
use rustvpn_net::config::is_default_route;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::netcfg::NetOptions;

/// Route metric of the default route installed through Wintun.  The tunnel
/// interface metric is lowered to [`TUNNEL_INTERFACE_METRIC`] so the effective
/// metric (1) is lower than a normal physical default route without deleting
/// or modifying the user's route.
pub const DEFAULT_ROUTE_METRIC: u32 = 0;
/// Interface metric applied to the Wintun interface for full-tunnel profiles.
pub const TUNNEL_INTERFACE_METRIC: u32 = 1;
/// Metric of the `/32` anti-loop route (more specific than any default).
pub const HOST_ROUTE_METRIC: u32 = 1;
/// Metric of split-tunnel routes (matches the Linux default-route metric).
pub const SPLIT_ROUTE_METRIC: u32 = 50;
/// IPv4 routes are never installed with a metric that could tie the OS
/// default selection.
pub const NRPT_DISPLAY: &str = "RustVPN tunnel DNS";
/// Fixed firewall rule name.  The name is RustVPN-owned by convention and is
/// only ever removed when recorded in the state file.
pub const IPV6_BLOCK_RULE: &str = "RustVPN-IPv6-LeakBlock";

/// Current state-file schema version.
pub const STATE_SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------
// Command vocabulary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    Host,
    Default,
    Split,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub dest: String,
    pub ifindex: u32,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
    pub kind: RouteKind,
}

impl RouteSpec {
    fn new(
        dest: impl Into<String>,
        ifindex: u32,
        next_hop: Ipv4Addr,
        metric: u32,
        kind: RouteKind,
    ) -> Self {
        Self {
            dest: dest.into(),
            ifindex,
            next_hop,
            metric,
            kind,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WinCommand {
    ListIpv4Routes,
    ListIpv4Interfaces,
    ListAdapters,
    GetAdapterInfo(String),
    GetIpv4Addresses(u32),
    FindRouteTo(Ipv4Addr),
    AddIpAddress {
        ifindex: u32,
        address: Ipv4Addr,
        prefix_len: u8,
    },
    RemoveIpAddress {
        ifindex: u32,
        address: Ipv4Addr,
    },
    AddRoute(RouteSpec),
    RemoveRoute {
        dest: String,
        ifindex: u32,
        next_hop: Ipv4Addr,
        metric: u32,
    },
    SetInterfaceMetric {
        ifindex: u32,
        metric: u32,
    },
    SetAutomaticMetric(u32),
    GetDnsServers(u32),
    SetDnsServers {
        ifindex: u32,
        servers: Vec<Ipv4Addr>,
    },
    ResetDnsServers(u32),
    AddNrpt {
        display: String,
        servers: Vec<Ipv4Addr>,
    },
    FindNrpt {
        display: String,
    },
    RemoveNrpt {
        name: String,
    },
    AddIpv6Block {
        name: String,
    },
    RemoveFirewallRule {
        name: String,
    },
}

/// Async command executor.
pub type RunnerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait WinRunner: Send + Sync {
    /// Run one command and return stdout.  A non-zero exit must be an error.
    fn run<'a>(&'a self, command: &'a WinCommand) -> RunnerFuture<'a, Result<String>>;
}

/// Persistent crash-recovery store.
pub trait StateStore: Send + Sync {
    fn load(&self) -> Result<Option<PersistedState>>;
    fn save(&self, state: &PersistedState) -> Result<()>;
    fn clear(&self) -> Result<()>;
    fn path(&self) -> PathBuf;
}

/// Whether a recorded owner process is still alive.
pub trait OwnerProbe: Send + Sync {
    fn is_alive(&self, owner: &OwnerToken) -> bool;
}

// ---------------------------------------------------------------------------
// PowerShell script generation
// ---------------------------------------------------------------------------

/// Quote a value for a PowerShell single-quoted literal.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn ps_array(values: &[impl ToString]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| ps_quote(&value.to_string()))
        .collect();
    format!("@({})", items.join(","))
}

/// Build the PowerShell script for a command.
///
/// Every interpolated value is either typed (IPs, indices, metrics) or a
/// validated name; [`ps_quote`] is still applied as defense in depth.  No
/// command string is ever passed through `cmd.exe`.
pub fn script_for(command: &WinCommand) -> String {
    match command {
        WinCommand::ListIpv4Routes => {
            "Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | \
             Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | \
             ConvertTo-Json -Compress"
                .into()
        }
        WinCommand::ListIpv4Interfaces => {
            "Get-NetIPInterface -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | \
             Select-Object InterfaceIndex,InterfaceMetric,AutomaticMetric,ConnectionState,NlMtu | \
             ConvertTo-Json -Compress"
                .into()
        }
        WinCommand::ListAdapters => {
            "Get-NetAdapter -ErrorAction Stop | Select-Object ifIndex,Name,Status | \
             ConvertTo-Json -Compress"
                .into()
        }
        WinCommand::GetAdapterInfo(name) => format!(
            "Get-NetAdapter -Name {} -ErrorAction Stop | \
             Select-Object ifIndex,Status | ConvertTo-Json -Compress",
            ps_quote(name)
        ),
        WinCommand::GetIpv4Addresses(ifindex) => format!(
            "Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex {ifindex} \
             -PolicyStore ActiveStore -ErrorAction Stop | \
             Select-Object IPAddress,PrefixLength | ConvertTo-Json -Compress"
        ),
        WinCommand::FindRouteTo(ip) => format!(
            // Windows 10's Find-NetRoute has no -AddressFamily parameter
            // (added later).  It emits one row with a null DestinationPrefix
            // (the local source address) plus the matching route row, so
            // filter to the row that actually carries a route.
            "Find-NetRoute -RemoteIPAddress {} -ErrorAction Stop | \
             Where-Object {{ $_.DestinationPrefix }} | \
             Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric,IPAddress | \
             ConvertTo-Json -Compress",
            ps_quote(&ip.to_string())
        ),
        WinCommand::AddIpAddress {
            ifindex,
            address,
            prefix_len,
        } => format!(
            "New-NetIPAddress -InterfaceIndex {ifindex} -IPAddress {} -PrefixLength {prefix_len} \
             -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
            ps_quote(&address.to_string())
        ),
        WinCommand::RemoveIpAddress { ifindex, address } => format!(
            "Remove-NetIPAddress -InterfaceIndex {ifindex} -IPAddress {} -PolicyStore ActiveStore \
             -Confirm:$false -ErrorAction Stop",
            ps_quote(&address.to_string())
        ),
        WinCommand::AddRoute(route) => format!(
            "New-NetRoute -DestinationPrefix {} -InterfaceIndex {} -NextHop {} -RouteMetric {} \
             -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop | Out-Null",
            ps_quote(&route.dest),
            route.ifindex,
            ps_quote(&route.next_hop.to_string()),
            route.metric
        ),
        WinCommand::RemoveRoute {
            dest,
            ifindex,
            next_hop,
            metric,
        } => format!(
            // Direct cmdlet only.  The previous `Get-NetRoute ... |
            // Remove-NetRoute -PolicyStore ActiveStore` pipeline stalled the
            // Windows network stack even with no Wintun adapter open; the
            // direct form with the same exact route identity was safe in
            // manual testing.
            "Remove-NetRoute -DestinationPrefix {dest} -InterfaceIndex {ifindex} \
             -NextHop {next_hop} -RouteMetric {metric} -Confirm:$false -ErrorAction Stop",
            dest = ps_quote(dest),
            next_hop = ps_quote(&next_hop.to_string()),
            metric = metric
        ),
        WinCommand::SetInterfaceMetric { ifindex, metric } => format!(
            "Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex {ifindex} \
             -InterfaceMetric {metric} -PolicyStore ActiveStore -ErrorAction Stop"
        ),
        WinCommand::SetAutomaticMetric(ifindex) => format!(
            "Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex {ifindex} \
             -AutomaticMetric Enabled -PolicyStore ActiveStore -ErrorAction Stop"
        ),
        WinCommand::GetDnsServers(ifindex) => format!(
            "Get-DnsClientServerAddress -InterfaceIndex {ifindex} -AddressFamily IPv4 \
             -ErrorAction Stop | Select-Object InterfaceIndex,ServerAddresses | \
             ConvertTo-Json -Compress"
        ),
        WinCommand::SetDnsServers { ifindex, servers } => format!(
            "Set-DnsClientServerAddress -InterfaceIndex {ifindex} -ServerAddresses {} \
             -ErrorAction Stop",
            ps_array(servers)
        ),
        WinCommand::ResetDnsServers(ifindex) => format!(
            "Set-DnsClientServerAddress -InterfaceIndex {ifindex} -ResetServerAddresses \
             -ErrorAction Stop"
        ),
        WinCommand::AddNrpt { display, servers } => format!(
            "Add-DnsClientNrptRule -Namespace '.' -NameServers {} -DisplayName {} \
             -Comment 'RustVPN tunnel DNS; removed on disconnect' -ErrorAction Stop | Out-Null",
            ps_array(servers),
            ps_quote(display)
        ),
        WinCommand::FindNrpt { display } => format!(
            "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.DisplayName -eq {} }} | \
             Select-Object Name,DisplayName | ConvertTo-Json -Compress",
            ps_quote(display)
        ),
        WinCommand::RemoveNrpt { name } => format!(
            "Remove-DnsClientNrptRule -Name {} -Force -ErrorAction Stop",
            ps_quote(name)
        ),
        WinCommand::AddIpv6Block { name } => format!(
            "New-NetFirewallRule -Name {} -DisplayName 'RustVPN IPv6 leak block' \
             -Description 'Blocks global/ULA IPv6 egress while the RustVPN full tunnel is up' \
             -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any \
             -RemoteAddress {} -ErrorAction Stop | Out-Null",
            ps_quote(name),
            ps_array(&["2000::/3", "fc00::/7"])
        ),
        WinCommand::RemoveFirewallRule { name } => format!(
            "Remove-NetFirewallRule -Name {} -ErrorAction SilentlyContinue",
            ps_quote(name)
        ),
    }
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

fn parse_json_rows<T: serde::de::DeserializeOwned>(text: &str) -> Result<Vec<T>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value =
        serde_json::from_str(text).with_context(|| format!("parse JSON {text:?}"))?;
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .into_iter()
            .map(|item| serde_json::from_value(item).context("parse JSON row"))
            .collect(),
        Value::Object(_) => Ok(vec![
            serde_json::from_value(value).context("parse JSON row")?
        ]),
        other => Err(anyhow!("expected a JSON object or array, got {other}")),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PsRoute {
    destination_prefix: String,
    interface_index: u32,
    next_hop: Option<String>,
    route_metric: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PsIface {
    interface_index: u32,
    interface_metric: u32,
    // Windows PowerShell 5.1 serializes these two CIM enums as numbers
    // (`AutomaticMetric: 0/1`, `ConnectionState: 0/1`) while tests and
    // Windows PowerShell 7 may emit the names.  Accept both shapes.
    automatic_metric: Option<Value>,
    connection_state: Option<Value>,
    nl_mtu: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PsAddress {
    #[serde(rename = "IPAddress")]
    ip_address: String,
    prefix_length: u8,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PsAdapter {
    #[serde(rename = "ifIndex")]
    if_index: u32,
    #[serde(rename = "Name")]
    name: String,
    // `MtuSize` from `Get-NetAdapter` is the NDIS L2 MTU.  For Wintun that is
    // the fixed 65535 link value, not the IP interface MTU the driver sets via
    // `SetIpInterfaceEntry`; the authoritative check uses
    // `Get-NetIPInterface ... NlMtu` after the address is assigned.  The field
    // is intentionally not parsed so it cannot be mistaken for the IP MTU.
    status: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PsDns {
    interface_index: u32,
    server_addresses: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PsNrpt {
    name: String,
    display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub dest: String,
    pub ifindex: u32,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub ifindex: u32,
    pub metric: u32,
    pub automatic: bool,
    pub connected: bool,
    pub mtu: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressEntry {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterNameEntry {
    pub ifindex: u32,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterInfo {
    pub ifindex: u32,
    pub up: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundRoute {
    pub dest: String,
    pub ifindex: u32,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

pub fn parse_routes(text: &str) -> Result<Vec<RouteEntry>> {
    Ok(parse_json_rows::<PsRoute>(text)?
        .into_iter()
        .map(|row| RouteEntry {
            dest: row.destination_prefix,
            ifindex: row.interface_index,
            next_hop: parse_next_hop(row.next_hop.as_deref()),
            metric: row.route_metric,
        })
        .collect())
}

/// Interpret a CIM enum emitted either as its name or as a numeric value.
///
/// `None` when the value is absent or an unexpected JSON shape, so callers can
/// keep their defaults.
fn ps_flag(value: Option<&Value>, name: &str) -> Option<bool> {
    match value? {
        Value::String(text) => Some(text.eq_ignore_ascii_case(name)),
        Value::Number(number) => Some(number.as_i64().is_some_and(|value| value != 0)),
        Value::Bool(value) => Some(*value),
        _ => None,
    }
}

pub fn parse_interfaces(text: &str) -> Result<Vec<InterfaceEntry>> {
    Ok(parse_json_rows::<PsIface>(text)?
        .into_iter()
        .map(|row| InterfaceEntry {
            ifindex: row.interface_index,
            metric: row.interface_metric,
            automatic: ps_flag(row.automatic_metric.as_ref(), "enabled").unwrap_or(false),
            connected: ps_flag(row.connection_state.as_ref(), "connected").unwrap_or(true),
            mtu: row.nl_mtu,
        })
        .collect())
}

pub fn parse_addresses(text: &str) -> Result<Vec<AddressEntry>> {
    parse_json_rows::<PsAddress>(text)?
        .into_iter()
        .map(|row| {
            let address = row
                .ip_address
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid IPv4 address {:?}", row.ip_address))?;
            Ok(AddressEntry {
                address,
                prefix_len: row.prefix_length,
            })
        })
        .collect()
}

pub fn parse_adapter(text: &str) -> Result<AdapterInfo> {
    let row = parse_json_rows::<PsAdapter>(text)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Get-NetAdapter returned no adapter"))?;
    Ok(AdapterInfo {
        ifindex: row.if_index,
        up: row
            .status
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("up"))
            .unwrap_or(true),
    })
}

pub fn parse_adapters(text: &str) -> Result<Vec<AdapterNameEntry>> {
    Ok(parse_json_rows::<PsAdapter>(text)?
        .into_iter()
        .map(|row| AdapterNameEntry {
            ifindex: row.if_index,
            name: row.name,
        })
        .collect())
}

pub fn parse_dns(text: &str) -> Result<Vec<Ipv4Addr>> {
    let rows = parse_json_rows::<PsDns>(text)?;
    let mut servers = Vec::new();
    for row in rows {
        for server in row.server_addresses {
            servers.push(
                server
                    .parse::<Ipv4Addr>()
                    .with_context(|| format!("invalid DNS address {server:?}"))?,
            );
        }
    }
    Ok(servers)
}

pub fn parse_nrpt(text: &str) -> Result<Vec<(String, String)>> {
    Ok(parse_json_rows::<PsNrpt>(text)?
        .into_iter()
        .map(|row| (row.name, row.display_name))
        .collect())
}

fn parse_next_hop(value: Option<&str>) -> Ipv4Addr {
    value
        .unwrap_or("")
        .trim()
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// `Find-NetRoute` emits one object per type (address + route).  Pick the
/// route object.
pub fn parse_found_route(text: &str) -> Result<FoundRoute> {
    let rows = parse_json_rows::<PsRoute>(text)?;
    let row = rows
        .into_iter()
        .find(|row| !row.destination_prefix.is_empty())
        .ok_or_else(|| anyhow!("Find-NetRoute returned no route"))?;
    let next_hop = parse_next_hop(row.next_hop.as_deref());
    Ok(FoundRoute {
        dest: row.destination_prefix,
        ifindex: row.interface_index,
        next_hop,
        metric: row.route_metric,
    })
}

// ---------------------------------------------------------------------------
// Profile parsing helpers
// ---------------------------------------------------------------------------

pub struct PlannedProfile {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub connected: String,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub routes: Vec<String>,
    pub has_default: bool,
}

pub fn plan_profile(spec: &ProfileSpec) -> Result<PlannedProfile> {
    if spec.ipv6 {
        bail!("IPv6 is not implemented");
    }
    if spec.address.trim().is_empty() {
        bail!("profile has no address");
    }
    let net: IpNet = spec
        .address
        .parse()
        .with_context(|| format!("invalid address {:?}", spec.address))?;
    let IpNet::V4(v4) = net else {
        bail!("IPv6 addresses are not supported");
    };
    if v4.prefix_len() == 0 {
        bail!("address prefix /0 is not allowed");
    }
    let gateway = if spec.gateway.trim().is_empty() {
        None
    } else {
        let gateway: Ipv4Addr = spec
            .gateway
            .parse()
            .with_context(|| format!("invalid gateway {:?}", spec.gateway))?;
        if gateway.is_unspecified() {
            bail!("gateway must not be 0.0.0.0");
        }
        if !rustvpn_net::shim::ipv4::in_same_subnet(gateway, v4.addr(), v4.prefix_len()) {
            bail!(
                "gateway {gateway} is not on-link for {}/{}; the Wintun shim cannot resolve                  an off-link next hop",
                v4.addr(),
                v4.prefix_len()
            );
        }
        Some(gateway)
    };
    let dns = spec
        .dns
        .iter()
        .map(|server| {
            server
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid DNS server {server:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if dns.is_empty() && spec.routes.iter().any(|route| is_default_route(route)) {
        bail!("full-tunnel profile requires at least one DNS server");
    }

    let mut routes = Vec::new();
    let mut has_default = false;
    for route in &spec.routes {
        let route = route.trim();
        if route.is_empty() {
            continue;
        }
        if is_default_route(route) {
            if !has_default {
                routes.push("0.0.0.0/0".to_string());
                has_default = true;
            }
            continue;
        }
        let net: IpNet = route
            .parse()
            .with_context(|| format!("invalid route {route:?}"))?;
        let IpNet::V4(net) = net else {
            bail!("IPv6 routes are not supported");
        };
        routes.push(net.trunc().to_string());
    }
    let connected = v4.trunc().to_string();
    Ok(PlannedProfile {
        address: v4.addr(),
        prefix_len: v4.prefix_len(),
        connected,
        gateway,
        dns,
        routes,
        has_default,
    })
}

// ---------------------------------------------------------------------------
// Crash-recovery state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerToken {
    pub pid: u32,
    /// Process creation time in 100 ns Windows FILETIME units; `0` when the
    /// platform cannot provide it (tests).  Comparing it prevents PID reuse
    /// from making a stale state look live.
    pub started: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRoute {
    pub dest: String,
    pub ifindex: u32,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
    pub kind: RouteKind,
    /// Adapter name recorded at install, used to detect interface-index reuse.
    #[serde(default)]
    pub alias: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedAddress {
    pub ifindex: u32,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMetric {
    pub ifindex: u32,
    pub previous_metric: u32,
    pub previous_automatic: bool,
    pub set_metric: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedDns {
    pub ifindex: u32,
    pub previous: Vec<Ipv4Addr>,
    pub applied: Vec<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedNrpt {
    pub display: String,
    pub servers: Vec<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedFirewall {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    pub schema: u32,
    pub owner: OwnerToken,
    pub iface: String,
    pub adapter_index: u32,
    pub updated_unix: u64,
    #[serde(default)]
    pub address: Option<PersistedAddress>,
    #[serde(default)]
    pub routes: Vec<PersistedRoute>,
    #[serde(default)]
    pub interface_metric: Option<PersistedMetric>,
    #[serde(default)]
    pub dns: Option<PersistedDns>,
    #[serde(default)]
    pub nrpt: Option<PersistedNrpt>,
    #[serde(default)]
    pub ipv6_block: Option<PersistedFirewall>,
}

impl PersistedState {
    fn new(owner: OwnerToken, iface: &str, adapter_index: u32) -> Self {
        Self {
            schema: STATE_SCHEMA,
            owner,
            iface: iface.to_string(),
            adapter_index,
            updated_unix: unix_now(),
            address: None,
            routes: Vec::new(),
            interface_metric: None,
            dns: None,
            nrpt: None,
            ipv6_block: None,
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Plain JSON state store.  The Windows executor wraps this with restrictive
/// ACLs (SYSTEM + Administrators); unit tests use it in a temporary directory.
pub struct FileStateStore {
    dir: PathBuf,
}

impl FileStateStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn state_path(dir: &std::path::Path) -> PathBuf {
        dir.join("netstate.json")
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<Option<PersistedState>> {
        let path = Self::state_path(&self.dir);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let state: PersistedState = serde_json::from_str(&text)
            .with_context(|| format!("parse state file {}", path.display()))?;
        if state.schema != STATE_SCHEMA {
            bail!(
                "state file {} has schema {} but this client understands {}; refusing to guess",
                path.display(),
                state.schema,
                STATE_SCHEMA
            );
        }
        Ok(Some(state))
    }

    fn save(&self, state: &PersistedState) -> Result<()> {
        crate::netcfg::winplan::secure_state_dir(&self.dir)?;
        let path = Self::state_path(&self.dir);
        let tmp = self.dir.join("netstate.json.tmp");
        let text = serde_json::to_vec_pretty(state).context("serialize network state")?;
        write_state_file(&tmp, &text).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("replace state file {}", path.display()))?;
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let path = Self::state_path(&self.dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
        }
    }

    fn path(&self) -> PathBuf {
        Self::state_path(&self.dir)
    }
}

#[cfg(windows)]
fn write_state_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    super::windows::write_secure_file(path, data)
}

#[cfg(not(windows))]
fn write_state_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(windows)]
pub(crate) fn secure_state_dir(dir: &std::path::Path) -> Result<()> {
    super::windows::ensure_secure_state_dir(dir)
}

#[cfg(not(windows))]
pub(crate) fn secure_state_dir(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))
}

// ---------------------------------------------------------------------------
// Route decisions
// ---------------------------------------------------------------------------

/// What to do with one planned route given the current route table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Add the route and record it as RustVPN-owned.
    Add,
    /// An identical RustVPN-owned route is already present (idempotent).
    Idempotent,
    /// An identical, unowned route is present; reuse it but never delete it.
    Reuse,
    /// The route is the adapter's connected route; nothing to add.
    SkipConnected,
}

pub fn decide_route(
    planned: &RouteSpec,
    existing: &[RouteEntry],
    owned: &[PersistedRoute],
    connected: Option<(&str, u32)>,
) -> Result<RouteDecision> {
    if planned.kind == RouteKind::Split {
        if let Some((connected_dest, connected_index)) = connected {
            if planned.dest == connected_dest && planned.ifindex == connected_index {
                return Ok(RouteDecision::SkipConnected);
            }
        }
    }
    let same_dest: Vec<&RouteEntry> = existing
        .iter()
        .filter(|route| route.dest == planned.dest)
        .collect();
    let exact = same_dest.iter().any(|route| {
        route.ifindex == planned.ifindex
            && route.next_hop == planned.next_hop
            && route.metric == planned.metric
    });
    let owned_exact = owned.iter().any(|route| {
        route.dest == planned.dest
            && route.ifindex == planned.ifindex
            && route.next_hop == planned.next_hop
            && route.metric == planned.metric
    });

    match planned.kind {
        RouteKind::Host => {
            if same_dest.is_empty() {
                return Ok(RouteDecision::Add);
            }
            if exact {
                return Ok(if owned_exact {
                    RouteDecision::Idempotent
                } else {
                    RouteDecision::Reuse
                });
            }
            Err(conflict(planned, &same_dest))
        }
        RouteKind::Default => {
            let on_tunnel: Vec<&RouteEntry> = same_dest
                .iter()
                .copied()
                .filter(|route| route.ifindex == planned.ifindex)
                .collect();
            if on_tunnel.is_empty() {
                // Physical default routes are expected; they are not modified.
                return Ok(RouteDecision::Add);
            }
            if exact && owned_exact {
                return Ok(RouteDecision::Idempotent);
            }
            Err(conflict(planned, &on_tunnel))
        }
        RouteKind::Split => {
            if same_dest.is_empty() {
                return Ok(RouteDecision::Add);
            }
            if exact && owned_exact {
                return Ok(RouteDecision::Idempotent);
            }
            Err(conflict(planned, &same_dest))
        }
    }
}

fn conflict(planned: &RouteSpec, existing: &[&RouteEntry]) -> anyhow::Error {
    let detail = existing
        .first()
        .map(|route| {
            format!(
                "interface {} next hop {} metric {}",
                route.ifindex, route.next_hop, route.metric
            )
        })
        .unwrap_or_else(|| "unknown".into());
    anyhow!(
        "route {} already exists ({detail}); refusing to overwrite a pre-existing route \
         (requested interface {} next hop {} metric {})",
        planned.dest,
        planned.ifindex,
        planned.next_hop,
        planned.metric
    )
}

/// Default routes that would still win over the tunnel default (effective
/// metric `interface + route`, both lower or equal to ours).
pub fn default_takeover_conflicts(
    routes: &[RouteEntry],
    interfaces: &[InterfaceEntry],
    tunnel_index: u32,
    our_effective_metric: u32,
) -> Vec<RouteEntry> {
    routes
        .iter()
        .filter(|route| {
            route.ifindex != tunnel_index
                && is_default_route(&route.dest)
                && interfaces
                    .iter()
                    .find(|iface| iface.ifindex == route.ifindex)
                    .map(|iface| iface.connected)
                    .unwrap_or(true)
                && interfaces
                    .iter()
                    .find(|iface| iface.ifindex == route.ifindex)
                    .map(|iface| iface.metric.saturating_add(route.metric) <= our_effective_metric)
                    .unwrap_or(true)
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

pub struct InstallContext<'a> {
    pub runner: &'a dyn WinRunner,
    pub store: &'a dyn StateStore,
    pub probe: &'a dyn OwnerProbe,
    pub owner: OwnerToken,
}

/// Result of a failed install that may have applied some state.
///
/// The caller must stop the data plane (peer tasks and the Wintun reader)
/// before rolling `state` back, and must clear the state file only after the
/// adapter close.  `state` is `None` when the failure happened before any
/// mutation.
#[derive(Debug)]
pub struct PartialInstall {
    pub error: anyhow::Error,
    pub state: Option<PersistedState>,
}

#[cfg(test)]
pub async fn install_with(
    ctx: InstallContext<'_>,
    spec: &ProfileSpec,
    outer: Option<SocketAddr>,
    inner_mtu: usize,
    options: NetOptions,
) -> Result<PersistedState> {
    install_with_partial(ctx, spec, outer, inner_mtu, options)
        .await
        .map_err(|failure| failure.error)
}

/// Like the error-only test helper, but hands a partially applied state back
/// on failure.
///
/// This is the engine-facing form: rollback must happen only after the data
/// plane has been stopped, so `install_with_partial` never mutates the network
/// or clears the state file on the error path.
pub async fn install_with_partial(
    ctx: InstallContext<'_>,
    spec: &ProfileSpec,
    outer: Option<SocketAddr>,
    inner_mtu: usize,
    options: NetOptions,
) -> std::result::Result<PersistedState, PartialInstall> {
    let mut state = None;
    match install_inner(&ctx, spec, outer, inner_mtu, options, &mut state).await {
        Ok(()) => Ok(state.expect("a successful install records its state")),
        Err(error) => Err(PartialInstall { error, state }),
    }
}

async fn install_inner(
    ctx: &InstallContext<'_>,
    spec: &ProfileSpec,
    outer: Option<SocketAddr>,
    inner_mtu: usize,
    options: NetOptions,
    state_out: &mut Option<PersistedState>,
) -> Result<()> {
    // A previous state file must have been cleaned *before* the adapter was
    // opened (the engine does that).  Never issue Remove-Net* against a live
    // Wintun session here: refuse instead of mutating another connection's
    // state, and let the caller retry the pre-open cleanup.
    if let Some(previous) = ctx.store.load()? {
        // State owned by another live process is definitely not ours.
        if previous.owner != ctx.owner && ctx.probe.is_alive(&previous.owner) {
            bail!(
                "another RustVPN network guard is active (pid {}); refusing to touch its \
                 routes/DNS/firewall state",
                previous.owner.pid
            );
        }
        bail!(
            "previous RustVPN network state (owner pid {}) is still recorded at {}; the daemon \
             must clean it before opening an adapter",
            previous.owner.pid,
            ctx.store.path().display()
        );
    }

    if options.firewall.kill_switch || spec.kill_switch {
        bail!(
            "kill_switch is not implemented on Windows; refusing to connect rather than \
             leaving the host fail-open (deferred)"
        );
    }
    if inner_mtu == 0 {
        bail!("derived inner IP MTU is zero");
    }

    let plan = plan_profile(spec)?;
    if plan.has_default && outer.is_none() {
        bail!("cannot install a default route without resolving the outer endpoint");
    }
    if plan.has_default && plan.gateway.is_none() {
        bail!("full-tunnel profile requires a gateway for the tunnel next hop");
    }
    if let Some(outer) = outer {
        if outer.is_ipv6() {
            bail!(
                "Windows M3 supports only IPv4 outer endpoints: IPv6 is not tunnelled and \
                 full-tunnel profiles block IPv6 egress"
            );
        }
    }
    if options.firewall.mss_v4.is_some() || options.firewall.mss_v6.is_some() {
        eprintln!(
            "warning: Windows M3 does not implement TCP MSS clamping; the tunnel relies on \
             the configured wire-MTU contract (MSS is reported as not applied)"
        );
    }

    let adapter = match ctx
        .runner
        .run(&WinCommand::GetAdapterInfo(spec.iface.clone()))
        .await
    {
        Ok(text) => {
            parse_adapter(&text).with_context(|| format!("read Wintun adapter {:?}", spec.iface))?
        }
        Err(error) => bail!("resolve Wintun adapter {:?}: {error:#}", spec.iface),
    };
    // The MTU is *not* checked here: `Get-NetAdapter MtuSize` is the NDIS L2
    // MTU (65535 for Wintun), not the IP interface `NlMtu` the driver sets.
    // The address assignment makes the interface visible to
    // `Get-NetIPInterface`, whose `NlMtu` is checked below before any route is
    // installed; a wrong MTU rolls back the address instead of silently using
    // the wire/frame budget.
    if !adapter.up {
        bail!(
            "Wintun adapter {:?} is not up; refusing to install routes",
            spec.iface
        );
    }
    let adapter_index = adapter.ifindex;

    let mut state = PersistedState::new(ctx.owner, &spec.iface, adapter_index);
    if let Err(error) = install_steps(
        ctx,
        spec,
        &plan,
        outer,
        adapter_index,
        inner_mtu,
        &mut state,
        options,
    )
    .await
    {
        // Hand the partial state to the caller.  It stops the data plane and
        // rolls back after the peer tasks and Wintun reader are stopped; the
        // state file is cleared only after the adapter close.
        *state_out = Some(state);
        return Err(error.context("network setup failed"));
    }
    *state_out = Some(state);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn install_steps(
    ctx: &InstallContext<'_>,
    spec: &ProfileSpec,
    plan: &PlannedProfile,
    outer: Option<SocketAddr>,
    adapter_index: u32,
    inner_mtu: usize,
    state: &mut PersistedState,
    options: NetOptions,
) -> Result<()> {
    // Refuse to shadow an existing route for the tunnel subnet on another
    // interface (for example a LAN that uses the same /24).  Adding the
    // connected route would otherwise silently steal that subnet.
    let pre_routes = parse_routes(&run_text(ctx.runner, &WinCommand::ListIpv4Routes).await?)?;
    if let Some(route) = pre_routes
        .iter()
        .find(|route| route.ifindex != adapter_index && route.dest == plan.connected)
    {
        bail!(
            "tunnel subnet {} is already routed via interface {}; refusing to shadow an \
             existing on-link route",
            plan.connected,
            route.ifindex
        );
    }

    // Address/prefix.  The adapter is created before the handshake with the MTU
    // only; the address is installed here, after the handshake, so a failed
    // handshake cannot add an on-link route before the tunnel exists.
    let addresses = parse_addresses(
        &run_text(ctx.runner, &WinCommand::GetIpv4Addresses(adapter_index)).await?,
    )?;
    let wanted = AddressEntry {
        address: plan.address,
        prefix_len: plan.prefix_len,
    };
    let present = addresses.iter().find(|entry| entry.address == plan.address);
    match present {
        Some(entry) if *entry == wanted => {
            // Adopt the exact profile address: it is ours even if an old
            // crash lost the state file.
            state.address = Some(PersistedAddress {
                ifindex: adapter_index,
                address: plan.address,
                prefix_len: plan.prefix_len,
            });
        }
        Some(entry) => bail!(
            "Wintun adapter {:?} already has {}/{}, but the profile asks for {}/{}; refusing \
             to replace an address that does not match",
            spec.iface,
            entry.address,
            entry.prefix_len,
            plan.address,
            plan.prefix_len
        ),
        None => {
            // Windows auto-configures an APIPA (169.254.0.0/16) address on an
            // up adapter that has no static address yet.  It is system-owned,
            // not administrator state, and must not block the profile address.
            // Any other address is a conflict and is refused.
            if let Some(entry) = addresses
                .iter()
                .find(|entry| !entry.address.is_link_local())
            {
                bail!(
                    "Wintun adapter {:?} already has unrelated address {}/{}, but the profile \
                     asks for {}/{}; refusing to replace it",
                    spec.iface,
                    entry.address,
                    entry.prefix_len,
                    plan.address,
                    plan.prefix_len
                );
            }
            ctx.runner
                .run(&WinCommand::AddIpAddress {
                    ifindex: adapter_index,
                    address: plan.address,
                    prefix_len: plan.prefix_len,
                })
                .await
                .with_context(|| {
                    format!(
                        "add {}/{} to {:?}",
                        plan.address, plan.prefix_len, spec.iface
                    )
                })?;
            state.address = Some(PersistedAddress {
                ifindex: adapter_index,
                address: plan.address,
                prefix_len: plan.prefix_len,
            });
            ctx.store.save(state)?;
            let after = parse_addresses(
                &run_text(ctx.runner, &WinCommand::GetIpv4Addresses(adapter_index)).await?,
            )?;
            if !after.contains(&wanted) {
                bail!(
                    "address {}/{} was not visible on {:?} after New-NetIPAddress",
                    plan.address,
                    plan.prefix_len,
                    spec.iface
                );
            }
        }
    }
    if state.address.is_some() {
        ctx.store.save(state)?;
    }

    // The address makes the Wintun interface visible to Get-NetIPInterface;
    // its metric and state are needed for the route plan.
    let interfaces =
        parse_interfaces(&run_text(ctx.runner, &WinCommand::ListIpv4Interfaces).await?)?;
    let tunnel_iface = interfaces
        .iter()
        .find(|iface| iface.ifindex == adapter_index)
        .ok_or_else(|| {
            anyhow!(
                "the Wintun adapter (index {adapter_index}) is not visible to \
                 Get-NetIPInterface after address assignment"
            )
        })?;
    if !tunnel_iface.connected {
        bail!(
            "Wintun adapter {:?} is not connected after address assignment; refusing to install routes",
            state.iface
        );
    }
    if let Some(mtu) = tunnel_iface.mtu {
        if mtu as usize != inner_mtu {
            bail!(
                "Wintun adapter {:?} reports interface MTU {mtu}, but the wire MTU derives inner \
                 IP MTU {inner_mtu}; refusing to use the wire/frame budget",
                state.iface
            );
        }
    }
    let mut existing_routes =
        parse_routes(&run_text(ctx.runner, &WinCommand::ListIpv4Routes).await?)?;
    let adapter_names = parse_adapters(&run_text(ctx.runner, &WinCommand::ListAdapters).await?)?;

    // Pin the outer endpoint to the original path whenever an installed route
    // could capture it (any default route, or a split route containing the
    // outer address).  This must happen before the tunnel route is added.
    let outer_ip: Option<Ipv4Addr> = match outer {
        Some(SocketAddr::V4(addr)) => Some(*addr.ip()),
        _ => None,
    };
    // The anti-loop host route is installed before *any* tunnel route
    // (default or split).  It is a /32 through the original path, so it stays
    // more specific than every route installed below, even a split route that
    // happens to contain the outer address.
    let needs_anti_loop = outer_ip.is_some() && !plan.routes.is_empty();
    if let Some(outer_ip) = outer_ip.filter(|_| needs_anti_loop) {
        let found =
            parse_found_route(&run_text(ctx.runner, &WinCommand::FindRouteTo(outer_ip)).await?)?;
        if found.ifindex == adapter_index {
            bail!(
                "the current route to outer endpoint {outer_ip} already uses the tunnel adapter; \
                 refusing to install a recursive anti-loop route"
            );
        }
        let host = RouteSpec::new(
            format!("{outer_ip}/32"),
            found.ifindex,
            found.next_hop,
            HOST_ROUTE_METRIC,
            RouteKind::Host,
        );
        match decide_route(&host, &existing_routes, &state.routes, None)? {
            RouteDecision::Add => {
                ctx.runner
                    .run(&WinCommand::AddRoute(host.clone()))
                    .await
                    .with_context(|| format!("add anti-loop route for {outer_ip}"))?;
                let host_alias = adapter_names
                    .iter()
                    .find(|adapter| adapter.ifindex == found.ifindex)
                    .map(|adapter| adapter.name.clone())
                    .unwrap_or_default();
                state.routes.push(persisted(&host, &host_alias));
                ctx.store.save(state)?;
                existing_routes.push(entry(&host));
            }
            RouteDecision::Idempotent | RouteDecision::Reuse => {}
            RouteDecision::SkipConnected => unreachable!("host routes are never skipped"),
        }
    }

    // Full tunnel: lower the tunnel interface metric, then add the default
    // route (the anti-loop host route above is already in place).
    if plan.has_default {
        let conflicts = default_takeover_conflicts(
            &existing_routes,
            &interfaces,
            adapter_index,
            TUNNEL_INTERFACE_METRIC + DEFAULT_ROUTE_METRIC,
        );
        if let Some(route) = conflicts.first() {
            bail!(
                "existing default route on interface {} (next hop {}, metric {}) would still win \
                 over the RustVPN tunnel; refusing to claim a full tunnel (lower the other route \
                 or disconnect it first)",
                route.ifindex,
                route.next_hop,
                route.metric
            );
        }

        if tunnel_iface.metric != TUNNEL_INTERFACE_METRIC || tunnel_iface.automatic {
            ctx.runner
                .run(&WinCommand::SetInterfaceMetric {
                    ifindex: adapter_index,
                    metric: TUNNEL_INTERFACE_METRIC,
                })
                .await
                .with_context(|| format!("lower Wintun interface metric on {:?}", spec.iface))?;
            state.interface_metric = Some(PersistedMetric {
                ifindex: adapter_index,
                previous_metric: tunnel_iface.metric,
                previous_automatic: tunnel_iface.automatic,
                set_metric: TUNNEL_INTERFACE_METRIC,
            });
            ctx.store.save(state)?;
        }

        // Wintun is L3: the OS route is on-link (NextHop 0.0.0.0).  The
        // profile gateway is the *shim's* next hop for synthetic ARP and is
        // validated below; using it as an OS next hop would make Windows try
        // to ARP a gateway that Wintun cannot answer.
        let default_route = RouteSpec::new(
            "0.0.0.0/0",
            adapter_index,
            Ipv4Addr::UNSPECIFIED,
            DEFAULT_ROUTE_METRIC,
            RouteKind::Default,
        );
        match decide_route(&default_route, &existing_routes, &state.routes, None)? {
            RouteDecision::Add => {
                ctx.runner
                    .run(&WinCommand::AddRoute(default_route.clone()))
                    .await
                    .context("add the tunnel default route")?;
                let alias = state.iface.clone();
                state.routes.push(persisted(&default_route, &alias));
                ctx.store.save(state)?;
                existing_routes.push(entry(&default_route));
            }
            RouteDecision::Idempotent => {}
            RouteDecision::Reuse => bail!("an unowned identical default route already exists"),
            RouteDecision::SkipConnected => unreachable!("default routes are never skipped"),
        }
    }

    // Split routes (the default was handled above).
    for dest in plan
        .routes
        .iter()
        .filter(|dest| dest.as_str() != "0.0.0.0/0")
    {
        let next_hop = plan.gateway.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let route = RouteSpec::new(
            dest.clone(),
            adapter_index,
            next_hop,
            SPLIT_ROUTE_METRIC,
            RouteKind::Split,
        );
        match decide_route(
            &route,
            &existing_routes,
            &state.routes,
            Some((&plan.connected, adapter_index)),
        )? {
            RouteDecision::Add => {
                ctx.runner
                    .run(&WinCommand::AddRoute(route.clone()))
                    .await
                    .with_context(|| format!("add split route {dest}"))?;
                let alias = state.iface.clone();
                state.routes.push(persisted(&route, &alias));
                ctx.store.save(state)?;
                existing_routes.push(entry(&route));
            }
            RouteDecision::SkipConnected => {
                eprintln!(
                    "route {dest} is the Wintun adapter's own connected subnet; \
                     it is already present and is not added again"
                );
            }
            RouteDecision::Idempotent | RouteDecision::Reuse => {}
        }
    }

    // DNS + NRPT.
    if options.no_host_dns {
        if !plan.dns.is_empty() {
            eprintln!(
                "--no-host-dns is set; leaving resolver configuration to the caller \
                 (profile DNS values are not applied)"
            );
        }
    } else if !plan.dns.is_empty() {
        let current =
            parse_dns(&run_text(ctx.runner, &WinCommand::GetDnsServers(adapter_index)).await?)?;
        if current != plan.dns {
            state.dns = Some(PersistedDns {
                ifindex: adapter_index,
                previous: current,
                applied: plan.dns.clone(),
            });
            ctx.store.save(state)?;
            ctx.runner
                .run(&WinCommand::SetDnsServers {
                    ifindex: adapter_index,
                    servers: plan.dns.clone(),
                })
                .await
                .with_context(|| format!("set DNS on {:?}", spec.iface))?;
            let after =
                parse_dns(&run_text(ctx.runner, &WinCommand::GetDnsServers(adapter_index)).await?)?;
            if after != plan.dns {
                bail!(
                    "DNS servers on {:?} are {after:?} after Set-DnsClientServerAddress, \
                     expected {:?}",
                    spec.iface,
                    plan.dns
                );
            }
        }
        if plan.has_default {
            let display = format!("{NRPT_DISPLAY} ({})", spec.iface);
            state.nrpt = Some(PersistedNrpt {
                display: display.clone(),
                servers: plan.dns.clone(),
            });
            ctx.store.save(state)?;
            // Remove a duplicate left by an interrupted run, then add.
            let stale = parse_nrpt(
                &run_text(
                    ctx.runner,
                    &WinCommand::FindNrpt {
                        display: display.clone(),
                    },
                )
                .await?,
            )?;
            for (name, _) in stale {
                ctx.runner
                    .run(&WinCommand::RemoveNrpt { name })
                    .await
                    .context("remove a stale RustVPN NRPT rule")?;
            }
            ctx.runner
                .run(&WinCommand::AddNrpt {
                    display: display.clone(),
                    servers: plan.dns.clone(),
                })
                .await
                .context("add the RustVPN NRPT rule")?;
            let created =
                parse_nrpt(&run_text(ctx.runner, &WinCommand::FindNrpt { display }).await?)?;
            if created.is_empty() {
                bail!("the RustVPN NRPT rule could not be located after Add-DnsClientNrptRule");
            }
        }
    } else if plan.has_default {
        bail!("full-tunnel profile requires at least one DNS server");
    }

    // IPv6 leak block: full tunnel only.  Global unicast and ULA destinations
    // are blocked; loopback/link-local/multicast stay usable for ND and local
    // services.  Split tunnels never install this rule.
    if plan.has_default {
        state.ipv6_block = Some(PersistedFirewall {
            name: IPV6_BLOCK_RULE.to_string(),
        });
        ctx.store.save(state)?;
        // Removing the fixed-name rule first makes retries idempotent without
        // relying on New-NetFirewallRule -Force (not available everywhere).
        ctx.runner
            .run(&WinCommand::RemoveFirewallRule {
                name: IPV6_BLOCK_RULE.to_string(),
            })
            .await
            .context("clear a stale Windows IPv6 leak block")?;
        ctx.runner
            .run(&WinCommand::AddIpv6Block {
                name: IPV6_BLOCK_RULE.to_string(),
            })
            .await
            .context("install the Windows IPv6 leak block")?;
    }

    ctx.store.save(state)?;
    Ok(())
}

async fn run_text(runner: &dyn WinRunner, command: &WinCommand) -> Result<String> {
    runner.run(command).await
}

fn persisted(route: &RouteSpec, alias: &str) -> PersistedRoute {
    PersistedRoute {
        dest: route.dest.clone(),
        ifindex: route.ifindex,
        next_hop: route.next_hop,
        metric: route.metric,
        kind: route.kind,
        alias: alias.to_string(),
    }
}

fn entry(route: &RouteSpec) -> RouteEntry {
    RouteEntry {
        dest: route.dest.clone(),
        ifindex: route.ifindex,
        next_hop: route.next_hop,
        metric: route.metric,
    }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct CleanupReport {
    pub actions: Vec<String>,
    pub errors: Vec<String>,
    pub skipped_live_owner: bool,
}

impl CleanupReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Clear the state file only when cleanup completed.
///
/// Call this **after** the Wintun adapter has been closed (or when no adapter
/// is open at all).  A crash/hang in the close window then leaves the recovery
/// record in place for the next daemon start instead of silently losing it.
pub fn clear_state_if_clean(store: &dyn StateStore, report: &CleanupReport) -> Result<bool> {
    if report.ok() {
        store.clear()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Remove everything recorded in `state`, verifying each entry before touching
/// it.  Never removes an entry that is not in the state file.
///
/// This is the crash-recovery form: it also removes the recorded IPv4 address.
pub async fn cleanup_state(runner: &dyn WinRunner, state: &PersistedState) -> CleanupReport {
    cleanup_state_with(runner, state, true).await
}

/// Remove RustVPN-owned network state, optionally keeping the Wintun address.
///
/// `remove_address == false` is the **normal disconnect/teardown** form.  The
/// Wintun adapter is closed immediately afterwards by the engine, and closing
/// a created Wintun adapter removes its address and the implicit connected
/// route.  Removing them explicitly first (`Remove-NetIPAddress` while the
/// session is still open) is the suspected trigger of the Windows network-stack
/// hang, so the connection path keeps the address and lets the adapter close
/// remove it.  Everything that outlives the adapter (anti-loop/split routes,
/// DNS, NRPT, interface metric, IPv6 firewall rule) is still removed here.
///
/// Crash recovery and stale-state cleanup keep `remove_address == true`: the
/// owning adapter may still exist (for example a pre-existing adapter that was
/// opened rather than created), and there is no following adapter close to
/// rely on.
pub async fn cleanup_state_with(
    runner: &dyn WinRunner,
    state: &PersistedState,
    remove_address: bool,
) -> CleanupReport {
    let mut report = CleanupReport::default();

    // NRPT first: once the tunnel routes go away, a rule forcing all DNS into
    // the tunnel would break name resolution.
    if let Some(nrpt) = &state.nrpt {
        match runner
            .run(&WinCommand::FindNrpt {
                display: nrpt.display.clone(),
            })
            .await
        {
            Ok(text) => match parse_nrpt(&text) {
                Ok(rules) => {
                    for (name, _) in rules {
                        match runner
                            .run(&WinCommand::RemoveNrpt { name: name.clone() })
                            .await
                        {
                            Ok(_) => report.actions.push(format!("remove NRPT rule {name}")),
                            Err(error) => report
                                .errors
                                .push(format!("remove NRPT rule {name}: {error:#}")),
                        }
                    }
                }
                Err(error) => report.errors.push(format!("list NRPT rules: {error:#}")),
            },
            Err(error) => report.errors.push(format!("find NRPT rule: {error:#}")),
        }
    }

    // Adapter names are used to detect Windows interface-index reuse: a stale
    // index that now belongs to another adapter must never be touched.
    let adapter_names = match runner.run(&WinCommand::ListAdapters).await {
        Ok(text) => match parse_adapters(&text) {
            Ok(adapters) => Some(adapters),
            Err(error) => {
                report.errors.push(format!("list adapters: {error:#}"));
                None
            }
        },
        Err(error) => {
            report.errors.push(format!("list adapters: {error:#}"));
            None
        }
    };
    let alias_matches = |ifindex: u32, expected: &str| {
        adapter_names
            .as_ref()
            .and_then(|adapters| {
                adapters
                    .iter()
                    .find(|adapter| adapter.ifindex == ifindex)
                    .map(|adapter| adapter.name.eq_ignore_ascii_case(expected))
            })
            .unwrap_or(false)
    };

    // DNS restore, only if the interface still exists with the recorded name
    // and still carries the servers we applied.
    if let Some(dns) = &state.dns {
        if !alias_matches(dns.ifindex, &state.iface) {
            report.actions.push(format!(
                "skip DNS restore on interface {}: index now belongs to another adapter or is gone",
                dns.ifindex
            ));
        } else {
            match runner.run(&WinCommand::GetDnsServers(dns.ifindex)).await {
                Ok(text) => match parse_dns(&text) {
                    Ok(current) if current == dns.applied => {
                        let restore = if dns.previous.is_empty() {
                            runner.run(&WinCommand::ResetDnsServers(dns.ifindex)).await
                        } else {
                            runner
                                .run(&WinCommand::SetDnsServers {
                                    ifindex: dns.ifindex,
                                    servers: dns.previous.clone(),
                                })
                                .await
                        };
                        match restore {
                            Ok(_) => report.actions.push(format!(
                                "restore DNS on interface {} to {:?}",
                                dns.ifindex, dns.previous
                            )),
                            Err(error) => report.errors.push(format!(
                                "restore DNS on interface {}: {error:#}",
                                dns.ifindex
                            )),
                        }
                    }
                    Ok(current) => report.actions.push(format!(
                        "skip DNS restore on interface {}: current {:?} differs from applied {:?}",
                        dns.ifindex, current, dns.applied
                    )),
                    Err(error) => report.errors.push(format!("read DNS servers: {error:#}")),
                },
                Err(error) => report.actions.push(format!(
                    "skip DNS restore on interface {}: {error:#}",
                    dns.ifindex
                )),
            }
        }
    }

    // Routes: tunnel routes first, the anti-loop host route last, so the outer
    // endpoint never briefly follows the tunnel default.
    let routes = match runner.run(&WinCommand::ListIpv4Routes).await {
        Ok(text) => match parse_routes(&text) {
            Ok(routes) => Some(routes),
            Err(error) => {
                report.errors.push(format!("list routes: {error:#}"));
                None
            }
        },
        Err(error) => {
            report.errors.push(format!("list routes: {error:#}"));
            None
        }
    };
    if let Some(current) = routes {
        let mut ordered: Vec<&PersistedRoute> = state
            .routes
            .iter()
            .filter(|route| route.kind != RouteKind::Host)
            .collect();
        ordered.extend(
            state
                .routes
                .iter()
                .filter(|route| route.kind == RouteKind::Host),
        );
        for route in ordered {
            if !route.alias.is_empty() && !alias_matches(route.ifindex, &route.alias) {
                report.actions.push(format!(
                    "skip route {} on interface {}: index now belongs to another adapter",
                    route.dest, route.ifindex
                ));
                continue;
            }
            let exists = current.iter().any(|entry| {
                entry.dest == route.dest
                    && entry.ifindex == route.ifindex
                    && entry.next_hop == route.next_hop
                    && entry.metric == route.metric
            });
            if !exists {
                report.actions.push(format!(
                    "route {} on interface {} already absent",
                    route.dest, route.ifindex
                ));
                continue;
            }
            match runner
                .run(&WinCommand::RemoveRoute {
                    dest: route.dest.clone(),
                    ifindex: route.ifindex,
                    next_hop: route.next_hop,
                    metric: route.metric,
                })
                .await
            {
                Ok(_) => report.actions.push(format!(
                    "remove route {} on interface {}",
                    route.dest, route.ifindex
                )),
                Err(error) => report.errors.push(format!(
                    "remove route {} on interface {}: {error:#}",
                    route.dest, route.ifindex
                )),
            }
        }
    }

    if let Some(address) = &state.address {
        if !remove_address {
            // Normal teardown: the adapter is closed next.  Closing a created
            // Wintun adapter removes the address and its implicit connected
            // route as part of the same NDIS teardown; issuing
            // `Remove-NetIPAddress` first while the session is open is the
            // suspected hang trigger.
            report.actions.push(format!(
                "keep address {}/{} on interface {} for the adapter close",
                address.address, address.prefix_len, address.ifindex
            ));
        } else if !alias_matches(address.ifindex, &state.iface) {
            report.actions.push(format!(
                "skip address removal on interface {}: index now belongs to another adapter",
                address.ifindex
            ));
        } else {
            match runner
                .run(&WinCommand::GetIpv4Addresses(address.ifindex))
                .await
            {
                Ok(text) => match parse_addresses(&text) {
                    Ok(entries)
                        if entries.iter().any(|entry| {
                            entry.address == address.address
                                && entry.prefix_len == address.prefix_len
                        }) =>
                    {
                        match runner
                            .run(&WinCommand::RemoveIpAddress {
                                ifindex: address.ifindex,
                                address: address.address,
                            })
                            .await
                        {
                            Ok(_) => report.actions.push(format!(
                                "remove address {}/{}",
                                address.address, address.prefix_len
                            )),
                            Err(error) => report
                                .errors
                                .push(format!("remove address {}: {error:#}", address.address)),
                        }
                    }
                    Ok(_) => report.actions.push(format!(
                        "address {} on interface {} already absent",
                        address.address, address.ifindex
                    )),
                    Err(error) => report.errors.push(format!("read addresses: {error:#}")),
                },
                Err(error) => report.actions.push(format!(
                    "skip address removal on interface {}: {error:#}",
                    address.ifindex
                )),
            }
        }
    }

    if let Some(metric) = &state.interface_metric {
        if !alias_matches(metric.ifindex, &state.iface) {
            report.actions.push(format!(
                "skip interface {} metric restore: index now belongs to another adapter",
                metric.ifindex
            ));
        } else {
            match runner.run(&WinCommand::ListIpv4Interfaces).await {
                Ok(text) => match parse_interfaces(&text) {
                    Ok(interfaces) => match interfaces
                        .iter()
                        .find(|iface| iface.ifindex == metric.ifindex)
                    {
                        Some(iface) if iface.metric == metric.set_metric && !iface.automatic => {
                            let restore = if metric.previous_automatic {
                                runner
                                    .run(&WinCommand::SetAutomaticMetric(metric.ifindex))
                                    .await
                            } else {
                                runner
                                    .run(&WinCommand::SetInterfaceMetric {
                                        ifindex: metric.ifindex,
                                        metric: metric.previous_metric,
                                    })
                                    .await
                            };
                            match restore {
                                Ok(_) => report
                                    .actions
                                    .push(format!("restore interface {} metric", metric.ifindex)),
                                Err(error) => report.errors.push(format!(
                                    "restore interface {} metric: {error:#}",
                                    metric.ifindex
                                )),
                            }
                        }
                        Some(iface) => report.actions.push(format!(
                            "skip interface {} metric restore: now {} (automatic {})",
                            metric.ifindex, iface.metric, iface.automatic
                        )),
                        None => report.actions.push(format!(
                            "interface {} no longer exists; metric is gone with it",
                            metric.ifindex
                        )),
                    },
                    Err(error) => report.errors.push(format!("read interfaces: {error:#}")),
                },
                Err(error) => report.errors.push(format!("read interfaces: {error:#}")),
            }
        }
    }

    if let Some(block) = &state.ipv6_block {
        match runner
            .run(&WinCommand::RemoveFirewallRule {
                name: block.name.clone(),
            })
            .await
        {
            Ok(_) => report
                .actions
                .push(format!("remove firewall rule {}", block.name)),
            Err(error) => report
                .errors
                .push(format!("remove firewall rule {}: {error:#}", block.name)),
        }
    }

    report
}

// ---------------------------------------------------------------------------
// Ordered Windows teardown
// ---------------------------------------------------------------------------

/// Phase 1 of the normal Windows teardown: remove everything except routes and
/// the address while the Wintun session is still open.
///
/// NRPT is removed first so DNS never points into a tunnel whose routes are
/// about to change; DNS, the interface metric and the IPv6 firewall block
/// follow.  No `Remove-NetRoute` or `Remove-NetIPAddress` is issued here:
/// removing the anti-loop host route while the Wintun session is live stalls
/// the Windows network stack, and the adapter close removes the Wintun address
/// and its connected routes.
pub async fn cleanup_non_route_state_with(
    runner: &dyn WinRunner,
    state: &PersistedState,
) -> CleanupReport {
    let mut filtered = state.clone();
    filtered.routes.clear();
    filtered.address = None;
    cleanup_state_with(runner, &filtered, false).await
}

/// Retry cleanup of state owned by *this* process (for example after a normal
/// disconnect whose first cleanup attempt failed).  Other daemons' state is
/// never touched.
pub async fn cleanup_owned_with(
    runner: &dyn WinRunner,
    store: &dyn StateStore,
    owner: &OwnerToken,
) -> Result<CleanupReport> {
    let Some(state) = store.load()? else {
        return Ok(CleanupReport::default());
    };
    if state.owner != *owner {
        return Ok(CleanupReport::default());
    }
    let report = cleanup_state(runner, &state).await;
    let _ = clear_state_if_clean(store, &report)?;
    Ok(report)
}

/// Startup crash recovery: clean only when the recorded owner is not alive.
pub async fn cleanup_stale_with(
    runner: &dyn WinRunner,
    store: &dyn StateStore,
    probe: &dyn OwnerProbe,
) -> Result<CleanupReport> {
    let Some(state) = store.load()? else {
        return Ok(CleanupReport::default());
    };
    if probe.is_alive(&state.owner) {
        return Ok(CleanupReport {
            skipped_live_owner: true,
            ..CleanupReport::default()
        });
    }
    let report = cleanup_state(runner, &state).await;
    let _ = clear_state_if_clean(store, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    fn iface(ifindex: u32, metric: u32) -> InterfaceEntry {
        InterfaceEntry {
            ifindex,
            metric,
            automatic: true,
            connected: true,
            mtu: Some(1500),
        }
    }

    fn route(dest: &str, ifindex: u32, next_hop: &str, metric: u32) -> RouteEntry {
        RouteEntry {
            dest: dest.into(),
            ifindex,
            next_hop: next_hop.parse().unwrap(),
            metric,
        }
    }

    #[test]
    fn parses_route_interface_and_dns_json() {
        let routes = parse_routes(
            r#"[{"DestinationPrefix":"0.0.0.0/0","InterfaceIndex":12,"NextHop":"192.168.1.1","RouteMetric":25},
                {"DestinationPrefix":"10.88.0.0/24","InterfaceIndex":7,"NextHop":"0.0.0.0","RouteMetric":256}]"#,
        )
        .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].next_hop, Ipv4Addr::new(192, 168, 1, 1));

        let interfaces = parse_interfaces(
            r#"{"InterfaceIndex":7,"InterfaceMetric":1,"AutomaticMetric":"Disabled","ConnectionState":"Connected","NlMtu":1500}"#,
        )
        .unwrap();
        assert_eq!(interfaces[0].mtu, Some(1500));
        assert!(!interfaces[0].automatic);

        // Windows PowerShell 5.1 emits the CIM enums as numbers: 0/1 for
        // AutomaticMetric (Disabled/Enabled) and ConnectionState
        // (Disconnected/Connected).
        let numeric = parse_interfaces(
            r#"[{"InterfaceIndex":7,"InterfaceMetric":5000,"AutomaticMetric":0,"ConnectionState":1,"NlMtu":1476},
                {"InterfaceIndex":12,"InterfaceMetric":25,"AutomaticMetric":1,"ConnectionState":0,"NlMtu":1500}]"#,
        )
        .unwrap();
        assert!(!numeric[0].automatic);
        assert!(numeric[0].connected);
        assert_eq!(numeric[0].mtu, Some(1476));
        assert!(numeric[1].automatic);
        assert!(!numeric[1].connected);

        let dns = parse_dns(r#"{"InterfaceIndex":7,"ServerAddresses":["10.88.0.1","10.88.0.2"]}"#)
            .unwrap();
        assert_eq!(
            dns,
            vec![Ipv4Addr::new(10, 88, 0, 1), Ipv4Addr::new(10, 88, 0, 2)]
        );
    }

    #[test]
    fn found_route_skips_the_address_object() {
        let found = parse_found_route(
            r#"[{"IPAddress":"192.168.1.50"},{"DestinationPrefix":"0.0.0.0/0","InterfaceIndex":12,"NextHop":"192.168.1.1","RouteMetric":25}]"#,
        )
        .unwrap();
        assert_eq!(found.ifindex, 12);
        assert_eq!(found.next_hop, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn profile_routes_are_normalised_and_ipv6_is_rejected() {
        let spec = ProfileSpec {
            address: "10.88.0.2/24".into(),
            gateway: "10.88.0.1".into(),
            routes: vec!["default".into(), "192.168.50.7/24".into(), "".into()],
            dns: vec!["10.88.0.1".into()],
            ..ProfileSpec::default()
        };
        let plan = plan_profile(&spec).unwrap();
        assert!(plan.has_default);
        assert_eq!(plan.routes, vec!["0.0.0.0/0", "192.168.50.0/24"]);
        assert_eq!(plan.connected, "10.88.0.0/24");

        let mut bad = spec.clone();
        bad.routes.push("2001:db8::/32".into());
        assert!(plan_profile(&bad).is_err());
    }

    #[test]
    fn identical_owned_routes_are_idempotent_and_conflicts_fail() {
        let planned = RouteSpec::new(
            "192.168.50.0/24",
            7,
            Ipv4Addr::UNSPECIFIED,
            50,
            RouteKind::Split,
        );
        let existing = vec![route("192.168.50.0/24", 7, "0.0.0.0", 50)];
        let owned = vec![PersistedRoute {
            dest: "192.168.50.0/24".into(),
            ifindex: 7,
            next_hop: Ipv4Addr::UNSPECIFIED,
            metric: 50,
            kind: RouteKind::Split,
            alias: "rsvpn0".into(),
        }];
        assert_eq!(
            decide_route(&planned, &existing, &owned, None).unwrap(),
            RouteDecision::Idempotent
        );
        let conflict = decide_route(&planned, &existing, &[], None).unwrap_err();
        assert!(
            conflict.to_string().contains("refusing to overwrite"),
            "{conflict}"
        );
        assert!(decide_route(&planned, &[], &[], None).unwrap() == RouteDecision::Add);
    }

    #[test]
    fn host_route_is_reused_without_ownership_but_never_conflicting() {
        let planned = RouteSpec::new(
            "203.0.113.10/32",
            12,
            Ipv4Addr::new(192, 168, 1, 1),
            1,
            RouteKind::Host,
        );
        let existing = vec![route("203.0.113.10/32", 12, "192.168.1.1", 1)];
        assert_eq!(
            decide_route(&planned, &existing, &[], None).unwrap(),
            RouteDecision::Reuse
        );
        let different = vec![route("203.0.113.10/32", 13, "0.0.0.0", 1)];
        assert!(decide_route(&planned, &different, &[], None).is_err());
    }

    #[test]
    fn default_routes_ignore_physical_defaults_but_not_tunnel_conflicts() {
        let planned = RouteSpec::new(
            "0.0.0.0/0",
            7,
            Ipv4Addr::new(10, 88, 0, 1),
            0,
            RouteKind::Default,
        );
        let physical = vec![route("0.0.0.0/0", 12, "192.168.1.1", 25)];
        assert_eq!(
            decide_route(&planned, &physical, &[], None).unwrap(),
            RouteDecision::Add
        );
        let on_tunnel = vec![route("0.0.0.0/0", 7, "10.88.0.1", 0)];
        assert!(decide_route(&planned, &on_tunnel, &[], None).is_err());
    }

    #[test]
    fn split_route_equal_to_the_connected_subnet_is_skipped() {
        let planned = RouteSpec::new(
            "10.88.0.0/24",
            7,
            Ipv4Addr::UNSPECIFIED,
            50,
            RouteKind::Split,
        );
        assert_eq!(
            decide_route(&planned, &[], &[], Some(("10.88.0.0/24", 7))).unwrap(),
            RouteDecision::SkipConnected
        );
    }

    #[test]
    fn takeover_check_finds_competing_defaults_only_on_connected_interfaces() {
        let routes = vec![
            route("0.0.0.0/0", 12, "192.168.1.1", 25),
            route("0.0.0.0/0", 13, "192.168.2.1", 1),
        ];
        let mut disconnected = iface(13, 0);
        disconnected.connected = false;
        let interfaces = vec![iface(12, 600), disconnected];
        let conflicts = default_takeover_conflicts(&routes, &interfaces, 7, 1);
        assert!(conflicts.is_empty(), "{conflicts:?}");

        let interfaces = vec![iface(12, 600), iface(13, 0)];
        let conflicts = default_takeover_conflicts(&routes, &interfaces, 7, 1);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].ifindex, 13);
    }

    #[test]
    fn remove_route_is_a_direct_cmdlet_without_pipeline_or_policy_store() {
        let script = script_for(&WinCommand::RemoveRoute {
            dest: "192.168.110.190/32".into(),
            ifindex: 6,
            next_hop: Ipv4Addr::new(192, 168, 110, 1),
            metric: 1,
        });
        assert!(script.starts_with("Remove-NetRoute "), "{script}");
        assert!(
            script.contains("-DestinationPrefix '192.168.110.190/32'"),
            "{script}"
        );
        assert!(script.contains("-InterfaceIndex 6"), "{script}");
        assert!(script.contains("-NextHop '192.168.110.1'"), "{script}");
        assert!(script.contains("-RouteMetric 1"), "{script}");
        assert!(script.contains("-Confirm:$false"), "{script}");
        assert!(!script.contains("Get-NetRoute"), "{script}");
        assert!(!script.contains("Where-Object"), "{script}");
        assert!(!script.contains("-PolicyStore"), "{script}");
        assert!(!script.contains('|'), "{script}");
    }

    #[test]
    fn scripts_quote_every_interpolated_value() {
        let script = script_for(&WinCommand::AddRoute(RouteSpec::new(
            "0.0.0.0/0",
            7,
            Ipv4Addr::new(10, 88, 0, 1),
            0,
            RouteKind::Default,
        )));
        assert!(script.contains("'0.0.0.0/0'"));
        assert!(script.contains("'10.88.0.1'"));
        assert!(!script.contains("cmd"));
        let script = script_for(&WinCommand::GetAdapterInfo("rsvpn0".into()));
        assert!(script.contains("'rsvpn0'"));
        // Never read the NDIS L2 MtuSize for the IP MTU decision.
        assert!(!script.contains("MtuSize"), "{script}");

        // Windows 10 Find-NetRoute rejects -AddressFamily and returns a null
        // source-address row before the route row.
        let script = script_for(&WinCommand::FindRouteTo("192.0.2.1".parse().unwrap()));
        assert!(!script.contains("-AddressFamily"), "{script}");
        assert!(script.contains("Where-Object"), "{script}");
        assert!(script.contains("'192.0.2.1'"), "{script}");
    }

    // ------------------------------------------------------------------
    // Fake Windows system for install/cleanup tests
    // ------------------------------------------------------------------

    struct FakeSystem {
        adapter_index: u32,
        routes: Mutex<Vec<RouteEntry>>,
        interfaces: Mutex<Vec<InterfaceEntry>>,
        adapters: Mutex<Vec<AdapterNameEntry>>,
        addresses: Mutex<Vec<AddressEntry>>,
        dns: Mutex<Vec<(u32, Vec<Ipv4Addr>)>>,
        nrpt: Mutex<Vec<(String, String)>>,
        firewall: Mutex<HashSet<String>>,
        found: Option<FoundRoute>,
        commands: Mutex<Vec<WinCommand>>,
        fail: Mutex<HashSet<String>>,
        next_nrpt: Mutex<u32>,
    }

    impl FakeSystem {
        fn new() -> Self {
            Self {
                adapter_index: 7,
                routes: Mutex::new(Vec::new()),
                interfaces: Mutex::new(vec![iface(7, 5000), iface(12, 25)]),
                adapters: Mutex::new(vec![
                    AdapterNameEntry {
                        ifindex: 7,
                        name: "rsvpn0".into(),
                    },
                    AdapterNameEntry {
                        ifindex: 12,
                        name: "eth0".into(),
                    },
                ]),
                addresses: Mutex::new(Vec::new()),
                dns: Mutex::new(vec![(7, Vec::new())]),
                nrpt: Mutex::new(Vec::new()),
                firewall: Mutex::new(HashSet::new()),
                found: Some(FoundRoute {
                    dest: "0.0.0.0/0".into(),
                    ifindex: 12,
                    next_hop: "192.168.1.1".parse().unwrap(),
                    metric: 25,
                }),
                commands: Mutex::new(Vec::new()),
                fail: Mutex::new(HashSet::new()),
                next_nrpt: Mutex::new(0),
            }
        }

        fn commands(&self) -> Vec<WinCommand> {
            self.commands.lock().unwrap().clone()
        }

        fn fail_on(&self, needle: &str) {
            self.fail.lock().unwrap().insert(needle.to_string());
        }

        fn should_fail(&self, label: &str) -> bool {
            self.fail.lock().unwrap().contains(label)
        }
    }

    fn routes_json(routes: &[RouteEntry]) -> String {
        let rows: Vec<Value> = routes
            .iter()
            .map(|route| {
                serde_json::json!({
                    "DestinationPrefix": route.dest,
                    "InterfaceIndex": route.ifindex,
                    "NextHop": route.next_hop.to_string(),
                    "RouteMetric": route.metric,
                })
            })
            .collect();
        serde_json::to_string(&rows).unwrap()
    }

    fn interfaces_json(interfaces: &[InterfaceEntry]) -> String {
        let rows: Vec<Value> = interfaces
            .iter()
            .map(|iface| {
                serde_json::json!({
                    "InterfaceIndex": iface.ifindex,
                    "InterfaceMetric": iface.metric,
                    "AutomaticMetric": if iface.automatic { "Enabled" } else { "Disabled" },
                    "ConnectionState": if iface.connected { "Connected" } else { "Disconnected" },
                    "NlMtu": iface.mtu,
                })
            })
            .collect();
        serde_json::to_string(&rows).unwrap()
    }

    fn addresses_json(addresses: &[AddressEntry]) -> String {
        let rows: Vec<Value> = addresses
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "IPAddress": entry.address.to_string(),
                    "PrefixLength": entry.prefix_len,
                })
            })
            .collect();
        serde_json::to_string(&rows).unwrap()
    }

    fn adapters_json(adapters: &[AdapterNameEntry]) -> String {
        let rows: Vec<Value> = adapters
            .iter()
            .map(|adapter| {
                serde_json::json!({
                    "ifIndex": adapter.ifindex,
                    "Name": adapter.name,
                    "Status": "Up",
                })
            })
            .collect();
        serde_json::to_string(&rows).unwrap()
    }

    fn found_route_json(found: &FoundRoute) -> String {
        serde_json::to_string(&serde_json::json!([{
            "IPAddress": "192.168.1.50",
            "DestinationPrefix": found.dest,
            "InterfaceIndex": found.ifindex,
            "NextHop": found.next_hop.to_string(),
            "RouteMetric": found.metric,
        }]))
        .unwrap()
    }

    fn nrpt_json(rules: &[(String, String)]) -> String {
        let rows: Vec<Value> = rules
            .iter()
            .map(|(name, display)| {
                serde_json::json!({
                    "Name": name,
                    "DisplayName": display,
                })
            })
            .collect();
        serde_json::to_string(&rows).unwrap()
    }

    impl WinRunner for FakeSystem {
        fn run<'a>(&'a self, command: &'a WinCommand) -> RunnerFuture<'a, Result<String>> {
            Box::pin(async move {
                self.commands.lock().unwrap().push(command.clone());
                match command {
                    WinCommand::GetAdapterInfo(_) => {
                        // Real Wintun reports the fixed NDIS L2 MTU 65535 in
                        // MtuSize; the IP interface NlMtu (InterfaceEntry::mtu,
                        // 1500 by default) is the authoritative value.  Keeping
                        // the real shape here prevents a regression to the
                        // pre-address MtuSize check.
                        Ok(serde_json::to_string(&serde_json::json!({
                            "ifIndex": self.adapter_index,
                            "MtuSize": 65535,
                            "Status": "Up",
                        }))
                        .unwrap())
                    }
                    WinCommand::ListIpv4Routes => Ok(routes_json(&self.routes.lock().unwrap())),
                    WinCommand::ListIpv4Interfaces => {
                        Ok(interfaces_json(&self.interfaces.lock().unwrap()))
                    }
                    WinCommand::ListAdapters => Ok(adapters_json(&self.adapters.lock().unwrap())),
                    WinCommand::GetIpv4Addresses(_) => {
                        Ok(addresses_json(&self.addresses.lock().unwrap()))
                    }
                    WinCommand::FindRouteTo(_) => self
                        .found
                        .clone()
                        .map(|found| found_route_json(&found))
                        .ok_or_else(|| anyhow!("no route")),
                    WinCommand::AddIpAddress {
                        ifindex,
                        address,
                        prefix_len,
                    } => {
                        if self.should_fail("add-address") {
                            bail!("injected add address failure");
                        }
                        self.addresses.lock().unwrap().push(AddressEntry {
                            address: *address,
                            prefix_len: *prefix_len,
                        });
                        let _ = ifindex;
                        Ok(String::new())
                    }
                    WinCommand::RemoveIpAddress { address, .. } => {
                        self.addresses
                            .lock()
                            .unwrap()
                            .retain(|entry| entry.address != *address);
                        Ok(String::new())
                    }
                    WinCommand::AddRoute(route) => {
                        if self.should_fail("add-route") {
                            bail!("injected add route failure");
                        }
                        self.routes.lock().unwrap().push(entry(route));
                        Ok(String::new())
                    }
                    WinCommand::RemoveRoute {
                        dest,
                        ifindex,
                        next_hop,
                        metric,
                    } => {
                        if self.should_fail("remove-route") {
                            bail!("injected remove route failure");
                        }
                        self.routes.lock().unwrap().retain(|route| {
                            !(route.dest == *dest
                                && route.ifindex == *ifindex
                                && route.next_hop == *next_hop
                                && route.metric == *metric)
                        });
                        Ok(String::new())
                    }
                    WinCommand::SetInterfaceMetric { ifindex, metric } => {
                        if self.should_fail("set-metric") {
                            bail!("injected metric failure");
                        }
                        let mut interfaces = self.interfaces.lock().unwrap();
                        if let Some(entry) = interfaces
                            .iter_mut()
                            .find(|entry| entry.ifindex == *ifindex)
                        {
                            entry.metric = *metric;
                            entry.automatic = false;
                        }
                        Ok(String::new())
                    }
                    WinCommand::SetAutomaticMetric(ifindex) => {
                        let mut interfaces = self.interfaces.lock().unwrap();
                        if let Some(entry) = interfaces
                            .iter_mut()
                            .find(|entry| entry.ifindex == *ifindex)
                        {
                            entry.automatic = true;
                            entry.metric = 5000;
                        }
                        Ok(String::new())
                    }
                    WinCommand::GetDnsServers(ifindex) => {
                        let dns = self.dns.lock().unwrap();
                        let servers = dns
                            .iter()
                            .find(|(index, _)| index == ifindex)
                            .map(|(_, servers)| servers.clone())
                            .unwrap_or_default();
                        Ok(serde_json::to_string(&serde_json::json!({
                            "InterfaceIndex": ifindex,
                            "ServerAddresses": servers,
                        }))
                        .unwrap())
                    }
                    WinCommand::SetDnsServers { ifindex, servers } => {
                        if self.should_fail("set-dns") {
                            bail!("injected DNS failure");
                        }
                        let mut dns = self.dns.lock().unwrap();
                        if let Some((_, current)) =
                            dns.iter_mut().find(|(index, _)| index == ifindex)
                        {
                            *current = servers.clone();
                        } else {
                            dns.push((*ifindex, servers.clone()));
                        }
                        Ok(String::new())
                    }
                    WinCommand::ResetDnsServers(ifindex) => {
                        let mut dns = self.dns.lock().unwrap();
                        if let Some((_, current)) =
                            dns.iter_mut().find(|(index, _)| index == ifindex)
                        {
                            current.clear();
                        }
                        Ok(String::new())
                    }
                    WinCommand::AddNrpt { display, .. } => {
                        if self.should_fail("add-nrpt") {
                            bail!("injected NRPT failure");
                        }
                        let mut counter = self.next_nrpt.lock().unwrap();
                        let name = format!("rule-{}", *counter);
                        *counter += 1;
                        self.nrpt.lock().unwrap().push((name, display.clone()));
                        Ok(String::new())
                    }
                    WinCommand::FindNrpt { display } => Ok(nrpt_json(
                        &self
                            .nrpt
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|(_, rule_display)| rule_display == display)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )),
                    WinCommand::RemoveNrpt { name } => {
                        self.nrpt.lock().unwrap().retain(|(rule, _)| rule != name);
                        Ok(String::new())
                    }
                    WinCommand::AddIpv6Block { name } => {
                        if self.should_fail("add-firewall") {
                            bail!("injected firewall failure");
                        }
                        self.firewall.lock().unwrap().insert(name.clone());
                        Ok(String::new())
                    }
                    WinCommand::RemoveFirewallRule { name } => {
                        self.firewall.lock().unwrap().remove(name);
                        Ok(String::new())
                    }
                }
            })
        }
    }

    struct TempStore {
        dir: PathBuf,
    }

    impl TempStore {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("rustvpn-winplan-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }
    }

    impl StateStore for TempStore {
        fn load(&self) -> Result<Option<PersistedState>> {
            FileStateStore::new(self.dir.clone()).load()
        }
        fn save(&self, state: &PersistedState) -> Result<()> {
            FileStateStore::new(self.dir.clone()).save(state)
        }
        fn clear(&self) -> Result<()> {
            FileStateStore::new(self.dir.clone()).clear()
        }
        fn path(&self) -> PathBuf {
            FileStateStore::state_path(&self.dir)
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Probe {
        alive: bool,
    }

    impl OwnerProbe for Probe {
        fn is_alive(&self, _owner: &OwnerToken) -> bool {
            self.alive
        }
    }

    const OWNER: OwnerToken = OwnerToken {
        pid: 4242,
        started: 7,
    };

    fn full_spec() -> ProfileSpec {
        ProfileSpec {
            name: "office".into(),
            remote: "203.0.113.10:1194".into(),
            proto: "udp".into(),
            verifier: "$argon2d$m=1024,t=4,p=1$AAECAwQFBgcICQoLDA0ODw".into(),
            mtu: 1515,
            timeout: 60,
            iface: "rsvpn0".into(),
            address: "10.88.0.2/24".into(),
            gateway: "10.88.0.1".into(),
            routes: vec!["default".into()],
            dns: vec!["10.88.0.1".into()],
            ..ProfileSpec::default()
        }
    }

    fn split_spec() -> ProfileSpec {
        let mut spec = full_spec();
        spec.routes = vec!["192.168.50.0/24".into()];
        spec.dns.clear();
        spec
    }

    fn ctx<'a>(
        system: &'a FakeSystem,
        store: &'a TempStore,
        probe: &'a Probe,
    ) -> InstallContext<'a> {
        InstallContext {
            runner: system,
            store,
            probe,
            owner: OWNER,
        }
    }

    /// Simulate the engine's install-failure rollback: the data plane is already
    /// stopped and only non-route state is removed.  Routes, the address and
    /// the state file are kept for the next connect/daemon start, which run the
    /// full cleanup with no Wintun session open.
    async fn rollback_after_stop(system: &FakeSystem, store: &TempStore, state: &PersistedState) {
        let before = system.commands().len();
        let report = cleanup_non_route_state_with(system, state).await;
        assert!(report.ok(), "{report:?}");
        assert!(
            !system.commands()[before..].iter().any(|command| matches!(
                command,
                WinCommand::RemoveRoute { .. } | WinCommand::RemoveIpAddress { .. }
            )),
            "rollback must not touch routes/address: {:?}",
            &system.commands()[before..]
        );
        assert!(
            store.load().unwrap().is_some(),
            "rollback keeps the state file for the next-start cleanup"
        );
    }

    #[tokio::test]
    async fn full_tunnel_installs_anti_loop_before_default_and_dns_nrpt_ipv6() {
        let system = FakeSystem::new();
        let store = TempStore::new("full");
        let probe = Probe { alive: false };
        let outer: SocketAddr = "203.0.113.10:1194".parse().unwrap();
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some(outer),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        assert!(store.load().unwrap().is_some());

        let commands = system.commands();
        let add_host = commands
            .iter()
            .position(
                |command| matches!(command, WinCommand::AddRoute(r) if r.kind == RouteKind::Host),
            )
            .expect("anti-loop route");
        let set_metric = commands
            .iter()
            .position(|command| matches!(command, WinCommand::SetInterfaceMetric { .. }))
            .expect("metric change");
        let add_default = commands
            .iter()
            .position(|command| matches!(command, WinCommand::AddRoute(r) if r.kind == RouteKind::Default))
            .expect("default route");
        assert!(
            add_host < set_metric && set_metric < add_default,
            "{commands:?}"
        );

        let routes = system.routes.lock().unwrap().clone();
        assert!(routes.iter().any(|route| route.dest == "203.0.113.10/32"
            && route.ifindex == 12
            && route.next_hop == Ipv4Addr::new(192, 168, 1, 1)));
        assert!(routes.iter().any(|route| route.dest == "0.0.0.0/0"
            && route.ifindex == 7
            && route.next_hop == Ipv4Addr::UNSPECIFIED
            && route.metric == 0));
        assert!(system.firewall.lock().unwrap().contains(IPV6_BLOCK_RULE));
        assert_eq!(system.nrpt.lock().unwrap().len(), 1);
        assert!(state.nrpt.is_some());
        assert!(state.interface_metric.is_some());
    }

    #[tokio::test]
    async fn split_tunnel_has_no_default_no_ipv6_block_and_no_dns_by_default() {
        let system = FakeSystem::new();
        let store = TempStore::new("split");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &split_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let commands = system.commands();
        assert!(!commands.iter().any(
            |command| matches!(command, WinCommand::AddRoute(r) if r.kind == RouteKind::Default)
        ));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::AddIpv6Block { .. })));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::AddNrpt { .. })));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::AddNrpt { .. })));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::SetDnsServers { .. })));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::SetInterfaceMetric { .. })));
        assert!(system.routes.lock().unwrap().iter().any(|route| {
            route.dest == "192.168.50.0/24" && route.ifindex == 7 && route.metric == 50
        }));
        assert!(state.dns.is_none());
        assert!(state.nrpt.is_none());
        assert!(state.ipv6_block.is_none());
    }

    #[tokio::test]
    async fn split_route_covering_the_outer_endpoint_gets_an_anti_loop_route() {
        let system = FakeSystem::new();
        let store = TempStore::new("split-loop");
        let probe = Probe { alive: false };
        let mut spec = split_spec();
        // 203.0.113.0/24 contains the outer endpoint 203.0.113.10.
        spec.routes = vec!["203.0.113.0/24".into()];
        install_with(
            ctx(&system, &store, &probe),
            &spec,
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let commands = system.commands();
        let host = commands
            .iter()
            .position(
                |command| matches!(command, WinCommand::AddRoute(r) if r.kind == RouteKind::Host),
            )
            .expect("anti-loop route");
        let split = commands
            .iter()
            .position(
                |command| matches!(command, WinCommand::AddRoute(r) if r.kind == RouteKind::Split),
            )
            .expect("split route");
        assert!(host < split, "{commands:?}");
    }

    #[tokio::test]
    async fn split_tunnel_applies_explicit_dns_without_nrpt_or_ipv6_block() {
        let system = FakeSystem::new();
        let store = TempStore::new("split-dns");
        let probe = Probe { alive: false };
        let mut spec = split_spec();
        spec.dns = vec!["10.88.0.1".into()];
        install_with(
            ctx(&system, &store, &probe),
            &spec,
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let commands = system.commands();
        assert!(commands
            .iter()
            .any(|command| matches!(command, WinCommand::SetDnsServers { .. })));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::AddNrpt { .. })));
        assert!(!commands
            .iter()
            .any(|command| matches!(command, WinCommand::AddIpv6Block { .. })));
    }

    #[tokio::test]
    async fn conflicting_preexisting_split_route_fails_and_rolls_back() {
        let system = FakeSystem::new();
        system
            .routes
            .lock()
            .unwrap()
            .push(route("192.168.50.0/24", 12, "192.168.1.1", 25));
        let store = TempStore::new("conflict");
        let probe = Probe { alive: false };
        let failure = install_with_partial(
            ctx(&system, &store, &probe),
            &split_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{:#}", failure.error).contains("refusing to overwrite"),
            "{:#}",
            failure.error
        );
        let state = failure.state.expect("partial state");
        // The engine stops the data plane and rolls back after this call: only
        // non-route state is removed now; routes/address/state are deferred.
        rollback_after_stop(&system, &store, &state).await;
        assert_eq!(system.addresses.lock().unwrap().len(), 1);
        assert!(!system.routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn competing_default_route_fails_instead_of_claiming_full_tunnel() {
        let system = FakeSystem::new();
        system
            .routes
            .lock()
            .unwrap()
            .push(route("0.0.0.0/0", 12, "192.168.1.1", 0));
        // Force the competing interface to effective metric 1 (0 + 1).
        system.interfaces.lock().unwrap()[1].metric = 1;
        let store = TempStore::new("takeover");
        let probe = Probe { alive: false };
        let failure = install_with_partial(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{:#}", failure.error).contains("would still win"),
            "{:#}",
            failure.error
        );
        let state = failure.state.expect("partial state");
        rollback_after_stop(&system, &store, &state).await;
        // The address and routes are left for the next-start cleanup; the
        // competing physical default route is untouched.
        assert_eq!(system.addresses.lock().unwrap().len(), 1);
        assert!(!system.routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tunnel_subnet_overlapping_an_existing_route_is_rejected() {
        let system = FakeSystem::new();
        system
            .routes
            .lock()
            .unwrap()
            .push(route("10.88.0.0/24", 12, "0.0.0.0", 256));
        let store = TempStore::new("subnet");
        let probe = Probe { alive: false };
        let error = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("already routed"), "{error:#}");
        assert!(system.addresses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn injected_route_failure_defers_routes_address_and_state_to_next_start() {
        let system = FakeSystem::new();
        system.fail_on("add-route");
        let store = TempStore::new("inject");
        let probe = Probe { alive: false };
        let failure = install_with_partial(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{:#}", failure.error).contains("injected add route failure"),
            "{:#}",
            failure.error
        );
        let state = failure.state.expect("partial state");
        // Rollback removes only non-route state; the address, routes and state
        // file are removed by the next-start cleanup with no adapter open.
        rollback_after_stop(&system, &store, &state).await;
        assert!(
            !system.addresses.lock().unwrap().is_empty(),
            "rollback must keep the address for the next-start cleanup"
        );
    }

    #[tokio::test]
    async fn adapter_mtu_mismatch_is_rejected() {
        let system = FakeSystem::new();
        let store = TempStore::new("mtu");
        let probe = Probe { alive: false };
        let error = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1476,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("interface MTU"), "{error:#}");
    }

    #[tokio::test]
    async fn windows_apipa_auto_address_does_not_block_the_profile_address() {
        // A Wintun adapter that is up but has no static address receives an
        // automatic 169.254.0.0/16 APIPA address.  It is system-owned and must
        // not be mistaken for administrator state that conflicts with the
        // profile.
        let system = FakeSystem::new();
        system.addresses.lock().unwrap().push(AddressEntry {
            address: "169.254.134.192".parse().unwrap(),
            prefix_len: 16,
        });
        let store = TempStore::new("apipa");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &split_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        assert!(state.address.is_some());
        let addresses = system.addresses.lock().unwrap().clone();
        assert!(addresses
            .iter()
            .any(|entry| entry.address == Ipv4Addr::new(10, 88, 0, 2)));
        // The APIPA address is left alone; only the profile address is ours.
        assert!(addresses
            .iter()
            .any(|entry| entry.address == Ipv4Addr::new(169, 254, 134, 192)));
    }

    #[tokio::test]
    async fn kill_switch_and_ipv6_outer_are_rejected() {
        let system = FakeSystem::new();
        let store = TempStore::new("reject");
        let probe = Probe { alive: false };
        let mut spec = full_spec();
        spec.kill_switch = true;
        let error = install_with(
            ctx(&system, &store, &probe),
            &spec,
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("kill_switch"), "{error:#}");

        let mut spec = full_spec();
        spec.kill_switch = false;
        let error = install_with(
            ctx(&system, &store, &probe),
            &spec,
            Some("[2001:db8::10]:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("IPv4 outer"), "{error:#}");
    }

    #[tokio::test]
    async fn cleanup_removes_only_recorded_entries_and_restores_state() {
        let system = FakeSystem::new();
        let store = TempStore::new("cleanup");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let unrelated = route("172.16.0.0/12", 12, "192.168.1.1", 25);
        system.routes.lock().unwrap().push(unrelated.clone());
        let report = cleanup_state(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        assert!(store.clear().is_ok());
        let routes = system.routes.lock().unwrap().clone();
        assert_eq!(routes, vec![unrelated]);
        assert!(system.addresses.lock().unwrap().is_empty());
        assert!(system.nrpt.lock().unwrap().is_empty());
        assert!(system.firewall.lock().unwrap().is_empty());
        assert_eq!(system.interfaces.lock().unwrap()[0].metric, 5000);
    }

    #[tokio::test]
    async fn non_route_cleanup_never_removes_routes_or_the_address_before_close() {
        // Normal teardown phase 1: remove DNS/NRPT/metric/IPv6 only.  No
        // Remove-NetRoute or Remove-NetIPAddress may run while the Wintun
        // session is open; routes go with the adapter close and host routes
        // are removed afterwards.
        let system = FakeSystem::new();
        let store = TempStore::new("keep-address");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(system.addresses.lock().unwrap().len(), 1);
        assert!(!system.routes.lock().unwrap().is_empty());

        let before = system.commands().len();
        let report = cleanup_non_route_state_with(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        let commands = system.commands();
        assert!(
            !commands[before..].iter().any(|command| matches!(
                command,
                WinCommand::RemoveRoute { .. } | WinCommand::RemoveIpAddress { .. }
            )),
            "no route/address command may run before the adapter close: {:?}",
            &commands[before..]
        );
        assert_eq!(
            system.addresses.lock().unwrap().len(),
            1,
            "pre-close cleanup must keep the address"
        );
        assert!(
            !system.routes.lock().unwrap().is_empty(),
            "pre-close cleanup must keep the routes for the adapter close"
        );
        assert!(system.nrpt.lock().unwrap().is_empty());
        assert!(system.firewall.lock().unwrap().is_empty());
        assert_eq!(system.interfaces.lock().unwrap()[0].metric, 5000);
        assert!(
            store.load().unwrap().is_some(),
            "the state file survives until post-close cleanup"
        );
    }

    #[tokio::test]
    async fn disconnect_keeps_host_routes_and_state_without_post_close_commands() {
        // Normal Disconnect phase 1: only DNS/NRPT/metric/IPv6 are removed.
        // The anti-loop host route, the address and netstate.json stay for the
        // next connect/daemon start; the disconnect path itself never issues
        // Remove-NetRoute or Remove-NetIPAddress, before or after the close.
        let system = FakeSystem::new();
        let store = TempStore::new("deferred-disconnect");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let host = state
            .routes
            .iter()
            .find(|route| route.kind == RouteKind::Host)
            .expect("anti-loop host route")
            .clone();

        let before = system.commands().len();
        let report = cleanup_non_route_state_with(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        assert!(
            !system.commands()[before..].iter().any(|command| matches!(
                command,
                WinCommand::RemoveRoute { .. } | WinCommand::RemoveIpAddress { .. }
            )),
            "the disconnect path must not touch routes/address: {:?}",
            &system.commands()[before..]
        );
        assert!(
            system
                .routes
                .lock()
                .unwrap()
                .iter()
                .any(|route| route.dest == host.dest && route.ifindex == host.ifindex),
            "the anti-loop host route stays for deferred cleanup"
        );
        assert_eq!(
            system.addresses.lock().unwrap().len(),
            1,
            "the address is left for the adapter close / next-start cleanup"
        );
        assert!(
            store.load().unwrap().is_some(),
            "netstate.json is the pending cleanup record"
        );
        assert!(system.nrpt.lock().unwrap().is_empty());
        assert!(system.firewall.lock().unwrap().is_empty());
        assert_eq!(system.interfaces.lock().unwrap()[0].metric, 5000);
    }

    #[tokio::test]
    async fn next_start_cleanup_removes_deferred_host_routes_and_clears_state() {
        // After the adapter close no Wintun session exists.  The next daemon
        // start (or the next connect, before opening an adapter) runs the full
        // cleanup, removes the deferred anti-loop host route and clears the
        // pending state file.
        let system = FakeSystem::new();
        let store = TempStore::new("next-start");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let host = state
            .routes
            .iter()
            .find(|route| route.kind == RouteKind::Host)
            .expect("anti-loop host route")
            .clone();
        let report = cleanup_non_route_state_with(&system, &state).await;
        assert!(report.ok(), "{report:?}");

        // Simulate the adapter close: Wintun removed its address and routes.
        system
            .routes
            .lock()
            .unwrap()
            .retain(|route| route.ifindex != 7);
        system.addresses.lock().unwrap().clear();

        let report = cleanup_stale_with(&system, &store, &Probe { alive: false })
            .await
            .unwrap();
        assert!(report.ok(), "{report:?}");
        assert!(
            !system
                .routes
                .lock()
                .unwrap()
                .iter()
                .any(|route| route.dest == host.dest && route.ifindex == host.ifindex),
            "the next-start cleanup removes the deferred host route"
        );
        assert!(
            store.load().unwrap().is_none(),
            "the state file is cleared only by the next-start cleanup"
        );
    }

    #[tokio::test]
    async fn pre_open_cleanup_removes_deferred_host_routes_before_the_next_adapter() {
        // The same process connects again while idle: cleanup_owned_with runs
        // before Tap::open, with no Wintun session, and removes the deferred
        // host route + state file.
        let system = FakeSystem::new();
        let store = TempStore::new("pre-open");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let host = state
            .routes
            .iter()
            .find(|route| route.kind == RouteKind::Host)
            .expect("anti-loop host route")
            .clone();
        let report = cleanup_non_route_state_with(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        system
            .routes
            .lock()
            .unwrap()
            .retain(|route| route.ifindex != 7);
        system.addresses.lock().unwrap().clear();

        let report = cleanup_owned_with(&system, &store, &OWNER).await.unwrap();
        assert!(report.ok(), "{report:?}");
        assert!(
            !system
                .routes
                .lock()
                .unwrap()
                .iter()
                .any(|route| route.dest == host.dest && route.ifindex == host.ifindex),
            "the pre-open cleanup removes the deferred host route"
        );
        assert!(store.load().unwrap().is_none());
    }

    #[tokio::test]
    async fn crash_cleanup_removes_the_address_after_routes_and_nrpt() {
        // Crash/stale cleanup has no following adapter close, so it must still
        // remove the address; the order keeps routes/NRPT gone first so a
        // leftover address cannot keep tunnel routing alive.
        let system = FakeSystem::new();
        let store = TempStore::new("address-order");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();

        let report = cleanup_state(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        let commands = system.commands();
        let position = |predicate: &dyn Fn(&WinCommand) -> bool| {
            commands
                .iter()
                .rposition(predicate)
                .unwrap_or_else(|| panic!("missing command in {commands:?}"))
        };
        let address = position(&|c| matches!(c, WinCommand::RemoveIpAddress { .. }));
        let route = position(&|c| matches!(c, WinCommand::RemoveRoute { .. }));
        let nrpt = position(&|c| matches!(c, WinCommand::RemoveNrpt { .. }));
        assert!(
            address > route,
            "address removal must follow routes: {commands:?}"
        );
        assert!(
            address > nrpt,
            "address removal must follow NRPT: {commands:?}"
        );
        assert!(system.addresses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn crash_recovery_cleans_dead_owner_and_preserves_live_owner() {
        let system = FakeSystem::new();
        let store = TempStore::new("crash");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        // Simulate a crash: the state file remains, the process is gone.
        let live = Probe { alive: true };
        let report = cleanup_stale_with(&system, &store, &live).await.unwrap();
        assert!(report.skipped_live_owner);
        assert!(store.load().unwrap().is_some());
        assert!(!system.routes.lock().unwrap().is_empty());

        let report = cleanup_stale_with(&system, &store, &probe).await.unwrap();
        assert!(report.ok(), "{report:?}");
        assert!(store.load().unwrap().is_none());
        assert!(system.routes.lock().unwrap().is_empty());
        assert!(state.routes.len() >= 2);
    }

    #[tokio::test]
    async fn owned_cleanup_retries_only_for_the_same_owner() {
        let system = FakeSystem::new();
        let store = TempStore::new("owned");
        let probe = Probe { alive: false };
        install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        // A different owner must not touch this state.
        let other = OwnerToken {
            pid: OWNER.pid + 1,
            started: OWNER.started,
        };
        let report = cleanup_owned_with(&system, &store, &other).await.unwrap();
        assert!(report.actions.is_empty());
        assert!(store.load().unwrap().is_some());
        // The same owner retries and clears it.
        let report = cleanup_owned_with(&system, &store, &OWNER).await.unwrap();
        assert!(report.ok(), "{report:?}");
        assert!(store.load().unwrap().is_none());
        assert!(system.routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn noop_cleanup_without_state_issues_no_commands() {
        let system = FakeSystem::new();
        let store = TempStore::new("noop");
        let probe = Probe { alive: false };
        let report = cleanup_stale_with(&system, &store, &probe).await.unwrap();
        assert!(report.ok());
        assert!(system.commands().is_empty());
    }

    #[tokio::test]
    async fn install_refuses_previous_state_without_mutating_a_live_adapter() {
        // P1-3: previous-state cleanup must run before an adapter is opened.
        // If it was not done, install must refuse instead of issuing
        // Remove-Net* against the still-open Wintun session.
        let system = FakeSystem::new();
        let store = TempStore::new("previous-refuse");
        let probe = Probe { alive: false };
        install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let before = system.commands().len();
        let addresses_before = system.addresses.lock().unwrap().clone();
        let routes_before = system.routes.lock().unwrap().clone();

        let error = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("previous RustVPN network state"),
            "{error:#}"
        );
        assert_eq!(
            system.commands().len(),
            before,
            "no network command may run while refusing previous state"
        );
        assert_eq!(*system.addresses.lock().unwrap(), addresses_before);
        assert_eq!(*system.routes.lock().unwrap(), routes_before);
        assert!(
            store.load().unwrap().is_some(),
            "state must remain for the pre-open cleanup"
        );
    }

    #[tokio::test]
    async fn stale_state_from_a_live_guard_blocks_a_second_install() {
        let system = FakeSystem::new();
        let store = TempStore::new("live-block");
        let dead = Probe { alive: false };
        install_with(
            ctx(&system, &store, &dead),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        let live = Probe { alive: true };
        let other_owner = OwnerToken {
            pid: OWNER.pid + 1,
            started: OWNER.started,
        };
        let error = install_with(
            InstallContext {
                runner: &system,
                store: &store,
                probe: &live,
                owner: other_owner,
            },
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("another RustVPN network guard"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn cleanup_does_not_touch_a_reused_interface_index() {
        let system = FakeSystem::new();
        let store = TempStore::new("reuse");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        // The Wintun adapter disappeared and Windows reused index 7 for a
        // different adapter by the time crash recovery runs.
        system.adapters.lock().unwrap()[0].name = "SomeOtherVPN".into();
        let report = cleanup_state(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        let routes = system.routes.lock().unwrap().clone();
        assert!(
            routes
                .iter()
                .any(|route| route.dest == "0.0.0.0/0" && route.ifindex == 7),
            "the default route on the reused index must be left alone: {routes:?}"
        );
        assert!(
            !routes.iter().any(|route| route.dest == "203.0.113.10/32"),
            "the host route alias still matches and is removed"
        );
        assert!(!system.addresses.lock().unwrap().is_empty());
        // Identity-based NRPT/firewall cleanup is still safe and proceeds.
        assert!(system.nrpt.lock().unwrap().is_empty());
        assert!(system.firewall.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cleanup_twice_is_idempotent() {
        let system = FakeSystem::new();
        let store = TempStore::new("twice");
        let probe = Probe { alive: false };
        let state = install_with(
            ctx(&system, &store, &probe),
            &full_spec(),
            Some("203.0.113.10:1194".parse().unwrap()),
            1500,
            NetOptions::default(),
        )
        .await
        .unwrap();
        assert!(cleanup_state(&system, &state).await.ok());
        let before = system.commands().len();
        let report = cleanup_state(&system, &state).await;
        assert!(report.ok(), "{report:?}");
        assert!(system.commands().len() > before, "cleanup probes happen");
        assert!(system.routes.lock().unwrap().is_empty());
        assert!(system.firewall.lock().unwrap().is_empty());
    }

    #[test]
    fn state_file_round_trips_and_rejects_unknown_schema() {
        let store = TempStore::new("state");
        let mut state = PersistedState::new(OWNER, "rsvpn0", 7);
        state.routes.push(PersistedRoute {
            dest: "0.0.0.0/0".into(),
            ifindex: 7,
            next_hop: Ipv4Addr::new(10, 88, 0, 1),
            metric: 0,
            kind: RouteKind::Default,
            alias: "rsvpn0".into(),
        });
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), state);
        let path = store.path();
        let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["schema"] = Value::from(99);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(store.load().is_err());
    }
}
