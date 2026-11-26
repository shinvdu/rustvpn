//! Opt-in nftables helpers: MSS clamping and a full-tunnel kill switch.
//!
//! Both features use their own `inet` tables whose names are derived from a
//! daemon instance scope (`rustvpn_mss_<suffix>` / `rustvpn_killswitch_<suffix>`)
//! so two RustVPN daemons in the same network namespace cannot delete each
//! other's rules.  A table is deleted before it is created and on disconnect;
//! startup cleanup removes leftovers from a crashed daemon with the same
//! scope.
//!
//! Only `rustvpn-clientd` calls the apply/remove functions.  Tests build the
//! command vectors and never execute `nft` on the host.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use tokio::process::Command;

pub const MSS_PREFIX: &str = "rustvpn_mss_";
pub const KILLSWITCH_PREFIX: &str = "rustvpn_killswitch_";

/// Stable per-daemon scope.  Derived from the IPC socket path so a restart
/// cleans up the previous instance's tables and a different daemon in the same
/// netns gets a different suffix.
pub fn instance_scope(socket_path: &Path) -> String {
    socket_path.to_string_lossy().into_owned()
}

/// First 8 hex digits of the FNV-1a hash of `scope`.
pub fn table_suffix(scope: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in scope.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let text = format!("{hash:016x}");
    text[..8].to_string()
}

pub fn mss_table(scope: &str) -> String {
    format!("{MSS_PREFIX}{}", table_suffix(scope))
}

pub fn killswitch_table(scope: &str) -> String {
    format!("{KILLSWITCH_PREFIX}{}", table_suffix(scope))
}

fn nft_bin() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTVPN_NFT_BIN") {
        return Some(PathBuf::from(path));
    }
    for candidate in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    // Last resort: a non-standard install (for example /usr/local/sbin).  We
    // still execute the binary directly, never through a shell.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("nft");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

async fn run(nft: &PathBuf, args: &[String]) -> Result<std::process::Output> {
    Command::new(nft)
        .args(args)
        .output()
        .await
        .map_err(|error| anyhow!("run {} {}: {error}", nft.display(), args.join(" ")))
}

async fn delete_table(table: &str) -> Result<()> {
    let Some(nft) = nft_bin() else {
        return Ok(());
    };
    let args = vec![
        "delete".to_string(),
        "table".to_string(),
        "inet".to_string(),
        table.to_string(),
    ];
    // A missing table is not an error for delete/cleanup.
    let _ = run(&nft, &args).await;
    Ok(())
}

/// Remove tables left behind by a previous daemon crashed with the same
/// instance scope.  Only this scope's RustVPN-owned tables are touched.
pub async fn cleanup_stale(scope: &str) {
    let _ = delete_table(&mss_table(scope)).await;
    let _ = delete_table(&killswitch_table(scope)).await;
}

async fn apply_commands(table: &str, commands: Vec<Vec<String>>) -> Result<()> {
    let nft = nft_bin().ok_or_else(|| {
        anyhow!("nftables is required for this feature but no `nft` binary was found")
    })?;
    // Make a retry after a crash deterministic: drop any old table first.
    let _ = delete_table(table).await;
    for args in &commands {
        let output = run(&nft, args).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let _ = delete_table(table).await;
            return Err(anyhow!("nft {} failed: {stderr}", args.join(" ")));
        }
    }
    Ok(())
}

/// TCP MSS clamp commands for frames that leave through the tunnel.
///
/// Both `output` (locally generated traffic) and `forward` (traffic routed
/// from another namespace/container) are covered.  IPv4 and IPv6 use separate
/// destination-header sizes, so they get separate rules.
pub fn mss_commands(
    scope: &str,
    iface: &str,
    mss_v4: Option<usize>,
    mss_v6: Option<usize>,
) -> Vec<Vec<String>> {
    let table = mss_table(scope);
    let quoted_iface = quote(iface);
    let mut commands = vec![
        cmd(&["add", "table", "inet", table.as_str()]),
        cmd(&["add", "chain", "inet", table.as_str(), "output"]),
        cmd(&["add", "chain", "inet", table.as_str(), "forward"]),
    ];
    // Chain declarations need one string argument so nft parses the braces
    // itself (we pass argv directly, never through a shell).
    commands[1].push("{ type filter hook output priority mangle; }".to_string());
    commands[2].push("{ type filter hook forward priority mangle; }".to_string());
    for chain in ["output", "forward"] {
        if let Some(mss) = mss_v4 {
            commands.push(mss_rule(&table, chain, &quoted_iface, "ip protocol", mss));
        }
        if let Some(mss) = mss_v6 {
            commands.push(mss_rule(&table, chain, &quoted_iface, "ip6 nexthdr", mss));
        }
    }
    commands
}

fn mss_rule(
    table: &str,
    chain: &str,
    quoted_iface: &str,
    family_match: &str,
    mss: usize,
) -> Vec<String> {
    let mss = mss.clamp(536, 65535).to_string();
    cmd(&[
        "add",
        "rule",
        "inet",
        table,
        chain,
        "oifname",
        quoted_iface,
        family_match,
        "tcp",
        "tcp",
        "flags",
        "&",
        "(syn|rst)",
        "==",
        "syn",
        "tcp",
        "option",
        "maxseg",
        "size",
        "set",
        mss.as_str(),
    ])
}

/// Full-tunnel kill switch: allow loopback, the tunnel interface, the VPN
/// outer endpoint, DHCP renewal and (scoped to the underlay interface)
/// IPv6 neighbour discovery/MLD/DHCPv6; drop every other local packet.
///
/// The scope is the host `output` chain only.  Forwarded/LAN/NAT traffic is
/// not filtered; see the documentation for that limitation.
pub fn kill_switch_commands(
    scope: &str,
    iface: &str,
    outer: SocketAddr,
    underlay: Option<&str>,
) -> Vec<Vec<String>> {
    let table = killswitch_table(scope);
    let family = if outer.is_ipv6() { "ip6" } else { "ip" };
    let addr = outer.ip().to_string();
    let port = outer.port().to_string();
    let quoted_iface = quote(iface);
    let mut commands = vec![
        cmd(&["add", "table", "inet", table.as_str()]),
        cmd(&[
            "add",
            "chain",
            "inet",
            table.as_str(),
            "output",
            "{ type filter hook output priority 0; policy drop; }",
        ]),
        cmd(&[
            "add",
            "rule",
            "inet",
            table.as_str(),
            "output",
            "oifname",
            quote("lo").as_str(),
            "accept",
        ]),
        cmd(&[
            "add",
            "rule",
            "inet",
            table.as_str(),
            "output",
            "oifname",
            quoted_iface.as_str(),
            "accept",
        ]),
    ];
    for proto in ["udp", "tcp"] {
        commands.push(cmd(&[
            "add",
            "rule",
            "inet",
            table.as_str(),
            "output",
            family,
            "daddr",
            addr.as_str(),
            proto,
            "dport",
            port.as_str(),
            "accept",
        ]));
    }
    // DHCPv4 client renewal keeps the underlay address alive.  Scope it to the
    // underlay device when known so it cannot become a broad UDP hole.
    let mut dhcp = vec!["add", "rule", "inet", table.as_str(), "output"];
    if let Some(dev) = underlay {
        dhcp.push("oifname");
        dhcp.push(dev);
    }
    dhcp.extend_from_slice(&["udp", "sport", "68", "udp", "dport", "67", "accept"]);
    commands.push(cmd(&dhcp));

    // IPv6 outer endpoints need neighbour discovery/MLD to survive neighbour
    // cache expiry, and DHCPv6 to keep the underlay address.  These are
    // link-local control packets only, scoped to the underlay interface.
    if let Some(dev) = underlay {
        commands.push(cmd(&[
            "add",
            "rule",
            "inet",
            table.as_str(),
            "output",
            "oifname",
            dev,
            "icmpv6",
            "type",
            "{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, \
             nd-neighbor-advert, mld-listener-query, mld-listener-report, \
             mld-listener-done, mld2-listener-report }",
            "accept",
        ]));
        for (sport, dport) in [("546", "547"), ("547", "546")] {
            commands.push(cmd(&[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "output",
                "oifname",
                dev,
                "udp",
                "sport",
                sport,
                "udp",
                "dport",
                dport,
                "accept",
            ]));
        }
    }
    commands
}

fn cmd(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn quote(value: &str) -> String {
    // Interface names and addresses are validated before reaching this
    // module; quote anyway so nft treats them as strings.
    format!("\"{}\"", value.replace('"', ""))
}

/// Install MSS clamping for `iface`.  Returns an error if nftables is
/// missing or a rule cannot be applied (the partial table is removed).
pub async fn apply_mss(
    scope: &str,
    iface: &str,
    mss_v4: Option<usize>,
    mss_v6: Option<usize>,
) -> Result<()> {
    if mss_v4.is_none() && mss_v6.is_none() {
        return Ok(());
    }
    apply_commands(
        &mss_table(scope),
        mss_commands(scope, iface, mss_v4, mss_v6),
    )
    .await
}

/// Install the kill switch.  The caller must only request this for
/// full-tunnel profiles; split-tunnel validation rejects it earlier.
///
/// `underlay` is the device carrying the outer endpoint.  It is required for
/// IPv6 outer endpoints so neighbour discovery/DHCPv6 can be allowed safely.
pub async fn apply_kill_switch(
    scope: &str,
    iface: &str,
    outer: SocketAddr,
    underlay: Option<&str>,
) -> Result<()> {
    if outer.is_ipv6() && underlay.is_none() {
        return Err(anyhow!(
            "refusing to install a kill switch for an IPv6 outer endpoint without a \
             resolvable underlay interface (neighbour discovery would be blocked)"
        ));
    }
    apply_commands(
        &killswitch_table(scope),
        kill_switch_commands(scope, iface, outer, underlay),
    )
    .await
}

pub async fn remove_mss(scope: &str) {
    let _ = delete_table(&mss_table(scope)).await;
}

pub async fn remove_kill_switch(scope: &str) {
    let _ = delete_table(&killswitch_table(scope)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(commands: &[Vec<String>]) -> String {
        commands
            .iter()
            .map(|args| args.join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn table_names_are_scoped_per_instance() {
        let a = mss_table("daemon-a");
        let b = mss_table("daemon-b");
        assert!(a.starts_with(MSS_PREFIX));
        assert_ne!(a, b);
        assert_eq!(a, mss_table("daemon-a"));
        assert!(killswitch_table("daemon-a").starts_with(KILLSWITCH_PREFIX));
        assert_ne!(killswitch_table("daemon-a"), killswitch_table("daemon-b"));
    }

    #[test]
    fn mss_rules_clamp_both_paths_and_families() {
        let commands = mss_commands("scope", "rsvpn0", Some(1460), Some(1440));
        let text = text(&commands);
        assert!(text.contains("hook output priority mangle"));
        assert!(text.contains("hook forward priority mangle"));
        assert_eq!(
            text.matches(
                "ip protocol tcp tcp flags & (syn|rst) == syn tcp option maxseg size set 1460"
            )
            .count(),
            2,
            "{text}"
        );
        assert_eq!(
            text.matches(
                "ip6 nexthdr tcp tcp flags & (syn|rst) == syn tcp option maxseg size set 1440"
            )
            .count(),
            2,
            "{text}"
        );
        assert!(text.contains("oifname \"rsvpn0\""));
    }

    #[test]
    fn kill_switch_allows_only_endpoint_tunnel_and_scope() {
        let outer: SocketAddr = "203.0.113.10:1194".parse().unwrap();
        let text = text(&kill_switch_commands(
            "scope",
            "rsvpn-gui",
            outer,
            Some("eth0"),
        ));
        assert!(text.contains("policy drop"));
        assert!(text.contains("oifname \"lo\" accept"));
        assert!(text.contains("oifname \"rsvpn-gui\" accept"));
        assert!(text.contains("ip daddr 203.0.113.10 udp dport 1194 accept"));
        assert!(text.contains("ip daddr 203.0.113.10 tcp dport 1194 accept"));
        // DHCPv4 and DHCPv6 are scoped to the underlay interface.
        assert!(text.contains("oifname eth0 udp sport 68 udp dport 67 accept"));
        assert!(text.contains("oifname eth0 udp sport 546 udp dport 547 accept"));
        assert!(text.contains("oifname eth0 udp sport 547 udp dport 546 accept"));
        assert!(text.contains("oifname eth0 icmpv6 type"));
        assert!(text.contains("nd-neighbor-solicit"));
        assert!(text.contains("mld2-listener-report"));
        // A broad underlay allow must not exist.
        assert!(!text.contains("oifname eth0 accept"));
    }

    #[test]
    fn kill_switch_uses_ip6_for_v6_endpoints() {
        let outer: SocketAddr = "[2001:db8::10]:1194".parse().unwrap();
        let text = text(&kill_switch_commands(
            "scope",
            "rsvpn0",
            outer,
            Some("eth0"),
        ));
        assert!(text.contains("ip6 daddr 2001:db8::10 udp dport 1194 accept"));
        assert!(text.contains("ip6 daddr 2001:db8::10 tcp dport 1194 accept"));
        assert!(text.contains("icmpv6"));
    }

    #[test]
    fn mss_is_clamped_to_sane_bounds() {
        let commands = mss_commands("scope", "x", Some(1), None);
        assert_eq!(commands.last().unwrap().last().unwrap(), "536");
        let high = mss_commands("scope", "x", Some(1_000_000), None);
        assert_eq!(high.last().unwrap().last().unwrap(), "65535");
    }

    #[tokio::test]
    async fn ipv6_endpoint_requires_underlay_scope() {
        let outer: SocketAddr = "[2001:db8::10]:1194".parse().unwrap();
        // The wrapper rejects before invoking nft; no host command is run.
        let error = apply_kill_switch("scope", "x", outer, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("underlay"), "{error}");
    }
}
