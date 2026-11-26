//! Declarative server-side TAP setup.
//!
//! This is the "no up script required" path for `peers.yaml` entries with a
//! `network:` section.  It creates the TAP when missing, configures the
//! address/MTU/routes/DNS, and rolls everything back if any step fails.  A
//! successful setup is tracked in [`TapGuard`] so the server can remove only
//! what it created on shutdown.
//!
//! Only `ip` and `resolvectl` are used.  No user-provided script is executed
//! on this path, and existing interfaces that are not TAP devices are
//! rejected instead of being reconfigured.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use tokio::process::Command;

use crate::config::PeerNetwork;

/// `ip link` alias that marks a TAP as owned by RustVPN.
///
/// The declarative server path refuses to touch a pre-existing TAP without
/// this marker so it cannot destroy an administrator's address/routes/DNS.
pub const TAP_ALIAS_MARKER: &str = "rustvpn-managed";

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinkInfo {
    // Retained for diagnostics/tests; the ownership policy no longer restores
    // a pre-existing interface because unmarked TAPs are refused.
    #[allow(dead_code)]
    mtu: usize,
    #[allow(dead_code)]
    was_up: bool,
    is_tap: bool,
    alias: Option<String>,
}

/// State needed to undo a successful declarative TAP setup.
#[derive(Debug)]
pub struct TapGuard {
    ip: PathBuf,
    iface: String,
    /// True when this interface is RustVPN-owned and should be deleted on
    /// cleanup (created here or adopted via the marker after a crash).
    owned_tap: bool,
    address: Option<String>,
    /// Full delete command arguments for routes this guard added.
    routes: Vec<Vec<String>>,
    dns: bool,
}

impl TapGuard {
    /// Undo the address/routes/DNS/link changes (and delete a TAP we created).
    pub async fn remove(mut self) {
        self.cleanup().await;
    }

    async fn cleanup(&mut self) {
        if self.dns {
            if let Some(resolvectl) = which_resolvectl() {
                let _ = run_command(&resolvectl, &["revert".into(), self.iface.clone()]).await;
            }
            self.dns = false;
        }
        let routes = std::mem::take(&mut self.routes);
        for args in routes.into_iter().rev() {
            let _ = self.run(&args).await;
        }
        if let Some(address) = self.address.take() {
            let _ = self
                .run(&[
                    "-4".into(),
                    "addr".into(),
                    "del".into(),
                    address,
                    "dev".into(),
                    self.iface.clone(),
                ])
                .await;
        }
        if self.owned_tap {
            // A peer task cancelled by a reload may still hold the TAP file
            // descriptor for a few milliseconds, making `ip link del` fail
            // with EBUSY.  Retry briefly so a removed peer does not leave its
            // declarative TAP behind until the server exits.
            let mut deleted = false;
            let mut last_error = String::new();
            for attempt in 0..4 {
                match self
                    .run(&[
                        "link".into(),
                        "del".into(),
                        "dev".into(),
                        self.iface.clone(),
                    ])
                    .await
                {
                    Ok(output) if output.status.success() => {
                        deleted = true;
                        break;
                    }
                    Ok(output) => {
                        last_error = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    }
                    Err(error) => last_error = error.to_string(),
                }
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
            if !deleted {
                eprintln!(
                    "delete declarative TAP {} failed after retries: {last_error}",
                    self.iface
                );
            }
            self.owned_tap = false;
        }
    }

    async fn run(&self, args: &[String]) -> Result<std::process::Output> {
        run_command(&self.ip, args).await
    }
}

/// Ensure `iface` is a RustVPN-owned TAP and apply the declarative network
/// settings.  `inner_ip_mtu` is the TAP IP MTU derived from the numeric wire
/// MTU (`Mode::max_payload(wire_mtu) - 14`), never the wire/frame budget.
///
/// A pre-existing TAP without the [`TAP_ALIAS_MARKER`] alias is refused; a
/// marked TAP is treated as an orphan from a previous RustVPN run, has its
/// stale IPv4 state flushed before the new config is applied, and is deleted
/// on cleanup.  On failure every change made so far is rolled back.
pub async fn configure_tap(
    iface: &str,
    inner_ip_mtu: usize,
    network: &PeerNetwork,
) -> Result<TapGuard> {
    if iface.is_empty() || iface.len() > 15 {
        bail!("declarative network requires a valid TAP interface name");
    }
    validate_network(network)?;
    let ip = ip_bin();
    let mut guard = TapGuard {
        ip: ip.clone(),
        iface: iface.to_string(),
        owned_tap: false,
        address: None,
        routes: Vec::new(),
        dns: false,
    };

    let existing = show_link(&ip, iface).await?;
    let mut adopted = false;
    match existing {
        Some(info) => {
            if !info.is_tap {
                bail!("{iface} already exists and is not a TAP device; refusing to reconfigure it");
            }
            if info.alias.as_deref() != Some(TAP_ALIAS_MARKER) {
                bail!(
                    "{iface} already exists but is not marked as RustVPN-owned \
                     (alias {TAP_ALIAS_MARKER:?}); refusing to modify a pre-existing TAP. \
                     `network:` owns TAP creation, so an `up` script configured alongside it \
                     must not create this interface (or must mark it itself with \
                     `ip link set dev {iface} alias {TAP_ALIAS_MARKER}`). \
                     Remove it or use a different iface name"
                );
            }
            // A marked TAP is an orphan from a previous RustVPN run (or a
            // previous config); adopt it and delete it on shutdown.
            guard.owned_tap = true;
            adopted = true;
        }
        None => {
            let output = run_command(
                &ip,
                &[
                    "tuntap".into(),
                    "add".into(),
                    "dev".into(),
                    iface.into(),
                    "mode".into(),
                    "tap".into(),
                ],
            )
            .await?;
            if !output.status.success() {
                bail!(
                    "create TAP {iface}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            guard.owned_tap = true;
            let mark = guard
                .run(&[
                    "link".into(),
                    "set".into(),
                    "dev".into(),
                    iface.into(),
                    "alias".into(),
                    TAP_ALIAS_MARKER.into(),
                ])
                .await?;
            if !mark.status.success() {
                guard.cleanup().await;
                bail!(
                    "mark TAP {iface} as RustVPN-owned: {}",
                    String::from_utf8_lossy(&mark.stderr).trim()
                );
            }
        }
    }

    // Only a marked (RustVPN-owned) orphan is flushed.  A pre-existing
    // unmarked interface never reaches this point, so administrator state is
    // untouched.  This removes stale addresses/routes/DNS left by the crashed
    // run before the new `network:` config is applied; otherwise `addr add`
    // would happily stack a second address on the adopted TAP.
    if adopted {
        if let Err(error) = guard.flush_adopted_state().await {
            guard.cleanup().await;
            return Err(error);
        }
    }

    if let Err(error) = guard.apply(inner_ip_mtu, network).await {
        guard.cleanup().await;
        return Err(error);
    }
    Ok(guard)
}

impl TapGuard {
    /// Drop stale IPv4 state from a marked orphan before applying new config.
    ///
    /// This TAP carries the RustVPN ownership marker, so its addresses and
    /// routes belong to a previous RustVPN instance.  IPv4-only matches the
    /// declarative `network:` feature; IPv6 is never configured here.
    async fn flush_adopted_state(&self) -> Result<()> {
        let addr = self
            .run(&[
                "-4".into(),
                "addr".into(),
                "flush".into(),
                "dev".into(),
                self.iface.clone(),
            ])
            .await?;
        if !addr.status.success() {
            bail!(
                "flush stale addresses on adopted TAP {}: {}",
                self.iface,
                String::from_utf8_lossy(&addr.stderr).trim()
            );
        }
        let route = self
            .run(&[
                "-4".into(),
                "route".into(),
                "flush".into(),
                "dev".into(),
                self.iface.clone(),
            ])
            .await?;
        if !route.status.success() {
            bail!(
                "flush stale routes on adopted TAP {}: {}",
                self.iface,
                String::from_utf8_lossy(&route.stderr).trim()
            );
        }
        if let Some(resolvectl) = which_resolvectl() {
            let _ = run_command(&resolvectl, &["revert".into(), self.iface.clone()]).await;
        }
        Ok(())
    }

    async fn apply(&mut self, inner_ip_mtu: usize, network: &PeerNetwork) -> Result<()> {
        let link = self
            .run(&[
                "link".into(),
                "set".into(),
                "dev".into(),
                self.iface.clone(),
                "mtu".into(),
                inner_ip_mtu.to_string(),
                "up".into(),
            ])
            .await?;
        if !link.status.success() {
            bail!(
                "configure {}: {}",
                self.iface,
                String::from_utf8_lossy(&link.stderr).trim()
            );
        }

        if !network.address.trim().is_empty() {
            // Non-destructive: `add` never overwrites a pre-existing address.
            // A pre-existing, identical address is treated as idempotent (for
            // example an adopted marked orphan) and is not recorded for
            // deletion; anything else is a conflict.
            let output = self
                .run(&[
                    "-4".into(),
                    "addr".into(),
                    "add".into(),
                    network.address.clone(),
                    "dev".into(),
                    self.iface.clone(),
                ])
                .await?;
            if output.status.success() {
                self.address = Some(network.address.clone());
            } else if stderr_is_exists(&output.stderr) {
                if !self.address_exists_exact(&network.address).await? {
                    bail!(
                        "address {} already exists on {} with different settings; \
                         refusing to override it",
                        network.address,
                        self.iface
                    );
                }
            } else {
                bail!(
                    "add address {}: {}",
                    network.address,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }

        for route in &network.routes {
            // Never `replace`: that would delete a pre-existing host route
            // (including a real default route) that this guard cannot
            // restore.  Only routes actually added here are recorded and
            // later deleted.
            let mut add = vec!["-4".into(), "route".into(), "add".into(), route.clone()];
            let mut delete = vec!["-4".into(), "route".into(), "del".into(), route.clone()];
            if !network.gateway.trim().is_empty() {
                add.push("via".into());
                add.push(network.gateway.clone());
                delete.push("via".into());
                delete.push(network.gateway.clone());
            }
            add.push("dev".into());
            add.push(self.iface.clone());
            delete.push("dev".into());
            delete.push(self.iface.clone());
            let output = self.run(&add).await?;
            if output.status.success() {
                self.routes.push(delete);
            } else if stderr_is_exists(&output.stderr) {
                if !self.route_exists_exact(route, &network.gateway).await? {
                    bail!(
                        "route {route} already exists on {} with different settings; \
                         refusing to override it",
                        self.iface
                    );
                }
            } else {
                bail!(
                    "add route {route}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }

        if !network.dns.is_empty() {
            let resolvectl = which_resolvectl().ok_or_else(|| {
                anyhow!(
                    "resolvectl not found; declarative network.dns requires systemd-resolved \
                     (or set RUSTVPN_RESOLVECTL_BIN)"
                )
            })?;
            let mut args = vec!["dns".to_string(), self.iface.clone()];
            args.extend(network.dns.iter().cloned());
            let output = run_command(&resolvectl, &args).await?;
            if !output.status.success() {
                bail!(
                    "resolvectl dns failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            self.dns = true;
            let domain = run_command(
                &resolvectl,
                &["domain".into(), self.iface.clone(), "~.".into()],
            )
            .await?;
            if !domain.status.success() {
                bail!(
                    "resolvectl domain failed: {}",
                    String::from_utf8_lossy(&domain.stderr).trim()
                );
            }
            let _ = run_command(
                &resolvectl,
                &["default-route".into(), self.iface.clone(), "yes".into()],
            )
            .await;
        }
        Ok(())
    }

    /// Whether this interface already carries exactly `address`.
    async fn address_exists_exact(&self, address: &str) -> Result<bool> {
        let output = self
            .run(&[
                "-4".into(),
                "-o".into(),
                "addr".into(),
                "show".into(),
                "dev".into(),
                self.iface.clone(),
            ])
            .await?;
        if !output.status.success() {
            return Ok(false);
        }
        let intended: IpNet = address
            .parse()
            .with_context(|| format!("invalid network address {address:?}"))?;
        Ok(parse_addr_show(&String::from_utf8_lossy(&output.stdout))
            .into_iter()
            .any(|net| net == intended))
    }

    /// Whether this interface already carries exactly `route` (with the same
    /// optional `gateway`).  Used only when `ip route add` reports `EEXIST`.
    async fn route_exists_exact(&self, route: &str, gateway: &str) -> Result<bool> {
        let output = self
            .run(&[
                "-4".into(),
                "route".into(),
                "show".into(),
                "dev".into(),
                self.iface.clone(),
            ])
            .await?;
        if !output.status.success() {
            return Ok(false);
        }
        let intended: IpNet = route
            .parse()
            .with_context(|| format!("invalid network route {route:?}"))?;
        let via = if gateway.trim().is_empty() {
            None
        } else {
            Some(gateway.trim())
        };
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| route_line_matches(line, &intended, via)))
    }
}

fn validate_network(network: &PeerNetwork) -> Result<()> {
    if !network.address.trim().is_empty() {
        let address: IpNet = network
            .address
            .parse()
            .with_context(|| format!("invalid network address {:?}", network.address))?;
        if !matches!(address, IpNet::V4(_)) {
            bail!("declarative network.address must be IPv4");
        }
    }
    if !network.gateway.trim().is_empty() {
        let gateway: IpAddr = network
            .gateway
            .parse()
            .with_context(|| format!("invalid network gateway {:?}", network.gateway))?;
        if !matches!(gateway, IpAddr::V4(_)) {
            bail!("declarative network.gateway must be IPv4");
        }
    }
    for route in &network.routes {
        if crate::config::is_default_route(route) {
            bail!(
                "declarative server routes must not contain a default route \
                 (including non-canonical prefix-0 forms like 00.0.0.0/0)"
            );
        }
        let net: IpNet = route
            .parse()
            .with_context(|| format!("invalid network route {route:?}"))?;
        if !matches!(net, IpNet::V4(_)) {
            bail!("declarative network.routes must be IPv4");
        }
    }
    for dns in &network.dns {
        let server: IpAddr = dns
            .parse()
            .with_context(|| format!("invalid network DNS {dns:?}"))?;
        if !matches!(server, IpAddr::V4(_)) {
            bail!("declarative network.dns must be IPv4");
        }
    }
    Ok(())
}

async fn show_link(ip: &PathBuf, iface: &str) -> Result<Option<LinkInfo>> {
    let output = run_command(
        ip,
        &[
            "-d".into(),
            "-o".into(),
            "link".into(),
            "show".into(),
            "dev".into(),
            iface.into(),
        ],
    )
    .await?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_link_info(&text)
        .map(Some)
        .ok_or_else(|| anyhow!("cannot parse link state for {iface}: {}", text.trim()))
}

fn parse_link_info(text: &str) -> Option<LinkInfo> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mtu = tokens
        .iter()
        .position(|token| *token == "mtu")
        .and_then(|index| tokens.get(index + 1))
        .and_then(|value| value.parse().ok())?;
    let flags = tokens
        .iter()
        .find(|token| token.starts_with('<') && token.ends_with('>'))
        .copied()
        .unwrap_or("");
    let was_up = flags
        .trim_matches(|c| c == '<' || c == '>')
        .split(',')
        .any(|flag| flag == "UP");
    // `ip -d -o link show` prints `tun type tap` for a TAP (the "tun" here is
    // the driver family).  TUN is L3 and must not be silently used where an
    // Ethernet TAP is required.  Older `ip` builds may print a bare `tap`.
    let type_tap = tokens
        .windows(3)
        .any(|window| window == ["tun", "type", "tap"]);
    let type_tun = tokens
        .windows(3)
        .any(|window| window == ["tun", "type", "tun"]);
    let has_tap = tokens.contains(&"tap");
    let alias = tokens
        .iter()
        .position(|token| *token == "alias")
        .and_then(|index| tokens.get(index + 1))
        .map(|value| value.trim_matches('"').to_string());
    Some(LinkInfo {
        mtu,
        was_up,
        is_tap: (type_tap || (has_tap && !type_tun)) && !type_tun,
        alias,
    })
}

fn stderr_is_exists(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.contains("File exists") || text.contains("RTNETLINK answers: File exists")
}

/// Extract every `inet <addr/prefix>` value from `ip -4 -o addr show` output.
fn parse_addr_show(text: &str) -> Vec<IpNet> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens
        .windows(2)
        .filter_map(|window| (window[0] == "inet").then_some(window[1]))
        .filter_map(|value| value.parse::<IpNet>().ok())
        .collect()
}

/// Does one `ip -4 route show` line describe the intended route?
///
/// Only the destination prefix and the optional `via` are compared; kernel
/// fields such as `proto`, `scope`, `src` and metrics are irrelevant to the
/// "same route" question.
fn route_line_matches(line: &str, intended: &IpNet, via: Option<&str>) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let Some(dest) = tokens.first() else {
        return false;
    };
    let dest_matches = dest
        .parse::<IpNet>()
        .map(|net| net.trunc() == intended.trunc())
        .unwrap_or(false);
    if !dest_matches {
        return false;
    }
    let found_via = tokens
        .iter()
        .position(|token| *token == "via")
        .and_then(|index| tokens.get(index + 1).copied());
    found_via == via
}

async fn run_command(program: &PathBuf, args: &[String]) -> Result<std::process::Output> {
    Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("run {}", program.display()))
}

fn ip_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("RUSTVPN_IP_BIN") {
        return PathBuf::from(path);
    }
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("ip")
}

fn which_resolvectl() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTVPN_RESOLVECTL_BIN") {
        return Some(PathBuf::from(path));
    }
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let path = Path::new(dir).join("resolvectl");
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    static NET_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn fake_ip(dir: &Path) -> PathBuf {
        let path = dir.join("ip");
        std::fs::write(
            &path,
            r#"#!/bin/sh
echo "$*" >> "$FAKE_LOG"
if [ -n "$FAKE_MISSING" ]; then
  case "$*" in
    *"link show"*) exit 1 ;;
  esac
fi
case "$*" in
  *"link show"*)
    echo "9: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noop tun type tap pi off${FAKE_ALIAS:+ alias $FAKE_ALIAS}"
    exit 0 ;;
  *"addr show dev"*)
    if [ -n "$FAKE_ADDR_SHOW" ]; then printf '%s\n' "$FAKE_ADDR_SHOW"; fi
    exit 0 ;;
  *"route show dev"*)
    if [ -n "$FAKE_ROUTE_SHOW" ]; then printf '%s\n' "$FAKE_ROUTE_SHOW"; fi
    exit 0 ;;
esac
if [ -n "$FAKE_EXISTS" ]; then
  case "$*" in
    *"route add"*|*"addr add"*)
      case "$*" in
        *"$FAKE_EXISTS"*) echo "RTNETLINK answers: File exists" >&2; exit 2 ;;
      esac ;;
  esac
fi
if [ -n "$FAKE_FAIL" ]; then
  case "$*" in
    *"$FAKE_FAIL"*) echo "simulated failure" >&2; exit 1 ;;
  esac
fi
exit 0
"#,
        )
        .unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn fake_resolvectl(dir: &Path) -> PathBuf {
        let path = dir.join("resolvectl");
        std::fs::write(
            &path,
            r#"#!/bin/sh
echo "resolvectl $*" >> "$FAKE_LOG"
exit 0
"#,
        )
        .unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn network() -> PeerNetwork {
        PeerNetwork {
            address: "10.88.0.1/24".into(),
            gateway: String::new(),
            dns: Vec::new(),
            routes: vec!["10.88.1.0/24".into()],
        }
    }

    #[tokio::test]
    async fn declarative_setup_is_idempotent_and_cleans_up() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        let resolvectl = fake_resolvectl(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("RUSTVPN_RESOLVECTL_BIN", &resolvectl);
        std::env::set_var("FAKE_LOG", &log);
        std::env::set_var("FAKE_ALIAS", TAP_ALIAS_MARKER);
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");
        std::env::remove_var("FAKE_EXISTS");
        std::env::remove_var("FAKE_ADDR_SHOW");
        std::env::remove_var("FAKE_ROUTE_SHOW");

        let guard = configure_tap("tap0", 1400, &network()).await.unwrap();
        guard.remove().await;
        let text = std::fs::read_to_string(&log).unwrap();
        for expected in [
            "link set dev tap0 mtu 1400 up",
            "addr add 10.88.0.1/24 dev tap0",
            "route add 10.88.1.0/24 dev tap0",
            "route del 10.88.1.0/24 dev tap0",
            "addr del 10.88.0.1/24 dev tap0",
            "link del dev tap0",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // Installation is non-destructive: never `replace`.
        assert!(!text.contains("addr replace"), "{text}");
        assert!(!text.contains("route replace"), "{text}");
        // A marked orphan is adopted, not recreated.
        assert!(!text.contains("tuntap add"), "{text}");

        std::env::remove_var("RUSTVPN_IP_BIN");
        std::env::remove_var("RUSTVPN_RESOLVECTL_BIN");
        std::env::remove_var("FAKE_LOG");
        std::env::remove_var("FAKE_ALIAS");
    }

    #[tokio::test]
    async fn declarative_failure_rolls_back_created_tap() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("FAKE_LOG", &log);
        std::env::set_var("FAKE_MISSING", "1");
        std::env::set_var("FAKE_FAIL", "route add");
        std::env::remove_var("FAKE_ALIAS");
        std::env::remove_var("FAKE_EXISTS");

        let error = configure_tap("tap0", 1400, &network()).await.unwrap_err();
        assert!(error.to_string().contains("route"), "{error:#}");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("tuntap add dev tap0 mode tap"), "{text}");
        // A freshly created TAP has no stale RustVPN state to flush.
        assert!(!text.contains("addr flush"), "{text}");
        assert!(!text.contains("route flush"), "{text}");
        assert!(
            text.contains("link set dev tap0 alias rustvpn-managed"),
            "{text}"
        );
        assert!(text.contains("addr del 10.88.0.1/24 dev tap0"), "{text}");
        assert!(text.contains("link del dev tap0"), "{text}");

        std::env::remove_var("RUSTVPN_IP_BIN");
        std::env::remove_var("FAKE_LOG");
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");
    }

    #[tokio::test]
    async fn refuses_unmarked_preexisting_tap() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("FAKE_LOG", &log);
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");
        std::env::remove_var("FAKE_ALIAS");

        let error = configure_tap("tap0", 1400, &network()).await.unwrap_err();
        let text = error.to_string();
        assert!(text.contains("not marked as RustVPN-owned"), "{text}");
        // `up` + `network:` is explicit: network owns TAP creation.
        assert!(text.contains("`network:` owns TAP creation"), "{text}");
        let log_text = std::fs::read_to_string(&log).unwrap();
        // Nothing may be changed on a pre-existing unmarked TAP.
        assert!(!log_text.contains("tuntap add"), "{log_text}");
        assert!(!log_text.contains("mtu 1400"), "{log_text}");
        assert!(!log_text.contains("addr add"), "{log_text}");
        assert!(!log_text.contains("route add"), "{log_text}");

        std::env::remove_var("RUSTVPN_IP_BIN");
        std::env::remove_var("FAKE_LOG");
    }

    #[tokio::test]
    async fn adopts_marked_orphan_after_a_crash() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        let resolvectl = fake_resolvectl(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("RUSTVPN_RESOLVECTL_BIN", &resolvectl);
        std::env::set_var("FAKE_LOG", &log);
        std::env::set_var("FAKE_ALIAS", TAP_ALIAS_MARKER);
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");
        std::env::remove_var("FAKE_EXISTS");

        let guard = configure_tap("tap0", 1476, &network()).await.unwrap();
        // Simulate a restart: the first run would have crashed without cleanup.
        guard.remove().await;
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(!text.contains("tuntap add"), "{text}");
        assert!(text.contains("link set dev tap0 mtu 1476 up"), "{text}");
        assert!(text.contains("link del dev tap0"), "{text}");

        std::env::remove_var("RUSTVPN_IP_BIN");
        std::env::remove_var("RUSTVPN_RESOLVECTL_BIN");
        std::env::remove_var("FAKE_LOG");
        std::env::remove_var("FAKE_ALIAS");
    }

    #[tokio::test]
    async fn adopting_marked_orphan_flushes_stale_state_before_new_config() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        let resolvectl = fake_resolvectl(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("RUSTVPN_RESOLVECTL_BIN", &resolvectl);
        std::env::set_var("FAKE_LOG", &log);
        std::env::set_var("FAKE_ALIAS", TAP_ALIAS_MARKER);
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");
        std::env::remove_var("FAKE_EXISTS");
        std::env::remove_var("FAKE_ADDR_SHOW");
        std::env::remove_var("FAKE_ROUTE_SHOW");

        // New config differs from the one a crashed run would have installed.
        let new_network = PeerNetwork {
            address: "10.88.9.1/30".into(),
            gateway: String::new(),
            dns: vec!["10.88.9.2".into()],
            routes: vec!["10.88.9.0/30".into()],
        };
        let guard = configure_tap("tap0", 1492, &new_network).await.unwrap();
        guard.remove().await;
        let text = std::fs::read_to_string(&log).unwrap();

        // Stale state is flushed only after the ownership marker is verified.
        assert!(text.contains("-4 addr flush dev tap0"), "{text}");
        assert!(text.contains("-4 route flush dev tap0"), "{text}");
        assert!(text.contains("resolvectl revert tap0"), "{text}");
        let flush_at = text.find("addr flush").unwrap();
        let add_at = text.find("addr add 10.88.9.1/30 dev tap0").unwrap();
        assert!(
            flush_at < add_at,
            "stale state must be flushed before the new address:\n{text}"
        );
        assert!(!text.contains("tuntap add"), "{text}");

        for var in [
            "RUSTVPN_IP_BIN",
            "RUSTVPN_RESOLVECTL_BIN",
            "FAKE_LOG",
            "FAKE_ALIAS",
            "FAKE_ADDR_SHOW",
            "FAKE_ROUTE_SHOW",
        ] {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn matching_eexist_is_idempotent_and_not_deleted() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        let resolvectl = fake_resolvectl(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("RUSTVPN_RESOLVECTL_BIN", &resolvectl);
        std::env::set_var("FAKE_LOG", &log);
        std::env::set_var("FAKE_ALIAS", TAP_ALIAS_MARKER);
        // Both the address and the route already exist with the same values
        // (for example an adopted marked orphan after a crash).
        std::env::set_var("FAKE_EXISTS", "10.88.");
        std::env::set_var(
            "FAKE_ADDR_SHOW",
            "9: tap0    inet 10.88.0.1/24 scope global tap0",
        );
        std::env::set_var("FAKE_ROUTE_SHOW", "10.88.1.0/24 dev tap0 scope link");
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");

        let guard = configure_tap("tap0", 1400, &network()).await.unwrap();
        guard.remove().await;
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("addr add 10.88.0.1/24 dev tap0"), "{text}");
        assert!(text.contains("route add 10.88.1.0/24 dev tap0"), "{text}");
        // Idempotent: state that was already present is never removed.
        assert!(!text.contains("addr del"), "{text}");
        assert!(!text.contains("route del"), "{text}");
        // The adopted TAP is still deleted.
        assert!(text.contains("link del dev tap0"), "{text}");

        for var in [
            "RUSTVPN_IP_BIN",
            "RUSTVPN_RESOLVECTL_BIN",
            "FAKE_LOG",
            "FAKE_ALIAS",
            "FAKE_EXISTS",
            "FAKE_ADDR_SHOW",
            "FAKE_ROUTE_SHOW",
        ] {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn eexist_conflict_rolls_back_and_leaves_preexisting_route() {
        let _guard = NET_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("commands.log");
        let ip = fake_ip(dir.path());
        let resolvectl = fake_resolvectl(dir.path());
        std::env::set_var("RUSTVPN_IP_BIN", &ip);
        std::env::set_var("RUSTVPN_RESOLVECTL_BIN", &resolvectl);
        std::env::set_var("FAKE_LOG", &log);
        std::env::set_var("FAKE_ALIAS", TAP_ALIAS_MARKER);
        // The route exists, but with a different next hop: adding it must
        // conflict instead of overwriting (or deleting) the pre-existing one.
        std::env::set_var("FAKE_EXISTS", "10.88.1.0/24");
        std::env::set_var(
            "FAKE_ROUTE_SHOW",
            "10.88.1.0/24 via 192.0.2.1 dev tap0 scope link",
        );
        std::env::remove_var("FAKE_ADDR_SHOW");
        std::env::remove_var("FAKE_MISSING");
        std::env::remove_var("FAKE_FAIL");

        let error = configure_tap("tap0", 1400, &network()).await.unwrap_err();
        assert!(
            error.to_string().contains("refusing to override"),
            "{error:#}"
        );
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("route add 10.88.1.0/24 dev tap0"), "{text}");
        assert!(!text.contains("route replace"), "{text}");
        // The pre-existing route must never be deleted; only the address this
        // attempt added is rolled back.
        assert!(!text.contains("route del"), "{text}");
        assert!(text.contains("addr del 10.88.0.1/24 dev tap0"), "{text}");
        assert!(text.contains("link del dev tap0"), "{text}");

        for var in [
            "RUSTVPN_IP_BIN",
            "RUSTVPN_RESOLVECTL_BIN",
            "FAKE_LOG",
            "FAKE_ALIAS",
            "FAKE_EXISTS",
            "FAKE_ROUTE_SHOW",
        ] {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn installs_tap_mtu_for_each_mode() {
        // Regression for the mode-only reload: the same wire MTU must yield
        // the mode-derived TAP IP MTU (plain 1500, noise 1476, encless 1492).
        for (inner_mtu, expected) in [
            (1500, "mtu 1500 up"),
            (1476, "mtu 1476 up"),
            (1492, "mtu 1492 up"),
        ] {
            let _guard = NET_TEST_LOCK.lock().await;
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("commands.log");
            let ip = fake_ip(dir.path());
            let resolvectl = fake_resolvectl(dir.path());
            std::env::set_var("RUSTVPN_IP_BIN", &ip);
            std::env::set_var("RUSTVPN_RESOLVECTL_BIN", &resolvectl);
            std::env::set_var("FAKE_LOG", &log);
            std::env::set_var("FAKE_ALIAS", TAP_ALIAS_MARKER);
            std::env::remove_var("FAKE_MISSING");
            std::env::remove_var("FAKE_FAIL");
            std::env::remove_var("FAKE_EXISTS");

            let guard = configure_tap("tap0", inner_mtu, &network()).await.unwrap();
            guard.remove().await;
            let text = std::fs::read_to_string(&log).unwrap();
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");

            std::env::remove_var("RUSTVPN_IP_BIN");
            std::env::remove_var("RUSTVPN_RESOLVECTL_BIN");
            std::env::remove_var("FAKE_LOG");
            std::env::remove_var("FAKE_ALIAS");
        }
    }

    #[test]
    fn parses_tap_link_state() {
        let info = parse_link_info(
            "5: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast \
             link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff promiscuity 0 \
             tun type tap pi off vnet_hdr off persist off alias rustvpn-managed",
        )
        .unwrap();
        assert_eq!(info.mtu, 1500);
        assert!(info.was_up);
        assert!(info.is_tap);
        assert_eq!(info.alias.as_deref(), Some(TAP_ALIAS_MARKER));

        let down = parse_link_info("5: tap0: <BROADCAST> mtu 1400 tap").unwrap();
        assert!(!down.was_up);
        assert_eq!(down.mtu, 1400);
        assert_eq!(down.alias, None);
    }

    #[test]
    fn rejects_tun_instead_of_tap() {
        let info = parse_link_info("6: tun0: <POINTOPOINT> mtu 1500 tun type tun").unwrap();
        assert!(!info.is_tap);
        // A bare `tap` token (older iproute) is still accepted.
        let info = parse_link_info("7: tap1: <BROADCAST> mtu 1500 tap").unwrap();
        assert!(info.is_tap);
    }

    #[test]
    fn validates_routes_and_addresses() {
        let mut network = PeerNetwork {
            address: "10.88.0.1/24".into(),
            gateway: String::new(),
            dns: vec![],
            routes: vec!["10.88.0.0/24".into()],
        };
        assert!(validate_network(&network).is_ok());
        for route in [
            "default",
            "DEFAULT",
            "0.0.0.0/0",
            "00.0.0.0/0",
            "0.0.0.00/0",
            "0.0.0.0/00",
        ] {
            network.routes = vec![route.into()];
            let error = validate_network(&network).unwrap_err().to_string();
            assert!(
                error.contains("default route"),
                "route {route:?} was not rejected as a default route: {error}"
            );
        }
        network.routes = vec!["2001:db8::/64".into()];
        assert!(validate_network(&network).is_err());
    }

    #[test]
    fn parses_address_and_route_show_output() {
        let addresses = parse_addr_show(
            "9: tap0    inet 10.88.0.1/24 scope global tap0\\       valid_lft forever\n",
        );
        assert_eq!(addresses, vec!["10.88.0.1/24".parse::<IpNet>().unwrap()]);

        let intended: IpNet = "10.88.1.0/24".parse().unwrap();
        assert!(route_line_matches(
            "10.88.1.0/24 dev tap0 scope link",
            &intended,
            None
        ));
        assert!(route_line_matches(
            "10.88.1.0/24 via 10.88.0.254 dev tap0",
            &intended,
            Some("10.88.0.254")
        ));
        assert!(!route_line_matches(
            "10.88.1.0/24 via 192.0.2.1 dev tap0",
            &intended,
            None
        ));
        assert!(!route_line_matches(
            "10.88.2.0/24 dev tap0",
            &intended,
            None
        ));
    }
}
