//! Linux address, route and DNS setup for GUI/daemon-managed profiles.
//!
//! This deliberately uses `ip` and `resolvectl` instead of putting the
//! daemon's whole network state behind rtnetlink in the first Linux build.
//! Every step records what it added so a disconnect or a failed setup can
//! restore the original state.  The anti-loop host route for the outer
//! (server or proxy) address is installed before the tunnel's default route.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use rustvpn_client_ipc::ProfileSpec;
use rustvpn_net::config::is_default_route;
use tokio::process::Command;

use crate::firewall;

const ROUTE_METRIC: u32 = 50;

/// Optional nftables features applied together with the address/route setup.
#[derive(Clone, Debug, Default)]
pub struct FirewallOptions {
    /// Clamp IPv4 TCP MSS to this value on the tunnel interface.
    pub mss_v4: Option<usize>,
    /// Clamp IPv6 TCP MSS to this value on the tunnel interface.
    pub mss_v6: Option<usize>,
    /// Install the full-tunnel kill switch (requires `outer`).
    pub kill_switch: bool,
    /// Per-daemon table-name scope (see [`firewall::instance_scope`]).
    pub scope: String,
}

#[derive(Clone, Debug, Default)]
pub struct NetOptions {
    pub firewall: FirewallOptions,
    /// Skip `resolvectl`; useful inside a network namespace or container
    /// where DNS is managed by the caller.
    pub no_host_dns: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRouteLite {
    pub via: Option<String>,
    pub dev: String,
}

#[derive(Clone, Debug)]
struct RoutePlan {
    family: &'static str,
    dest: String,
    via: Option<String>,
    metric: u32,
}

impl RoutePlan {
    fn delete_args(&self, iface: &str) -> Vec<String> {
        let mut args = vec![
            self.family.to_string(),
            "route".into(),
            "del".into(),
            self.dest.clone(),
        ];
        args.extend(self.via_args());
        args.push("dev".into());
        args.push(iface.into());
        args.push("metric".into());
        args.push(self.metric.to_string());
        args
    }

    fn add_args(&self, iface: &str) -> Vec<String> {
        let mut args = vec![
            self.family.to_string(),
            "route".into(),
            "add".into(),
            self.dest.clone(),
        ];
        args.extend(self.via_args());
        args.push("dev".into());
        args.push(iface.into());
        args.push("metric".into());
        args.push(self.metric.to_string());
        args
    }

    fn via_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(via) = &self.via {
            args.push("via".into());
            args.push(via.clone());
        }
        args
    }
}

/// Bring the TAP link up before the peer tasks start reading it.
///
/// This intentionally does not add an address or routes: it only prevents a
/// down TAP from returning EOF while the handshake runs.
pub async fn bring_link_up(iface: &str, mtu: usize) -> Result<()> {
    let ip = ip_bin();
    let output = run_command(
        &ip,
        &[
            "-4".into(),
            "link".into(),
            "set".into(),
            "dev".into(),
            iface.into(),
            "mtu".into(),
            mtu.to_string(),
            "up".into(),
        ],
    )
    .await?;
    if !output.status.success() {
        bail!(
            "bring up {iface}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Remove a marked IPv6 blackhole left behind by a crashed tunnel.
///
/// Only call this while holding the tunnel lock; the marker (`proto 66` +
/// metric 50) is specific to this client.
pub async fn cleanup_stale_ipv6_blackhole() {
    let ip = ip_bin();
    let args = ipv6_blackhole_args(false);
    let _ = run_command(&ip, &args).await;
}

/// Remove tables left behind by a crashed client daemon with the same
/// instance scope.
///
/// Only this scope's RustVPN-owned tables are deleted; host NAT/filter rules
/// and other RustVPN daemons in the same netns are not touched.
pub async fn cleanup_stale_firewall(scope: &str) {
    firewall::cleanup_stale(scope).await;
}

pub struct NetworkGuard {
    ip: PathBuf,
    enabled: bool,
    iface: String,
    address: Option<String>,
    routes: Vec<RoutePlan>,
    host_route: Option<Vec<String>>,
    dns: bool,
    ipv6_blackhole: bool,
    mss: bool,
    kill_switch: bool,
    scope: String,
}

impl NetworkGuard {
    /// Apply the profile's address, routes, DNS and optional firewall rules.
    ///
    /// `outer` is the resolved server or proxy address; it is pinned to the
    /// original default route so tunnel traffic does not recursively enter
    /// the tunnel. `inner_mtu` is the derived IP MTU for the TAP interface
    /// from the numeric wire MTU (never the wire/frame budget itself).
    #[allow(clippy::too_many_arguments)]
    pub async fn install(
        spec: &ProfileSpec,
        outer: Option<SocketAddr>,
        inner_mtu: usize,
        options: NetOptions,
    ) -> Result<Self> {
        if spec.address.trim().is_empty() && !spec.routes.is_empty() {
            bail!("profile has routes but no address");
        }
        if spec.ipv6 {
            bail!("IPv6 is not implemented");
        }
        if has_default_route(&spec.routes) && outer.is_none() {
            bail!("cannot install a default route without resolving the outer endpoint");
        }
        if options.firewall.kill_switch && !has_default_route(&spec.routes) {
            bail!("kill_switch is only supported for full-tunnel profiles");
        }

        let ip = ip_bin();
        let mut guard = Self {
            ip,
            enabled: true,
            iface: spec.iface.clone(),
            address: None,
            routes: Vec::new(),
            host_route: None,
            dns: false,
            ipv6_blackhole: false,
            mss: false,
            kill_switch: false,
            scope: options.firewall.scope.clone(),
        };

        if let Err(error) = guard.apply(spec, outer, inner_mtu, options).await {
            guard.remove().await;
            return Err(error);
        }
        Ok(guard)
    }

    async fn apply(
        &mut self,
        spec: &ProfileSpec,
        outer: Option<SocketAddr>,
        inner_mtu: usize,
        options: NetOptions,
    ) -> Result<()> {
        let has_default = has_default_route(&spec.routes);
        let mut underlay: Option<String> = None;
        if has_default {
            if let Some(outer) = outer {
                let family = if outer.is_ipv6() { "-6" } else { "-4" };
                let route = read_default_route(&self.ip, family).await?;
                if let Some(route) = route {
                    underlay = Some(route.dev.clone());
                    let dest = match outer.ip() {
                        IpAddr::V4(addr) => format!("{addr}/32"),
                        IpAddr::V6(addr) => format!("{addr}/128"),
                    };
                    let mut args = vec![family.to_string(), "route".into(), "add".into(), dest];
                    if let Some(via) = route.via {
                        args.push("via".into());
                        args.push(via);
                    }
                    args.push("dev".into());
                    args.push(route.dev);
                    let output = self.run(&args).await?;
                    if output.status.success() {
                        self.host_route = Some(args);
                    } else if !stderr_is_exists(&output.stderr) {
                        bail!(
                            "install anti-loop route for {outer}: {}",
                            String::from_utf8_lossy(&output.stderr).trim()
                        );
                    }
                } else {
                    bail!("cannot find the original default route; refusing to install a default route");
                }
            }
        }

        let mtu = inner_mtu.to_string();
        let link = self
            .run(&[
                "-4".into(),
                "link".into(),
                "set".into(),
                "dev".into(),
                self.iface.clone(),
                "mtu".into(),
                mtu,
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
        if !spec.address.trim().is_empty() {
            let addr = self
                .run(&[
                    "-4".into(),
                    "addr".into(),
                    "replace".into(),
                    spec.address.clone(),
                    "dev".into(),
                    self.iface.clone(),
                ])
                .await?;
            if !addr.status.success() {
                bail!(
                    "address {}: {}",
                    spec.address,
                    String::from_utf8_lossy(&addr.stderr).trim()
                );
            }
            self.address = Some(spec.address.clone());
        }

        for route in &spec.routes {
            if route.is_empty() {
                continue;
            }
            let plan = route_plan(route, &spec.gateway)?;
            let args = plan.add_args(&self.iface);
            let output = self.run(&args).await?;
            if output.status.success() {
                self.routes.push(plan);
            } else if stderr_is_exists(&output.stderr) {
                if is_default_route(route) {
                    bail!(
                        "default route metric 50 already exists; refusing to pretend the tunnel owns it"
                    );
                }
            } else {
                bail!(
                    "add route {route}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }

        if has_default {
            self.block_ipv6().await?;
        }

        if options.no_host_dns {
            if !spec.dns.is_empty() {
                eprintln!(
                    "--no-host-dns is set; leaving resolver configuration to the caller \
                     (profile DNS values are not applied)"
                );
            }
        } else if !spec.dns.is_empty() {
            let resolvectl = which("resolvectl").ok_or_else(|| {
                anyhow!("resolvectl not found; refusing to connect with an unmanaged DNS leak")
            })?;
            let mut args = vec!["dns".to_string(), self.iface.clone()];
            args.extend(spec.dns.iter().cloned());
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
                    "resolvectl domain ~. failed: {}",
                    String::from_utf8_lossy(&domain.stderr).trim()
                );
            }
            let _ = run_command(
                &resolvectl,
                &["default-route".into(), self.iface.clone(), "yes".into()],
            )
            .await;
        } else if has_default {
            bail!("full-tunnel profile requires at least one DNS server");
        }

        let mss_v4 = options.firewall.mss_v4;
        let mss_v6 = options.firewall.mss_v6;
        if mss_v4.is_some() || mss_v6.is_some() {
            match firewall::apply_mss(&self.scope, &self.iface, mss_v4, mss_v6).await {
                Ok(()) => {
                    self.mss = true;
                    eprintln!(
                        "nft: MSS clamped on {} (v4={:?}, v6={:?})",
                        self.iface, mss_v4, mss_v6
                    );
                }
                Err(error) => {
                    // MSS clamping is a best-effort optimisation; a missing
                    // nft binary must not turn a working tunnel into a
                    // failed connection.  Keep the failure visible.
                    eprintln!("warning: MSS clamp not applied: {error:#}");
                }
            }
        }

        if options.firewall.kill_switch {
            let outer = outer.ok_or_else(|| {
                anyhow!("cannot install kill switch without a resolved outer endpoint")
            })?;
            firewall::apply_kill_switch(&self.scope, &self.iface, outer, underlay.as_deref())
                .await?;
            self.kill_switch = true;
            eprintln!(
                "nft: kill switch active (loopback, {}, outer {}, underlay {})",
                self.iface,
                outer,
                underlay.as_deref().unwrap_or("-")
            );
        }

        Ok(())
    }

    async fn block_ipv6(&mut self) -> Result<()> {
        // A previous daemon crash can leave the blackhole behind (it is not
        // attached to the TAP, so the kernel will not remove it for us).
        let stale = ipv6_blackhole_args(false);
        let _ = self.run(&stale).await;

        let args = ipv6_blackhole_args(true);
        let output = self.run(&args).await?;
        if output.status.success() {
            self.ipv6_blackhole = true;
        } else if ipv6_unavailable(&output.stderr) {
            eprintln!("IPv6 is unavailable; no IPv6 blackhole route was installed");
        } else {
            bail!(
                "block IPv6 default route: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Undo everything `install` added.  Safe to call more than once.
    pub async fn remove(mut self) {
        if !self.enabled {
            return;
        }
        let routes = std::mem::take(&mut self.routes);
        for route in routes.into_iter().rev() {
            let args = route.delete_args(&self.iface);
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
        let _ = self
            .run(&[
                "-4".into(),
                "link".into(),
                "set".into(),
                "dev".into(),
                self.iface.clone(),
                "down".into(),
            ])
            .await;
        if let Some(args) = self.host_route.take() {
            let mut args = args;
            if args.len() >= 3 {
                args[2] = "del".into();
            }
            let _ = self.run(&args).await;
        }
        if self.ipv6_blackhole {
            let args = ipv6_blackhole_args(false);
            let _ = self.run(&args).await;
            self.ipv6_blackhole = false;
        }
        if self.dns {
            if let Some(resolvectl) = which("resolvectl") {
                let _ = run_command(&resolvectl, &["revert".into(), self.iface.clone()]).await;
            }
        }
        // Remove firewall state last so the tunnel stays leak-free until the
        // routes are gone.  Both helpers are idempotent and ignore a missing
        // nft binary.
        if self.kill_switch {
            firewall::remove_kill_switch(&self.scope).await;
            self.kill_switch = false;
        }
        if self.mss {
            firewall::remove_mss(&self.scope).await;
            self.mss = false;
        }
    }

    /// Whether the MSS clamp table was applied successfully.
    pub fn mss_applied(&self) -> bool {
        self.mss
    }

    /// Whether the kill switch table was applied successfully.
    pub fn kill_switch_applied(&self) -> bool {
        self.kill_switch
    }

    async fn run(&self, args: &[String]) -> Result<std::process::Output> {
        run_command(&self.ip, args).await
    }
}

fn has_default_route(routes: &[String]) -> bool {
    // Canonical check: recognises `default`, `0.0.0.0/0` and non-canonical
    // prefix-0 spellings that `ipnet` normalises.
    routes.iter().any(|route| is_default_route(route))
}

fn ipv6_blackhole_args(add: bool) -> Vec<String> {
    vec![
        "-6".into(),
        "route".into(),
        if add { "add".into() } else { "del".into() },
        "blackhole".into(),
        "default".into(),
        "proto".into(),
        "66".into(),
        "metric".into(),
        "50".into(),
    ]
}

fn ipv6_unavailable(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    text.contains("address family not supported")
        || text.contains("protocol not supported")
        || text.contains("operation not supported")
        || text.contains("network is unreachable")
        || text.contains("cannot open netlink socket")
}

fn route_plan(route: &str, gateway: &str) -> Result<RoutePlan> {
    let via = if gateway.trim().is_empty() {
        None
    } else {
        Some(gateway.to_string())
    };
    let (family, dest) = if route.trim().eq_ignore_ascii_case("default") {
        ("-4", "default".to_string())
    } else {
        let net: IpNet = route
            .parse()
            .with_context(|| format!("invalid route {route:?}"))?;
        let family = if matches!(net, IpNet::V4(_)) {
            "-4"
        } else {
            "-6"
        };
        if is_default_route(route) {
            // Normalise every IPv4 prefix-0 spelling to the keyword form;
            // `ip route add 00.0.0.0/0` is not portable across iproute2.
            (family, "default".to_string())
        } else {
            (family, route.to_string())
        }
    };
    Ok(RoutePlan {
        family,
        dest,
        via,
        metric: ROUTE_METRIC,
    })
}

async fn read_default_route(ip: &PathBuf, family: &str) -> Result<Option<DefaultRouteLite>> {
    let output = run_command(
        ip,
        &[
            family.to_string(),
            "route".into(),
            "show".into(),
            "default".into(),
        ],
    )
    .await?;
    if !output.status.success() {
        bail!(
            "read default route: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_default_route(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub fn parse_default_route(text: &str) -> Option<DefaultRouteLite> {
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() != Some(&"default") {
            continue;
        }
        let mut via = None;
        let mut dev = None;
        let mut index = 0;
        while index + 1 < tokens.len() {
            match tokens[index] {
                "via" => via = Some(tokens[index + 1].to_string()),
                "dev" => dev = Some(tokens[index + 1].to_string()),
                _ => {}
            }
            index += 1;
        }
        if let Some(dev) = dev {
            return Some(DefaultRouteLite { via, dev });
        }
    }
    None
}

fn stderr_is_exists(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.contains("File exists") || text.contains("RTNETLINK answers: File exists")
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

fn which(name: &str) -> Option<PathBuf> {
    if name == "resolvectl" {
        if let Some(path) = std::env::var_os("RUSTVPN_RESOLVECTL_BIN") {
            return Some(PathBuf::from(path));
        }
    }
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let path = PathBuf::from(dir).join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_via_and_dev() {
        let route = parse_default_route(
            "default via 192.168.1.1 dev wlp3s0 proto dhcp src 192.168.1.50 metric 600\n",
        )
        .unwrap();
        assert_eq!(route.via.as_deref(), Some("192.168.1.1"));
        assert_eq!(route.dev, "wlp3s0");
    }

    #[test]
    fn parses_dev_only_and_ignores_garbage() {
        assert!(parse_default_route("garbage\n").is_none());
        let route = parse_default_route("default dev ppp0 scope link\n").unwrap();
        assert_eq!(route.via, None);
        assert_eq!(route.dev, "ppp0");
    }

    #[test]
    fn builds_route_commands() {
        let plan = route_plan("default", "10.88.0.1").unwrap();
        assert_eq!(
            plan.add_args("rsvpn0"),
            vec![
                "-4",
                "route",
                "add",
                "default",
                "via",
                "10.88.0.1",
                "dev",
                "rsvpn0",
                "metric",
                "50"
            ]
        );
        assert_eq!(
            plan.delete_args("rsvpn0"),
            vec![
                "-4",
                "route",
                "del",
                "default",
                "via",
                "10.88.0.1",
                "dev",
                "rsvpn0",
                "metric",
                "50"
            ]
        );
    }

    #[test]
    fn recognises_default_route_spellings() {
        assert!(has_default_route(&["default".into()]));
        assert!(has_default_route(&["0.0.0.0/0".into()]));
        for route in ["DEFAULT", "00.0.0.0/0", "0.0.0.00/0", "0.0.0.0/00"] {
            assert!(
                has_default_route(&[route.into()]),
                "{route:?} must enable full-tunnel semantics"
            );
        }
        assert!(!has_default_route(&["0.0.0.0/1".into()]));
        assert!(!has_default_route(&["10.0.0.0/8".into()]));
    }

    #[test]
    fn route_plan_normalises_noncanonical_default_routes() {
        for route in [
            "default",
            "DEFAULT",
            "0.0.0.0/0",
            "00.0.0.0/0",
            "0.0.0.0/00",
        ] {
            let plan = route_plan(route, "10.88.0.1").unwrap();
            assert_eq!(plan.family, "-4", "{route:?}");
            assert_eq!(plan.dest, "default", "{route:?}");
        }
        let plan = route_plan("10.88.1.0/24", "").unwrap();
        assert_eq!(plan.dest, "10.88.1.0/24");
        // An IPv6 default is never rewritten as IPv4.
        let plan = route_plan("::/0", "").unwrap();
        assert_eq!(plan.family, "-6");
        assert_eq!(plan.dest, "default");
    }

    #[test]
    fn detects_existing_route() {
        assert!(stderr_is_exists(b"RTNETLINK answers: File exists\n"));
        assert!(!stderr_is_exists(b"Operation not permitted\n"));
    }
    #[test]
    fn builds_ipv6_blackhole_and_cleanup_args() {
        let add = ipv6_blackhole_args(true);
        assert_eq!(add[2], "add");
        assert_eq!(add[3], "blackhole");
        assert_eq!(add[4], "default");
        assert_eq!(add[6], "66");
        let delete = ipv6_blackhole_args(false);
        assert_eq!(delete[2], "del");
        assert!(ipv6_unavailable(
            b"Address family not supported by protocol"
        ));
        assert!(!ipv6_unavailable(b"Operation not permitted"));
    }
}
