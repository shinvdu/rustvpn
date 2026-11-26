//! Wire-MTU contract helpers.
//!
//! In v1 the configured `mtu` is a **two-sided wire contract**: both peers must
//! use the same numeric value.  The client must never derive its own
//! `PeerConfig.mtu` from the local path, because that changes the handshake and
//! transport wire lengths and makes the other side reject the packets with
//! `TooLarge`.
//!
//! Only the TAP **interface IP MTU** and the TCP MSS clamp are derived from
//! the numeric wire MTU:
//!
//! ```text
//! inner_ip_mtu = Mode::max_payload(wire_mtu) - 14
//! ipv4_mss     = inner_ip_mtu - 40
//! ipv6_mss     = inner_ip_mtu - 60
//! ```
//!
//! Per-mode payload budgets (see `rustvpn-proto`):
//!
//! | mode    | max payload for mtu 1515 | inner IP MTU |
//! |---------|--------------------------|--------------|
//! | plain   | 1514                     | 1500         |
//! | noise   | 1490                     | 1476         |
//! | encless | 1506                     | 1492         |
//!
//! `mtu: auto` and `mtu: 0` are rejected in v1; path-MTU negotiation is
//! deferred to a future protocol version.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use rustvpn_proto::{Mode, MTU_MAX};
use tokio::process::Command;

pub const ETH_HEADER: usize = 14;
/// Conservative underlay used only for the best-effort encless capacity warning.
pub const DEFAULT_UNDERLAY_MTU: usize = 1500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OuterFamily {
    V4,
    V6,
}

impl OuterFamily {
    pub fn from_addr(addr: &SocketAddr) -> Self {
        if addr.is_ipv6() {
            OuterFamily::V6
        } else {
            OuterFamily::V4
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            OuterFamily::V4 => "ipv4",
            OuterFamily::V6 => "ipv6",
        }
    }

    /// Outer IP + UDP/TCP header bytes.
    pub fn header_len(self, proto: &str) -> usize {
        match (self, proto) {
            (OuterFamily::V4, "tcp") => 20 + 20,
            (OuterFamily::V6, "tcp") => 40 + 20,
            (OuterFamily::V4, _) => 20 + 8,
            (OuterFamily::V6, _) => 40 + 8,
        }
    }
}

/// Values derived from the numeric wire MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireMtu {
    /// Configured transport frame budget shared by both peers.
    pub wire_mtu: usize,
    pub mode: Mode,
    /// IP MTU to configure on the TAP interface.
    pub inner_ip_mtu: usize,
    /// IPv4 TCP MSS clamp value.
    pub mss_v4: usize,
    /// IPv6 TCP MSS clamp value (smaller by the 20-byte larger header).
    pub mss_v6: usize,
}

impl WireMtu {
    pub fn log_line(&self) -> String {
        format!(
            "mtu: wire={} mode={} -> inner_ip_mtu={} mss_v4={} mss_v6={} \
             (wire MTU is a two-sided contract; auto/path-MTU is deferred to v2)",
            self.wire_mtu,
            mode_label(self.mode),
            self.inner_ip_mtu,
            self.mss_v4,
            self.mss_v6
        )
    }
}

/// Derive the TAP IP MTU and MSS values from a numeric wire MTU.
///
/// `wire_mtu` must be a positive numeric value; `mtu: auto`/`mtu: 0` are
/// rejected because v1 has no MTU negotiation.
pub fn from_wire(mode: Mode, wire_mtu: usize) -> Result<WireMtu> {
    if wire_mtu == 0 {
        bail!(
            "mtu: 0 is invalid; configure a numeric wire MTU shared by both peers (for example 1515)"
        );
    }
    if wire_mtu < mode.min_mtu() {
        bail!(
            "wire MTU {wire_mtu} is below the {}-byte minimum for {} mode",
            mode.min_mtu(),
            mode_label(mode)
        );
    }
    if wire_mtu > MTU_MAX {
        bail!("wire MTU {wire_mtu} exceeds the maximum {MTU_MAX}");
    }
    let inner_ip_mtu = mode.max_payload(wire_mtu).saturating_sub(ETH_HEADER);
    Ok(WireMtu {
        wire_mtu,
        mode,
        inner_ip_mtu,
        mss_v4: inner_ip_mtu.saturating_sub(40),
        mss_v6: inner_ip_mtu.saturating_sub(60),
    })
}

pub fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Plain => "plain",
        Mode::Noise => "noise",
        Mode::Encless => "encless",
    }
}

#[derive(Clone, Debug)]
pub struct PathMtu {
    pub underlay_mtu: usize,
    pub dev: String,
    pub source: String,
}

/// Ask the kernel for the route to `outer` and read the link MTU of its
/// outgoing device.  Used only for the encless capacity warning; it never
/// changes the configured wire MTU.
pub async fn detect_path_mtu(outer: SocketAddr) -> Result<PathMtu> {
    let ip = ip_bin();
    let family = if outer.is_ipv6() { "-6" } else { "-4" };
    let target = outer.ip().to_string();
    let output = Command::new(&ip)
        .args([family, "route", "get", &target])
        .output()
        .await
        .with_context(|| format!("run {} route get {target}", ip.display()))?;
    if !output.status.success() {
        bail!(
            "route to {target} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let dev = token_after(&text, "dev")
        .ok_or_else(|| anyhow!("route to {target} did not name an output device"))?;
    if let Some(mtu) = token_after(&text, "mtu").and_then(|value| value.parse().ok()) {
        return Ok(PathMtu {
            underlay_mtu: mtu,
            dev,
            source: "route".into(),
        });
    }

    let link = Command::new(&ip)
        .args(["-o", "link", "show", "dev", &dev])
        .output()
        .await
        .with_context(|| format!("run {} link show dev {dev}", ip.display()))?;
    if !link.status.success() {
        bail!(
            "read link MTU for {dev}: {}",
            String::from_utf8_lossy(&link.stderr).trim()
        );
    }
    let link_text = String::from_utf8_lossy(&link.stdout);
    let mtu = token_after(&link_text, "mtu")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| anyhow!("link {dev} did not report an MTU"))?;
    Ok(PathMtu {
        underlay_mtu: mtu,
        dev,
        source: "link".into(),
    })
}

fn token_after(text: &str, key: &str) -> Option<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens
        .iter()
        .position(|token| *token == key)
        .and_then(|index| tokens.get(index + 1))
        .map(|value| value.trim_end_matches(':').to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_1515_matches_a_standard_ethernet_mtu() {
        let value = from_wire(Mode::Plain, 1515).unwrap();
        assert_eq!(value.inner_ip_mtu, 1500);
        assert_eq!(value.mss_v4, 1460);
        assert_eq!(value.mss_v6, 1440);
    }

    #[test]
    fn noise_1515_reserves_the_padding_bytes() {
        let value = from_wire(Mode::Noise, 1515).unwrap();
        assert_eq!(value.inner_ip_mtu, 1476);
        assert_eq!(value.mss_v4, 1436);
        assert_eq!(value.mss_v6, 1416);
    }

    #[test]
    fn encless_1515_matches_the_aont_budget() {
        let value = from_wire(Mode::Encless, 1515).unwrap();
        assert_eq!(value.inner_ip_mtu, 1492);
    }

    #[test]
    fn zero_and_tiny_mtus_are_rejected() {
        let zero = from_wire(Mode::Plain, 0).unwrap_err();
        assert!(zero.to_string().contains("0 is invalid"), "{zero}");
        assert!(from_wire(Mode::Plain, 67).is_err());
        assert!(from_wire(Mode::Noise, 119).is_err());
    }

    #[test]
    fn log_line_records_the_contract_and_derived_values() {
        let line = from_wire(Mode::Noise, 1515).unwrap().log_line();
        assert!(line.contains("wire=1515"));
        assert!(line.contains("inner_ip_mtu=1476"));
        assert!(line.contains("mss_v4=1436"));
        assert!(line.contains("mss_v6=1416"));
        assert!(line.contains("two-sided contract"));
    }

    #[test]
    fn parses_route_and_link_tokens() {
        assert_eq!(
            token_after("1.2.3.4 dev eth0 src 10.0.0.2 uid 1000", "dev").as_deref(),
            Some("eth0")
        );
        assert_eq!(
            token_after("2: eth0: <BROADCAST> mtu 1500 qdisc fq", "mtu").as_deref(),
            Some("1500")
        );
        assert!(token_after("no fields", "dev").is_none());
    }
}
