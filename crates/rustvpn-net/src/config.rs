//! Server `peers.yaml` and shared peer configuration.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use rustvpn_crypto::verifier::Verifier;
use rustvpn_crypto::xtea::Xtea;
use rustvpn_proto::{Mode, MTU_DEFAULT, MTU_MAX, MTU_MIN, MTU_MIN_NOISE};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::DEFAULT_TIMEOUT;

/// True when `route` denotes the default route.
///
/// `ipnet` accepts non-canonical spellings such as `00.0.0.0/0`,
/// `0.0.0.00/0` and `0.0.0.0/00` and normalises them to prefix length zero.
/// Comparing raw strings (`"default"` / `"0.0.0.0/0"`) therefore misses those
/// forms and lets a declarative server route silently hijack the host default
/// route.  This canonical check is shared by the server config validator and
/// the declarative TAP installer.
pub fn is_default_route(route: &str) -> bool {
    let route = route.trim();
    if route.eq_ignore_ascii_case("default") {
        return true;
    }
    route
        .parse::<IpNet>()
        .map(|net| net.prefix_len() == 0)
        .unwrap_or(false)
}

/// Declarative network setup for a server peer TAP.
///
/// This is a RustVPN extension.  When present, `rustvpn-server` can create
/// and configure the TAP without an `up` script.  `peers.yaml` files without
/// this section remain byte-for-byte GoVPN-compatible; see the migration note
/// in `docs/en/configuration.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerNetwork {
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub routes: Vec<String>,
}

impl PeerNetwork {
    /// Stable representation used by reload diffing.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.address,
            self.gateway,
            self.dns.join(","),
            self.routes.join(",")
        )
    }
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub id: [u8; 16],
    pub name: String,
    pub iface: String,
    pub mtu: usize,
    pub up: String,
    pub down: String,
    pub timeout: Duration,
    pub noise: bool,
    pub cpr: u32,
    pub encless: bool,
    pub time_sync: i64,
    /// Idle keepalive interval; zero preserves the timeout/4 heartbeat.
    pub keepalive: Duration,
    /// Time-driven rekey interval for client sessions; zero disables it.
    pub rekey_time: Duration,
    /// Random jitter added to `rekey_time`; zero means no jitter.
    pub rekey_jitter: Duration,
    /// Optional declarative TAP configuration (server-side extension).
    pub network: Option<PeerNetwork>,
    pub verifier: Verifier,
    pub signing_key: Option<ed25519_dalek::SigningKey>,
}

impl PeerConfig {
    pub fn mode(&self) -> Mode {
        if self.encless {
            Mode::Encless
        } else if self.noise {
            Mode::Noise
        } else {
            Mode::Plain
        }
    }

    pub fn max_payload(&self) -> usize {
        self.mode().max_payload(self.mtu)
    }

    pub fn mode_label(&self) -> &'static str {
        match self.mode() {
            Mode::Plain => "plain",
            Mode::Noise => "noise",
            Mode::Encless => "encless",
        }
    }

    /// IP MTU for the TAP interface derived from the numeric wire MTU.
    ///
    /// This must never be the wire/frame budget itself: the kernel would then
    /// be able to emit frames larger than the mode payload budget and the
    /// reader would drop them.
    pub fn inner_ip_mtu(&self) -> usize {
        self.max_payload().saturating_sub(14)
    }

    /// IPv4 TCP MSS clamp value derived from the TAP IP MTU.
    pub fn mss_v4(&self) -> usize {
        self.inner_ip_mtu().saturating_sub(40)
    }

    /// IPv6 TCP MSS clamp value derived from the TAP IP MTU.
    pub fn mss_v6(&self) -> usize {
        self.inner_ip_mtu().saturating_sub(60)
    }

    /// Interval used for heartbeat/ticker scheduling (Go's `Peer.Timeout`).
    pub fn peer_timeout(&self) -> Duration {
        if self.cpr > 0 {
            self.cpr_cycle()
        } else {
            self.timeout / 4
        }
    }

    pub fn cpr_cycle(&self) -> Duration {
        let rate = if self.cpr == 0 {
            return Duration::ZERO;
        } else {
            let wire = if self.encless {
                self.mtu + rustvpn_proto::ENCLESS_ENLARGE_SIZE
            } else {
                self.mtu
            };
            (self.cpr as usize * 1024)
                .saturating_div(wire.max(1))
                .max(1)
        };
        Duration::from_secs_f64(1.0 / rate as f64)
    }

    pub fn heartbeat_interval(&self) -> Duration {
        if self.cpr > 0 {
            self.cpr_cycle()
        } else {
            self.timeout / 4
        }
    }

    /// Idle interval used by the sender task.
    ///
    /// With `keepalive: 0` this is exactly the historical `timeout / 4`
    /// heartbeat.  A configured keepalive overrides that interval while
    /// remaining below `timeout`, so it cannot mask peer death.
    pub fn send_interval(&self) -> Duration {
        if self.cpr > 0 {
            self.cpr_cycle()
        } else if !self.keepalive.is_zero() {
            self.keepalive
        } else {
            self.heartbeat_interval()
        }
    }

    /// True when the keepalive (rather than the legacy heartbeat) controls
    /// idle empty-packet timing.
    pub fn keepalive_enabled(&self) -> bool {
        self.cpr == 0 && !self.keepalive.is_zero()
    }

    /// Render this runtime peer back into the GoVPN 5.7 YAML schema.
    ///
    /// The long-form verifier is required: a server configuration without the
    /// public key cannot be written back without changing its meaning.
    pub fn to_yaml(&self) -> Result<PeerYaml> {
        Ok(PeerYaml {
            iface: self.iface.clone(),
            mtu: self.mtu,
            up: self.up.clone(),
            down: self.down.clone(),
            timeout: self.timeout.as_secs() as i64,
            noise: self.noise,
            cpr: self.cpr,
            encless: self.encless,
            timesync: self.time_sync,
            network: self.network.as_ref().map(|network| PeerNetworkYaml {
                address: network.address.clone(),
                gateway: network.gateway.clone(),
                dns: network.dns.clone(),
                routes: network.routes.clone(),
            }),
            verifier: self.verifier.long_form()?,
        })
    }
}

/// One `peers.yaml` entry.
///
/// This is the exact GoVPN 5.7 schema.  It is public so the admin service can
/// render and edit configurations without duplicating the field list, while
/// `deny_unknown_fields` keeps the strict-compatibility guarantee.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PeerYaml {
    #[serde(default)]
    pub iface: String,
    /// Numeric wire MTU; an explicit `0` is rejected.  Omitted values keep the
    /// historical GoVPN default (1515).
    #[serde(
        default,
        skip_serializing_if = "is_zero",
        deserialize_with = "de_explicit_mtu"
    )]
    pub mtu: usize,
    #[serde(default)]
    pub up: String,
    #[serde(default)]
    pub down: String,
    #[serde(default)]
    pub timeout: i64,
    #[serde(default)]
    pub noise: bool,
    #[serde(default)]
    pub cpr: u32,
    #[serde(default)]
    pub encless: bool,
    #[serde(default)]
    pub timesync: i64,
    /// Optional RustVPN-only declarative TAP setup.  Omitted for
    /// GoVPN-compatible configurations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<PeerNetworkYaml>,
    pub verifier: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerNetworkYaml {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub routes: Vec<String>,
}

/// Reject an explicit `mtu: 0` while still allowing the field to be omitted
/// (the `default` attribute handles the omitted case).
fn de_explicit_mtu<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    let value = usize::deserialize(deserializer)?;
    if value == 0 {
        return Err(de::Error::custom(
            "mtu must be a positive numeric value; 0 is invalid",
        ));
    }
    Ok(value)
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Default)]
pub struct ConfigSet {
    pub peers: Vec<Arc<PeerConfig>>,
    pub by_id: HashMap<[u8; 16], Arc<PeerConfig>>,
}

impl ConfigSet {
    pub fn from_peers(peers: Vec<PeerConfig>) -> Result<Self> {
        let mut by_id = HashMap::new();
        let mut out = Vec::with_capacity(peers.len());
        let mut ifaces: HashMap<String, String> = HashMap::new();
        for p in peers {
            let p = Arc::new(p);
            if by_id.contains_key(&p.id) {
                return Err(anyhow!("duplicate peer verifier id for {}", p.name));
            }
            if !p.iface.is_empty() {
                if let Some(other) = ifaces.insert(p.iface.clone(), p.name.clone()) {
                    return Err(anyhow!(
                        "peers {} and {} share interface {}; one TAP per peer is required",
                        other,
                        p.name,
                        p.iface
                    ));
                }
            }
            by_id.insert(p.id, p.clone());
            out.push(p);
        }
        Ok(Self { peers: out, by_id })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_str(&data)
    }

    /// Parse the same YAML accepted by [`ConfigSet::from_file`].  Used by the
    /// admin service to validate rendered configurations before they touch
    /// disk.
    ///
    /// The name mirrors the existing constructor style in this module; it is
    /// intentionally not the `FromStr` trait because parsing needs `anyhow`
    /// context and is fallible with more than one error shape.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(data: &str) -> Result<Self> {
        let raw: BTreeMap<String, PeerYaml> =
            serde_yaml_ng::from_str(data).context("parse peers.yaml")?;
        let mut peers = Vec::with_capacity(raw.len());
        for (name, y) in raw {
            let verifier = Verifier::from_string(&y.verifier)
                .map_err(|e| anyhow!("{name}: invalid verifier: {e}"))?;
            if verifier.public.is_none() {
                return Err(anyhow!("{name}: server verifier has no public key"));
            }
            if y.iface.is_empty() && y.up.is_empty() {
                return Err(anyhow!("{name}: either iface or up script is required"));
            }
            if y.timesync < 0 {
                return Err(anyhow!("{name}: timesync must not be negative"));
            }
            let mut mtu = if y.mtu == 0 { MTU_DEFAULT } else { y.mtu };
            mtu = mtu.clamp(MTU_MIN, MTU_MAX);
            let encless = y.encless;
            let noise = y.noise || encless;
            if noise && mtu < MTU_MIN_NOISE {
                mtu = MTU_MIN_NOISE;
            }
            let timeout_secs = if y.timeout <= 0 {
                DEFAULT_TIMEOUT.as_secs() as i64
            } else {
                y.timeout
            };
            let network = parse_peer_network(&name, y.network.as_ref())?;
            peers.push(PeerConfig {
                id: verifier.id,
                name,
                iface: y.iface,
                mtu,
                up: y.up,
                down: y.down,
                timeout: Duration::from_secs(timeout_secs as u64),
                noise,
                cpr: y.cpr,
                encless,
                time_sync: y.timesync,
                keepalive: Duration::ZERO,
                rekey_time: Duration::ZERO,
                rekey_jitter: Duration::ZERO,
                network,
                verifier,
                signing_key: None,
            });
        }
        Self::from_peers(peers)
    }

    /// Deterministically render the enabled peers as a `peers.yaml` map.
    pub fn to_yaml_map(&self) -> Result<BTreeMap<String, PeerYaml>> {
        let mut out = BTreeMap::new();
        for peer in &self.peers {
            out.insert(peer.name.clone(), peer.to_yaml()?);
        }
        Ok(out)
    }

    /// Render a complete `peers.yaml` document.
    pub fn render_yaml(&self) -> Result<String> {
        Ok(serde_yaml_ng::to_string(&self.to_yaml_map()?)?)
    }

    pub fn find_identity(&self, data: &[u8]) -> Option<&Arc<PeerConfig>> {
        if data.len() < 16 {
            return None;
        }
        let first = &data[..8];
        let last = &data[data.len() - 8..];
        for cfg in &self.peers {
            let cipher = Xtea::new(&cfg.id);
            let mut block = [0u8; 8];
            block.copy_from_slice(last);
            cipher.decrypt_block(&mut block);
            add_time_sync(cfg.time_sync, &mut block);
            if block.ct_eq(first).unwrap_u8() == 1 {
                return Some(cfg);
            }
        }
        None
    }
}

fn parse_peer_network(
    name: &str,
    network: Option<&PeerNetworkYaml>,
) -> Result<Option<PeerNetwork>> {
    let Some(network) = network else {
        return Ok(None);
    };
    if !network.address.trim().is_empty() {
        let address: IpNet = network
            .address
            .parse()
            .with_context(|| format!("{name}: invalid network.address {:?}", network.address))?;
        if !matches!(address, IpNet::V4(_)) {
            return Err(anyhow!("{name}: network.address must be IPv4"));
        }
    }
    if !network.gateway.trim().is_empty() {
        let gateway: std::net::IpAddr = network
            .gateway
            .parse()
            .with_context(|| format!("{name}: invalid network.gateway {:?}", network.gateway))?;
        if !matches!(gateway, std::net::IpAddr::V4(_)) {
            return Err(anyhow!("{name}: network.gateway must be IPv4"));
        }
    }
    for dns in &network.dns {
        let server: std::net::IpAddr = dns
            .parse()
            .with_context(|| format!("{name}: invalid network.dns {dns:?}"))?;
        if !matches!(server, std::net::IpAddr::V4(_)) {
            return Err(anyhow!("{name}: network.dns must be IPv4"));
        }
    }
    for route in &network.routes {
        if is_default_route(route) {
            return Err(anyhow!(
                "{name}: network.routes must not contain a default route on the server \
                 (including non-canonical prefix-0 forms)"
            ));
        }
        let net: IpNet = route
            .parse()
            .with_context(|| format!("{name}: invalid network.route {route:?}"))?;
        if !matches!(net, IpNet::V4(_)) {
            return Err(anyhow!("{name}: network.routes must be IPv4"));
        }
    }
    Ok(Some(PeerNetwork {
        address: network.address.clone(),
        gateway: network.gateway.clone(),
        dns: network.dns.clone(),
        routes: network.routes.clone(),
    }))
}

pub fn add_time_sync(time_sync: i64, data: &mut [u8]) {
    if time_sync <= 0 {
        return;
    }
    let ts = time_sync as u64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / ts
        * ts;
    let bytes = now.to_be_bytes();
    for i in 0..8 {
        data[i] ^= bytes[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: [u8; 16]) -> PeerConfig {
        PeerConfig {
            id,
            name: "test".into(),
            iface: "tap0".into(),
            mtu: MTU_DEFAULT,
            up: String::new(),
            down: String::new(),
            timeout: Duration::from_secs(60),
            noise: false,
            cpr: 0,
            encless: false,
            time_sync: 0,
            keepalive: Duration::ZERO,
            rekey_time: Duration::ZERO,
            rekey_jitter: Duration::ZERO,
            network: None,
            verifier: Verifier::new(1, 1, 1, id),
            signing_key: None,
        }
    }

    #[test]
    fn keepalive_interval_selection_preserves_default_heartbeat() {
        let mut p = peer([5u8; 16]);
        p.timeout = Duration::from_secs(60);
        assert_eq!(p.send_interval(), Duration::from_secs(15));
        assert!(!p.keepalive_enabled());

        p.keepalive = Duration::from_secs(25);
        assert_eq!(p.send_interval(), Duration::from_secs(25));
        assert!(p.keepalive_enabled());

        // CPR owns the clock even if a keepalive was configured.
        p.cpr = 10;
        assert_eq!(p.send_interval(), p.cpr_cycle());
        assert!(!p.keepalive_enabled());
    }

    #[test]
    fn peer_yaml_network_is_optional_and_go_compatible() {
        let id = [2u8; 16];
        let mut verifier = Verifier::new(1, 1, 1, id);
        verifier.public = Some([0x44u8; 32]);
        let long = verifier.long_form().unwrap();
        // Without `network`, rendering must not invent a RustVPN-only key.
        let yaml = format!("peer:\n  iface: tap9\n  verifier: {long}\n");
        let set = ConfigSet::from_str(&yaml).unwrap();
        let rendered = set.render_yaml().unwrap();
        assert!(!rendered.contains("network:"), "{rendered}");

        let with_network = format!(
            "peer:\n  iface: tap9\n  network:\n    address: 10.88.0.1/24\n    routes: [10.88.0.0/24]\n  verifier: {long}\n"
        );
        let set = ConfigSet::from_str(&with_network).unwrap();
        let network = set.peers[0].network.as_ref().unwrap();
        assert_eq!(network.address, "10.88.0.1/24");
        assert_eq!(network.routes, vec!["10.88.0.0/24"]);
        let rendered = set.render_yaml().unwrap();
        assert!(rendered.contains("network:"));
    }

    #[test]
    fn peer_yaml_rejects_unsafe_network_values() {
        let id = [3u8; 16];
        let mut verifier = Verifier::new(1, 1, 1, id);
        verifier.public = Some([0x55u8; 32]);
        let long = verifier.long_form().unwrap();
        for network in [
            "    address: 2001:db8::1/64\n",
            "    address: 10.88.0.1/24\n    routes: [default]\n",
            "    address: 10.88.0.1/24\n    dns: [2001:db8::53]\n",
        ] {
            let yaml = format!("peer:\n  iface: tap9\n  network:\n{network}  verifier: {long}\n");
            assert!(ConfigSet::from_str(&yaml).is_err(), "{network}");
        }
    }

    #[test]
    fn default_route_detection_covers_canonical_and_noncanonical_forms() {
        for route in [
            "default",
            "DEFAULT",
            " default ",
            "0.0.0.0/0",
            "00.0.0.0/0",
            "0.0.0.00/0",
            "0.0.0.0/00",
        ] {
            assert!(
                is_default_route(route),
                "{route:?} should be a default route"
            );
        }
        for route in ["10.0.0.0/8", "0.0.0.0/1", "::/1", "not-a-route", ""] {
            assert!(!is_default_route(route), "{route:?} is not a default route");
        }
    }

    #[test]
    fn server_network_rejects_noncanonical_default_routes() {
        let mut verifier = Verifier::new(1, 1, 1, [0x31; 16]);
        verifier.public = Some([0x31; 32]);
        let long = verifier.long_form().unwrap();
        for route in [
            "00.0.0.0/0",
            "0.0.0.00/0",
            "0.0.0.0/00",
            "DEFAULT",
            " ::/0 ",
        ] {
            let yaml = format!(
                "peer:\n  iface: tap9\n  network:\n    address: 10.88.0.1/24\n    routes: [\"{route}\"]\n  verifier: {long}\n"
            );
            let error = format!("{:#}", ConfigSet::from_str(&yaml).unwrap_err());
            assert!(
                error.contains("default route"),
                "route {route:?} was not rejected as a default route: {error}"
            );
        }
    }

    #[test]
    fn finds_identity_by_idtag() {
        let id = [9u8; 16];
        let set = ConfigSet::from_peers(vec![peer(id)]).unwrap();
        let mut data = vec![0u8; 48];
        data[..8].copy_from_slice(b"12345678");
        let cipher = Xtea::new(&id);
        let tag = cipher.encrypt_u64(u64::from_be_bytes(data[..8].try_into().unwrap()));
        data[40..48].copy_from_slice(&tag);
        let found = set.find_identity(&data).expect("identity");
        assert_eq!(found.id, id);
        data[0] ^= 0xff;
        assert!(set.find_identity(&data).is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        let id = [3u8; 16];
        let mut verifier = Verifier::new(1, 1, 1, id);
        verifier.public = Some([0x33u8; 32]);
        let long = verifier.long_form().unwrap();
        let path =
            std::env::temp_dir().join(format!("rustvpn-unknown-{}.yaml", std::process::id()));
        std::fs::write(
            &path,
            format!("peer:\n  iface: tap1\n  verifier: {long}\n  bogus: 1\n"),
        )
        .unwrap();
        assert!(ConfigSet::from_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_duplicate_ids_and_shared_iface() {
        let id = [4u8; 16];
        let a = peer(id);
        let mut b = peer(id);
        b.name = "b".into();
        assert!(ConfigSet::from_peers(vec![a, b]).is_err());

        let mut a = peer([5u8; 16]);
        a.iface = "tap7".into();
        let mut b = peer([6u8; 16]);
        b.iface = "tap7".into();
        assert!(ConfigSet::from_peers(vec![a, b]).is_err());
    }

    #[test]
    fn rejects_missing_iface_and_up() {
        let id = [7u8; 16];
        let mut verifier = Verifier::new(1, 1, 1, id);
        verifier.public = Some([0x44u8; 32]);
        let long = verifier.long_form().unwrap();
        let path =
            std::env::temp_dir().join(format!("rustvpn-noiface-{}.yaml", std::process::id()));
        std::fs::write(&path, format!("peer:\n  verifier: {long}\n")).unwrap();
        assert!(ConfigSet::from_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn renders_and_reparses_yaml() {
        let id = [8u8; 16];
        let mut verifier = Verifier::new(1024, 4, 1, id);
        verifier.password_apply("passphrase").unwrap();
        let mut p = peer(id);
        p.name = "alice".into();
        p.iface = "tap3".into();
        p.mtu = 1540;
        p.noise = true;
        p.verifier = verifier;
        let set = ConfigSet::from_peers(vec![p]).unwrap();
        let yaml = set.render_yaml().unwrap();
        assert!(yaml.contains("alice:"));
        let parsed = ConfigSet::from_str(&yaml).unwrap();
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].name, "alice");
        assert_eq!(parsed.peers[0].iface, "tap3");
        assert_eq!(parsed.peers[0].mtu, 1540);
        assert!(parsed.peers[0].noise);
    }

    #[test]
    fn inner_ip_mtu_derives_from_the_numeric_wire_mtu() {
        let mut plain = peer([0x11; 16]);
        plain.mtu = 1515;
        plain.noise = false;
        assert_eq!(plain.inner_ip_mtu(), 1500);
        assert_eq!(plain.mss_v4(), 1460);
        assert_eq!(plain.mss_v6(), 1440);

        let mut noise = peer([0x12; 16]);
        noise.mtu = 1515;
        noise.noise = true;
        assert_eq!(noise.inner_ip_mtu(), 1476);
        assert_eq!(noise.mss_v4(), 1436);
        assert_eq!(noise.mss_v6(), 1416);
    }

    fn parse_peer_mtu(mtu_line: &str) -> Result<ConfigSet> {
        let mut verifier = Verifier::new(1, 1, 1, [0x21; 16]);
        verifier.public = Some([0x21; 32]);
        let long = verifier.long_form().unwrap();
        ConfigSet::from_str(&format!(
            "peer:\n  iface: tap9\n{mtu_line}  verifier: {long}\n"
        ))
    }

    #[test]
    fn rejects_explicit_zero_mtu_but_defaults_when_omitted() {
        let error = format!("{:#}", parse_peer_mtu("  mtu: 0\n").unwrap_err());
        assert!(error.contains("0 is invalid"), "{error}");
        let set = parse_peer_mtu("").unwrap();
        assert_eq!(set.peers[0].mtu, MTU_DEFAULT);
    }

    #[test]
    fn parses_yaml_and_clamps_mtu() {
        let id = [1u8; 16];
        let mut verifier = Verifier::new(1, 1, 1, id);
        verifier.public = Some([0x22u8; 32]);
        let long = verifier.long_form().unwrap();
        let path = std::env::temp_dir().join(format!("rustvpn-test-{}.yaml", std::process::id()));
        std::fs::write(
            &path,
            format!("peer:\n  iface: tap9\n  mtu: 10\n  noise: true\n  verifier: {long}\n"),
        )
        .unwrap();
        let set = ConfigSet::from_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let p = &set.peers[0];
        assert_eq!(p.iface, "tap9");
        assert_eq!(p.mtu, MTU_MIN_NOISE);
        assert!(p.noise);
        assert_eq!(p.timeout, Duration::from_secs(60));
        assert_eq!(p.mode(), Mode::Noise);
    }
}
