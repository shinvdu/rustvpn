//! Server `peers.yaml` and shared peer configuration.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use rustvpn_crypto::verifier::Verifier;
use rustvpn_crypto::xtea::Xtea;
use rustvpn_proto::{Mode, MTU_DEFAULT, MTU_MAX, MTU_MIN, MTU_MIN_NOISE};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::DEFAULT_TIMEOUT;

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
    #[serde(default)]
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
    pub verifier: String,
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
            verifier: Verifier::new(1, 1, 1, id),
            signing_key: None,
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
