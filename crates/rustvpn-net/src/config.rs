//! Server `peers.yaml` and shared peer configuration.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use rustvpn_crypto::verifier::Verifier;
use rustvpn_crypto::xtea::Xtea;
use rustvpn_proto::{Mode, MTU_DEFAULT, MTU_MAX, MTU_MIN, MTU_MIN_NOISE};
use serde::Deserialize;
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
}

#[derive(Deserialize, Default)]
struct YamlPeer {
    #[serde(default)]
    iface: String,
    #[serde(default)]
    mtu: usize,
    #[serde(default)]
    up: String,
    #[serde(default)]
    down: String,
    #[serde(default)]
    timeout: i64,
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    cpr: u32,
    #[serde(default)]
    encless: bool,
    #[serde(default)]
    timesync: i64,
    verifier: String,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigSet {
    pub peers: Vec<Arc<PeerConfig>>,
    pub by_id: HashMap<[u8; 16], Arc<PeerConfig>>,
}

impl ConfigSet {
    pub fn from_peers(peers: Vec<PeerConfig>) -> Result<Self> {
        let mut by_id = HashMap::new();
        for p in peers {
            let p = Arc::new(p);
            by_id.insert(p.id, p.clone());
        }
        let peers = by_id.values().cloned().collect();
        Ok(Self { peers, by_id })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let raw: HashMap<String, YamlPeer> =
            serde_yaml_ng::from_str(&data).context("parse peers.yaml")?;
        let mut peers = Vec::with_capacity(raw.len());
        for (name, y) in raw {
            let verifier = Verifier::from_string(&y.verifier)
                .map_err(|e| anyhow!("{name}: invalid verifier: {e}"))?;
            if verifier.public.is_none() {
                return Err(anyhow!("{name}: server verifier has no public key"));
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
