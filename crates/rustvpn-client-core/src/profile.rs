//! Profile validation shared by the daemon and any future profile importer.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use ipnet::IpNet;
use rustvpn_client_ipc::ProfileSpec;
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::PeerConfig;
use rustvpn_proto::{MTU_MAX, MTU_MIN, MTU_MIN_NOISE};

pub struct ValidatedProfile {
    spec: ProfileSpec,
    verifier: Verifier,
    effective_proto: String,
}

impl ValidatedProfile {
    pub fn new(spec: &ProfileSpec) -> Result<Self> {
        if spec.name.trim().is_empty() {
            bail!("profile name is empty");
        }
        if spec.name.len() > 64 {
            bail!("profile name is too long (max 64 bytes)");
        }
        if spec.remote.trim().is_empty() {
            bail!("remote address is empty");
        }
        if spec.verifier.trim().is_empty() {
            bail!("verifier is empty");
        }
        let verifier =
            Verifier::from_string(&spec.verifier).map_err(|e| anyhow!("invalid verifier: {e}"))?;

        let proxy = !spec.proxy.trim().is_empty();
        let effective_proto = if proxy {
            "tcp".to_string()
        } else {
            spec.proto.to_ascii_lowercase()
        };
        if effective_proto != "udp" && effective_proto != "tcp" {
            bail!("unknown protocol {:?}; use udp or tcp", spec.proto);
        }
        if spec.encless && effective_proto != "tcp" {
            bail!("encless mode works only with TCP");
        }
        if spec.mtu < MTU_MIN || spec.mtu > MTU_MAX {
            bail!("MTU must be between {MTU_MIN} and {MTU_MAX}");
        }
        if (spec.noise || spec.encless) && spec.mtu < MTU_MIN_NOISE {
            bail!("minimum permissible MTU for noise mode is {MTU_MIN_NOISE}");
        }
        if spec.timeout == 0 {
            bail!("timeout must be positive");
        }
        if spec.iface.is_empty() || spec.iface.len() > 15 {
            bail!("interface name must be 1..=15 characters");
        }
        if !spec
            .iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            bail!("interface name contains unsupported characters");
        }
        if spec.ipv6 {
            bail!("IPv6 profiles are not implemented yet; set ipv6: false");
        }

        if spec.address.trim().is_empty() {
            bail!("profile has no address; GUI/daemon profiles must configure one");
        }
        let address: IpNet = spec
            .address
            .parse()
            .with_context(|| format!("invalid address {:?}", spec.address))?;
        if !matches!(address, IpNet::V4(_)) {
            bail!("IPv6 addresses are not supported yet");
        }
        if spec.gateway.trim().is_empty() {
            if has_default_route(&spec.routes) {
                bail!("full-tunnel profile requires a gateway");
            }
        } else {
            let gateway: IpAddr = spec
                .gateway
                .parse()
                .with_context(|| format!("invalid gateway {:?}", spec.gateway))?;
            if !matches!(gateway, IpAddr::V4(_)) {
                bail!("IPv6 gateways are not supported yet");
            }
        }
        for dns in &spec.dns {
            let server: IpAddr = dns
                .parse()
                .with_context(|| format!("invalid DNS server {dns:?}"))?;
            if !matches!(server, IpAddr::V4(_)) {
                bail!("IPv6 DNS servers are not supported yet");
            }
        }
        for route in &spec.routes {
            if route == "default" || route.is_empty() {
                continue;
            }
            let net: IpNet = route
                .parse()
                .with_context(|| format!("invalid route {route:?}"))?;
            if !matches!(net, IpNet::V4(_)) {
                bail!("IPv6 routes are not supported yet");
            }
        }
        if has_default_route(&spec.routes) && spec.dns.is_empty() {
            bail!("full-tunnel profile requires at least one DNS server");
        }

        Ok(Self {
            spec: spec.clone(),
            verifier,
            effective_proto,
        })
    }

    pub fn spec(&self) -> &ProfileSpec {
        &self.spec
    }

    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    pub fn proto(&self) -> &str {
        &self.effective_proto
    }

    pub fn mode(&self) -> &'static str {
        if self.spec.encless {
            "encless"
        } else if self.spec.noise {
            "noise"
        } else {
            "plain"
        }
    }

    pub fn derive_signing_key(&mut self, password: &str) -> Result<SigningKey> {
        if password.is_empty() {
            bail!("empty passphrase");
        }
        self.verifier
            .password_apply(password)
            .map_err(|e| anyhow!("derive key: {e}"))
    }

    pub fn peer_config(&self, signing_key: SigningKey) -> Arc<PeerConfig> {
        Arc::new(PeerConfig {
            id: self.verifier.id,
            name: self.spec.name.clone(),
            iface: self.spec.iface.clone(),
            mtu: self.spec.mtu,
            up: String::new(),
            down: String::new(),
            timeout: Duration::from_secs(self.spec.timeout.max(1)),
            noise: self.spec.noise || self.spec.encless,
            cpr: self.spec.cpr,
            encless: self.spec.encless,
            time_sync: self.spec.timesync,
            verifier: self.verifier.clone(),
            signing_key: Some(signing_key),
        })
    }

    pub fn outer_host(&self) -> &str {
        if self.spec.proxy.trim().is_empty() {
            &self.spec.remote
        } else {
            &self.spec.proxy
        }
    }
}

fn has_default_route(routes: &[String]) -> bool {
    routes
        .iter()
        .any(|route| matches!(route.as_str(), "default" | "0.0.0.0/0"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ProfileSpec {
        ProfileSpec {
            name: "office".into(),
            remote: "vpn.example.com:1194".into(),
            verifier: "$argon2d$m=1024,t=4,p=1$AAECAwQFBgcICQoLDA0ODw".into(),
            address: "10.88.0.2/24".into(),
            gateway: "10.88.0.1".into(),
            routes: vec!["default".into()],
            dns: vec!["10.88.0.1".into()],
            ..ProfileSpec::default()
        }
    }

    #[test]
    fn proxy_forces_tcp_and_encless_needs_tcp() {
        let mut spec = base();
        spec.proto = "udp".into();
        spec.proxy = "127.0.0.1:3128".into();
        let validated = ValidatedProfile::new(&spec).unwrap();
        assert_eq!(validated.proto(), "tcp");

        spec.proxy.clear();
        spec.encless = true;
        assert!(ValidatedProfile::new(&spec).is_err());
    }

    #[test]
    fn rejects_bad_mtu_and_ipv6() {
        let mut spec = base();
        spec.mtu = 67;
        assert!(ValidatedProfile::new(&spec).is_err());
        spec.mtu = 1515;
        spec.noise = true;
        spec.mtu = MTU_MIN_NOISE - 1;
        assert!(ValidatedProfile::new(&spec).is_err());
        spec.noise = false;
        spec.ipv6 = true;
        assert!(ValidatedProfile::new(&spec).is_err());
    }

    #[test]
    fn validates_network_fields() {
        let mut spec = base();
        spec.address = "10.88.0.2/24".into();
        spec.gateway = "10.88.0.1".into();
        spec.routes = vec!["default".into(), "192.168.50.0/24".into()];
        spec.dns = vec!["10.88.0.1".into()];
        assert!(ValidatedProfile::new(&spec).is_ok());

        spec.address = "10.88.0.2/99".into();
        assert!(ValidatedProfile::new(&spec).is_err());
        spec.address.clear();
        spec.routes = vec!["not-a-route".into()];
        assert!(ValidatedProfile::new(&spec).is_err());
    }
    #[test]
    fn requires_address_and_full_tunnel_essentials() {
        let mut spec = base();
        spec.address.clear();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.dns.clear();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.gateway.clear();
        assert!(ValidatedProfile::new(&spec).is_err());
    }

    #[test]
    fn rejects_ipv6_network_fields() {
        let mut spec = base();
        spec.address = "2001:db8::1/64".into();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.gateway = "2001:db8::1".into();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.routes = vec!["default".into(), "2001:db8::/32".into()];
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.dns = vec!["2001:4860:4860::8888".into()];
        assert!(ValidatedProfile::new(&spec).is_err());
    }
}
