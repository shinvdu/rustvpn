//! Profile validation shared by the daemon and any future profile importer.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use ipnet::IpNet;
use rustvpn_client_ipc::ProfileSpec;
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::{is_default_route, PeerConfig};
use rustvpn_proto::Mode;

/// Keepalive bounds shared by profile validation and the CLI (the verifier
/// enforces the same limits with its dependency-light copy).
/// Noise/encless keepalives are padded to the MTU, so they get a stricter
/// floor to avoid a silent bandwidth burn.
pub const KEEPALIVE_MIN: u64 = 10;
pub const KEEPALIVE_MIN_PADDED: u64 = 25;
pub const KEEPALIVE_MAX: u64 = 3600;
const REKEY_TIME_MIN: u64 = 60;
const REKEY_TIME_MAX: u64 = 86_400;
const REKEY_JITTER_MAX: u64 = 3600;

/// IPC input bounds.  The frame layer caps a message at 1 MiB, but that is far
/// too large for a profile: an unbounded `remote` is written to SYSTEM logs on
/// every retry, and unbounded route/DNS lists amplify memory and PowerShell
/// work.  These are deliberately generous for real deployments.
const MAX_REMOTE_LEN: usize = 255;
const MAX_PROXY_LEN: usize = 255;
const MAX_PROXY_AUTH_LEN: usize = 512;
const MAX_VERIFIER_LEN: usize = 512;
const MAX_ADDRESS_LEN: usize = 64;
const MAX_GATEWAY_LEN: usize = 64;
const MAX_ROUTE_LEN: usize = 64;
const MAX_DNS_LEN: usize = 64;
const MAX_ROUTES: usize = 256;
const MAX_DNS_SERVERS: usize = 16;
/// Stricter client-side Argon2 ceiling.  The verifier crate accepts up to
/// 256 MiB / 4096 passes for server compatibility; accepting that from a local
/// IPC peer would let a standard user monopolise the SYSTEM daemon.
const MAX_PROFILE_ARGON2_M: u32 = 65_536;
const MAX_PROFILE_ARGON2_T: u32 = 512;
const MAX_PROFILE_ARGON2_P: u32 = 4;

fn reject_control(field: &str, value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("{field} contains control characters");
    }
    Ok(())
}

fn check_len(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        bail!("{field} is too long (max {max} bytes)");
    }
    Ok(())
}

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
        check_len("profile name", &spec.name, 64)?;
        reject_control("profile name", &spec.name)?;
        if spec.remote.trim().is_empty() {
            bail!("remote address is empty");
        }
        check_len("remote address", &spec.remote, MAX_REMOTE_LEN)?;
        reject_control("remote address", &spec.remote)?;
        if spec.verifier.trim().is_empty() {
            bail!("verifier is empty");
        }
        check_len("verifier", &spec.verifier, MAX_VERIFIER_LEN)?;
        reject_control("verifier", &spec.verifier)?;
        if spec.proxy.len() > MAX_PROXY_LEN {
            bail!("proxy is too long (max {MAX_PROXY_LEN} bytes)");
        }
        reject_control("proxy", &spec.proxy)?;
        if spec.proxy_auth.len() > MAX_PROXY_AUTH_LEN {
            bail!("proxy auth is too long (max {MAX_PROXY_AUTH_LEN} bytes)");
        }
        reject_control("proxy auth", &spec.proxy_auth)?;
        if spec.routes.len() > MAX_ROUTES {
            bail!("too many routes (max {MAX_ROUTES})");
        }
        for route in &spec.routes {
            check_len("route", route, MAX_ROUTE_LEN)?;
            reject_control("route", route)?;
        }
        if spec.dns.len() > MAX_DNS_SERVERS {
            bail!("too many DNS servers (max {MAX_DNS_SERVERS})");
        }
        for server in &spec.dns {
            check_len("DNS server", server, MAX_DNS_LEN)?;
            reject_control("DNS server", server)?;
        }
        check_len("address", &spec.address, MAX_ADDRESS_LEN)?;
        reject_control("address", &spec.address)?;
        check_len("gateway", &spec.gateway, MAX_GATEWAY_LEN)?;
        reject_control("gateway", &spec.gateway)?;

        let verifier =
            Verifier::from_string(&spec.verifier).map_err(|e| anyhow!("invalid verifier: {e}"))?;
        if verifier.m > MAX_PROFILE_ARGON2_M
            || verifier.t > MAX_PROFILE_ARGON2_T
            || verifier.p > MAX_PROFILE_ARGON2_P
        {
            bail!(
                "verifier Argon2 cost is too high for the client (m<={MAX_PROFILE_ARGON2_M}, \
                 t<={MAX_PROFILE_ARGON2_T}, p<={MAX_PROFILE_ARGON2_P})"
            );
        }

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
        if spec.mtu_is_auto() {
            // `MTU_AUTO` is the legacy `0` sentinel, so this covers both
            // `mtu: auto` and `mtu: 0`.
            bail!(
                "mtu: auto and mtu: 0 are not supported in v1; the wire MTU is a two-sided \
                 contract. Configure the same numeric MTU as the server (for example 1515); \
                 path-MTU negotiation is deferred to v2"
            );
        }
        // Reject an unusable derived TAP IP MTU (Linux `ip link set mtu`
        // refuses values below 68) before any network state is touched.
        let wire = crate::mtu::from_wire(self_mode(spec), spec.mtu)
            .map_err(|error| anyhow!("{error:#}"))?;
        // Windows adapters (Wintun) additionally refuse an interface IP MTU
        // below the classic IPv4 minimum; reject it here, before TAP creation.
        #[cfg(windows)]
        if wire.inner_ip_mtu < 576 {
            bail!(
                "wire MTU {} derives interface IP MTU {}, below the Windows minimum 576; \
                 raise the wire MTU (and the matching server MTU) before connecting",
                spec.mtu,
                wire.inner_ip_mtu
            );
        }
        #[cfg(not(windows))]
        let _ = wire;
        if spec.timeout == 0 {
            bail!("timeout must be positive");
        }
        if spec.keepalive > 0 {
            let minimum = if spec.noise || spec.encless {
                KEEPALIVE_MIN_PADDED
            } else {
                KEEPALIVE_MIN
            };
            if spec.keepalive < minimum {
                bail!(
                    "keepalive must be 0 (off) or at least {minimum}s for {} mode",
                    spec.mode_name()
                );
            }
            if spec.keepalive > KEEPALIVE_MAX {
                bail!("keepalive must not exceed {KEEPALIVE_MAX}s");
            }
            if spec.keepalive >= spec.timeout {
                bail!(
                    "keepalive ({}s) must be shorter than timeout ({}s)",
                    spec.keepalive,
                    spec.timeout
                );
            }
        }
        if spec.rekey_time > 0 {
            if !(REKEY_TIME_MIN..=REKEY_TIME_MAX).contains(&spec.rekey_time) {
                bail!(
                    "rekey_time must be 0 (off) or between {REKEY_TIME_MIN} and {REKEY_TIME_MAX}s"
                );
            }
            if spec.rekey_jitter > REKEY_JITTER_MAX || spec.rekey_jitter > spec.rekey_time {
                bail!("rekey_jitter must be 0..=min(rekey_time, {REKEY_JITTER_MAX})");
            }
        } else if spec.rekey_jitter > 0 {
            bail!("rekey_jitter requires a non-zero rekey_time");
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
            // The keyword form has no address family; canonical and
            // non-canonical IPv4 prefix-0 spellings parse below and are
            // accepted as IPv4.  An IPv6 `::/0` must still be rejected.
            if route.trim().is_empty() || route.trim().eq_ignore_ascii_case("default") {
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
        if spec.kill_switch && !has_default_route(&spec.routes) {
            bail!(
                "kill_switch requires a full-tunnel profile (routes must contain default); \
                 split-tunnel profiles cannot enable the kill switch"
            );
        }
        // A Windows kill switch would have to be fail-closed and recoverable;
        // it is deferred, so reject the profile instead of leaving the host
        // fail-open while the UI claims otherwise.
        #[cfg(windows)]
        if spec.kill_switch {
            bail!(
                "kill_switch is not implemented on Windows; disable it in the profile \
                 (the Windows full-tunnel guard still blocks IPv6 egress)"
            );
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
        self.spec.mode_name()
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
        self.peer_config_with_mtu(signing_key, self.spec.mtu)
    }

    /// Build the runtime peer with an explicit wire MTU.
    ///
    /// This is always the numeric profile MTU; v1 never derives it from the
    /// local path.  Only the TAP interface IP MTU and MSS are derived from it.
    pub fn peer_config_with_mtu(&self, signing_key: SigningKey, mtu: usize) -> Arc<PeerConfig> {
        Arc::new(PeerConfig {
            id: self.verifier.id,
            name: self.spec.name.clone(),
            iface: self.spec.iface.clone(),
            mtu,
            up: String::new(),
            down: String::new(),
            timeout: Duration::from_secs(self.spec.timeout.max(1)),
            noise: self.spec.noise || self.spec.encless,
            cpr: self.spec.cpr,
            encless: self.spec.encless,
            time_sync: self.spec.timesync,
            keepalive: Duration::from_secs(self.spec.keepalive),
            rekey_time: Duration::from_secs(self.spec.rekey_time),
            rekey_jitter: Duration::from_secs(self.spec.rekey_jitter),
            network: None,
            verifier: self.verifier.clone(),
            signing_key: Some(signing_key),
        })
    }

    pub fn mode_enum(&self) -> Mode {
        self_mode(&self.spec)
    }

    pub fn outer_host(&self) -> &str {
        if self.spec.proxy.trim().is_empty() {
            &self.spec.remote
        } else {
            &self.spec.proxy
        }
    }
}

fn self_mode(spec: &ProfileSpec) -> Mode {
    if spec.encless {
        Mode::Encless
    } else if spec.noise {
        Mode::Noise
    } else {
        Mode::Plain
    }
}

fn has_default_route(routes: &[String]) -> bool {
    // Canonical check: also recognises non-canonical prefix-0 spellings such
    // as `00.0.0.0/0`, so they still enable full-tunnel semantics.
    routes.iter().any(|route| is_default_route(route))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustvpn_proto::MTU_MIN_NOISE;

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
    fn rejects_derived_tap_ip_mtu_below_the_kernel_minimum() {
        let mut spec = base();
        spec.mtu = 68;
        let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
        assert!(error.contains("derives TAP IP MTU 53"), "{error}");
        assert!(error.contains("at least 83"), "{error}");

        spec.mtu = 83;
        #[cfg(not(windows))]
        assert!(ValidatedProfile::new(&spec).is_ok());
        #[cfg(windows)]
        {
            let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
            assert!(error.contains("Windows minimum 576"), "{error}");
        }

        // The padded-mode floor derives a usable TAP IP MTU on Linux (noise
        // 120 -> inner 81).  Windows requires at least 576, so the same wire
        // MTU is rejected there and 615 (noise -> inner 576) is the success
        // case.  The Linux-only 119 check stays below the mode floor.
        spec.noise = true;
        spec.mtu = 120;
        #[cfg(not(windows))]
        assert!(ValidatedProfile::new(&spec).is_ok());
        #[cfg(windows)]
        {
            let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
            assert!(error.contains("Windows minimum 576"), "{error}");

            // noise 615 -> max_payload 590 -> interface IP MTU 576 exactly.
            spec.mtu = 615;
            assert!(ValidatedProfile::new(&spec).is_ok());
            spec.mtu = 614;
            let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
            assert!(error.contains("Windows minimum 576"), "{error}");
        }
        spec.mtu = 119;
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
    fn rejects_auto_and_zero_mtu() {
        let mut spec = base();
        spec.mtu = rustvpn_client_ipc::MTU_AUTO;
        let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
        assert!(error.contains("auto"), "{error}");
        assert!(error.contains("numeric"), "{error}");

        let mut spec = base();
        spec.mtu = 0;
        let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
        assert!(error.contains("mtu: 0"), "{error}");
    }

    #[test]
    fn noncanonical_default_routes_still_enable_full_tunnel_semantics() {
        for route in [
            "default",
            "DEFAULT",
            "0.0.0.0/0",
            "00.0.0.0/0",
            "0.0.0.00/0",
            "0.0.0.0/00",
        ] {
            // A full-tunnel profile requires DNS ...
            let mut spec = base();
            spec.routes = vec![route.into()];
            spec.dns.clear();
            let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
            assert!(error.contains("DNS"), "route {route:?}: {error}");

            // ... and permits the full-tunnel-only kill switch.
            spec.dns = vec!["10.88.0.1".into()];
            spec.kill_switch = true;
            #[cfg(not(windows))]
            assert!(
                ValidatedProfile::new(&spec).is_ok(),
                "route {route:?} was not treated as a default route"
            );
            // Windows rejects the deferred kill switch explicitly.
            #[cfg(windows)]
            assert!(ValidatedProfile::new(&spec).is_err(), "route {route:?}");
        }

        // A split-tunnel prefix is not a default route.
        let mut spec = base();
        spec.routes = vec!["0.0.0.0/1".into()];
        spec.dns.clear();
        spec.kill_switch = true;
        assert!(ValidatedProfile::new(&spec).is_err());
    }

    #[test]
    fn rejects_split_tunnel_kill_switch() {
        let mut spec = base();
        spec.kill_switch = true;
        #[cfg(not(windows))]
        assert!(ValidatedProfile::new(&spec).is_ok());
        #[cfg(windows)]
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.routes = vec!["10.88.0.0/24".into()];
        spec.dns.clear(); // split tunnel does not require DNS
        spec.kill_switch = true;
        let error = match ValidatedProfile::new(&spec) {
            Ok(_) => panic!("split-tunnel kill switch must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("kill_switch"), "{error}");
    }

    #[test]
    fn validates_keepalive_and_rekey_bounds() {
        let mut spec = base();
        spec.keepalive = 25;
        assert!(ValidatedProfile::new(&spec).is_ok());

        let mut spec = base();
        spec.keepalive = 9;
        assert!(ValidatedProfile::new(&spec).is_err());
        spec.keepalive = 10;
        assert!(ValidatedProfile::new(&spec).is_ok());

        // Noise keepalives are MTU-padded, so the floor is 25s.
        let mut spec = base();
        spec.noise = true;
        spec.keepalive = 24;
        assert!(ValidatedProfile::new(&spec).is_err());
        spec.keepalive = 25;
        assert!(ValidatedProfile::new(&spec).is_ok());

        let mut spec = base();
        spec.keepalive = spec.timeout;
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.rekey_time = 1800;
        spec.rekey_jitter = 30;
        assert!(ValidatedProfile::new(&spec).is_ok());

        let mut spec = base();
        spec.rekey_time = 10;
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.rekey_jitter = 30;
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.rekey_time = 1800;
        spec.rekey_jitter = 1801;
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

        // An IPv6 default route has prefix length 0 but is still IPv6.
        let mut spec = base();
        spec.routes = vec!["::/0".into()];
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.dns = vec!["2001:4860:4860::8888".into()];
        assert!(ValidatedProfile::new(&spec).is_err());
    }

    #[test]
    fn rejects_oversized_or_controlled_ipc_fields() {
        let mut spec = base();
        spec.remote = "x".repeat(MAX_REMOTE_LEN + 1);
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.remote = "vpn.example.com:1194\nforged log line".into();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.routes = (0..=MAX_ROUTES)
            .map(|index| format!("10.{}.0.0/16", index % 250))
            .collect();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.dns = (0..=MAX_DNS_SERVERS)
            .map(|index| format!("10.88.0.{}", (index % 250) + 1))
            .collect();
        assert!(ValidatedProfile::new(&spec).is_err());

        let mut spec = base();
        spec.verifier = "$argon2d$m=262144,t=4096,p=64$AAECAwQFBgcICQoLDA0ODw".into();
        let error = ValidatedProfile::new(&spec).err().unwrap().to_string();
        assert!(error.contains("Argon2 cost"), "{error}");
    }
}
