//! Request, response, event and status DTOs.

use ipnet::IpNet;
use serde::de::{self, Deserializer};
use serde::ser::{Error as SerError, Serializer};
use serde::{Deserialize, Serialize};

/// Canonical default-route test shared by client profile handling.
///
/// Mirrors `rustvpn_net::config::is_default_route` (this crate must stay
/// dependency-light, so it cannot depend on `rustvpn-net`).  `ipnet` accepts
/// non-canonical prefix-0 spellings such as `00.0.0.0/0`, so a raw string
/// comparison against `default`/`0.0.0.0/0` would misclassify them as
/// split-tunnel routes.
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

/// Legacy sentinel that used to mean `mtu: auto`.
///
/// v1 rejects both `mtu: auto` and `mtu: 0`; the constant is kept so callers
/// can recognise profiles written by older builds and report a clear error.
pub const MTU_AUTO: usize = 0;

/// Valid wire-MTU range, mirrored from `rustvpn-proto` so this crate stays
/// dependency-light.  The daemon remains authoritative; the GUI re-checks the
/// same bounds before it writes a profile.
pub const MTU_MIN: usize = 68;
/// Padded modes (noise/encless) carry more per-frame overhead.
pub const MTU_MIN_NOISE: usize = 120;
pub const MTU_MAX: usize = 9015;

fn default_mtu() -> usize {
    1515
}

/// Accept a numeric MTU or a numeric string.  `auto` and `0` are rejected
/// because the v1 wire MTU must be a positive value shared by both peers.
fn de_mtu<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Number(usize),
        Text(String),
    }
    let value = match Raw::deserialize(deserializer)? {
        Raw::Number(value) => value,
        Raw::Text(text) => {
            let text = text.trim();
            if text.eq_ignore_ascii_case("auto") {
                return Err(de::Error::custom(
                    "mtu: auto is not supported in v1; configure the numeric wire MTU shared \
                     by both peers (for example 1515); path-MTU negotiation is deferred to v2",
                ));
            }
            text.parse::<usize>().map_err(de::Error::custom)?
        }
    };
    if value == 0 {
        return Err(de::Error::custom(
            "mtu: 0 is invalid; configure the numeric wire MTU shared by both peers \
             (for example 1515)",
        ));
    }
    Ok(value)
}

fn ser_mtu<S>(mtu: &usize, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *mtu == MTU_AUTO {
        // Never rewrite the legacy sentinel into a non-numeric `"auto"`.
        // Rejecting here makes a zero MTU a hard error at every serialization
        // boundary instead of silently producing a profile v1 cannot load.
        return Err(<S::Error as SerError>::custom(
            "mtu 0/auto is invalid and cannot be serialized; \
             use a numeric wire MTU (for example 1515)",
        ));
    }
    serializer.serialize_u64(*mtu as u64)
}

/// Accept `true`/`false`, or `auto`/`off` for options that can be derived.
fn de_bool_or_auto<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Bool(bool),
        Text(String),
    }
    match Raw::deserialize(deserializer)? {
        Raw::Bool(value) => Ok(value),
        Raw::Text(text) => match text.trim().to_ascii_lowercase().as_str() {
            "auto" | "true" | "yes" | "on" => Ok(true),
            "off" | "false" | "no" => Ok(false),
            other => Err(de::Error::custom(format!(
                "expected a boolean or \"auto\", got {other:?}"
            ))),
        },
    }
}

/// A profile as owned by the GUI and handed to the daemon for validation.
///
/// Passwords are never part of a profile; they travel only in `Connect`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileSpec {
    pub name: String,
    pub remote: String,
    pub proto: String,
    pub verifier: String,
    /// Numeric wire MTU shared with the server.  [`MTU_AUTO`] (legacy `0`) and
    /// the string `auto` are rejected; v1 has no MTU negotiation.
    #[serde(
        default = "default_mtu",
        deserialize_with = "de_mtu",
        serialize_with = "ser_mtu"
    )]
    pub mtu: usize,
    /// Clamp TCP MSS on the tunnel interface with nftables.
    #[serde(default, deserialize_with = "de_bool_or_auto")]
    pub mss_clamp: bool,
    /// Install a full-tunnel nftables kill switch (opt-in only).
    #[serde(default, deserialize_with = "de_bool_or_auto")]
    pub kill_switch: bool,
    /// Idle keepalive interval in seconds (0 = legacy timeout/4 heartbeat).
    #[serde(default, alias = "persistent_keepalive")]
    pub keepalive: u64,
    /// Time-driven rekey interval in seconds (0 = only the 4 GiB threshold).
    #[serde(default)]
    pub rekey_time: u64,
    /// Random jitter added to `rekey_time`, in seconds.
    #[serde(default)]
    pub rekey_jitter: u64,
    pub timeout: u64,
    pub timesync: i64,
    pub noise: bool,
    pub encless: bool,
    pub cpr: u32,
    pub proxy: String,
    pub proxy_auth: String,
    pub iface: String,
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub routes: Vec<String>,
    pub ipv6: bool,
}

impl ProfileSpec {
    pub fn mtu_is_auto(&self) -> bool {
        self.mtu == MTU_AUTO
    }

    /// Validate the numeric MTU before a profile is persisted.
    ///
    /// The daemon performs the authoritative validation before connecting;
    /// this is a defense-in-depth check for the GUI, which serializes profiles
    /// written by the webview.  Legacy `0`/`auto` values are rejected rather
    /// than rewritten.
    pub fn validate_mtu(&self) -> Result<(), String> {
        if self.mtu == MTU_AUTO {
            return Err(
                "mtu: auto and mtu: 0 are not supported in v1; configure the numeric wire MTU \
                 shared by both peers (for example 1515)"
                    .into(),
            );
        }
        if !(MTU_MIN..=MTU_MAX).contains(&self.mtu) {
            return Err(format!("MTU must be between {MTU_MIN} and {MTU_MAX}"));
        }
        if (self.noise || self.encless) && self.mtu < MTU_MIN_NOISE {
            return Err(format!(
                "minimum permissible MTU for noise/encless mode is {MTU_MIN_NOISE}"
            ));
        }
        Ok(())
    }

    pub fn mode_name(&self) -> &'static str {
        if self.encless {
            "encless"
        } else if self.noise {
            "noise"
        } else {
            "plain"
        }
    }

    pub fn has_default_route(&self) -> bool {
        self.routes.iter().any(|route| is_default_route(route))
    }
}

impl Default for ProfileSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            remote: String::new(),
            proto: "udp".into(),
            verifier: String::new(),
            mtu: default_mtu(),
            mss_clamp: false,
            kill_switch: false,
            keepalive: 0,
            rekey_time: 0,
            rekey_jitter: 0,
            timeout: 60,
            timesync: 0,
            noise: false,
            encless: false,
            cpr: 0,
            proxy: String::new(),
            proxy_auth: String::new(),
            iface: "rsvpn-gui".into(),
            address: String::new(),
            gateway: String::new(),
            dns: Vec::new(),
            routes: vec!["default".into()],
            ipv6: false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrafficSample {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_payload_bytes: u64,
    pub tx_payload_bytes: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub uptime_s: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineStatus {
    /// `idle`, `connecting`, `connected`, `reconnecting`, `disconnecting`
    /// or `error`.
    pub state: String,
    pub profile: Option<String>,
    pub remote: Option<String>,
    pub proto: Option<String>,
    pub mode: Option<String>,
    pub iface: Option<String>,
    pub since_unix: Option<i64>,
    pub next_retry_in: Option<u64>,
    pub last_error: Option<String>,
    /// Remote/peer endpoint reported by the live session (server address in
    /// client mode; never contains credentials).
    pub endpoint: Option<String>,
    /// Time of the last authenticated packet/heartbeat, unix seconds.
    pub last_handshake_unix: Option<i64>,
    /// Seconds until the next 4 GiB rekey at the current rate, if known.
    pub rekey_in_sec: Option<u64>,
    pub heartbeat_sent: Option<u64>,
    pub heartbeat_recv: Option<u64>,
    pub frames_unauth: Option<u64>,
    pub frames_dup: Option<u64>,
    /// Configured daemon MTU (the two-sided wire value used by the codec).
    pub mtu: Option<usize>,
    /// Derived IP MTU configured on the TAP interface.
    pub inner_mtu: Option<usize>,
    /// Derived IPv4 TCP MSS clamp value, if clamping is enabled.
    pub mss: Option<usize>,
    /// Derived IPv6 TCP MSS clamp value, if clamping is enabled.
    pub mss_v6: Option<usize>,
    /// Whether the MSS clamp table was actually applied.
    pub mss_applied: Option<bool>,
    /// Configured kill-switch value (profile), independent of availability.
    pub kill_switch: Option<bool>,
    /// Whether the kill-switch table was actually applied.
    pub kill_switch_applied: Option<bool>,
    /// Origin of the wire MTU (`configured` in v1; `auto` is deferred to v2).
    pub mtu_source: Option<String>,
    /// Configured idle keepalive interval, if enabled.
    pub keepalive_sec: Option<u64>,
    /// Configured time-driven rekey interval, if enabled.
    pub rekey_time_sec: Option<u64>,
    /// Whether the rate fields are sampled over a known window.
    pub rates_available: bool,
    /// Sampling window for the rate fields, in seconds.
    pub rate_window_sec: Option<u64>,
    pub traffic: TrafficSample,
}

/// Stable schema identifier for `status --json`.
pub const STATUS_SCHEMA: &str = "rustvpn.status.v1";

/// Versioned, secret-free status document for automation and monitoring.
///
/// Only counters, endpoint metadata and configuration identifiers that are
/// already non-secret (profile name, interface, mode, MTU) are included.
/// Passwords, keys, proxy credentials and verifier secrets are never copied
/// into this struct.
#[derive(Clone, Debug, Serialize)]
pub struct ClientStatusV1 {
    pub schema: &'static str,
    pub role: &'static str,
    pub state: String,
    pub since: Option<String>,
    pub profile: Option<String>,
    pub server: Option<String>,
    pub proto: Option<String>,
    pub mode: Option<String>,
    pub iface: Option<String>,
    pub endpoint: Option<String>,
    pub last_handshake: Option<String>,
    pub rekey_in_sec: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_rate_bps: u64,
    pub rx_rate_bps: u64,
    pub rates_available: bool,
    pub rate_window_sec: Option<u64>,
    pub frames_unauth: Option<u64>,
    pub frames_dup: Option<u64>,
    pub heartbeat_sent: Option<u64>,
    pub heartbeat_recv: Option<u64>,
    pub mtu: Option<usize>,
    pub inner_mtu: Option<usize>,
    pub mss: Option<usize>,
    pub mss_v6: Option<usize>,
    pub mss_applied: Option<bool>,
    pub kill_switch: Option<bool>,
    pub kill_switch_applied: Option<bool>,
    pub mtu_source: Option<String>,
    pub keepalive_sec: Option<u64>,
    pub rekey_time_sec: Option<u64>,
    pub last_error: Option<String>,
}

impl ClientStatusV1 {
    pub fn from_status(status: &EngineStatus) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            role: "client",
            state: status.state.clone(),
            since: status.since_unix.and_then(format_unix),
            profile: status.profile.clone(),
            server: status.remote.clone(),
            proto: status.proto.clone(),
            mode: status.mode.clone(),
            iface: status.iface.clone(),
            endpoint: status.endpoint.clone(),
            last_handshake: status.last_handshake_unix.and_then(format_unix),
            rekey_in_sec: status.rekey_in_sec,
            tx_bytes: status.traffic.tx_bytes,
            rx_bytes: status.traffic.rx_bytes,
            tx_rate_bps: status.traffic.tx_bps,
            rx_rate_bps: status.traffic.rx_bps,
            rates_available: status.rates_available,
            rate_window_sec: status.rate_window_sec,
            frames_unauth: status.frames_unauth,
            frames_dup: status.frames_dup,
            heartbeat_sent: status.heartbeat_sent,
            heartbeat_recv: status.heartbeat_recv,
            mtu: status.mtu,
            inner_mtu: status.inner_mtu,
            mss: status.mss,
            mss_v6: status.mss_v6,
            mss_applied: status.mss_applied,
            kill_switch: status.kill_switch,
            kill_switch_applied: status.kill_switch_applied,
            mtu_source: status.mtu_source.clone(),
            keepalive_sec: status.keepalive_sec,
            rekey_time_sec: status.rekey_time_sec,
            last_error: status.last_error.clone(),
        }
    }

    /// Placeholder document used when the daemon cannot be reached.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            role: "client",
            state: "unavailable".into(),
            since: None,
            profile: None,
            server: None,
            proto: None,
            mode: None,
            iface: None,
            endpoint: None,
            last_handshake: None,
            rekey_in_sec: None,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_rate_bps: 0,
            rx_rate_bps: 0,
            rates_available: false,
            rate_window_sec: None,
            frames_unauth: None,
            frames_dup: None,
            heartbeat_sent: None,
            heartbeat_recv: None,
            mtu: None,
            inner_mtu: None,
            mss: None,
            mss_v6: None,
            mss_applied: None,
            kill_switch: None,
            kill_switch_applied: None,
            mtu_source: None,
            keepalive_sec: None,
            rekey_time_sec: None,
            last_error: Some(message.into()),
        }
    }
}

fn format_unix(seconds: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogLine {
    pub ts_ms: i64,
    pub level: String,
    pub line: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Hello {
        version: u32,
    },
    Status,
    Connect {
        profile: Box<ProfileSpec>,
        password: String,
    },
    Disconnect,
    Logs {
        limit: u32,
    },
    Shutdown,
    Subscribe,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Hello {
        version: u32,
        daemon_version: String,
    },
    Status {
        status: Box<EngineStatus>,
    },
    Ok,
    Logs {
        lines: Vec<LogLine>,
    },
    Subscribed,
    Error {
        message: String,
    },
}

impl Response {
    pub fn into_result(self) -> Result<Self, String> {
        match self {
            Response::Error { message } => Err(message),
            other => Ok(other),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum Event {
    State(EngineStatus),
    Traffic(TrafficSample),
    Log(LogLine),
    /// The subscriber fell behind; the UI should re-fetch `Status`.
    Lagged {
        missed: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_json() -> serde_json::Value {
        serde_json::json!({
            "name": "office",
            "remote": "vpn.example.com:1194",
            "verifier": "$argon2d$m=1024,t=4,p=1$AAECAwQFBgcICQoLDA0ODw",
            "mtu": 1515,
            "mss_clamp": "auto",
            "kill_switch": true,
            "keepalive": 25,
            "rekey_time": 1800,
            "rekey_jitter": 30,
        })
    }

    #[test]
    fn numeric_mtu_round_trips_with_tuning_fields() {
        let spec: ProfileSpec = serde_json::from_value(profile_json()).unwrap();
        assert!(!spec.mtu_is_auto());
        assert_eq!(spec.mtu, 1515);
        assert!(spec.mss_clamp);
        assert!(spec.kill_switch);
        assert_eq!(spec.keepalive, 25);
        assert_eq!(spec.rekey_time, 1800);
        assert_eq!(spec.rekey_jitter, 30);
        let encoded = serde_json::to_value(&spec).unwrap();
        assert_eq!(encoded["mtu"], 1515);
        assert_eq!(encoded["timeout"], 60);
    }

    #[test]
    fn auto_and_zero_mtu_are_rejected_at_the_ipc_boundary() {
        for mtu in [
            serde_json::json!("auto"),
            serde_json::json!(0),
            serde_json::json!("0"),
        ] {
            let mut json = profile_json();
            json["mtu"] = mtu.clone();
            let error = serde_json::from_value::<ProfileSpec>(json).unwrap_err();
            let text = error.to_string();
            assert!(
                text.contains("auto") || text.contains("0 is invalid"),
                "unexpected error for {mtu}: {text}"
            );
        }
    }

    #[test]
    fn persistent_keepalive_alias_is_accepted() {
        let spec: ProfileSpec = serde_json::from_value(serde_json::json!({
            "name": "x",
            "remote": "host:1194",
            "verifier": "v",
            "persistent_keepalive": 25,
        }))
        .unwrap();
        assert_eq!(spec.keepalive, 25);
    }

    #[test]
    fn numeric_mtu_still_parses() {
        let mut json = profile_json();
        json["mtu"] = serde_json::json!(1540);
        let spec: ProfileSpec = serde_json::from_value(json).unwrap();
        assert!(!spec.mtu_is_auto());
        assert_eq!(spec.mtu, 1540);
        let encoded = serde_json::to_value(&spec).unwrap();
        assert_eq!(encoded["mtu"], 1540);
    }

    #[test]
    fn zero_mtu_is_never_silently_serialized_as_auto() {
        let spec = ProfileSpec {
            mtu: MTU_AUTO,
            ..ProfileSpec::default()
        };
        let json_error = serde_json::to_value(&spec).unwrap_err().to_string();
        assert!(
            json_error.contains("cannot be serialized"),
            "unexpected JSON error: {json_error}"
        );
        let yaml_error = serde_yaml_ng::to_string(&spec).unwrap_err().to_string();
        assert!(
            yaml_error.contains("cannot be serialized"),
            "unexpected YAML error: {yaml_error}"
        );
        // A numeric MTU remains numeric; the legacy string is never emitted.
        let encoded = serde_json::to_value(ProfileSpec::default()).unwrap();
        assert_eq!(encoded["mtu"], 1515);
        assert_ne!(encoded["mtu"], "auto");
    }

    #[test]
    fn validate_mtu_rejects_zero_auto_range_and_padded_minimum() {
        let mut spec = ProfileSpec {
            mtu: 1515,
            ..ProfileSpec::default()
        };
        assert!(spec.validate_mtu().is_ok());

        spec.mtu = MTU_AUTO;
        assert!(spec.validate_mtu().unwrap_err().contains("auto"));

        spec.mtu = MTU_MIN - 1;
        assert!(spec.validate_mtu().unwrap_err().contains("between"));

        spec.mtu = MTU_MAX + 1;
        assert!(spec.validate_mtu().unwrap_err().contains("between"));

        spec.mtu = MTU_MIN_NOISE - 1;
        assert!(spec.validate_mtu().is_ok());
        spec.noise = true;
        assert!(spec.validate_mtu().unwrap_err().contains("noise"));
        spec.noise = false;
        spec.encless = true;
        assert!(spec.validate_mtu().unwrap_err().contains("noise"));
        spec.encless = false;
        spec.mtu = MTU_MIN_NOISE;
        assert!(spec.validate_mtu().is_ok());
    }

    #[test]
    fn generated_profile_yaml_parses() {
        // Shape emitted by `rustvpn-verifier -profile ...`.
        let yaml = r#"
name: "office"
remote: "vpn.example.com:1194"
proto: "udp"
verifier: "$argon2d$m=4096,t=128,p=1$AAECAwQFBgcICQoLDA0ODw"
mtu: 1515
mss_clamp: true
kill_switch: false
keepalive: 25
rekey_time: 1800
rekey_jitter: 30
timeout: 60
timesync: 0
noise: false
encless: false
cpr: 0
iface: "rsvpn-gui"
address: "10.88.0.2/24"
gateway: "10.88.0.1"
dns: ["10.88.0.1"]
routes: ["default"]
ipv6: false
"#;
        let spec: ProfileSpec = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(spec.mtu, 1515);
        assert!(!spec.mtu_is_auto());
        assert!(spec.mss_clamp);
        assert!(!spec.kill_switch);
        assert_eq!(spec.keepalive, 25);
        assert_eq!(spec.rekey_time, 1800);
        assert_eq!(spec.rekey_jitter, 30);
        assert!(spec.has_default_route());
    }

    #[test]
    fn has_default_route_covers_noncanonical_prefix_zero_spellings() {
        for route in [
            "default",
            "DEFAULT",
            "0.0.0.0/0",
            "00.0.0.0/0",
            "0.0.0.00/0",
            "0.0.0.0/00",
        ] {
            assert!(is_default_route(route), "{route:?}");
            let spec = ProfileSpec {
                routes: vec![route.into()],
                ..ProfileSpec::default()
            };
            assert!(spec.has_default_route(), "{route:?}");
        }
        for route in ["0.0.0.0/1", "10.0.0.0/8", ""] {
            assert!(!is_default_route(route), "{route:?}");
        }
    }

    #[test]
    fn absent_optional_fields_use_defaults() {
        let spec: ProfileSpec = serde_json::from_value(serde_json::json!({
            "name": "x",
            "remote": "host:1194",
            "verifier": "v",
        }))
        .unwrap();
        assert_eq!(spec.mtu, 1515);
        assert!(!spec.mss_clamp);
        assert!(!spec.kill_switch);
    }

    #[test]
    fn status_json_is_versioned_and_has_no_secrets() {
        let mut status = EngineStatus {
            state: "connected".into(),
            remote: Some("vpn.example.com:1194".into()),
            proto: Some("udp".into()),
            mode: Some("noise".into()),
            iface: Some("rsvpn-gui".into()),
            since_unix: Some(0),
            ..EngineStatus::default()
        };
        status.traffic.tx_bytes = 10;
        status.traffic.rx_bytes = 20;
        status.frames_unauth = Some(0);
        let doc = ClientStatusV1::from_status(&status);
        let value = serde_json::to_value(&doc).unwrap();
        assert_eq!(value["schema"], STATUS_SCHEMA);
        assert_eq!(value["role"], "client");
        assert_eq!(value["state"], "connected");
        assert_eq!(value["since"], "1970-01-01T00:00:00Z");
        assert_eq!(value["tx_bytes"], 10);
        let text = value.to_string().to_ascii_lowercase();
        for secret in ["password", "proxy_auth", "private", "signing"] {
            assert!(!text.contains(secret), "leaked field {secret}: {text}");
        }
    }
}
