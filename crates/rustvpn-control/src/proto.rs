//! Request/response/event types shared by the server control plane and the
//! admin daemon.

use serde::{Deserialize, Serialize};

/// Per-session counters, mirroring the GoVPN `/stats` fields.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub payload_in: u64,
    pub payload_out: u64,
    pub frames_in: u64,
    pub frames_out: u64,
    pub unauth: u64,
    pub dup: u64,
    pub heartbeat_recv: u64,
    pub heartbeat_sent: u64,
}

/// An active session as seen by the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: u64,
    pub peer_id: String,
    pub name: String,
    pub addr: String,
    pub proto: String,
    pub mode: String,
    pub mtu: usize,
    pub established: String,
    pub started_at_unix: i64,
    pub last_ping: String,
    pub last_sent: String,
    pub counters: Counters,
}

/// Global counters exposed by the server.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerCounters {
    pub handshake_requests: u64,
    pub handshake_rate_limited: u64,
    pub handshake_errors: u64,
    pub tcp_connections_rejected: u64,
    pub sessions_started: u64,
    pub sessions_finished: u64,
    pub events_dropped: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub server_version: String,
    pub server_instance: u64,
    pub uptime_seconds: u64,
    pub bind: String,
    pub proto: String,
    pub active_sessions: usize,
    pub configured_peers: usize,
    pub config_generation: u64,
    pub config_last_loaded_at: Option<String>,
    pub config_last_error: Option<String>,
    pub counters: ServerCounters,
}

/// Stable schema identifier for `status --json`.
pub const STATUS_SCHEMA: &str = "rustvpn.status.v1";

/// Versioned, secret-free server status document.
#[derive(Clone, Debug, Serialize)]
pub struct ServerStatusV1 {
    pub schema: &'static str,
    pub role: &'static str,
    pub state: String,
    pub since: Option<String>,
    pub server_version: String,
    pub server_instance: u64,
    pub bind: String,
    pub proto: String,
    pub uptime_seconds: u64,
    pub active_sessions: usize,
    pub configured_peers: usize,
    pub config_generation: u64,
    pub config_last_loaded_at: Option<String>,
    pub config_last_error: Option<String>,
    /// Error that prevents producing a live document (`unavailable` state).
    pub last_error: Option<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_rate_bps: Option<u64>,
    pub rx_rate_bps: Option<u64>,
    /// Server-side rate sampling is not implemented, so rates are `None`.
    pub rates_available: bool,
    /// Sampling window for `*_rate_bps`, if rates are available.
    pub rate_window_sec: Option<u64>,
    pub heartbeat_sent: u64,
    pub heartbeat_recv: u64,
    pub frames_unauth: u64,
    pub frames_dup: u64,
    pub sessions: Vec<ServerSessionV1>,
    pub counters: ServerCounters,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServerSessionV1 {
    pub session_id: u64,
    pub peer_id: String,
    pub name: String,
    pub addr: String,
    pub proto: String,
    pub mode: String,
    pub mtu: usize,
    pub established: String,
    pub last_ping: String,
    pub counters: Counters,
}

impl ServerStatusV1 {
    pub fn from_parts(status: &ServerStatus, sessions: &[SessionInfo]) -> Self {
        let since = crate::now_unix().saturating_sub(status.uptime_seconds as i64);
        let mut tx_bytes = 0u64;
        let mut rx_bytes = 0u64;
        let mut heartbeat_sent = 0u64;
        let mut heartbeat_recv = 0u64;
        let mut frames_unauth = 0u64;
        let mut frames_dup = 0u64;
        for session in sessions {
            // From the server's perspective, BytesOut goes to the client.
            tx_bytes = tx_bytes.saturating_add(session.counters.bytes_out);
            rx_bytes = rx_bytes.saturating_add(session.counters.bytes_in);
            heartbeat_sent = heartbeat_sent.saturating_add(session.counters.heartbeat_sent);
            heartbeat_recv = heartbeat_recv.saturating_add(session.counters.heartbeat_recv);
            frames_unauth = frames_unauth.saturating_add(session.counters.unauth);
            frames_dup = frames_dup.saturating_add(session.counters.dup);
        }
        Self {
            schema: STATUS_SCHEMA,
            role: "server",
            state: "running".into(),
            since: Some(crate::rfc3339(since)),
            server_version: status.server_version.clone(),
            server_instance: status.server_instance,
            bind: status.bind.clone(),
            proto: status.proto.clone(),
            uptime_seconds: status.uptime_seconds,
            active_sessions: status.active_sessions,
            configured_peers: status.configured_peers,
            config_generation: status.config_generation,
            config_last_loaded_at: status.config_last_loaded_at.clone(),
            config_last_error: status.config_last_error.clone(),
            last_error: None,
            tx_bytes,
            rx_bytes,
            tx_rate_bps: None,
            rx_rate_bps: None,
            rates_available: false,
            rate_window_sec: None,
            heartbeat_sent,
            heartbeat_recv,
            frames_unauth,
            frames_dup,
            sessions: sessions
                .iter()
                .map(|session| ServerSessionV1 {
                    session_id: session.session_id,
                    peer_id: session.peer_id.clone(),
                    name: session.name.clone(),
                    addr: session.addr.clone(),
                    proto: session.proto.clone(),
                    mode: session.mode.clone(),
                    mtu: session.mtu,
                    established: session.established.clone(),
                    last_ping: session.last_ping.clone(),
                    counters: session.counters,
                })
                .collect(),
            counters: status.counters.clone(),
        }
    }

    /// Schema-complete placeholder used when the control socket is
    /// unreachable.  Automation can rely on the same keys as a running
    /// document instead of special-casing a partial object.
    pub fn unavailable(bind: &str, message: impl Into<String>) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            role: "server",
            state: "unavailable".into(),
            since: None,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            server_instance: 0,
            bind: bind.to_string(),
            proto: String::new(),
            uptime_seconds: 0,
            active_sessions: 0,
            configured_peers: 0,
            config_generation: 0,
            config_last_loaded_at: None,
            config_last_error: None,
            last_error: Some(message.into()),
            tx_bytes: 0,
            rx_bytes: 0,
            tx_rate_bps: None,
            rx_rate_bps: None,
            rates_available: false,
            rate_window_sec: None,
            heartbeat_sent: 0,
            heartbeat_recv: 0,
            frames_unauth: 0,
            frames_dup: 0,
            sessions: Vec::new(),
            counters: ServerCounters::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KickReport {
    pub kicked: bool,
    pub session_id: u64,
    pub addr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReloadReport {
    pub applied: bool,
    pub generation: u64,
}

/// A session that started.  Sent as an event and also used for catch-up.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStarted {
    pub session_id: u64,
    pub peer_id: String,
    pub name: String,
    pub addr: String,
    pub proto: String,
    pub mode: String,
    pub mtu: usize,
    pub started_at: i64,
    pub counters: Counters,
}

/// A session that ended, including its final counters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionEnded {
    pub session_id: u64,
    pub peer_id: String,
    pub name: String,
    pub addr: String,
    pub ended_at: i64,
    pub reason: String,
    pub counters: Counters,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigReloaded {
    pub generation: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum Event {
    SessionStarted(SessionStarted),
    SessionEnded(SessionEnded),
    ConfigReloaded(ConfigReloaded),
    /// The subscriber fell behind and lost events; re-synchronise.
    Lagged {
        missed: u64,
    },
    ServerShutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Hello {
        version: u32,
    },
    Status,
    Sessions,
    Kick {
        id: String,
        reason: String,
    },
    Reload,
    RecentSessions {
        limit: u32,
    },
    /// Preflight a proposed `peers.yaml` with the server's exact parser and
    /// script policy.  Does not change the running configuration.
    ValidateConfig {
        enabled_yaml: String,
    },
    Subscribe,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Hello {
        version: u32,
        server_version: String,
        server_instance: u64,
    },
    Status {
        status: ServerStatus,
    },
    Sessions {
        sessions: Vec<SessionInfo>,
    },
    Kick {
        report: KickReport,
    },
    Reload {
        report: ReloadReport,
    },
    RecentSessions {
        sessions: Vec<SessionEnded>,
    },
    ConfigValidation {
        valid: bool,
        errors: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_json_is_versioned_and_aggregates_sessions() {
        let status = ServerStatus {
            server_version: "0.2.0".into(),
            server_instance: 7,
            uptime_seconds: 10,
            bind: "[::]:1194".into(),
            proto: "udp".into(),
            active_sessions: 1,
            configured_peers: 2,
            config_generation: 3,
            config_last_loaded_at: None,
            config_last_error: None,
            counters: ServerCounters::default(),
        };
        let session = SessionInfo {
            session_id: 1,
            peer_id: "00".repeat(16),
            name: "alice".into(),
            addr: "203.0.113.10:5000".into(),
            proto: "udp".into(),
            mode: "noise".into(),
            mtu: 1515,
            established: "2026-11-26T08:00:00Z".into(),
            started_at_unix: 0,
            last_ping: "2026-11-26T08:00:01Z".into(),
            last_sent: "2026-11-26T08:00:01Z".into(),
            counters: Counters {
                bytes_in: 11,
                bytes_out: 22,
                heartbeat_sent: 1,
                heartbeat_recv: 2,
                unauth: 0,
                dup: 0,
                ..Counters::default()
            },
        };
        let doc = ServerStatusV1::from_parts(&status, &[session]);
        let value = serde_json::to_value(&doc).unwrap();
        assert_eq!(value["schema"], STATUS_SCHEMA);
        assert_eq!(value["role"], "server");
        assert_eq!(value["state"], "running");
        assert_eq!(value["rx_bytes"], 11);
        assert_eq!(value["tx_bytes"], 22);
        assert_eq!(value["sessions"][0]["name"], "alice");
        let text = value.to_string().to_ascii_lowercase();
        for secret in ["password", "verifier", "private_key"] {
            assert!(!text.contains(secret), "leaked field {secret}: {text}");
        }
        assert_eq!(value["rates_available"], false);
        assert!(value["rate_window_sec"].is_null());
    }

    /// Top-level keys documented for the server `status --json` document.
    /// Keeping this list in a test makes a docs/schema drift visible.
    const SERVER_STATUS_KEYS: &[&str] = &[
        "schema",
        "role",
        "state",
        "since",
        "server_version",
        "server_instance",
        "bind",
        "proto",
        "uptime_seconds",
        "active_sessions",
        "configured_peers",
        "config_generation",
        "config_last_loaded_at",
        "config_last_error",
        "last_error",
        "tx_bytes",
        "rx_bytes",
        "tx_rate_bps",
        "rx_rate_bps",
        "rates_available",
        "rate_window_sec",
        "heartbeat_sent",
        "heartbeat_recv",
        "frames_unauth",
        "frames_dup",
        "sessions",
        "counters",
    ];

    const SERVER_SESSION_KEYS: &[&str] = &[
        "session_id",
        "peer_id",
        "name",
        "addr",
        "proto",
        "mode",
        "mtu",
        "established",
        "last_ping",
        "counters",
    ];

    const SERVER_COUNTER_KEYS: &[&str] = &[
        "handshake_requests",
        "handshake_rate_limited",
        "handshake_errors",
        "tcp_connections_rejected",
        "sessions_started",
        "sessions_finished",
        "events_dropped",
    ];

    const SESSION_COUNTER_KEYS: &[&str] = &[
        "bytes_in",
        "bytes_out",
        "payload_in",
        "payload_out",
        "frames_in",
        "frames_out",
        "unauth",
        "dup",
        "heartbeat_recv",
        "heartbeat_sent",
    ];

    fn sorted_keys(value: &serde_json::Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    fn assert_keys(value: &serde_json::Value, expected: &[&str]) {
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        assert_eq!(sorted_keys(value), expected);
    }

    #[test]
    fn documented_status_keys_match_serialization() {
        let doc = ServerStatusV1::unavailable("[::]:1194", "unreachable");
        let value = serde_json::to_value(&doc).unwrap();
        assert_keys(&value, SERVER_STATUS_KEYS);
        assert_keys(&value["counters"], SERVER_COUNTER_KEYS);
        let object = value.as_object().unwrap();

        // Client-only fields must never be documented or emitted as top-level
        // server fields.
        for key in [
            "iface",
            "endpoint",
            "last_handshake",
            "rekey_in_sec",
            "rekey_time_sec",
            "keepalive_sec",
        ] {
            assert!(
                !object.contains_key(key),
                "server emitted client field {key}"
            );
        }

        let session = SessionInfo {
            session_id: 1,
            peer_id: "00".repeat(16),
            name: "alice".into(),
            addr: "203.0.113.10:5000".into(),
            proto: "udp".into(),
            mode: "noise".into(),
            mtu: 1515,
            established: "2026-11-26T08:00:00Z".into(),
            started_at_unix: 0,
            last_ping: "2026-11-26T08:00:01Z".into(),
            last_sent: "2026-11-26T08:00:01Z".into(),
            counters: Counters::default(),
        };
        let status = ServerStatus {
            server_version: "0.2.0".into(),
            server_instance: 1,
            uptime_seconds: 1,
            bind: "[::]:1194".into(),
            proto: "udp".into(),
            active_sessions: 1,
            configured_peers: 1,
            config_generation: 0,
            config_last_loaded_at: None,
            config_last_error: None,
            counters: ServerCounters::default(),
        };
        let value = serde_json::to_value(ServerStatusV1::from_parts(&status, &[session])).unwrap();
        let sessions = value["sessions"].as_array().unwrap();
        assert_keys(&sessions[0], SERVER_SESSION_KEYS);
        assert_keys(&sessions[0]["counters"], SESSION_COUNTER_KEYS);
        assert_eq!(sessions[0]["mode"], "noise");
        assert_eq!(sessions[0]["mtu"], 1515);
    }

    #[test]
    fn unavailable_document_is_schema_complete() {
        let doc = ServerStatusV1::unavailable("[::]:1194", "control socket timed out");
        let value = serde_json::to_value(&doc).unwrap();
        assert_eq!(value["schema"], STATUS_SCHEMA);
        assert_eq!(value["role"], "server");
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value["last_error"], "control socket timed out");
        assert_eq!(value["rates_available"], false);
        assert!(value["rate_window_sec"].is_null());
        // Running-only fields are present with neutral values.
        assert_eq!(value["active_sessions"], 0);
        assert!(value["sessions"].as_array().unwrap().is_empty());
        assert!(value["counters"].is_object());
    }
}
