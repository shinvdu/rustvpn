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
    Hello { version: u32 },
    Status,
    Sessions,
    Kick { id: String, reason: String },
    Reload,
    RecentSessions { limit: u32 },
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
