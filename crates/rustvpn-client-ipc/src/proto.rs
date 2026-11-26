//! Request, response, event and status DTOs.

use serde::{Deserialize, Serialize};

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
    pub mtu: usize,
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

impl Default for ProfileSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            remote: String::new(),
            proto: "udp".into(),
            verifier: String::new(),
            mtu: 1515,
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
    pub traffic: TrafficSample,
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
