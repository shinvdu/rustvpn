//! Shared admin DTOs, backend traits and small helpers.
//!
//! The admin service knows nothing about TAP devices or the packet path.  The
//! server implements [`AdminBackend`] and [`SessionObserver`], which keeps the
//! HTTP layer testable with a fake backend.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::SystemTime;

use async_trait::async_trait;
use rustvpn_net::config::PeerYaml;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type PeerId = [u8; 16];

pub fn id_hex(id: &PeerId) -> String {
    hex::encode(id)
}

pub fn parse_id(input: &str) -> Result<PeerId, String> {
    let bytes = hex::decode(input).map_err(|_| "peer id must be 32 hex characters".to_string())?;
    if bytes.len() != 16 {
        return Err("peer id must be 32 hex characters".to_string());
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Derive the verifier identity from a `peers.yaml` entry.
pub fn peer_id_of(peer: &PeerYaml) -> Option<PeerId> {
    rustvpn_crypto::verifier::Verifier::from_string(&peer.verifier)
        .ok()
        .map(|v| v.id)
}

pub fn mode_name(noise: bool, encless: bool) -> &'static str {
    if encless {
        "encless"
    } else if noise {
        "noise"
    } else {
        "plain"
    }
}

/// Per-session counters as exposed by `LiveStats`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
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

impl Counters {
    /// Compute the delta since `prev`.  A decrease means the counters were
    /// reset (a new session with a reused identifier, which should not happen
    /// because session ids are process-unique); treat it as a fresh baseline.
    pub fn delta_since(&self, prev: &Self) -> Self {
        if self.bytes_in < prev.bytes_in || self.bytes_out < prev.bytes_out {
            return *self;
        }
        Self {
            bytes_in: self.bytes_in - prev.bytes_in,
            bytes_out: self.bytes_out - prev.bytes_out,
            payload_in: self.payload_in.saturating_sub(prev.payload_in),
            payload_out: self.payload_out.saturating_sub(prev.payload_out),
            frames_in: self.frames_in.saturating_sub(prev.frames_in),
            frames_out: self.frames_out.saturating_sub(prev.frames_out),
            unauth: self.unauth.saturating_sub(prev.unauth),
            dup: self.dup.saturating_sub(prev.dup),
            heartbeat_recv: self.heartbeat_recv.saturating_sub(prev.heartbeat_recv),
            heartbeat_sent: self.heartbeat_sent.saturating_sub(prev.heartbeat_sent),
        }
    }

    pub fn payload_total(&self) -> u64 {
        self.payload_in.saturating_add(self.payload_out)
    }
}

/// Lifetime traffic aggregated from finished sessions.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TrafficTotals {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub payload_in: u64,
    pub payload_out: u64,
    pub sessions: u64,
}

impl TrafficTotals {
    pub fn checked_add(&mut self, other: &Self) {
        self.bytes_in = self.bytes_in.saturating_add(other.bytes_in);
        self.bytes_out = self.bytes_out.saturating_add(other.bytes_out);
        self.payload_in = self.payload_in.saturating_add(other.payload_in);
        self.payload_out = self.payload_out.saturating_add(other.payload_out);
        self.sessions = self.sessions.saturating_add(other.sessions);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Rate {
    pub rate_in_bps: u64,
    pub rate_out_bps: u64,
}

#[derive(Clone, Debug, Serialize)]
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
    pub rate_in_bps: u64,
    pub rate_out_bps: u64,
}

impl SessionInfo {
    pub fn with_rate(mut self, rate: Option<&Rate>) -> Self {
        if let Some(rate) = rate {
            self.rate_in_bps = rate.rate_in_bps;
            self.rate_out_bps = rate.rate_out_bps;
        }
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerView {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub state: String,
    pub session_id: Option<u64>,
    pub addr: Option<String>,
    pub proto: Option<String>,
    pub mode: String,
    pub mtu: usize,
    pub iface: String,
    pub established: Option<String>,
    pub last_ping: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub rate_in_bps: u64,
    pub rate_out_bps: u64,
    pub session: Counters,
    pub lifetime: TrafficTotals,
    pub notes: Option<String>,
    pub quota_bytes_month: Option<u64>,
    pub month_usage: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerDetail {
    #[serde(flatten)]
    pub view: PeerView,
    pub up: String,
    pub down: String,
    pub timeout: i64,
    pub noise: bool,
    pub encless: bool,
    pub cpr: u32,
    pub timesync: i64,
    pub verifier_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub configured: usize,
    pub disabled: usize,
    pub online: usize,
    pub rate_in_bps: u64,
    pub rate_out_bps: u64,
    pub today_payload_in: u64,
    pub today_payload_out: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerList {
    pub summary: Summary,
    pub peers: Vec<PeerView>,
}

/// Parsed view of the two configuration files.
#[derive(Clone, Debug, Default)]
pub struct ConfigFiles {
    pub enabled: BTreeMap<String, PeerYaml>,
    pub disabled: BTreeMap<String, PeerYaml>,
}

#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub enabled_yaml: String,
    pub disabled_yaml: String,
    pub etag: String,
    pub files: ConfigFiles,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApplyRequest {
    pub enabled_yaml: String,
    pub disabled_yaml: String,
    pub expected_etag: String,
    #[serde(default)]
    pub comment: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplyReport {
    pub applied: bool,
    pub generation: u64,
    pub etag: String,
    pub backups: Vec<String>,
    pub revoked: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreviewReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub revoked: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BackupInfo {
    pub name: String,
    pub size: u64,
    pub modified: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KickReport {
    pub kicked: bool,
    pub session_id: u64,
    pub addr: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigStatus {
    pub path: String,
    pub disabled_path: String,
    pub generation: u64,
    pub last_loaded_at: Option<String>,
    pub last_error: Option<String>,
    pub etag: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ServerCounters {
    pub handshake_requests: u64,
    pub handshake_rate_limited: u64,
    pub handshake_errors: u64,
    pub tcp_connections_rejected: u64,
    pub sessions_started: u64,
    pub sessions_finished: u64,
    pub admin_hook_dropped: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemStatus {
    pub uptime_seconds: u64,
    pub bind: String,
    pub proto: String,
    pub admin_addr: String,
    pub active_sessions: usize,
    pub configured_peers: usize,
    pub disabled_peers: usize,
    pub config: ConfigStatus,
    pub counters: ServerCounters,
    /// False when the control socket is unreachable; the UI is then showing
    /// the last known sessions and local configuration only.
    pub server_online: bool,
    pub server_instance: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventView {
    pub ts: i64,
    pub kind: String,
    pub peer: Option<String>,
    pub addr: Option<String>,
    pub detail: Option<String>,
}

/// Bounded in-process event ring used by the dashboard.
pub struct EventLog {
    inner: Mutex<VecDeque<EventView>>,
    capacity: usize,
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn push(&self, event: EventView) {
        let mut events = self.inner.lock().unwrap();
        if events.len() >= self.capacity {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn snapshot(&self) -> Vec<EventView> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(2000)
    }
}

#[derive(Clone, Debug)]
pub struct SessionStart {
    pub session_id: u64,
    pub peer_id: PeerId,
    pub name: String,
    pub addr: String,
    pub proto: String,
    pub mode: String,
    pub started_at: i64,
    pub counters: Counters,
}

#[derive(Clone, Debug)]
pub struct SessionEnd {
    pub session_id: u64,
    pub peer_id: PeerId,
    pub ended_at: i64,
    pub reason: String,
    pub counters: Counters,
}

pub trait SessionObserver: Send + Sync {
    /// Must never block: implementations drop the event on a full queue.
    fn session_started(&self, start: SessionStart);
    fn session_ended(&self, end: SessionEnd);
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration changed on disk (current etag {current_etag})")]
    Conflict { current_etag: String },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("configuration I/O error: {0}")]
    Io(String),
}

impl ConfigError {
    pub fn invalid(message: impl Into<String>) -> Self {
        ConfigError::Invalid(message.into())
    }
}

#[async_trait]
pub trait AdminBackend: Send + Sync {
    async fn system_status(&self) -> SystemStatus;
    async fn config_snapshot(&self) -> Result<ConfigSnapshot, ConfigError>;
    async fn preview_config(
        &self,
        enabled_yaml: &str,
        disabled_yaml: &str,
    ) -> Result<PreviewReport, ConfigError>;
    async fn apply_config(&self, request: ApplyRequest) -> Result<ApplyReport, ConfigError>;
    async fn active_sessions(&self) -> Vec<SessionInfo>;
    async fn kick(&self, id: PeerId, reason: String) -> Result<KickReport, String>;
    async fn list_backups(&self) -> Result<Vec<BackupInfo>, ConfigError>;
    async fn restore_backup(&self, name: &str, comment: String)
        -> Result<ApplyReport, ConfigError>;
    fn events(&self) -> Vec<EventView>;
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn rfc3339(seconds: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
