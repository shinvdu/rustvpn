//! GoVPN 5.7-compatible Rust server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Context, Result};
use rand_core::{OsRng, RngCore};
use rustvpn_crypto::egd::EgDRng;
use rustvpn_crypto::xtea::Xtea;
use rustvpn_net::config::{add_time_sync, ConfigSet, PeerConfig};
use rustvpn_net::peer::{spawn_tcp, spawn_udp_peer, PeerEvent, WireWriter};
use rustvpn_net::scripts::{call_down, run_script};
#[cfg(feature = "admin")]
use rustvpn_net::stats::PeerStats;
use rustvpn_net::stats::{stats_listener, LiveStats, StatsState};
use rustvpn_net::tap::Tap;
use rustvpn_proto::{
    HandshakeConfig, ServerHandshake, ServerOutput, ENCLESS_ENLARGE_SIZE, MTU_MAX,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "admin")]
use async_trait::async_trait;
#[cfg(feature = "admin")]
use rustvpn_admin::config_edit::{self, ConfigPaths};
#[cfg(feature = "admin")]
use rustvpn_admin::history::History;
#[cfg(feature = "admin")]
use rustvpn_admin::model::{
    id_hex, mode_name, now_unix, rfc3339, AdminBackend, ApplyReport, ApplyRequest, BackupInfo,
    ConfigError, ConfigSnapshot, ConfigStatus, Counters, EventLog, EventView, KickReport,
    PreviewReport, ServerCounters, SessionEnd, SessionInfo, SessionObserver, SessionStart,
    SystemStatus,
};
#[cfg(feature = "admin")]
use rustvpn_admin::store::Store;
#[cfg(feature = "admin")]
use rustvpn_admin::{AdminOptions, AdminState};

const WARRANTY: &str = "This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.";

struct Args {
    bind: String,
    proto: String,
    conf: String,
    stats: String,
    proxy: String,
    egd: String,
    admin: String,
    admin_db: String,
    admin_disabled_conf: String,
    admin_cookie_secure: bool,
    admin_script_dir: Vec<String>,
    warranty: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-server:\n\
         \x20 -bind string (default \"[::]:1194\")\n\
         \x20 -conf string (default \"peers.yaml\")\n\
         \x20 -egd string\n\
         \x20 -proto string (default \"udp\")\n\
         \x20 -proxy string\n\
         \x20 -stats string\n\
         \x20 -admin string (optional, build with --features admin)\n\
         \x20 -admin-db string (default \"/var/lib/rustvpn/admin.db\")\n\
         \x20 -admin-disabled-conf string (default \"peers.disabled.yaml\") \n\
         \x20 -admin-cookie-secure (set Secure/__Host- cookies; behind TLS)\n\
         \x20 -admin-script-dir string (repeatable; restrict up/down paths)\n\
         \x20 -warranty"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        bind: "[::]:1194".into(),
        proto: "udp".into(),
        conf: "peers.yaml".into(),
        stats: String::new(),
        proxy: String::new(),
        egd: String::new(),
        admin: String::new(),
        admin_db: "/var/lib/rustvpn/admin.db".into(),
        admin_disabled_conf: String::new(),
        admin_cookie_secure: false,
        admin_script_dir: Vec::new(),
        warranty: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.trim_start_matches('-').to_string(), Some(v.to_string())),
            None => (arg.trim_start_matches('-').to_string(), None),
        };
        let mut take = |name: &str| -> String {
            inline.clone().unwrap_or_else(|| {
                it.next().unwrap_or_else(|| {
                    eprintln!("flag needs an argument: -{name}");
                    usage();
                })
            })
        };
        match name.as_str() {
            "bind" => a.bind = take("bind"),
            "proto" => a.proto = take("proto"),
            "conf" => a.conf = take("conf"),
            "stats" => a.stats = take("stats"),
            "proxy" => a.proxy = take("proxy"),
            "egd" => a.egd = take("egd"),
            "admin" => a.admin = take("admin"),
            "admin-db" => a.admin_db = take("admin-db"),
            "admin-disabled-conf" => a.admin_disabled_conf = take("admin-disabled-conf"),
            "admin-cookie-secure" => a.admin_cookie_secure = true,
            "admin-script-dir" => a.admin_script_dir.push(take("admin-script-dir")),
            "warranty" => a.warranty = true,
            "h" | "help" => usage(),
            "" => usage(),
            other => {
                eprintln!("flag provided but not defined: -{other}");
                usage();
            }
        }
    }
    a
}

enum Rng {
    Os(OsRng),
    Egd(EgDRng),
}

impl Rng {
    fn new(egd: &str) -> Self {
        if egd.is_empty() {
            Rng::Os(OsRng)
        } else {
            Rng::Egd(EgDRng::new(egd))
        }
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        match self {
            Rng::Os(r) => r.next_u32(),
            Rng::Egd(r) => r.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            Rng::Os(r) => r.next_u64(),
            Rng::Egd(r) => r.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Rng::Os(r) => r.fill_bytes(dest),
            Rng::Egd(r) => r.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            Rng::Os(r) => r.try_fill_bytes(dest),
            Rng::Egd(r) => r.try_fill_bytes(dest),
        }
    }
}

static NEXT_PEER_TOKEN: AtomicU64 = AtomicU64::new(1);

struct PeerEntry {
    token: u64,
    addr: SocketAddr,
    id: [u8; 16],
    cfg: Arc<PeerConfig>,
    tap: Arc<Tap>,
    stats: Arc<LiveStats>,
    cancel: CancellationToken,
    inbound: Option<mpsc::Sender<Vec<u8>>>,
    #[cfg_attr(not(feature = "admin"), allow(dead_code))]
    proto: &'static str,
}

#[derive(Default)]
struct RegistryInner {
    peers: HashMap<SocketAddr, Arc<PeerEntry>>,
    by_id: HashMap<[u8; 16], SocketAddr>,
}

#[derive(Default)]
struct Registry {
    inner: Mutex<RegistryInner>,
}

impl Registry {
    fn get(&self, addr: &SocketAddr) -> Option<Arc<PeerEntry>> {
        self.inner.lock().unwrap().peers.get(addr).cloned()
    }
    fn addr_by_id(&self, id: &[u8; 16]) -> Option<SocketAddr> {
        self.inner.lock().unwrap().by_id.get(id).copied()
    }
    fn insert(&self, entry: Arc<PeerEntry>) {
        let mut inner = self.inner.lock().unwrap();
        inner.peers.insert(entry.addr, entry.clone());
        inner.by_id.insert(entry.id, entry.addr);
    }
    fn remove_addr(&self, addr: &SocketAddr) -> Option<Arc<PeerEntry>> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.peers.remove(addr);
        if let Some(e) = &entry {
            if inner.by_id.get(&e.id) == Some(addr) {
                inner.by_id.remove(&e.id);
            }
        }
        entry
    }
    fn snapshot(&self) -> Vec<Arc<PeerEntry>> {
        self.inner.lock().unwrap().peers.values().cloned().collect()
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct RateLimiter {
    buckets: HashMap<IpAddr, Bucket>,
    global: Bucket,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64) -> Self {
        let now = Instant::now();
        Self {
            buckets: HashMap::new(),
            global: Bucket {
                tokens: burst,
                last: now,
            },
            rate,
            burst,
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let (rate, burst) = (self.rate, self.burst);
        let bucket = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: burst,
            last: Instant::now(),
        });
        bucket.take(rate, burst)
    }

    fn allow_global(&mut self) -> bool {
        self.global.take(self.rate, self.burst)
    }

    fn cleanup(&mut self) {
        if self.buckets.len() > 8192 {
            let now = Instant::now();
            self.buckets
                .retain(|_, b| now.saturating_duration_since(b.last) < Duration::from_secs(60));
        }
    }
}

type ConfigStore = Arc<RwLock<ConfigSet>>;

/// Serialises disk reloads from the 60-second poller and the admin service.
struct Reloader {
    path: PathBuf,
    store: ConfigStore,
    requests: mpsc::Sender<MainRequest>,
    guard: tokio::sync::Mutex<()>,
    last_bytes: Mutex<Option<Vec<u8>>>,
    generation: AtomicU64,
    last_loaded: Mutex<Option<SystemTime>>,
    last_error: Mutex<Option<String>>,
}

impl Reloader {
    fn new(
        path: PathBuf,
        store: ConfigStore,
        requests: mpsc::Sender<MainRequest>,
        initial_bytes: Option<Vec<u8>>,
        generation: u64,
    ) -> Self {
        Self {
            path,
            store,
            requests,
            guard: tokio::sync::Mutex::new(()),
            last_bytes: Mutex::new(initial_bytes),
            generation: AtomicU64::new(generation),
            last_loaded: Mutex::new(Some(SystemTime::now())),
            last_error: Mutex::new(None),
        }
    }

    async fn reload_from_disk(&self) -> Result<bool> {
        let _guard = self.guard.lock().await;
        let bytes = tokio::fs::read(&self.path)
            .await
            .with_context(|| format!("read {}", self.path.display()))?;
        {
            let last = self.last_bytes.lock().unwrap();
            if last.as_deref() == Some(bytes.as_slice()) {
                return Ok(false);
            }
        }
        let text = std::str::from_utf8(&bytes).context("peers.yaml is not valid UTF-8")?;
        let set = match ConfigSet::from_str(text) {
            Ok(set) => set,
            Err(error) => {
                *self.last_error.lock().unwrap() = Some(format!("{error:#}"));
                return Err(error);
            }
        };
        let fingerprints = set
            .peers
            .iter()
            .map(|peer| (peer.id, config_fingerprint(peer)))
            .collect();
        *self.store.write().await = set;
        *self.last_bytes.lock().unwrap() = Some(bytes);
        self.generation.fetch_add(1, AtomicOrdering::Relaxed);
        *self.last_loaded.lock().unwrap() = Some(SystemTime::now());
        *self.last_error.lock().unwrap() = None;
        let _ = self
            .requests
            .send(MainRequest::ConfigReloaded { fingerprints })
            .await;
        Ok(true)
    }

    #[cfg(feature = "admin")]
    fn generation(&self) -> u64 {
        self.generation.load(AtomicOrdering::Relaxed)
    }

    #[cfg(feature = "admin")]
    fn last_loaded(&self) -> Option<SystemTime> {
        *self.last_loaded.lock().unwrap()
    }

    #[cfg(feature = "admin")]
    fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

#[cfg(feature = "admin")]
#[derive(Default)]
struct AdminMetrics {
    handshake_requests: AtomicU64,
    handshake_rate_limited: AtomicU64,
    handshake_errors: AtomicU64,
    tcp_connections_rejected: AtomicU64,
    sessions_started: AtomicU64,
    sessions_finished: AtomicU64,
}

#[cfg(feature = "admin")]
impl AdminMetrics {
    fn snapshot(&self) -> ServerCounters {
        ServerCounters {
            handshake_requests: self.handshake_requests.load(AtomicOrdering::Relaxed),
            handshake_rate_limited: self.handshake_rate_limited.load(AtomicOrdering::Relaxed),
            handshake_errors: self.handshake_errors.load(AtomicOrdering::Relaxed),
            tcp_connections_rejected: self.tcp_connections_rejected.load(AtomicOrdering::Relaxed),
            sessions_started: self.sessions_started.load(AtomicOrdering::Relaxed),
            sessions_finished: self.sessions_finished.load(AtomicOrdering::Relaxed),
            admin_hook_dropped: 0,
        }
    }
}

#[cfg(feature = "admin")]
struct AdminRuntime {
    history: Arc<History>,
    events: Arc<EventLog>,
    metrics: Arc<AdminMetrics>,
}

#[cfg(feature = "admin")]
struct ServerBackend {
    registry: Arc<Registry>,
    configs: ConfigStore,
    requests: mpsc::Sender<MainRequest>,
    reloader: Arc<Reloader>,
    paths: ConfigPaths,
    events: Arc<EventLog>,
    metrics: Arc<AdminMetrics>,
    config_write: tokio::sync::Mutex<()>,
    bind: String,
    proto: String,
    admin_addr: String,
    started_at: SystemTime,
}

#[cfg(feature = "admin")]
#[async_trait]
impl AdminBackend for ServerBackend {
    async fn system_status(&self) -> SystemStatus {
        let configured_peers = self.configs.read().await.peers.len();
        let paths = self.paths.clone();
        let loaded = tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .ok()
            .and_then(|result| result.ok());
        let (disabled_peers, etag, load_error) = match loaded {
            Some(loaded) => (loaded.files.disabled.len(), loaded.etag(), None),
            None => (
                0,
                String::new(),
                Some("unable to read peers.yaml".to_string()),
            ),
        };
        let last_loaded_at = self.reloader.last_loaded().and_then(|time| {
            time.duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|d| rfc3339(d.as_secs() as i64))
        });
        SystemStatus {
            uptime_seconds: SystemTime::now()
                .duration_since(self.started_at)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            bind: self.bind.clone(),
            proto: self.proto.clone(),
            admin_addr: self.admin_addr.clone(),
            active_sessions: self.registry.snapshot().len(),
            configured_peers,
            disabled_peers,
            config: ConfigStatus {
                path: self.paths.enabled.display().to_string(),
                disabled_path: self.paths.disabled.display().to_string(),
                generation: self.reloader.generation(),
                last_loaded_at,
                last_error: self.reloader.last_error().or(load_error),
                etag,
            },
            counters: self.metrics.snapshot(),
        }
    }

    async fn config_snapshot(&self) -> Result<ConfigSnapshot, ConfigError> {
        let paths = self.paths.clone();
        tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .map_err(|e| ConfigError::Io(e.to_string()))?
            .map(|loaded| loaded.snapshot())
    }

    async fn preview_config(
        &self,
        enabled_yaml: &str,
        disabled_yaml: &str,
    ) -> Result<PreviewReport, ConfigError> {
        let paths = self.paths.clone();
        let enabled = enabled_yaml.to_string();
        let disabled = disabled_yaml.to_string();
        tokio::task::spawn_blocking(move || {
            let current = config_edit::load(&paths)?;
            config_edit::preview(&current, &enabled, &disabled)
        })
        .await
        .map_err(|e| ConfigError::Io(e.to_string()))?
    }

    async fn apply_config(&self, request: ApplyRequest) -> Result<ApplyReport, ConfigError> {
        let _guard = self.config_write.lock().await;
        let paths = self.paths.clone();
        let current = tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .map_err(|e| ConfigError::Io(e.to_string()))??;
        if current.etag() != request.expected_etag {
            return Err(ConfigError::Conflict {
                current_etag: current.etag(),
            });
        }
        let files = config_edit::parse_files(&request.enabled_yaml, &request.disabled_yaml)?;
        let (_, _, _, revoked) = config_edit::diff(&current.files, &files);
        let paths = self.paths.clone();
        let report = tokio::task::spawn_blocking(move || config_edit::commit(&paths, &files))
            .await
            .map_err(|e| ConfigError::Io(e.to_string()))??;
        let applied = self
            .reloader
            .reload_from_disk()
            .await
            .map_err(|e| ConfigError::Io(format!("{e:#}")))?;
        Ok(ApplyReport {
            applied,
            generation: self.reloader.generation(),
            etag: report.etag,
            backups: report.backups,
            revoked,
            warnings: report.warnings,
        })
    }

    async fn active_sessions(&self) -> Vec<SessionInfo> {
        self.registry
            .snapshot()
            .into_iter()
            .map(|entry| {
                let stats = entry.stats.snapshot();
                SessionInfo {
                    session_id: entry.token,
                    peer_id: id_hex(&entry.id),
                    name: entry.cfg.name.clone(),
                    addr: entry.addr.to_string(),
                    proto: entry.proto.to_string(),
                    mode: mode_name(entry.cfg.noise, entry.cfg.encless).to_string(),
                    mtu: entry.cfg.mtu,
                    established: rfc3339(stats.established.timestamp()),
                    started_at_unix: stats.established.timestamp(),
                    last_ping: rfc3339(stats.last_ping.timestamp()),
                    last_sent: rfc3339(stats.last_sent.timestamp()),
                    counters: counters_from(&stats),
                    rate_in_bps: 0,
                    rate_out_bps: 0,
                }
            })
            .collect()
    }

    async fn kick(&self, id: [u8; 16], reason: String) -> Result<KickReport, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.requests
            .send(MainRequest::Kick {
                id,
                reason,
                reply: tx,
            })
            .await
            .map_err(|_| "server is shutting down".to_string())?;
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("kick request was cancelled".into()),
            Err(_) => Err("kick request timed out".into()),
        }
    }

    async fn list_backups(&self) -> Result<Vec<BackupInfo>, ConfigError> {
        let paths = self.paths.clone();
        tokio::task::spawn_blocking(move || config_edit::list_backups(&paths))
            .await
            .map_err(|e| ConfigError::Io(e.to_string()))?
    }

    async fn restore_backup(
        &self,
        name: &str,
        _comment: String,
    ) -> Result<ApplyReport, ConfigError> {
        let _guard = self.config_write.lock().await;
        let paths = self.paths.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || config_edit::restore(&paths, &name))
            .await
            .map_err(|e| ConfigError::Io(e.to_string()))??;
        let applied = self
            .reloader
            .reload_from_disk()
            .await
            .map_err(|e| ConfigError::Io(format!("{e:#}")))?;
        let paths = self.paths.clone();
        let current = tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .map_err(|e| ConfigError::Io(e.to_string()))??;
        Ok(ApplyReport {
            applied,
            generation: self.reloader.generation(),
            etag: current.etag(),
            backups: Vec::new(),
            revoked: Vec::new(),
            warnings: Vec::new(),
        })
    }

    fn events(&self) -> Vec<EventView> {
        self.events.snapshot()
    }
}

#[derive(Clone)]
struct ServerContext {
    registry: Arc<Registry>,
    configs: ConfigStore,
    stats: Arc<StatsState>,
    events: mpsc::Sender<(SocketAddr, [u8; 16], u64, PeerEvent)>,
    requests: mpsc::Sender<MainRequest>,
    udp_send: Arc<Mutex<Option<rustvpn_net::udp_batch::UdpBatchSender>>>,
    hs_limit: Arc<Mutex<RateLimiter>>,
    hs_global: Arc<Mutex<RateLimiter>>,
    tcp_limit: Arc<Semaphore>,
    egd: Arc<String>,
    #[cfg(feature = "admin")]
    admin: Option<Arc<AdminRuntime>>,
}

enum MainRequest {
    TcpPeer {
        addr: SocketAddr,
        cfg: Arc<PeerConfig>,
        key: [u8; 32],
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
        tap: Arc<Tap>,
    },
    ConfigReloaded {
        fingerprints: Vec<([u8; 16], String)>,
    },
    #[cfg(feature = "admin")]
    Kick {
        id: [u8; 16],
        reason: String,
        reply: tokio::sync::oneshot::Sender<Result<KickReport, String>>,
    },
}

#[derive(Clone, Copy, Debug)]
enum EndReason {
    Timeout,
    Rehandshake,
    TcpClosed,
    TapClosed,
    Replaced,
    ConfigRevoke,
    Shutdown,
    #[cfg(feature = "admin")]
    AdminKick,
}

impl EndReason {
    #[cfg(feature = "admin")]
    fn as_str(self) -> &'static str {
        match self {
            EndReason::Timeout => "timeout",
            EndReason::Rehandshake => "rehandshake",
            EndReason::TcpClosed => "tcp_closed",
            EndReason::TapClosed => "tap_closed",
            EndReason::Replaced => "replaced",
            EndReason::ConfigRevoke => "config_revoke",
            EndReason::Shutdown => "shutdown",
            EndReason::AdminKick => "admin_kick",
        }
    }
}

fn end_reason_from_event(event: PeerEvent) -> EndReason {
    match event {
        PeerEvent::Timeout => EndReason::Timeout,
        PeerEvent::Rehandshake => EndReason::Rehandshake,
        PeerEvent::TcpClosed => EndReason::TcpClosed,
        PeerEvent::TapClosed => EndReason::TapClosed,
    }
}

/// Remove a session and publish its final counters exactly once.
async fn end_session(ctx: &ServerContext, entry: Arc<PeerEntry>, reason: EndReason) {
    if ctx.registry.remove_addr(&entry.addr).is_none() {
        return;
    }
    entry.cancel.cancel();
    #[cfg(feature = "admin")]
    let snapshot = entry.stats.snapshot();
    ctx.stats.remove(&entry.stats.addr);
    #[cfg(feature = "admin")]
    if let Some(admin) = &ctx.admin {
        admin.history.session_ended(SessionEnd {
            session_id: entry.token,
            peer_id: entry.id,
            ended_at: now_unix(),
            reason: reason.as_str().to_string(),
            counters: counters_from(&snapshot),
        });
        admin.events.push(EventView {
            ts: now_unix(),
            kind: "peer_removed".into(),
            peer: Some(entry.cfg.name.clone()),
            addr: Some(entry.addr.to_string()),
            detail: Some(reason.as_str().into()),
        });
        admin
            .metrics
            .sessions_finished
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
    if !matches!(reason, EndReason::Replaced) {
        call_down(&entry.cfg.down, entry.tap.name(), &entry.addr.to_string()).await;
    }
}

#[cfg(feature = "admin")]
fn notify_session_started(ctx: &ServerContext, entry: &PeerEntry) {
    if let Some(admin) = &ctx.admin {
        let stats = entry.stats.snapshot();
        admin.history.session_started(SessionStart {
            session_id: entry.token,
            peer_id: entry.id,
            name: entry.cfg.name.clone(),
            addr: entry.addr.to_string(),
            proto: entry.proto.to_string(),
            mode: mode_name(entry.cfg.noise, entry.cfg.encless).to_string(),
            started_at: stats.established.timestamp(),
            counters: counters_from(&stats),
        });
        admin.events.push(EventView {
            ts: now_unix(),
            kind: "peer_created".into(),
            peer: Some(entry.cfg.name.clone()),
            addr: Some(entry.addr.to_string()),
            detail: Some(entry.proto.to_string()),
        });
        admin
            .metrics
            .sessions_started
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
}

#[cfg(feature = "admin")]
fn counters_from(stats: &PeerStats) -> Counters {
    Counters {
        bytes_in: stats.bytes_in,
        bytes_out: stats.bytes_out,
        payload_in: stats.payload_in,
        payload_out: stats.payload_out,
        frames_in: stats.frames_in,
        frames_out: stats.frames_out,
        unauth: stats.unauth,
        dup: stats.dup,
        heartbeat_recv: stats.heartbeat_recv,
        heartbeat_sent: stats.heartbeat_sent,
    }
}

struct PendingHandshake {
    hs: ServerHandshake,
    rng: Rng,
    cfg: Arc<PeerConfig>,
    created: Instant,
    /// Last server flight, resent when the client retransmits msg1.
    last_reply: Vec<u8>,
}

/// Replace an existing session for the same identity, reusing its TAP.
async fn take_old_peer(ctx: &ServerContext, id: [u8; 16]) -> Option<Arc<Tap>> {
    let old_addr = ctx.registry.addr_by_id(&id)?;
    let old = ctx.registry.get(&old_addr)?;
    let tap = old.tap.clone();
    end_session(ctx, old, EndReason::Replaced).await;
    // Give the old reader/writer tasks a moment to observe cancellation
    // before the replacement starts using the same TAP.
    tokio::time::sleep(Duration::from_millis(10)).await;
    Some(tap)
}

/// Open a fresh TAP for one peer.  The up script runs first (GoVPN
/// contract) and is expected to create the persistent device; scripts are
/// time-bounded by `run_script`.
async fn open_tap(cfg: &PeerConfig, remote: &str) -> Result<(Arc<Tap>, String)> {
    let mut iface = cfg.iface.clone();
    if !cfg.up.is_empty() {
        if let Some(out) = run_script(&cfg.up, &cfg.iface, remote).await? {
            if cfg.iface.is_empty() {
                iface = out.lines().next().unwrap_or("").trim().to_string();
            }
        }
    }
    if iface.is_empty() {
        return Err(anyhow!("empty interface name"));
    }
    Ok((Arc::new(Tap::open(&iface, cfg.mtu)?), iface))
}

fn watch_peer(
    handle_events: mpsc::Receiver<PeerEvent>,
    addr: SocketAddr,
    id: [u8; 16],
    token: u64,
    tx: mpsc::Sender<(SocketAddr, [u8; 16], u64, PeerEvent)>,
) {
    let mut events = handle_events;
    tokio::spawn(async move {
        if let Some(ev) = events.recv().await {
            let _ = tx.send((addr, id, token, ev)).await;
        }
    });
}

async fn create_udp_peer(
    ctx: &ServerContext,
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    cfg: Arc<PeerConfig>,
    key: [u8; 32],
) -> Result<()> {
    let tap = match take_old_peer(ctx, cfg.id).await {
        Some(t) => t,
        None => open_tap(&cfg, &addr.to_string()).await?.0,
    };
    let stats = LiveStats::new(
        addr.to_string(),
        cfg.id,
        cfg.noise,
        cfg.cpr,
        cfg.encless,
        cfg.mtu,
    );
    ctx.stats.insert(stats.clone());
    let writer = match ctx.udp_send.lock().unwrap().clone() {
        Some(tx) => WireWriter::UdpBatch { tx, remote: addr },
        None => WireWriter::Udp {
            socket,
            remote: addr,
        },
    };
    let handle = spawn_udp_peer(cfg.clone(), tap.clone(), key, false, stats.clone(), writer);
    let token = NEXT_PEER_TOKEN.fetch_add(1, AtomicOrdering::Relaxed);
    watch_peer(handle.events, addr, cfg.id, token, ctx.events.clone());
    let entry = Arc::new(PeerEntry {
        token,
        addr,
        id: cfg.id,
        cfg,
        tap,
        stats,
        cancel: handle.cancel,
        inbound: handle.inbound,
        proto: "udp",
    });
    ctx.registry.insert(entry.clone());
    #[cfg(feature = "admin")]
    notify_session_started(ctx, &entry);
    eprintln!("peer created: {addr}");
    Ok(())
}

fn msg1_len(cfg: &PeerConfig) -> usize {
    if cfg.encless {
        ENCLESS_ENLARGE_SIZE + cfg.mtu
    } else if cfg.noise {
        cfg.mtu
    } else {
        48
    }
}

/// Does this packet look like a fresh first handshake message for `cfg`?
/// The last 8 bytes are the XTEA ID-tag of the first 8 bytes; transport
/// packets do not satisfy that relation.
/// Stable fingerprint of the settings that must revoke an existing
/// session when they change on config reload.
fn config_fingerprint(cfg: &PeerConfig) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        cfg.verifier.long_form().unwrap_or_default(),
        cfg.iface,
        cfg.mtu,
        cfg.noise,
        cfg.encless,
        cfg.cpr,
        cfg.time_sync
    )
}

fn is_msg1_for(cfg: &PeerConfig, data: &[u8]) -> bool {
    if data.len() < 16 || data.len() != msg1_len(cfg) {
        return false;
    }
    let mut block = [0u8; 8];
    block.copy_from_slice(&data[data.len() - 8..]);
    let cipher = Xtea::new(&cfg.id);
    cipher.decrypt_block(&mut block);
    add_time_sync(cfg.time_sync, &mut block);
    block == data[..8]
}

fn msg3_len(cfg: &PeerConfig) -> usize {
    if cfg.encless {
        ENCLESS_ENLARGE_SIZE + cfg.mtu
    } else if cfg.noise {
        cfg.mtu
    } else {
        120
    }
}

fn server_handshake_config(cfg: &PeerConfig) -> Result<HandshakeConfig> {
    let public = cfg
        .verifier
        .public
        .ok_or_else(|| anyhow!("verifier has no public key"))?;
    Ok(HandshakeConfig::server(
        cfg.id,
        cfg.mtu,
        cfg.noise,
        cfg.encless,
        cfg.time_sync,
        public,
    ))
}

/// Complete a UDP handshake off the receive loop: open the TAP and start
/// the peer first, then send the final reply (so a setup failure never
/// leaves the client believing it is connected).
fn finish_udp_handshake(
    ctx: &ServerContext,
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    cfg: Arc<PeerConfig>,
    key: [u8; 32],
    reply: Vec<u8>,
    completing: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
) {
    completing.lock().unwrap().insert(addr, Instant::now());
    let ctx = ctx.clone();
    tokio::spawn(async move {
        match create_udp_peer(&ctx, socket.clone(), addr, cfg, key).await {
            Ok(()) => {
                if let Err(e) = socket.send_to(&reply, addr).await {
                    eprintln!("handshake reply to {addr} failed: {e}");
                }
            }
            Err(e) => eprintln!("peer setup failed: {e:#}"),
        }
        completing.lock().unwrap().remove(&addr);
    });
}

async fn handle_udp_packet(
    ctx: &ServerContext,
    socket: &Arc<UdpSocket>,
    addr: SocketAddr,
    data: &[u8],
    handshakes: &mut HashMap<SocketAddr, PendingHandshake>,
    completing: &Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    last_seen: &mut HashMap<SocketAddr, Instant>,
) {
    // Setup for this address is already in progress; drop duplicates.
    if completing.lock().unwrap().contains_key(&addr) {
        return;
    }
    if let Some(peer) = ctx.registry.get(&addr) {
        // A reconnecting client may reuse its source port.  If the peer
        // has been idle briefly and this packet looks like a fresh msg1
        // for the same identity, replace the old session instead of
        // feeding the handshake bytes to its transport decoder.
        let idle = last_seen
            .get(&addr)
            .is_none_or(|t| t.elapsed() > Duration::from_millis(500));
        last_seen.insert(addr, Instant::now());
        if !(idle && is_msg1_for(&peer.cfg, data)) {
            if let Some(tx) = &peer.inbound {
                let _ = tx.try_send(data.to_vec());
            }
            return;
        }
        if let Some(old) = ctx.registry.get(&addr) {
            end_session(ctx, old, EndReason::Replaced).await;
        }
        handshakes.remove(&addr);
        eprintln!("reconnect detected, replacing peer at {addr}");
    }
    if let Some(mut ph) = handshakes.remove(&addr) {
        let mut keep = true;
        match ph.hs.server(data, &mut ph.rng) {
            Ok(ServerOutput::Reply(reply)) => {
                ph.last_reply = reply.clone();
                let _ = socket.send_to(&reply, addr).await;
            }
            Ok(ServerOutput::Complete { reply, session_key }) => {
                keep = false;
                finish_udp_handshake(
                    ctx,
                    socket.clone(),
                    addr,
                    ph.cfg.clone(),
                    session_key,
                    reply,
                    completing.clone(),
                );
            }
            // A client that lost our reply retransmits msg1; at this stage it
            // is parsed as msg3 and fails.  Replay the cached server flight
            // so the handshake can resume without a full restart.
            Err(e) => {
                #[cfg(feature = "admin")]
                if let Some(admin) = &ctx.admin {
                    admin
                        .metrics
                        .handshake_errors
                        .fetch_add(1, AtomicOrdering::Relaxed);
                }
                eprintln!("handshake error from {addr}: {e}");
                if !ph.last_reply.is_empty() {
                    let reply = ph.last_reply.clone();
                    let _ = socket.send_to(&reply, addr).await;
                }
            }
        }
        if keep {
            handshakes.insert(addr, ph);
        }
        return;
    }
    let cfg = {
        let set = ctx.configs.read().await;
        set.find_identity(data).cloned()
    };
    let Some(cfg) = cfg else {
        return;
    };
    #[cfg(feature = "admin")]
    if let Some(admin) = &ctx.admin {
        admin
            .metrics
            .handshake_requests
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
    if handshakes.len() >= 4096 {
        return;
    }
    if handshakes.keys().filter(|a| a.ip() == addr.ip()).count() >= 16 {
        return;
    }
    let ip = addr.ip();
    if !ctx.hs_limit.lock().unwrap().allow(ip) || !ctx.hs_global.lock().unwrap().allow_global() {
        #[cfg(feature = "admin")]
        if let Some(admin) = &ctx.admin {
            admin
                .metrics
                .handshake_rate_limited
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        return;
    }
    let hcfg = match server_handshake_config(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    let mut hs = ServerHandshake::new(hcfg);
    let mut rng = Rng::new(&ctx.egd);
    match hs.server(data, &mut rng) {
        Ok(ServerOutput::Reply(reply)) => {
            let _ = socket.send_to(&reply, addr).await;
            handshakes.insert(
                addr,
                PendingHandshake {
                    hs,
                    rng,
                    cfg,
                    created: Instant::now(),
                    last_reply: reply,
                },
            );
        }
        Ok(ServerOutput::Complete { reply, session_key }) => {
            finish_udp_handshake(
                ctx,
                socket.clone(),
                addr,
                cfg,
                session_key,
                reply,
                completing.clone(),
            );
        }
        Err(e) => {
            #[cfg(feature = "admin")]
            if let Some(admin) = &ctx.admin {
                admin
                    .metrics
                    .handshake_errors
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
            eprintln!("handshake error from {addr}: {e}")
        }
    }
}

async fn udp_loop(socket: Arc<UdpSocket>, ctx: ServerContext) {
    use rustvpn_net::udp_batch;
    let buf_size = ENCLESS_ENLARGE_SIZE + MTU_MAX + 64;
    let mut bufs: Vec<Vec<u8>> = (0..udp_batch::MAX_BATCH)
        .map(|_| vec![0u8; buf_size])
        .collect();
    let mut lens = vec![0usize; udp_batch::MAX_BATCH];
    let mut addrs = vec![SocketAddr::from(([0u8, 0, 0, 0], 0)); udp_batch::MAX_BATCH];
    let mut handshakes: HashMap<SocketAddr, PendingHandshake> = HashMap::new();
    let completing: Arc<Mutex<HashMap<SocketAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut last_seen: HashMap<SocketAddr, Instant> = HashMap::new();
    let mut cleanup = tokio::time::interval(Duration::from_secs(10));
    loop {
        let received = tokio::select! {
            _ = cleanup.tick() => {
                handshakes.retain(|_, ph| ph.created.elapsed() < Duration::from_secs(60));
                completing
                    .lock()
                    .unwrap()
                    .retain(|_, started| started.elapsed() < Duration::from_secs(60));
                last_seen.retain(|_, seen| seen.elapsed() < Duration::from_secs(60));
                ctx.hs_limit.lock().unwrap().cleanup();
                ctx.hs_global.lock().unwrap().cleanup();
                continue;
            }
            r = udp_batch::recv_batch(&socket, &mut bufs, &mut lens, &mut addrs) => match r {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("udp receive failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        };
        for i in 0..received {
            if lens[i] == 0 {
                continue;
            }
            handle_udp_packet(
                &ctx,
                &socket,
                addrs[i],
                &bufs[i][..lens[i]],
                &mut handshakes,
                &completing,
                &mut last_seen,
            )
            .await;
        }
    }
}

async fn read_until_identity(
    stream: &mut TcpStream,
    configs: &ConfigStore,
    max: usize,
) -> Result<(Vec<u8>, Arc<PeerConfig>)> {
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("connection closed during handshake"));
        }
        buf.extend_from_slice(&tmp[..n]);
        let found = {
            let set = configs.read().await;
            set.find_identity(&buf).cloned()
        };
        if let Some(cfg) = found {
            let need = msg1_len(&cfg);
            if buf.len() < need {
                let mut rest = vec![0u8; need - buf.len()];
                stream.read_exact(&mut rest).await?;
                buf.extend_from_slice(&rest);
            }
            if buf.len() != need {
                return Err(anyhow!("unexpected handshake packet size"));
            }
            return Ok((buf, cfg));
        }
        if buf.len() > max {
            return Err(anyhow!("no identity found in handshake packet"));
        }
    }
}

async fn handle_tcp_conn(mut stream: TcpStream, ctx: ServerContext) -> Result<()> {
    let addr = stream.peer_addr()?;
    let max = ENCLESS_ENLARGE_SIZE + MTU_MAX + 64;
    let (msg1, cfg) = tokio::time::timeout(
        Duration::from_secs(60),
        read_until_identity(&mut stream, &ctx.configs, max),
    )
    .await??;
    let hcfg = server_handshake_config(&cfg)?;
    let mut hs = ServerHandshake::new(hcfg);
    let mut rng = Rng::new(&ctx.egd);
    let msg2 = match hs.server(&msg1, &mut rng)? {
        ServerOutput::Reply(r) => r,
        _ => return Err(anyhow!("handshake completed too early")),
    };
    stream.write_all(&msg2).await?;
    let mut msg3 = vec![0u8; msg3_len(&cfg)];
    tokio::time::timeout(cfg.timeout, stream.read_exact(&mut msg3)).await??;
    let (msg4, key) = match hs.server(&msg3, &mut rng)? {
        ServerOutput::Complete { reply, session_key } => (reply, session_key),
        _ => return Err(anyhow!("handshake did not complete")),
    };
    // Prepare the TAP before telling the client the handshake succeeded:
    // otherwise it would run its up script and black-hole traffic if TAP
    // creation or the up script fails.
    let tap = match take_old_peer(&ctx, cfg.id).await {
        Some(t) => t,
        None => open_tap(&cfg, &addr.to_string()).await?.0,
    };
    stream.write_all(&msg4).await?;
    let (read, write) = stream.into_split();
    ctx.requests
        .send(MainRequest::TcpPeer {
            addr,
            cfg,
            key,
            read,
            write,
            tap,
        })
        .await
        .map_err(|_| anyhow!("server shutting down"))?;
    Ok(())
}

async fn create_tcp_peer(
    ctx: &ServerContext,
    addr: SocketAddr,
    cfg: Arc<PeerConfig>,
    key: [u8; 32],
    read: OwnedReadHalf,
    write: OwnedWriteHalf,
    tap: Arc<Tap>,
) -> Result<()> {
    let stats = LiveStats::new(
        addr.to_string(),
        cfg.id,
        cfg.noise,
        cfg.cpr,
        cfg.encless,
        cfg.mtu,
    );
    ctx.stats.insert(stats.clone());
    let handle = spawn_tcp(
        read,
        write,
        cfg.clone(),
        tap.clone(),
        key,
        false,
        stats.clone(),
    );
    let token = NEXT_PEER_TOKEN.fetch_add(1, AtomicOrdering::Relaxed);
    watch_peer(handle.events, addr, cfg.id, token, ctx.events.clone());
    let entry = Arc::new(PeerEntry {
        token,
        addr,
        id: cfg.id,
        cfg,
        tap,
        stats,
        cancel: handle.cancel,
        inbound: None,
        proto: "tcp",
    });
    ctx.registry.insert(entry.clone());
    #[cfg(feature = "admin")]
    notify_session_started(ctx, &entry);
    eprintln!("peer created: {addr}");
    Ok(())
}

async fn tcp_listener_loop(listener: TcpListener, ctx: ServerContext) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = ctx.tcp_limit.clone().try_acquire_owned() else {
                    #[cfg(feature = "admin")]
                    if let Some(admin) = &ctx.admin {
                        admin
                            .metrics
                            .tcp_connections_rejected
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    eprintln!("tcp connection limit reached, dropping {stream:?}");
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_tcp_conn(stream, ctx.clone()).await {
                        #[cfg(feature = "admin")]
                        if let Some(admin) = &ctx.admin {
                            admin
                                .metrics
                                .handshake_errors
                                .fetch_add(1, AtomicOrdering::Relaxed);
                        }
                        eprintln!("tcp handshake failed: {e:#}");
                    }
                });
            }
            Err(e) => {
                eprintln!("tcp accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn proxy_conn(stream: TcpStream, ctx: ServerContext) -> Result<()> {
    let mut stream = stream;
    let mut hdr = Vec::new();
    let mut b = [0u8; 1024];
    loop {
        let n = stream.read(&mut b).await?;
        if n == 0 {
            return Ok(());
        }
        hdr.extend_from_slice(&b[..n]);
        if hdr.windows(4).any(|w| w == b"\r\n\r\n") || hdr.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if hdr.len() > 8192 {
            return Err(anyhow!("proxy request too large"));
        }
    }
    stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await?;
    handle_tcp_conn(stream, ctx).await
}

async fn proxy_listener_loop(listener: TcpListener, ctx: ServerContext) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = ctx.tcp_limit.clone().try_acquire_owned() else {
                    eprintln!("proxy connection limit reached, dropping {stream:?}");
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = proxy_conn(stream, ctx).await {
                        eprintln!("proxy connection failed: {e:#}");
                    }
                });
            }
            Err(e) => {
                eprintln!("proxy accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn main() {
    let args = parse_args();
    if args.warranty {
        println!("{WARRANTY}");
        return;
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(run(args)) {
        eprintln!("{e:#}");
        process::exit(1);
    }
}

#[cfg(feature = "admin")]
async fn start_admin(
    args: &Args,
    registry: Arc<Registry>,
    configs: ConfigStore,
    requests: mpsc::Sender<MainRequest>,
    reloader: Arc<Reloader>,
) -> Result<Option<Arc<AdminRuntime>>> {
    if args.admin.is_empty() {
        return Ok(None);
    }
    let db_path = PathBuf::from(&args.admin_db);
    let store = match Store::open(&db_path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!("admin disabled: {error}");
            return Ok(None);
        }
    };
    match store.admin_count() {
        Ok(0) => {
            eprintln!(
                "admin disabled: no admin user in {}; run: rustvpn-admin-passwd -db {}",
                db_path.display(),
                db_path.display()
            );
            return Ok(None);
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("admin disabled: {error}");
            return Ok(None);
        }
    }
    let disabled_path = if args.admin_disabled_conf.is_empty() {
        let conf = PathBuf::from(&args.conf);
        conf.parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("peers.disabled.yaml")
    } else {
        PathBuf::from(&args.admin_disabled_conf)
    };
    let backup_dir = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("backups");
    let paths = ConfigPaths {
        enabled: PathBuf::from(&args.conf),
        disabled: disabled_path,
        backup_dir,
    };
    let history = History::spawn(store.clone());
    let events = Arc::new(EventLog::new(2000));
    let metrics = Arc::new(AdminMetrics::default());
    let backend = Arc::new(ServerBackend {
        registry,
        configs,
        requests,
        reloader,
        paths,
        events: events.clone(),
        metrics: metrics.clone(),
        config_write: tokio::sync::Mutex::new(()),
        bind: args.bind.clone(),
        proto: args.proto.clone(),
        admin_addr: args.admin.clone(),
        started_at: SystemTime::now(),
    });
    let options = AdminOptions {
        secure_cookies: args.admin_cookie_secure,
        script_dirs: args.admin_script_dir.iter().map(PathBuf::from).collect(),
    };
    let state = AdminState::new(backend, store, history.clone(), options);
    let listener = TcpListener::bind(&args.admin)
        .await
        .with_context(|| format!("bind admin {}", args.admin))?;
    eprintln!("Listening on admin: {}", args.admin);
    if !is_loopback_bind(&args.admin) {
        eprintln!("warning: admin endpoint is not bound to loopback; use TLS and a firewall");
    }
    tokio::spawn(async move {
        if let Err(error) = rustvpn_admin::serve(listener, state).await {
            eprintln!("admin server failed: {error:#}");
        }
    });
    Ok(Some(Arc::new(AdminRuntime {
        history,
        events,
        metrics,
    })))
}

#[cfg(feature = "admin")]
fn is_loopback_bind(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(addr)
        .trim_start_matches('[')
        .trim_end_matches(']');
    host == "127.0.0.1" || host == "::1" || host == "localhost"
}

async fn run(args: Args) -> Result<()> {
    if args.proto != "udp" && args.proto != "tcp" && args.proto != "all" {
        return Err(anyhow!("Unknown protocol specified"));
    }
    #[cfg(not(feature = "admin"))]
    {
        if !args.admin.is_empty() {
            return Err(anyhow!(
                "admin support is not compiled in; rebuild with --features admin"
            ));
        }
        let _ = (
            &args.admin_db,
            &args.admin_disabled_conf,
            args.admin_cookie_secure,
            &args.admin_script_dir,
        );
    }
    let conf_path = PathBuf::from(&args.conf);
    let set = ConfigSet::from_file(&conf_path)?;
    let configs: ConfigStore = Arc::new(RwLock::new(set));
    let registry = Arc::new(Registry::default());
    let stats = StatsState::new();
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let (requests_tx, mut requests_rx) = mpsc::channel(64);
    let egd = Arc::new(args.egd.clone());
    let initial_bytes = std::fs::read(&conf_path).ok();
    let reloader = Arc::new(Reloader::new(
        conf_path.clone(),
        configs.clone(),
        requests_tx.clone(),
        initial_bytes,
        1,
    ));

    #[cfg(feature = "admin")]
    let admin_runtime = start_admin(
        &args,
        registry.clone(),
        configs.clone(),
        requests_tx.clone(),
        reloader.clone(),
    )
    .await?;

    let ctx = ServerContext {
        registry: registry.clone(),
        configs: configs.clone(),
        stats: stats.clone(),
        events: events_tx,
        requests: requests_tx,
        udp_send: Arc::new(Mutex::new(None)),
        hs_limit: Arc::new(Mutex::new(RateLimiter::new(5.0, 10.0))),
        hs_global: Arc::new(Mutex::new(RateLimiter::new(200.0, 400.0))),
        tcp_limit: Arc::new(Semaphore::new(512)),
        egd: egd.clone(),
        #[cfg(feature = "admin")]
        admin: admin_runtime.clone(),
    };

    if !args.stats.is_empty() {
        let listener = TcpListener::bind(&args.stats).await?;
        let state = stats.clone();
        tokio::spawn(async move { stats_listener(listener, state).await });
    }
    if !args.proxy.is_empty() {
        let listener = TcpListener::bind(&args.proxy).await?;
        let ctx = ctx.clone();
        tokio::spawn(async move { proxy_listener_loop(listener, ctx).await });
    }
    if args.proto == "udp" || args.proto == "all" {
        let socket = Arc::new(UdpSocket::bind(&args.bind).await?);
        let tx = rustvpn_net::udp_batch::spawn_udp_batcher(socket.clone());
        *ctx.udp_send.lock().unwrap() = Some(tx);
        eprintln!("Listening on UDP: {}", args.bind);
        let ctx = ctx.clone();
        tokio::spawn(async move { udp_loop(socket, ctx).await });
    }
    if args.proto == "tcp" || args.proto == "all" {
        let listener = TcpListener::bind(&args.bind).await?;
        eprintln!("Listening on TCP: {}", args.bind);
        let ctx = ctx.clone();
        tokio::spawn(async move { tcp_listener_loop(listener, ctx).await });
    }
    {
        let reloader = reloader.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if let Err(error) = reloader.reload_from_disk().await {
                    eprintln!("config refresh failed: {error:#}");
                }
            }
        });
    }
    eprintln!("Server started");

    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            wait_signal().await;
            shutdown.cancel();
        });
    }

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            ev = events_rx.recv() => {
                let Some((addr, id, token, event)) = ev else { break };
                if let Some(entry) = registry.get(&addr) {
                    if entry.id == id && entry.token == token {
                        end_session(&ctx, entry, end_reason_from_event(event)).await;
                        eprintln!("peer removed ({event:?}): {addr}");
                    }
                }
            }
            req = requests_rx.recv() => {
                match req {
                    Some(MainRequest::TcpPeer { addr, cfg, key, read, write, tap }) => {
                        if let Err(e) =
                            create_tcp_peer(&ctx, addr, cfg, key, read, write, tap).await
                        {
                            eprintln!("peer setup failed: {e:#}");
                        }
                    }
                    Some(MainRequest::ConfigReloaded { fingerprints }) => {
                        let keep: HashMap<[u8; 16], String> = fingerprints.into_iter().collect();
                        for entry in registry.snapshot() {
                            let stale = keep
                                .get(&entry.id)
                                .is_none_or(|fp| *fp != config_fingerprint(&entry.cfg));
                            if stale {
                                let addr = entry.addr;
                                end_session(&ctx, entry, EndReason::ConfigRevoke).await;
                                eprintln!("peer revoked by config reload: {addr}");
                            }
                        }
                    }
                    #[cfg(feature = "admin")]
                    Some(MainRequest::Kick { id, reason, reply }) => {
                        let result = match registry.addr_by_id(&id) {
                            Some(addr) => match registry.get(&addr) {
                                Some(entry) => {
                                    let report = KickReport {
                                        kicked: true,
                                        session_id: entry.token,
                                        addr: entry.addr.to_string(),
                                    };
                                    end_session(&ctx, entry, EndReason::AdminKick).await;
                                    let _ = reason;
                                    Ok(report)
                                }
                                None => Err("peer is not online".to_string()),
                            },
                            None => Err("peer is not online".to_string()),
                        };
                        let _ = reply.send(result);
                    }
                    None => break,
                }
            }
        }
    }

    for entry in registry.snapshot() {
        end_session(&ctx, entry, EndReason::Shutdown).await;
    }
    Ok(())
}

async fn wait_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
