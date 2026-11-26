//! GoVPN 5.7-compatible Rust server.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rand_core::{OsRng, RngCore};
use rustvpn_control::client::ControlClient;
use rustvpn_control::{
    id_hex, mode_name, now_unix, read_frame, rfc3339, write_frame, ConfigReloaded, Counters, Event,
    KickReport, ReloadReport, Request, Response, ServerCounters, ServerStatus, ServerStatusV1,
    SessionEnded, SessionInfo, SessionStarted, PROTOCOL_VERSION,
};
use rustvpn_crypto::egd::EgDRng;
use rustvpn_crypto::xtea::Xtea;
use rustvpn_net::config::{add_time_sync, ConfigSet, PeerConfig, PeerNetwork};
use rustvpn_net::peer::{spawn_tcp, spawn_udp_peer, PeerEvent, WireWriter};
use rustvpn_net::scripts::{call_down, run_script};
use rustvpn_net::stats::{stats_listener, LiveStats, PeerStats, StatsState};
use rustvpn_net::tap::Tap;
use rustvpn_proto::{
    HandshakeConfig, ServerHandshake, ServerOutput, ENCLESS_ENLARGE_SIZE, MTU_MAX,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

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
    control: String,
    control_group: String,
    script_dir: Vec<String>,
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
         \x20 -control string (optional local admin control socket)\n\
         \x20 -control-group string (socket group; default owner-only)\n\
         \x20 -script-dir string (repeatable; restrict up/down paths)\n\
         \x20 -warranty\n\
         \n\
         Subcommand:\n\
         \x20 status [--json] -control PATH\n\
         \x20   Query a running server over its control socket."
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
        control: String::new(),
        control_group: String::new(),
        script_dir: Vec::new(),
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
            "control" => a.control = take("control"),
            "control-group" => a.control_group = take("control-group"),
            "script-dir" => a.script_dir.push(take("script-dir")),
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

/// Normalised difference between two parsed `peers.yaml` configurations.
///
/// Only fingerprints of semantically relevant settings participate, so
/// comments, field order and whitespace never revoke sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReloadPlan {
    added: Vec<([u8; 16], String)>,
    removed: Vec<([u8; 16], String)>,
    /// `(id, name, comma-separated changed fields)`.
    changed: Vec<([u8; 16], String, String)>,
    unchanged: Vec<([u8; 16], String)>,
}

impl ReloadPlan {
    fn is_noop(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    fn revoked_ids(&self) -> HashSet<[u8; 16]> {
        self.removed
            .iter()
            .map(|(id, _)| *id)
            .chain(self.changed.iter().map(|(id, _, _)| *id))
            .collect()
    }

    fn summary(&self) -> String {
        fn names(entries: &[([u8; 16], String)]) -> String {
            if entries.is_empty() {
                return "-".into();
            }
            let mut names: Vec<&str> = entries.iter().map(|(_, name)| name.as_str()).collect();
            names.sort_unstable();
            names.join(",")
        }
        let mut changed: Vec<String> = self
            .changed
            .iter()
            .map(|(_, name, fields)| format!("{name}{{{fields}}}"))
            .collect();
        changed.sort_unstable();
        format!(
            "added={} [{}] removed={} [{}] changed={} [{}] unchanged={} [{}]",
            self.added.len(),
            names(&self.added),
            self.removed.len(),
            names(&self.removed),
            self.changed.len(),
            if changed.is_empty() {
                "-".into()
            } else {
                changed.join(",")
            },
            self.unchanged.len(),
            names(&self.unchanged)
        )
    }
}

fn config_map(set: &ConfigSet) -> BTreeMap<[u8; 16], (String, String)> {
    set.peers
        .iter()
        .map(|peer| {
            (
                peer.id,
                (peer.name.clone(), config_fingerprint(peer.as_ref())),
            )
        })
        .collect()
}

fn plan_reload(previous: &ConfigSet, next: &ConfigSet) -> ReloadPlan {
    let before = config_map(previous);
    let after = config_map(next);
    let before_cfg: HashMap<[u8; 16], &PeerConfig> = previous
        .peers
        .iter()
        .map(|peer| (peer.id, peer.as_ref()))
        .collect();
    let after_cfg: HashMap<[u8; 16], &PeerConfig> = next
        .peers
        .iter()
        .map(|peer| (peer.id, peer.as_ref()))
        .collect();
    let mut plan = ReloadPlan::default();
    for (id, (name, fingerprint)) in &after {
        match before.get(id) {
            None => plan.added.push((*id, name.clone())),
            Some((_, old)) if old != fingerprint => {
                let fields = match (before_cfg.get(id), after_cfg.get(id)) {
                    (Some(old), Some(new)) => config_changed_fields(old, new).join(","),
                    _ => "unknown".into(),
                };
                plan.changed.push((*id, name.clone(), fields));
            }
            Some(_) => plan.unchanged.push((*id, name.clone())),
        }
    }
    for (id, (name, _)) in &before {
        if !after.contains_key(id) {
            plan.removed.push((*id, name.clone()));
        }
    }
    plan
}

/// Field-level explanation for a revoked peer, used in reload logs.
fn config_changed_fields(old: &PeerConfig, new: &PeerConfig) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if old.verifier.long_form().ok() != new.verifier.long_form().ok() {
        fields.push("verifier");
    }
    if old.name != new.name {
        fields.push("name");
    }
    if old.iface != new.iface {
        fields.push("iface");
    }
    if old.mtu != new.mtu {
        fields.push("mtu");
    }
    if old.noise != new.noise {
        fields.push("noise");
    }
    if old.encless != new.encless {
        fields.push("encless");
    }
    if old.cpr != new.cpr {
        fields.push("cpr");
    }
    if old.time_sync != new.time_sync {
        fields.push("timesync");
    }
    if old.timeout != new.timeout {
        fields.push("timeout");
    }
    if old.up != new.up {
        fields.push("up");
    }
    if old.down != new.down {
        fields.push("down");
    }
    if old.keepalive != new.keepalive {
        fields.push("keepalive");
    }
    if old.rekey_time != new.rekey_time {
        fields.push("rekey_time");
    }
    if old.rekey_jitter != new.rekey_jitter {
        fields.push("rekey_jitter");
    }
    if old.network != new.network {
        fields.push("network");
    }
    fields
}

/// Is this snapshot still the live configuration for the same peer id?
///
/// Used before creating/inserting a peer so a snapshot taken during the
/// handshake cannot resurrect a peer after the reload revocation pass.
fn config_is_current(set: &ConfigSet, cfg: &PeerConfig) -> bool {
    set.by_id
        .get(&cfg.id)
        .is_some_and(|current| config_fingerprint(current) == config_fingerprint(cfg))
}

/// Serialises disk reloads from the 60-second poller and the admin service.
struct Reloader {
    path: PathBuf,
    store: ConfigStore,
    requests: mpsc::Sender<MainRequest>,
    script_dirs: Arc<Vec<PathBuf>>,
    events: Mutex<Option<broadcast::Sender<Event>>>,
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
        script_dirs: Arc<Vec<PathBuf>>,
        events: Option<broadcast::Sender<Event>>,
    ) -> Self {
        Self {
            path,
            store,
            requests,
            script_dirs,
            events: Mutex::new(events),
            guard: tokio::sync::Mutex::new(()),
            last_bytes: Mutex::new(initial_bytes),
            generation: AtomicU64::new(generation),
            last_loaded: Mutex::new(Some(SystemTime::now())),
            last_error: Mutex::new(None),
        }
    }

    fn emit_reload(&self, last_error: Option<String>) {
        let generation = self.generation();
        if let Some(tx) = self.events.lock().unwrap().as_ref() {
            let _ = tx.send(Event::ConfigReloaded(ConfigReloaded {
                generation,
                last_error,
            }));
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
                let message = format!("{error:#}");
                *self.last_error.lock().unwrap() = Some(message.clone());
                self.emit_reload(Some(message));
                return Err(error);
            }
        };
        if let Err(error) = validate_script_paths(&set, &self.script_dirs) {
            let message = format!("{error:#}");
            *self.last_error.lock().unwrap() = Some(message.clone());
            self.emit_reload(Some(message));
            return Err(error);
        }
        let previous = self.store.read().await.clone();
        let plan = plan_reload(&previous, &set);
        if plan.is_noop() {
            // Comments, key order or whitespace changed, but the parsed
            // configuration is semantically identical.  Keep the existing
            // store/generation and preserve every session.
            *self.last_bytes.lock().unwrap() = Some(bytes);
            *self.last_loaded.lock().unwrap() = Some(SystemTime::now());
            *self.last_error.lock().unwrap() = None;
            eprintln!(
                "reload: semantic no-op ({} peer(s) unchanged)",
                plan.unchanged.len()
            );
            return Ok(false);
        }
        *self.store.write().await = set;
        *self.last_bytes.lock().unwrap() = Some(bytes);
        self.generation.fetch_add(1, AtomicOrdering::Relaxed);
        *self.last_loaded.lock().unwrap() = Some(SystemTime::now());
        *self.last_error.lock().unwrap() = None;
        self.emit_reload(None);
        let _ = self
            .requests
            .send(MainRequest::ConfigReloaded { plan })
            .await;
        Ok(true)
    }

    fn generation(&self) -> u64 {
        self.generation.load(AtomicOrdering::Relaxed)
    }

    fn last_loaded(&self) -> Option<SystemTime> {
        *self.last_loaded.lock().unwrap()
    }

    fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct ServerMetrics {
    handshake_requests: AtomicU64,
    handshake_rate_limited: AtomicU64,
    handshake_errors: AtomicU64,
    tcp_connections_rejected: AtomicU64,
    sessions_started: AtomicU64,
    sessions_finished: AtomicU64,
    events_dropped: AtomicU64,
}

impl ServerMetrics {
    fn snapshot(&self) -> ServerCounters {
        ServerCounters {
            handshake_requests: self.handshake_requests.load(AtomicOrdering::Relaxed),
            handshake_rate_limited: self.handshake_rate_limited.load(AtomicOrdering::Relaxed),
            handshake_errors: self.handshake_errors.load(AtomicOrdering::Relaxed),
            tcp_connections_rejected: self.tcp_connections_rejected.load(AtomicOrdering::Relaxed),
            sessions_started: self.sessions_started.load(AtomicOrdering::Relaxed),
            sessions_finished: self.sessions_finished.load(AtomicOrdering::Relaxed),
            events_dropped: self.events_dropped.load(AtomicOrdering::Relaxed),
        }
    }
}

const RECENT_SESSIONS_CAPACITY: usize = 1024;

/// In-process event hub for the optional control socket.  It keeps a bounded
/// ring of recent session ends so an admin daemon that reconnects can
/// reconcile sessions it missed while it was down.
struct ControlRuntime {
    events: broadcast::Sender<Event>,
    recent: Mutex<VecDeque<SessionEnded>>,
}

impl ControlRuntime {
    fn new() -> Arc<Self> {
        let (events, _) = broadcast::channel(256);
        Arc::new(Self {
            events,
            recent: Mutex::new(VecDeque::with_capacity(RECENT_SESSIONS_CAPACITY)),
        })
    }

    fn sender(&self) -> broadcast::Sender<Event> {
        self.events.clone()
    }

    fn session_started(&self, started: SessionStarted) {
        let _ = self.events.send(Event::SessionStarted(started));
    }

    fn session_ended(&self, ended: SessionEnded) {
        {
            let mut recent = self.recent.lock().unwrap();
            if recent.len() >= RECENT_SESSIONS_CAPACITY {
                recent.pop_front();
            }
            recent.push_back(ended.clone());
        }
        let _ = self.events.send(Event::SessionEnded(ended));
    }

    fn recent(&self, limit: usize) -> Vec<SessionEnded> {
        let recent = self.recent.lock().unwrap();
        let skip = recent.len().saturating_sub(limit);
        recent.iter().skip(skip).cloned().collect()
    }

    fn shutdown(&self) {
        let _ = self.events.send(Event::ServerShutdown);
    }
}

/// When `script_dirs` is non-empty, every configured `up`/`down` path must:
/// - resolve under one of those directories,
/// - be a regular file,
/// - not be writable by group or others,
/// - be owned by root or by the server's own effective uid.
///
/// This closes the escalation path where a non-privileged admin process can
/// write `peers.yaml` and point it at a script it controls.
fn validate_proposed_config(enabled_yaml: &str, script_dirs: &[PathBuf]) -> Result<()> {
    let set = ConfigSet::from_str(enabled_yaml).context("parse proposed peers.yaml")?;
    validate_script_paths(&set, script_dirs)
}

fn validate_control_configuration(control: &str, script_dirs: &[PathBuf]) -> Result<()> {
    if !control.is_empty() && script_dirs.is_empty() {
        bail!(
            "-control requires at least one -script-dir; refusing to expose admin control without a script allow-list"
        );
    }
    Ok(())
}

fn validate_script_paths(set: &ConfigSet, script_dirs: &[PathBuf]) -> Result<()> {
    if script_dirs.is_empty() {
        return Ok(());
    }
    let allowed: Vec<PathBuf> = script_dirs
        .iter()
        .map(|dir| {
            dir.canonicalize()
                .with_context(|| format!("resolve script dir {}", dir.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let server_uid = server_euid();
    for dir in &allowed {
        validate_dir_safe("script", dir, server_uid)?;
    }
    for peer in &set.peers {
        for (label, script) in [("up", &peer.up), ("down", &peer.down)] {
            if script.is_empty() {
                continue;
            }
            validate_script_path(label, Path::new(script), &allowed, server_uid)?;
        }
    }
    Ok(())
}

/// Effective uid of the server process.  Reading `/proc/self/status` avoids
/// an unsafe libc call in the main (non-FFI) module.
fn server_euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    let mut fields = line.split_whitespace();
    fields.next()?; // "Uid:"
    fields.next()?; // real uid
    fields.next()?.parse().ok() // effective uid
}

/// Directories on the script path must not be writable by the admin group:
/// otherwise rename(2) can replace a root-owned script after the config has
/// been accepted, and the next up/down call would execute the replacement.
fn validate_dir_safe(label: &str, dir: &Path, server_uid: Option<u32>) -> Result<()> {
    let metadata = std::fs::metadata(dir)
        .with_context(|| format!("stat {label} directory {}", dir.display()))?;
    if !metadata.is_dir() {
        bail!("{label} directory {} is not a directory", dir.display());
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "{label} directory {} is writable by group or others",
            dir.display()
        );
    }
    if metadata.uid() != 0 && Some(metadata.uid()) != server_uid {
        bail!(
            "{label} directory {} is not owned by root or the server user",
            dir.display()
        );
    }
    Ok(())
}

fn validate_script_path(
    label: &str,
    path: &Path,
    allowed: &[PathBuf],
    server_uid: Option<u32>,
) -> Result<()> {
    if allowed.is_empty() {
        return Ok(());
    }
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve {label} script {}", path.display()))?;
    let Some(allowed_dir) = allowed.iter().find(|dir| canonical.starts_with(dir)) else {
        bail!(
            "{label} script {} is outside the allowed -script-dir list",
            path.display()
        );
    };
    let metadata = std::fs::metadata(&canonical)
        .with_context(|| format!("stat {label} script {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} script {} is not a regular file", path.display());
    }
    // Validate every directory from the allowed root down to the script's
    // parent; a writable intermediate directory allows admin-group rename.
    let mut cursor = canonical.parent();
    while let Some(dir) = cursor {
        validate_dir_safe(label, dir, server_uid)?;
        if dir == allowed_dir.as_path() {
            break;
        }
        cursor = dir.parent();
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "{label} script {} is writable by group or others",
            path.display()
        );
    }
    if metadata.uid() != 0 && Some(metadata.uid()) != server_uid {
        bail!(
            "{label} script {} is not owned by root or the server user",
            path.display()
        );
    }
    Ok(())
}

struct AppliedNetwork {
    fingerprint: String,
    guard: rustvpn_net::network::TapGuard,
}

#[derive(Clone)]
struct ServerContext {
    registry: Arc<Registry>,
    network_guards: Arc<tokio::sync::Mutex<HashMap<String, AppliedNetwork>>>,
    configs: ConfigStore,
    stats: Arc<StatsState>,
    events: mpsc::Sender<(SocketAddr, [u8; 16], u64, PeerEvent)>,
    requests: mpsc::Sender<MainRequest>,
    udp_send: Arc<Mutex<Option<rustvpn_net::udp_batch::UdpBatchSender>>>,
    hs_limit: Arc<Mutex<RateLimiter>>,
    hs_global: Arc<Mutex<RateLimiter>>,
    tcp_limit: Arc<Semaphore>,
    egd: Arc<String>,
    reloader: Arc<Reloader>,
    metrics: Arc<ServerMetrics>,
    control: Option<Arc<ControlRuntime>>,
    script_dirs: Arc<Vec<PathBuf>>,
    server_uid: Option<u32>,
    instance: u64,
    bind: String,
    proto: String,
    started_at: Instant,
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
        plan: ReloadPlan,
    },
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
    Rekey,
    TcpClosed,
    TapClosed,
    Replaced,
    ConfigRevoke,
    Shutdown,
    AdminKick,
}

impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            EndReason::Timeout => "timeout",
            EndReason::Rehandshake => "rehandshake",
            EndReason::Rekey => "rekey",
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
        PeerEvent::Rekey => EndReason::Rekey,
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
    let snapshot = entry.stats.snapshot();
    ctx.stats.remove(&entry.stats.addr);
    ctx.metrics
        .sessions_finished
        .fetch_add(1, AtomicOrdering::Relaxed);
    if let Some(control) = &ctx.control {
        control.session_ended(SessionEnded {
            session_id: entry.token,
            peer_id: id_hex(&entry.id),
            name: entry.cfg.name.clone(),
            addr: entry.addr.to_string(),
            ended_at: now_unix(),
            reason: reason.as_str().to_string(),
            counters: counters_from(&snapshot),
        });
    }
    if !matches!(reason, EndReason::Replaced) {
        call_down_checked(ctx, &entry.cfg, entry.tap.name(), &entry.addr.to_string()).await;
    }
}

fn notify_session_started(ctx: &ServerContext, entry: &PeerEntry) {
    let stats = entry.stats.snapshot();
    ctx.metrics
        .sessions_started
        .fetch_add(1, AtomicOrdering::Relaxed);
    if let Some(control) = &ctx.control {
        control.session_started(SessionStarted {
            session_id: entry.token,
            peer_id: id_hex(&entry.id),
            name: entry.cfg.name.clone(),
            addr: entry.addr.to_string(),
            proto: entry.proto.to_string(),
            mode: mode_name(entry.cfg.noise, entry.cfg.encless).to_string(),
            mtu: entry.cfg.mtu,
            started_at: stats.established.timestamp(),
            counters: counters_from(&stats),
        });
    }
}

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
async fn run_up_checked(
    ctx: &ServerContext,
    cfg: &PeerConfig,
    remote: &str,
) -> Result<Option<String>> {
    if cfg.up.is_empty() {
        return Ok(None);
    }
    validate_script_path("up", Path::new(&cfg.up), &ctx.script_dirs, ctx.server_uid)?;
    run_script(&cfg.up, &cfg.iface, remote).await
}

async fn call_down_checked(ctx: &ServerContext, cfg: &PeerConfig, iface: &str, remote: &str) {
    if cfg.down.is_empty() {
        return;
    }
    if let Err(error) = validate_script_path(
        "down",
        Path::new(&cfg.down),
        &ctx.script_dirs,
        ctx.server_uid,
    ) {
        eprintln!("down script rejected: {error:#}");
        return;
    }
    call_down(&cfg.down, iface, remote).await;
}

async fn open_tap(
    ctx: &ServerContext,
    cfg: &PeerConfig,
    remote: &str,
) -> Result<(Arc<Tap>, String)> {
    let mut iface = cfg.iface.clone();
    if !cfg.up.is_empty() {
        if let Some(out) = run_up_checked(ctx, cfg, remote).await? {
            if cfg.iface.is_empty() {
                iface = out.lines().next().unwrap_or("").trim().to_string();
            }
        }
    }
    if iface.is_empty() {
        return Err(anyhow!("empty interface name"));
    }

    let Some(network) = &cfg.network else {
        // GoVPN-compatible path: up script (if any) owns TAP/routing.
        return Ok((Arc::new(Tap::open(&iface, cfg.mtu)?), iface));
    };

    // Declarative path: create/configure the TAP without a script.  A guard
    // is shared per interface so repeated handshakes with the same config are
    // no-ops and a config change tears down only the old declarative state.
    let fingerprint = declarative_network_fingerprint(cfg, network);
    let mut guards = ctx.network_guards.lock().await;
    let needs_apply = declarative_reapply_needed(
        guards
            .get(&iface)
            .map(|applied| applied.fingerprint.as_str()),
        &fingerprint,
    );
    if needs_apply {
        if let Some(old) = guards.remove(&iface) {
            old.guard.remove().await;
        }
        let inner_ip_mtu = cfg.inner_ip_mtu();
        eprintln!(
            "declarative network: wire_mtu={} mode={} -> inner_ip_mtu={} mss_v4={} mss_v6={} on {iface}",
            cfg.mtu,
            cfg.mode_label(),
            inner_ip_mtu,
            cfg.mss_v4(),
            cfg.mss_v6()
        );
        let guard = rustvpn_net::network::configure_tap(&iface, inner_ip_mtu, network).await?;
        let tap = match Tap::open(&iface, cfg.mtu) {
            Ok(tap) => Arc::new(tap),
            Err(error) => {
                guard.remove().await;
                return Err(error.into());
            }
        };
        guards.insert(iface.clone(), AppliedNetwork { fingerprint, guard });
        eprintln!("declarative network configured on {iface}");
        Ok((tap, iface))
    } else {
        Ok((Arc::new(Tap::open(&iface, cfg.mtu)?), iface))
    }
}

/// Fingerprint of all declarative TAP state that must be reapplied.
///
/// The wire MTU alone is not enough: the TAP IP MTU is derived from the
/// *mode* (`Mode::max_payload(wire_mtu) - 14`), so a plain→noise reload with
/// the same wire MTU must still reconfigure the TAP (1500 → 1476).
fn declarative_network_fingerprint(cfg: &PeerConfig, network: &PeerNetwork) -> String {
    format!(
        "wire_mtu={}|mode={}|inner_ip_mtu={}|{}",
        cfg.mtu,
        cfg.mode_label(),
        cfg.inner_ip_mtu(),
        network.fingerprint()
    )
}

/// True when the applied fingerprint differs from the current one.
fn declarative_reapply_needed(applied: Option<&str>, current: &str) -> bool {
    applied != Some(current)
}

/// Whether the applied declarative guard no longer matches `cfg`.
async fn declarative_needs_reapply(ctx: &ServerContext, cfg: &PeerConfig, iface: &str) -> bool {
    let Some(network) = &cfg.network else {
        return false;
    };
    let fingerprint = declarative_network_fingerprint(cfg, network);
    let guards = ctx.network_guards.lock().await;
    declarative_reapply_needed(
        guards
            .get(iface)
            .map(|applied| applied.fingerprint.as_str()),
        &fingerprint,
    )
}

/// Acquire the TAP for a peer, reusing an existing one only when its
/// declarative state (including the mode-derived MTU) still matches.
async fn peer_tap(ctx: &ServerContext, cfg: &PeerConfig, remote: &str) -> Result<Arc<Tap>> {
    match take_old_peer(ctx, cfg.id).await {
        Some(tap) => {
            if declarative_needs_reapply(ctx, cfg, tap.name()).await {
                // The old TAP would keep a stale IP MTU; rebuild it before the
                // new session starts.
                drop(tap);
                open_tap(ctx, cfg, remote).await.map(|(tap, _)| tap)
            } else {
                Ok(tap)
            }
        }
        None => open_tap(ctx, cfg, remote).await.map(|(tap, _)| tap),
    }
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
    // Close the reload race: the handshake may have started before a config
    // change revoked this peer.
    if !config_is_current(&*ctx.configs.read().await, &cfg) {
        bail!("configuration changed during handshake; refusing to create peer");
    }
    let tap = peer_tap(ctx, &cfg, &addr.to_string()).await?;
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
    // This runs in a spawned task, so unlike the TCP path it is NOT
    // serialised with the main task's reload revocation pass.  Publish the
    // entry and then re-validate it; a reload that lands between the check
    // above and the insert would otherwise miss (and leak) this stale peer.
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
    publish_peer_checked(ctx, entry).await
}

/// Publish a peer and then verify it against the live configuration.
///
/// If a reload revoked/changed the snapshot while this task was setting up,
/// remove the just-published session, tear down declarative state created for
/// that stale config, and fail so the caller does not send a success reply.
async fn publish_peer_checked(ctx: &ServerContext, entry: Arc<PeerEntry>) -> Result<()> {
    // Publish the start event before the registry entry becomes visible:
    // any subsequent end (kick/timeout/reload) can only happen after the
    // insert, so subscribers observe start before end.
    notify_session_started(ctx, &entry);
    ctx.registry.insert(entry.clone());
    if config_is_current(&*ctx.configs.read().await, &entry.cfg) {
        return Ok(());
    }
    // A reload raced the insert.  The main task's revocation pass may already
    // have removed the entry; `end_session` only acts on a still-present
    // registry entry, so this is idempotent in that case.
    eprintln!(
        "reload: peer {} published after a config change; revoking ({})",
        entry.cfg.name, entry.addr
    );
    end_session(ctx, entry.clone(), EndReason::ConfigRevoke).await;
    cleanup_stale_declarative_guard(ctx, &entry).await;
    bail!("configuration changed while publishing the peer; session revoked");
}

/// Remove the declarative guard for this session's TAP only when it still
/// matches this (stale) config.  A newer valid session may already own a
/// different guard on the same interface; it must not be disturbed.
async fn cleanup_stale_declarative_guard(ctx: &ServerContext, entry: &PeerEntry) {
    let Some(network) = &entry.cfg.network else {
        return;
    };
    let fingerprint = declarative_network_fingerprint(&entry.cfg, network);
    let guard = {
        let mut guards = ctx.network_guards.lock().await;
        take_matching_guard(&mut guards, entry.tap.name(), &fingerprint)
    };
    if let Some(guard) = guard {
        guard.remove().await;
    }
}

/// Take an applied guard only if its fingerprint matches exactly.
fn take_matching_guard(
    guards: &mut HashMap<String, AppliedNetwork>,
    iface: &str,
    fingerprint: &str,
) -> Option<rustvpn_net::network::TapGuard> {
    let matches = guard_fingerprint_matches(
        guards
            .get(iface)
            .map(|applied| applied.fingerprint.as_str()),
        fingerprint,
    );
    if matches {
        guards.remove(iface).map(|applied| applied.guard)
    } else {
        None
    }
}

fn guard_fingerprint_matches(applied: Option<&str>, expected: &str) -> bool {
    applied == Some(expected)
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
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        cfg.verifier.long_form().unwrap_or_default(),
        cfg.name,
        cfg.iface,
        cfg.mtu,
        cfg.noise,
        cfg.encless,
        cfg.cpr,
        cfg.time_sync,
        cfg.timeout.as_secs(),
        cfg.up,
        cfg.down,
        cfg.keepalive.as_secs(),
        cfg.rekey_time.as_secs(),
        cfg.rekey_jitter.as_secs()
    ) + &format!(
        "|network={}",
        cfg.network
            .as_ref()
            .map(|network| network.fingerprint())
            .unwrap_or_else(|| "-".into())
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
                ctx.metrics
                    .handshake_errors
                    .fetch_add(1, AtomicOrdering::Relaxed);
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
    ctx.metrics
        .handshake_requests
        .fetch_add(1, AtomicOrdering::Relaxed);
    if handshakes.len() >= 4096 {
        return;
    }
    if handshakes.keys().filter(|a| a.ip() == addr.ip()).count() >= 16 {
        return;
    }
    let ip = addr.ip();
    if !ctx.hs_limit.lock().unwrap().allow(ip) || !ctx.hs_global.lock().unwrap().allow_global() {
        ctx.metrics
            .handshake_rate_limited
            .fetch_add(1, AtomicOrdering::Relaxed);
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
            ctx.metrics
                .handshake_errors
                .fetch_add(1, AtomicOrdering::Relaxed);
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
    if !config_is_current(&*ctx.configs.read().await, &cfg) {
        return Err(anyhow!(
            "configuration changed during handshake; refusing to create peer"
        ));
    }
    // Prepare the TAP before telling the client the handshake succeeded:
    // otherwise it would run its up script and black-hole traffic if TAP
    // creation or the up script fails.
    let tap = peer_tap(&ctx, &cfg, &addr.to_string()).await?;
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
    if !config_is_current(&*ctx.configs.read().await, &cfg) {
        bail!("configuration changed during handshake; refusing to create peer");
    }
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
    // Publish the start event before the registry entry becomes visible:
    // any subsequent end (kick/timeout/reload) can only happen after the
    // insert, so subscribers observe start before end.
    notify_session_started(ctx, &entry);
    ctx.registry.insert(entry.clone());
    eprintln!("peer created: {addr}");
    Ok(())
}

async fn tcp_listener_loop(listener: TcpListener, ctx: ServerContext) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = ctx.tcp_limit.clone().try_acquire_owned() else {
                    ctx.metrics
                        .tcp_connections_rejected
                        .fetch_add(1, AtomicOrdering::Relaxed);
                    eprintln!("tcp connection limit reached, dropping {stream:?}");
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_tcp_conn(stream, ctx.clone()).await {
                        ctx.metrics
                            .handshake_errors
                            .fetch_add(1, AtomicOrdering::Relaxed);
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

struct StatusArgs {
    json: bool,
    control: Option<PathBuf>,
}

fn status_usage() -> ! {
    eprintln!(
        "Usage of rustvpn-server status:\n\
         \x20 -control PATH     Server control socket (or RUSTVPN_CONTROL_SOCKET)\n\
         \x20 --json            Print the stable rustvpn.status.v1 document\n\
         \x20 --help            Show this help"
    );
    process::exit(2);
}

fn parse_status_args() -> StatusArgs {
    let mut args = StatusArgs {
        json: false,
        control: std::env::var_os("RUSTVPN_CONTROL_SOCKET").map(PathBuf::from),
    };
    let mut it = std::env::args().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" | "-json" | "-j" => args.json = true,
            "--control" | "-control" => {
                let Some(path) = it.next() else {
                    eprintln!("-control needs an argument");
                    status_usage();
                };
                args.control = Some(PathBuf::from(path));
            }
            "--help" | "-h" | "-help" => status_usage(),
            other => {
                eprintln!("unexpected status argument: {other}");
                status_usage();
            }
        }
    }
    args
}

fn print_server_status_json(document: &ServerStatusV1) {
    match serde_json::to_string_pretty(document) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("serialize status: {error}"),
    }
}

fn server_status_command() -> ! {
    let args = parse_status_args();
    let Some(control) = args.control else {
        eprintln!("-control PATH is required for `rustvpn-server status`");
        process::exit(2);
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(error) => {
            eprintln!("runtime: {error}");
            process::exit(1);
        }
    };
    let exit = rt.block_on(async {
        match tokio::time::timeout(Duration::from_secs(3), ControlClient::connect(&control)).await {
            Ok(Ok(mut client)) => {
                let status = match client.status().await {
                    Ok(status) => status,
                    Err(error) => {
                        eprintln!("status request failed: {error}");
                        return 1;
                    }
                };
                let sessions = match client.sessions().await {
                    Ok(sessions) => sessions,
                    Err(error) => {
                        eprintln!("sessions request failed: {error}");
                        Vec::new()
                    }
                };
                let document = ServerStatusV1::from_parts(&status, &sessions);
                if args.json {
                    match serde_json::to_string_pretty(&document) {
                        Ok(text) => println!("{text}"),
                        Err(error) => {
                            eprintln!("serialize status: {error}");
                            return 1;
                        }
                    }
                } else {
                    println!("state:      running");
                    println!("version:    {}", status.server_version);
                    println!("bind:       {} ({})", status.bind, status.proto);
                    println!("uptime:     {}s", status.uptime_seconds);
                    println!(
                        "sessions:   {} active / {} configured",
                        status.active_sessions, status.configured_peers
                    );
                    println!(
                        "traffic:    tx={} rx={}",
                        document.tx_bytes, document.rx_bytes
                    );
                    println!(
                        "heartbeat:  sent={} recv={}",
                        document.heartbeat_sent, document.heartbeat_recv
                    );
                    println!(
                        "frames:     unauth={} dup={}",
                        document.frames_unauth, document.frames_dup
                    );
                }
                0
            }
            Ok(Err(error)) => {
                if args.json {
                    let document = ServerStatusV1::unavailable("", error.to_string());
                    print_server_status_json(&document);
                } else {
                    eprintln!("connect control socket {}: {error}", control.display());
                }
                1
            }
            Err(_) => {
                if args.json {
                    let document = ServerStatusV1::unavailable("", "control socket timed out");
                    print_server_status_json(&document);
                } else {
                    eprintln!("connect control socket {}: timed out", control.display());
                }
                1
            }
        }
    });
    process::exit(exit);
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("status") {
        server_status_command();
    }
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

fn random_token_base() -> u64 {
    let mut rng = OsRng;
    let value = rng.next_u64() & ((1u64 << 52) - 1);
    if value == 0 {
        1
    } else {
        value
    }
}

async fn run(args: Args) -> Result<()> {
    if args.proto != "udp" && args.proto != "tcp" && args.proto != "all" {
        return Err(anyhow!("Unknown protocol specified"));
    }
    let conf_path = PathBuf::from(&args.conf);
    let set = ConfigSet::from_file(&conf_path)?;
    let script_dirs: Arc<Vec<PathBuf>> =
        Arc::new(args.script_dir.iter().map(PathBuf::from).collect());
    validate_control_configuration(&args.control, &script_dirs)?;
    validate_script_paths(&set, &script_dirs)?;
    let server_uid = server_euid();

    // Session identifiers must not collide across server restarts: the admin
    // history database keys sessions by this value.  A 52-bit base keeps the
    // SQLite key positive (i64) and avoids JavaScript Number precision loss
    // for any API consumer that treats session ids as numbers.
    let instance = random_token_base();
    NEXT_PEER_TOKEN.store(instance, AtomicOrdering::Relaxed);
    let metrics = Arc::new(ServerMetrics::default());
    let control = if args.control.is_empty() {
        None
    } else {
        Some(ControlRuntime::new())
    };

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
        script_dirs.clone(),
        control.as_ref().map(|runtime| runtime.sender()),
    ));

    let ctx = ServerContext {
        registry: registry.clone(),
        network_guards: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        configs: configs.clone(),
        stats: stats.clone(),
        events: events_tx,
        requests: requests_tx,
        udp_send: Arc::new(Mutex::new(None)),
        hs_limit: Arc::new(Mutex::new(RateLimiter::new(5.0, 10.0))),
        hs_global: Arc::new(Mutex::new(RateLimiter::new(200.0, 400.0))),
        tcp_limit: Arc::new(Semaphore::new(512)),
        egd: egd.clone(),
        reloader: reloader.clone(),
        metrics: metrics.clone(),
        control: control.clone(),
        script_dirs: script_dirs.clone(),
        server_uid,
        instance,
        bind: args.bind.clone(),
        proto: args.proto.clone(),
        started_at: Instant::now(),
    };

    if !args.control.is_empty() {
        start_control(&args.control, &args.control_group, ctx.clone()).await?;
    }

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
                    Some(MainRequest::ConfigReloaded { plan }) => {
                        let revoked = plan.revoked_ids();
                        let summary = plan.summary();
                        let changed_fields: HashMap<[u8; 16], String> = plan
                            .changed
                            .iter()
                            .map(|(id, _, fields)| (*id, fields.clone()))
                            .collect();
                        let removed: HashSet<[u8; 16]> =
                            plan.removed.iter().map(|(id, _)| *id).collect();
                        let mut revoked_count = 0usize;
                        for entry in registry.snapshot() {
                            if revoked.contains(&entry.id) {
                                let addr = entry.addr;
                                let name = entry.cfg.name.clone();
                                let reason = if let Some(fields) = changed_fields.get(&entry.id) {
                                    format!("changed fields: {fields}")
                                } else if removed.contains(&entry.id) {
                                    "removed from peers.yaml".to_string()
                                } else {
                                    "changed/removed".to_string()
                                };
                                end_session(&ctx, entry, EndReason::ConfigRevoke).await;
                                revoked_count += 1;
                                eprintln!(
                                    "reload: peer {name} {reason}, session revoked ({addr})"
                                );
                            }
                        }
                        eprintln!("reload: {summary}; revoked {revoked_count} active session(s)");
                    }
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
    // Let cancelled peer tasks drop their TAP handles before deleting a
    // declarative device.
    tokio::time::sleep(Duration::from_millis(25)).await;
    // Undo only the declarative network state created above; script-managed
    // TAPs are intentionally left to their down scripts.
    let guards: Vec<rustvpn_net::network::TapGuard> = {
        let mut applied = ctx.network_guards.lock().await;
        applied.drain().map(|(_, entry)| entry.guard).collect()
    };
    for guard in guards {
        guard.remove().await;
    }
    if let Some(control) = &ctx.control {
        control.shutdown();
    }
    Ok(())
}

async fn start_control(path: &str, group: &str, ctx: ServerContext) -> Result<()> {
    let socket_path = Path::new(path);
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            bail!(
                "control socket directory {} does not exist",
                parent.display()
            );
        }
    }
    match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!(
                    "control path {} exists and is not a socket",
                    socket_path.display()
                );
            }
            match UnixStream::connect(socket_path).await {
                Ok(_) => bail!("control socket {} is already in use", socket_path.display()),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(socket_path).with_context(|| {
                        format!("remove stale control socket {}", socket_path.display())
                    })?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("probe control socket {}", socket_path.display()))
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect control socket {}", socket_path.display()))
        }
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind control socket {}", socket_path.display()))?;
    let gid = if group.is_empty() {
        None
    } else {
        Some(resolve_gid(group)?)
    };
    let mode = if gid.is_some() { 0o660 } else { 0o600 };
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod control socket {}", socket_path.display()))?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(socket_path, None, Some(gid))
            .with_context(|| format!("chown control socket {}", socket_path.display()))?;
    }
    eprintln!(
        "Listening on control: {} (mode {:o}{})",
        socket_path.display(),
        mode,
        if gid.is_some() {
            ", group-restricted"
        } else {
            ""
        }
    );
    tokio::spawn(async move {
        control_accept_loop(listener, ctx, gid).await;
    });
    Ok(())
}

fn resolve_gid(name: &str) -> Result<u32> {
    // Local groups only; keep this dependency-free and free of unsafe libc
    // calls.  NSS/LDAP-only groups can use the numeric form if needed.
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    let groups = std::fs::read_to_string("/etc/group")
        .with_context(|| "read /etc/group to resolve -control-group")?;
    for line in groups.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            let _password = fields.next();
            if let Some(gid) = fields.next() {
                return gid
                    .parse()
                    .with_context(|| format!("invalid gid for group {name}"));
            }
        }
    }
    bail!("control group {name} not found in /etc/group")
}

fn control_peer_allowed(stream: &UnixStream, gid: Option<u32>) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    if cred.uid() == 0 {
        return true;
    }
    match gid {
        Some(gid) => cred.gid() == gid,
        None => server_euid().is_some_and(|uid| cred.uid() == uid),
    }
}

async fn control_accept_loop(listener: UnixListener, ctx: ServerContext, gid: Option<u32>) {
    let limit = Arc::new(Semaphore::new(8));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if !control_peer_allowed(&stream, gid) {
                    eprintln!("control: rejected unauthorized peer");
                    continue;
                }
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    eprintln!("control: too many connections, dropping client");
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_control_connection(stream, ctx).await {
                        eprintln!("control client failed: {error:#}");
                    }
                });
            }
            Err(error) => {
                eprintln!("control accept failed: {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_control_connection(mut stream: UnixStream, ctx: ServerContext) -> Result<()> {
    let Some(hello) = read_frame::<_, Request>(&mut stream).await? else {
        return Ok(());
    };
    match hello {
        Request::Hello { version } if version == PROTOCOL_VERSION => {
            write_frame(
                &mut stream,
                &Response::Hello {
                    version: PROTOCOL_VERSION,
                    server_version: env!("CARGO_PKG_VERSION").to_string(),
                    server_instance: ctx.instance,
                },
            )
            .await?;
        }
        Request::Hello { version } => {
            let _ = write_frame(
                &mut stream,
                &Response::Error {
                    message: format!(
                        "control protocol mismatch: client v{version}, server v{PROTOCOL_VERSION}"
                    ),
                },
            )
            .await;
            return Ok(());
        }
        _ => {
            let _ = write_frame(
                &mut stream,
                &Response::Error {
                    message: "control handshake required".to_string(),
                },
            )
            .await;
            return Ok(());
        }
    }

    loop {
        let Some(request) = read_frame::<_, Request>(&mut stream).await? else {
            return Ok(());
        };
        match request {
            Request::Hello { .. } => {
                write_frame(
                    &mut stream,
                    &Response::Error {
                        message: "control session already initialized".to_string(),
                    },
                )
                .await?;
            }
            Request::Status => {
                write_frame(
                    &mut stream,
                    &Response::Status {
                        status: control_status(&ctx).await,
                    },
                )
                .await?;
            }
            Request::Sessions => {
                write_frame(
                    &mut stream,
                    &Response::Sessions {
                        sessions: control_sessions(&ctx),
                    },
                )
                .await?;
            }
            Request::Kick { id, reason } => {
                let response = match control_kick(&ctx, &id, &reason).await {
                    Ok(report) => Response::Kick { report },
                    Err(message) => Response::Error { message },
                };
                write_frame(&mut stream, &response).await?;
            }
            Request::Reload => {
                let response = match ctx.reloader.reload_from_disk().await {
                    Ok(applied) => Response::Reload {
                        report: ReloadReport {
                            applied,
                            generation: ctx.reloader.generation(),
                        },
                    },
                    Err(error) => Response::Error {
                        message: format!("{error:#}"),
                    },
                };
                write_frame(&mut stream, &response).await?;
            }
            Request::RecentSessions { limit } => {
                let limit = (limit as usize).clamp(1, RECENT_SESSIONS_CAPACITY);
                let sessions = ctx
                    .control
                    .as_ref()
                    .map(|control| control.recent(limit))
                    .unwrap_or_default();
                write_frame(&mut stream, &Response::RecentSessions { sessions }).await?;
            }
            Request::ValidateConfig { enabled_yaml } => {
                let response = match validate_proposed_config(&enabled_yaml, &ctx.script_dirs) {
                    Ok(()) => Response::ConfigValidation {
                        valid: true,
                        errors: Vec::new(),
                    },
                    Err(error) => Response::ConfigValidation {
                        valid: false,
                        errors: vec![format!("{error:#}")],
                    },
                };
                write_frame(&mut stream, &response).await?;
            }
            Request::Subscribe => {
                let Some(control) = &ctx.control else {
                    write_frame(
                        &mut stream,
                        &Response::Error {
                            message: "control plane is not available".to_string(),
                        },
                    )
                    .await?;
                    return Ok(());
                };
                let mut events = control.events.subscribe();
                write_frame(&mut stream, &Response::Subscribed).await?;
                loop {
                    match events.recv().await {
                        Ok(event) => {
                            if write_frame(&mut stream, &event).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            let event = Event::Lagged { missed };
                            if write_frame(&mut stream, &event).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                }
            }
        }
    }
}

async fn control_status(ctx: &ServerContext) -> ServerStatus {
    let configured_peers = ctx.configs.read().await.peers.len();
    let last_loaded = ctx
        .reloader
        .last_loaded()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| rfc3339(elapsed.as_secs() as i64));
    ServerStatus {
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        server_instance: ctx.instance,
        uptime_seconds: ctx.started_at.elapsed().as_secs(),
        bind: ctx.bind.clone(),
        proto: ctx.proto.clone(),
        active_sessions: ctx.registry.snapshot().len(),
        configured_peers,
        config_generation: ctx.reloader.generation(),
        config_last_loaded_at: last_loaded,
        config_last_error: ctx.reloader.last_error(),
        counters: ctx.metrics.snapshot(),
    }
}

fn control_sessions(ctx: &ServerContext) -> Vec<SessionInfo> {
    ctx.registry
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
            }
        })
        .collect()
}

async fn control_kick(ctx: &ServerContext, id: &str, reason: &str) -> Result<KickReport, String> {
    let bytes = hex::decode(id).map_err(|_| "peer id must be 32 hex characters".to_string())?;
    if bytes.len() != 16 {
        return Err("peer id must be 32 hex characters".to_string());
    }
    let mut peer_id = [0u8; 16];
    peer_id.copy_from_slice(&bytes);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    ctx.requests
        .send(MainRequest::Kick {
            id: peer_id,
            reason: reason.to_string(),
            reply: reply_tx,
        })
        .await
        .map_err(|_| "server is shutting down".to_string())?;
    match tokio::time::timeout(Duration::from_secs(5), reply_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("kick request was cancelled".to_string()),
        Err(_) => Err("kick request timed out".to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, mode: u32) -> PathBuf {
        let path = dir.join("hook.sh");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn secure_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn accepts_script_in_allowed_directory() {
        let dir = secure_dir();
        let allowed = dir.path().canonicalize().unwrap();
        let path = script(dir.path(), 0o755);
        let uid = server_euid();
        let result = validate_script_path("up", &path, &[allowed], uid);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn rejects_group_writable_script() {
        let dir = secure_dir();
        let allowed = dir.path().canonicalize().unwrap();
        let path = script(dir.path(), 0o775);
        let uid = server_euid();
        let error = validate_script_path("up", &path, &[allowed], uid).unwrap_err();
        assert!(error.to_string().contains("writable by group or others"));
    }

    #[test]
    fn rejects_script_outside_allowed_directories() {
        let allowed_dir = secure_dir();
        let other_dir = secure_dir();
        let allowed = allowed_dir.path().canonicalize().unwrap();
        let path = script(other_dir.path(), 0o755);
        let uid = server_euid();
        let error = validate_script_path("up", &path, &[allowed], uid).unwrap_err();
        assert!(error.to_string().contains("outside the allowed"));
    }

    #[test]
    fn rejects_directory_as_script() {
        let dir = secure_dir();
        let allowed = dir.path().canonicalize().unwrap();
        let uid = server_euid();
        let error = validate_script_path("up", dir.path(), &[allowed], uid).unwrap_err();
        assert!(
            error.to_string().contains("not a regular file"),
            "{error:#}"
        );
    }

    #[test]
    fn control_requires_a_script_allowlist() {
        assert!(validate_control_configuration("/run/rustvpn/control.sock", &[]).is_err());
        assert!(validate_control_configuration(
            "/run/rustvpn/control.sock",
            &[PathBuf::from("/etc/rustvpn/scripts")]
        )
        .is_ok());
        assert!(validate_control_configuration("", &[]).is_ok());
    }

    #[test]
    fn rejects_group_writable_script_directory() {
        let dir = secure_dir();
        let path = script(dir.path(), 0o755);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let allowed = dir.path().canonicalize().unwrap();
        let uid = server_euid();
        let error = validate_script_path("up", &path, &[allowed], uid).unwrap_err();
        assert!(error.to_string().contains("directory"));
        assert!(error.to_string().contains("writable by group or others"));
    }

    #[test]
    fn proposed_config_uses_server_script_policy() {
        use rustvpn_crypto::verifier::Verifier;

        let dir = secure_dir();
        let allowed = dir.path().canonicalize().unwrap();
        let up = script(dir.path(), 0o755);
        let mut verifier = Verifier::new(1024, 2, 1, [7u8; 16]);
        verifier.password_apply("test").unwrap();
        let yaml = format!(
            "alice:\n  iface: tap0\n  up: {}\n  verifier: '{}'\n",
            up.display(),
            verifier.long_form().unwrap()
        );
        assert!(validate_proposed_config(&yaml, std::slice::from_ref(&allowed)).is_ok());
        let bad = yaml.replace(&up.display().to_string(), "/tmp/not-allowed.sh");
        assert!(validate_proposed_config(&bad, &[allowed]).is_err());
    }

    #[test]
    fn token_base_is_52_bit() {
        for _ in 0..32 {
            let value = random_token_base();
            assert!(value > 0);
            assert!(value < (1u64 << 52));
        }
    }

    fn test_peer(name: &str, id: [u8; 16], mtu: usize) -> PeerConfig {
        let mut verifier = rustvpn_crypto::verifier::Verifier::new(1024, 2, 1, id);
        verifier.public = Some([id[0]; 32]);
        PeerConfig {
            id,
            name: name.into(),
            iface: format!("tap-{name}"),
            mtu,
            up: String::new(),
            down: String::new(),
            timeout: Duration::from_secs(60),
            noise: false,
            cpr: 0,
            encless: false,
            time_sync: 0,
            keepalive: Duration::ZERO,
            rekey_time: Duration::ZERO,
            rekey_jitter: Duration::ZERO,
            network: None,
            verifier,
            signing_key: None,
        }
    }

    fn config_set(peers: Vec<PeerConfig>) -> ConfigSet {
        ConfigSet::from_peers(peers).unwrap()
    }

    #[test]
    fn reload_plan_changes_only_the_modified_peer() {
        let alice = test_peer("alice", [1u8; 16], 1515);
        let bob = test_peer("bob", [2u8; 16], 1515);
        let carol = test_peer("carol", [3u8; 16], 1515);
        let old = config_set(vec![alice.clone(), bob.clone(), carol.clone()]);
        let mut changed = carol;
        changed.mtu = 1540;
        let new = config_set(vec![alice, bob, changed]);

        let plan = plan_reload(&old, &new);
        assert_eq!(plan.changed.len(), 1, "{plan:?}");
        assert_eq!(plan.changed[0].1, "carol");
        assert_eq!(plan.unchanged.len(), 2, "{plan:?}");
        let unchanged: Vec<&str> = plan
            .unchanged
            .iter()
            .map(|(_, name)| name.as_str())
            .collect();
        assert!(unchanged.contains(&"alice") && unchanged.contains(&"bob"));
        assert_eq!(plan.revoked_ids().len(), 1);
        assert!(plan.revoked_ids().contains(&[3u8; 16]));
    }

    #[test]
    fn reload_plan_detects_added_and_removed_peers() {
        let alice = test_peer("alice", [1u8; 16], 1515);
        let bob = test_peer("bob", [2u8; 16], 1515);
        let old = config_set(vec![alice.clone(), bob.clone()]);
        let added = test_peer("dave", [4u8; 16], 1515);
        let new = config_set(vec![alice, added]);
        let plan = plan_reload(&old, &new);
        assert_eq!(plan.added[0].1, "dave");
        assert_eq!(plan.removed[0].1, "bob");
        assert_eq!(plan.unchanged[0].1, "alice");
        assert!(plan.revoked_ids().contains(&[2u8; 16]));
        assert!(!plan.revoked_ids().contains(&[4u8; 16]));
    }

    #[test]
    fn semantic_yaml_differences_do_not_trigger_reload() {
        let long = {
            let mut verifier = rustvpn_crypto::verifier::Verifier::new(1024, 2, 1, [9u8; 16]);
            verifier.password_apply("test").unwrap();
            verifier.long_form().unwrap()
        };
        // Same peers, different key order/comments/whitespace/quoting.
        let one = format!("alice:\n  iface: tap0\n  verifier: '{long}'\n");
        let two = format!(
            "# comment\n\n\nalice:\n    verifier: \"{long}\"\n    iface: tap0\n    # trailing\n"
        );
        let a = ConfigSet::from_str(&one).unwrap();
        let b = ConfigSet::from_str(&two).unwrap();
        let plan = plan_reload(&a, &b);
        assert!(plan.is_noop(), "{plan:?}");
        assert!(plan.revoked_ids().is_empty());
    }

    #[tokio::test]
    async fn reloader_semantic_noop_does_not_bump_generation() {
        let long = {
            let mut verifier = rustvpn_crypto::verifier::Verifier::new(1024, 2, 1, [6u8; 16]);
            verifier.password_apply("test").unwrap();
            verifier.long_form().unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.yaml");
        let one = format!("alice:\n  iface: tap0\n  verifier: '{long}'\n");
        std::fs::write(&path, &one).unwrap();
        let set = ConfigSet::from_str(&one).unwrap();
        let store = Arc::new(RwLock::new(set));
        let (requests, mut requests_rx) = mpsc::channel(4);
        let reloader = Reloader::new(
            path.clone(),
            store,
            requests,
            Some(one.as_bytes().to_vec()),
            1,
            Arc::new(Vec::new()),
            None,
        );

        let two = format!("# comment\nalice:\n  verifier: \"{long}\"\n  iface: tap0\n");
        std::fs::write(&path, &two).unwrap();
        assert!(!reloader.reload_from_disk().await.unwrap());
        assert_eq!(reloader.generation(), 1);
        assert!(requests_rx.try_recv().is_err());

        let changed = format!("alice:\n  iface: tap0\n  mtu: 1540\n  verifier: '{long}'\n");
        std::fs::write(&path, &changed).unwrap();
        assert!(reloader.reload_from_disk().await.unwrap());
        assert_eq!(reloader.generation(), 2);
        let request = requests_rx.try_recv().expect("reload request");
        match request {
            MainRequest::ConfigReloaded { plan } => {
                assert_eq!(plan.changed.len(), 1);
                assert_eq!(plan.changed[0].1, "alice");
            }
            _ => panic!("unexpected request"),
        }
    }

    #[test]
    fn reload_plan_reports_changed_fields() {
        let alice = test_peer("alice", [1u8; 16], 1515);
        let old = config_set(vec![alice.clone()]);
        let mut changed = alice;
        changed.mtu = 1540;
        changed.keepalive = Duration::from_secs(25);
        let new = config_set(vec![changed]);
        let plan = plan_reload(&old, &new);
        let fields = &plan.changed[0].2;
        assert!(fields.contains("mtu"), "{fields}");
        assert!(fields.contains("keepalive"), "{fields}");
        assert!(!fields.contains("iface"), "{fields}");
        assert!(plan.summary().contains("alice{"), "{}", plan.summary());
    }

    #[test]
    fn config_is_current_rejects_revoked_or_changed_snapshots() {
        let alice = test_peer("alice", [1u8; 16], 1515);
        let set = config_set(vec![alice.clone()]);
        assert!(config_is_current(&set, &alice));

        let mut changed = alice.clone();
        changed.mtu = 1540;
        assert!(!config_is_current(&set, &changed));

        let empty = config_set(Vec::new());
        assert!(!config_is_current(&empty, &alice));
    }

    #[test]
    fn network_changes_are_part_of_the_fingerprint() {
        let alice = test_peer("alice", [1u8; 16], 1515);
        let old = config_set(vec![alice.clone()]);
        let mut changed = alice;
        changed.network = Some(rustvpn_net::config::PeerNetwork {
            address: "10.88.0.1/24".into(),
            gateway: String::new(),
            dns: Vec::new(),
            routes: vec!["10.88.0.0/24".into()],
        });
        let new = config_set(vec![changed]);
        let plan = plan_reload(&old, &new);
        assert_eq!(plan.changed.len(), 1);
    }

    fn declarative_network() -> PeerNetwork {
        PeerNetwork {
            address: "10.88.0.1/24".into(),
            gateway: String::new(),
            dns: Vec::new(),
            routes: vec!["10.88.0.0/24".into()],
        }
    }

    #[test]
    fn mode_only_change_reapplies_declarative_tap_mtu() {
        let network = declarative_network();
        let mut plain = test_peer("alice", [1u8; 16], 1515);
        plain.noise = false;
        plain.network = Some(network.clone());
        let plain_fp = declarative_network_fingerprint(&plain, &network);
        assert_eq!(plain.inner_ip_mtu(), 1500);

        // Same wire MTU, only the mode changes: the applied fingerprint must
        // differ so `open_tap` reconfigures the TAP IP MTU before the session.
        let mut noise = plain.clone();
        noise.noise = true;
        let noise_fp = declarative_network_fingerprint(&noise, &network);
        assert_eq!(noise.inner_ip_mtu(), 1476);
        assert!(declarative_reapply_needed(Some(&plain_fp), &noise_fp));

        let mut encless = plain.clone();
        encless.noise = true;
        encless.encless = true;
        let encless_fp = declarative_network_fingerprint(&encless, &network);
        assert_eq!(encless.inner_ip_mtu(), 1492);
        assert!(declarative_reapply_needed(Some(&noise_fp), &encless_fp));

        // noise → plain is also detected.
        assert!(declarative_reapply_needed(Some(&noise_fp), &plain_fp));
        // Unchanged mode/MTU/network is still a no-op.
        assert!(!declarative_reapply_needed(Some(&plain_fp), &plain_fp));
    }

    #[test]
    fn publish_after_reload_detects_stale_snapshot_and_matching_guard() {
        let alice = test_peer("alice", [1u8; 16], 1515);
        let old = config_set(vec![alice.clone()]);
        assert!(config_is_current(&old, &alice));

        // A spawned UDP task can hold the old snapshot while the main task
        // installs a changed config before `registry.insert`.  The post-insert
        // re-check must see the stale snapshot.
        let mut changed = alice.clone();
        changed.noise = true;
        let reloaded = config_set(vec![changed]);
        assert!(
            !config_is_current(&reloaded, &alice),
            "post-publish recheck must revoke a snapshot the reload already replaced"
        );

        // Cleanup must only take the guard that belongs to the stale config.
        assert!(guard_fingerprint_matches(Some("stale"), "stale"));
        assert!(!guard_fingerprint_matches(Some("new"), "stale"));
        assert!(!guard_fingerprint_matches(None, "stale"));
    }
}
