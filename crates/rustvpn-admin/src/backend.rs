//! `AdminBackend` implementation backed by the server's local control socket.
//!
//! Configuration editing stays in the admin process; live session reads,
//! kicks and reloads go through `rustvpn-control`.  A background subscription
//! feeds the session history and the dashboard event log, and also reconciles
//! sessions after a reconnect.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rustvpn_control as ctl;
use rustvpn_control::client::{call_once, ControlClient, ControlError};
use rustvpn_control::{Event, Request, Response};

use crate::config_edit::{self, ConfigPaths};
use crate::history::History;
use crate::model::{
    now_unix, parse_id, AdminBackend, ApplyReport, ApplyRequest, BackupInfo, ConfigError,
    ConfigSnapshot, ConfigStatus, Counters, EventLog, EventView, KickReport, PreviewReport,
    ServerCounters, SessionEnd, SessionInfo, SessionObserver, SessionStart, SystemStatus,
};
use crate::store::Store;

#[derive(Clone, Copy)]
enum EventKind {
    Connected,
    Disconnected,
    Lagged,
    SessionStart,
    SessionEnd,
    ConfigReload,
}

pub struct ControlBackend {
    paths: ConfigPaths,
    control_path: PathBuf,
    listen: String,
    history: Arc<History>,
    events: Arc<EventLog>,
    store: Arc<Store>,
    cache: Mutex<Vec<SessionInfo>>,
    online: AtomicBool,
    script_dirs: Vec<PathBuf>,
    config_write: tokio::sync::Mutex<()>,
}

impl ControlBackend {
    pub fn new(
        paths: ConfigPaths,
        control_path: PathBuf,
        listen: String,
        history: Arc<History>,
        events: Arc<EventLog>,
        store: Arc<Store>,
        script_dirs: Vec<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            paths,
            control_path,
            listen,
            history,
            events,
            store,
            cache: Mutex::new(Vec::new()),
            online: AtomicBool::new(false),
            script_dirs,
            config_write: tokio::sync::Mutex::new(()),
        })
    }

    /// Start the control-event subscription loop.  Reconnects forever with
    /// backoff; the HTTP server keeps serving in the meantime.
    pub fn start_subscription(self: &Arc<Self>) {
        let backend = self.clone();
        tokio::spawn(async move { backend.subscription_loop().await });
    }

    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    async fn call(&self, request: Request) -> Result<Response, String> {
        let path = self.control_path.clone();
        let timeout = request_timeout(&request);
        let result = tokio::time::timeout(timeout, call_once(path, &request)).await;
        match result {
            Ok(Ok(response)) => {
                self.online.store(true, Ordering::Relaxed);
                Ok(response)
            }
            Ok(Err(error)) => {
                // A server-side application error (e.g. "peer is not online")
                // proves the control plane is reachable; do not flip the UI
                // to offline for it.
                let reachable = matches!(error, ControlError::Remote(_));
                self.online.store(reachable, Ordering::Relaxed);
                Err(error.to_string())
            }
            Err(_) => {
                self.online.store(false, Ordering::Relaxed);
                Err("control request timed out".to_string())
            }
        }
    }

    async fn prevalidate_config(&self, enabled_yaml: &str) -> Result<(), ConfigError> {
        match self
            .call(Request::ValidateConfig {
                enabled_yaml: enabled_yaml.to_string(),
            })
            .await
        {
            Ok(Response::ConfigValidation { valid: true, .. }) => Ok(()),
            Ok(Response::ConfigValidation {
                valid: false,
                errors,
            }) => {
                let message = if errors.is_empty() {
                    "server rejected the proposed configuration".to_string()
                } else {
                    errors.join("; ")
                };
                Err(ConfigError::Invalid(message))
            }
            Ok(_) => Err(ConfigError::Io(
                "unexpected config validation response".to_string(),
            )),
            Err(error) => Err(ConfigError::Io(format!(
                "server config preflight failed: {error}"
            ))),
        }
    }

    fn note(
        &self,
        kind: EventKind,
        peer: Option<String>,
        addr: Option<String>,
        detail: Option<String>,
    ) {
        let kind = match kind {
            EventKind::Connected => "control_connected",
            EventKind::Disconnected => "control_disconnected",
            EventKind::Lagged => "control_lagged",
            EventKind::SessionStart => "peer_created",
            EventKind::SessionEnd => "peer_removed",
            EventKind::ConfigReload => "config_reloaded",
        };
        self.events.push(EventView {
            ts: now_unix(),
            kind: kind.to_string(),
            peer,
            addr,
            detail,
        });
    }

    async fn subscription_loop(self: Arc<Self>) {
        let mut delay = Duration::from_secs(1);
        loop {
            match self.subscribe_once().await {
                Ok(()) => {
                    self.online.store(false, Ordering::Relaxed);
                    delay = Duration::from_secs(1);
                }
                Err(error) => {
                    self.online.store(false, Ordering::Relaxed);
                    self.note(
                        EventKind::Disconnected,
                        None,
                        None,
                        Some(format!("control subscription: {error}")),
                    );
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
            tokio::time::sleep(delay).await;
        }
    }

    async fn subscribe_once(&self) -> Result<(), String> {
        let client = ControlClient::connect(&self.control_path)
            .await
            .map_err(|error| error.to_string())?;
        let mut subscription = client
            .subscribe()
            .await
            .map_err(|error| error.to_string())?;
        self.online.store(true, Ordering::Relaxed);
        self.note(EventKind::Connected, None, None, None);
        if let Err(error) = self.reconcile().await {
            self.note(
                EventKind::Disconnected,
                None,
                None,
                Some(format!("control reconcile: {error}")),
            );
        }
        loop {
            match subscription.next().await {
                Ok(Some(Event::SessionStarted(started))) => {
                    self.note(
                        EventKind::SessionStart,
                        Some(started.name.clone()),
                        Some(started.addr.clone()),
                        Some(started.proto.clone()),
                    );
                    match SessionStart::try_from(started) {
                        Ok(start) => self.history.session_started(start),
                        Err(error) => self.note(
                            EventKind::Disconnected,
                            None,
                            None,
                            Some(format!("invalid session start: {error}")),
                        ),
                    }
                }
                Ok(Some(Event::SessionEnded(ended))) => {
                    self.note(
                        EventKind::SessionEnd,
                        Some(ended.name.clone()),
                        Some(ended.addr.clone()),
                        Some(ended.reason.clone()),
                    );
                    let session_id = ended.session_id;
                    match SessionEnd::try_from(ended) {
                        Ok(end) => self.history.session_ended(end),
                        Err(error) => self.note(
                            EventKind::Disconnected,
                            None,
                            None,
                            Some(format!("invalid session end: {error}")),
                        ),
                    }
                    self.cache
                        .lock()
                        .unwrap()
                        .retain(|s| s.session_id != session_id);
                }
                Ok(Some(Event::ConfigReloaded(reloaded))) => {
                    self.note(
                        EventKind::ConfigReload,
                        None,
                        None,
                        Some(match &reloaded.last_error {
                            Some(error) => {
                                format!("generation {} failed: {error}", reloaded.generation)
                            }
                            None => format!("generation {}", reloaded.generation),
                        }),
                    );
                }
                Ok(Some(Event::Lagged { missed })) => {
                    self.note(
                        EventKind::Lagged,
                        None,
                        None,
                        Some(format!("{missed} control events dropped")),
                    );
                    if let Err(error) = self.reconcile().await {
                        self.note(
                            EventKind::Disconnected,
                            None,
                            None,
                            Some(format!("control reconcile: {error}")),
                        );
                    }
                }
                Ok(Some(Event::ServerShutdown)) => {
                    self.note(
                        EventKind::Disconnected,
                        None,
                        None,
                        Some("server shutdown".into()),
                    );
                    return Ok(());
                }
                Ok(None) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    /// Replay active sessions and recent ends after a reconnect or lag.
    async fn reconcile(&self) -> Result<(), String> {
        let sessions = match self.call(Request::Sessions).await? {
            Response::Sessions { sessions } => sessions,
            _ => return Err("unexpected sessions response".into()),
        };
        let mapped: Vec<SessionInfo> = sessions.iter().cloned().map(Into::into).collect();
        *self.cache.lock().unwrap() = mapped;
        let active: HashSet<u64> = sessions.iter().map(|s| s.session_id).collect();
        for session in sessions {
            if let Ok(start) = SessionStart::try_from(session) {
                self.history.session_started(start);
            }
        }
        let mut recently_ended = HashSet::new();
        if let Ok(Response::RecentSessions { sessions }) =
            self.call(Request::RecentSessions { limit: 1024 }).await
        {
            for session in sessions {
                recently_ended.insert(session.session_id);
                if let Ok(end) = SessionEnd::try_from(session) {
                    self.history.session_ended(end);
                }
            }
        }
        self.close_orphan_sessions(active, recently_ended).await;
        Ok(())
    }

    /// Close rows for sessions the server no longer knows about.  Sessions
    /// that are active or whose end is still in the server's recent ring are
    /// left to the normal start/end path.
    async fn close_orphan_sessions(&self, active: HashSet<u64>, recently_ended: HashSet<u64>) {
        let store = self.store.clone();
        let ended_at = now_unix();
        match tokio::task::spawn_blocking(move || -> Result<(), String> {
            for session_id in store.open_session_ids()? {
                if !active.contains(&session_id) && !recently_ended.contains(&session_id) {
                    store.close_session(session_id, "server_restart", ended_at)?;
                }
            }
            Ok(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => self.note(
                EventKind::Disconnected,
                None,
                None,
                Some(format!("session reconcile: {error}")),
            ),
            Err(error) => self.note(
                EventKind::Disconnected,
                None,
                None,
                Some(format!("session reconcile task failed: {error}")),
            ),
        }
    }

    fn cached_sessions(&self) -> Vec<SessionInfo> {
        self.cache.lock().unwrap().clone()
    }

    async fn reload_server(&self) -> (bool, u64, Vec<String>) {
        match self.call(Request::Reload).await {
            Ok(Response::Reload { report }) => (report.applied, report.generation, Vec::new()),
            Ok(_) => (
                false,
                0,
                vec!["unexpected response from server reload".to_string()],
            ),
            Err(error) => (
                false,
                0,
                vec![format!(
                    "configuration was written, but the server reload failed: {error}"
                )],
            ),
        }
    }
}

fn request_timeout(request: &Request) -> Duration {
    match request {
        // The server waits up to 5s for a kick and may parse a full config on
        // reload; do not undercut those operations with a 3s client timeout
        // that reports failure while the action succeeds.
        Request::Kick { .. } | Request::Reload | Request::ValidateConfig { .. } => {
            Duration::from_secs(10)
        }
        _ => Duration::from_secs(3),
    }
}

#[async_trait]
impl AdminBackend for ControlBackend {
    async fn system_status(&self) -> SystemStatus {
        let paths = self.paths.clone();
        let loaded = tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .ok()
            .and_then(|result| result.ok());
        let (configured, disabled, etag, load_error) = match &loaded {
            Some(loaded) => (
                loaded.files.enabled.len(),
                loaded.files.disabled.len(),
                loaded.etag(),
                None,
            ),
            None => (
                0,
                0,
                String::new(),
                Some("unable to read peers.yaml".to_string()),
            ),
        };
        let config_path = self.paths.enabled.display().to_string();
        let disabled_path = self.paths.disabled.display().to_string();
        match self.call(Request::Status).await {
            Ok(Response::Status { status }) => SystemStatus {
                uptime_seconds: status.uptime_seconds,
                bind: status.bind,
                proto: status.proto,
                admin_addr: self.listen.clone(),
                active_sessions: status.active_sessions,
                configured_peers: configured,
                disabled_peers: disabled,
                config: ConfigStatus {
                    path: config_path,
                    disabled_path,
                    generation: status.config_generation,
                    last_loaded_at: status.config_last_loaded_at,
                    last_error: status.config_last_error.or(load_error),
                    etag,
                },
                counters: ServerCounters {
                    handshake_requests: status.counters.handshake_requests,
                    handshake_rate_limited: status.counters.handshake_rate_limited,
                    handshake_errors: status.counters.handshake_errors,
                    tcp_connections_rejected: status.counters.tcp_connections_rejected,
                    sessions_started: status.counters.sessions_started,
                    sessions_finished: status.counters.sessions_finished,
                    admin_hook_dropped: status.counters.events_dropped,
                },
                server_online: true,
                server_instance: Some(status.server_instance),
            },
            Ok(_) => SystemStatus {
                uptime_seconds: 0,
                bind: "-".into(),
                proto: "-".into(),
                admin_addr: self.listen.clone(),
                active_sessions: self.cached_sessions().len(),
                configured_peers: configured,
                disabled_peers: disabled,
                config: ConfigStatus {
                    path: config_path,
                    disabled_path,
                    generation: 0,
                    last_loaded_at: None,
                    last_error: load_error.or(Some("unexpected control response".into())),
                    etag,
                },
                counters: ServerCounters::default(),
                server_online: false,
                server_instance: None,
            },
            Err(error) => SystemStatus {
                uptime_seconds: 0,
                bind: "-".into(),
                proto: "-".into(),
                admin_addr: self.listen.clone(),
                active_sessions: self.cached_sessions().len(),
                configured_peers: configured,
                disabled_peers: disabled,
                config: ConfigStatus {
                    path: config_path,
                    disabled_path,
                    generation: 0,
                    last_loaded_at: None,
                    last_error: Some(format!("control unavailable: {error}")),
                    etag,
                },
                counters: ServerCounters::default(),
                server_online: false,
                server_instance: None,
            },
        }
    }

    async fn config_snapshot(&self) -> Result<ConfigSnapshot, ConfigError> {
        let paths = self.paths.clone();
        tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))?
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
        .map_err(|error| ConfigError::Io(error.to_string()))?
    }

    async fn apply_config(&self, request: ApplyRequest) -> Result<ApplyReport, ConfigError> {
        let _guard = self.config_write.lock().await;
        let paths = self.paths.clone();
        let current = tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))??;
        if current.etag() != request.expected_etag {
            return Err(ConfigError::Conflict {
                current_etag: current.etag(),
            });
        }
        let files = config_edit::parse_files(&request.enabled_yaml, &request.disabled_yaml)?;
        for (name, peer) in files.enabled.iter().chain(files.disabled.iter()) {
            config_edit::validate_script_allowlist(name, peer, &self.script_dirs)?;
        }
        self.prevalidate_config(&request.enabled_yaml).await?;
        let (_, _, _, revoked) = config_edit::diff(&current.files, &files);
        let paths = self.paths.clone();
        let report = tokio::task::spawn_blocking(move || config_edit::commit(&paths, &files))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))??;
        let (applied, generation, mut warnings) = self.reload_server().await;
        warnings.extend(report.warnings);
        Ok(ApplyReport {
            applied,
            generation,
            etag: report.etag,
            backups: report.backups,
            revoked,
            warnings,
        })
    }

    async fn active_sessions(&self) -> Vec<SessionInfo> {
        match self.call(Request::Sessions).await {
            Ok(Response::Sessions { sessions }) => {
                let mapped: Vec<SessionInfo> = sessions.into_iter().map(Into::into).collect();
                *self.cache.lock().unwrap() = mapped.clone();
                mapped
            }
            // Do not report an empty list on a transient control failure:
            // the history sampler would synthesise ends for every session.
            _ => self.cached_sessions(),
        }
    }

    async fn kick(&self, id: [u8; 16], reason: String) -> Result<KickReport, String> {
        let id = hex::encode(id);
        match self.call(Request::Kick { id, reason }).await? {
            Response::Kick { report } => Ok(report.into()),
            _ => Err("unexpected response from server kick".to_string()),
        }
    }

    async fn list_backups(&self) -> Result<Vec<BackupInfo>, ConfigError> {
        let paths = self.paths.clone();
        tokio::task::spawn_blocking(move || config_edit::list_backups(&paths))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))?
    }

    async fn restore_backup(
        &self,
        name: &str,
        _comment: String,
    ) -> Result<ApplyReport, ConfigError> {
        let _guard = self.config_write.lock().await;
        let paths = self.paths.clone();
        let name = name.to_string();
        let plan = tokio::task::spawn_blocking(move || config_edit::plan_restore(&paths, &name))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))??;
        for (peer_name, peer) in plan
            .files()
            .enabled
            .iter()
            .chain(plan.files().disabled.iter())
        {
            config_edit::validate_script_allowlist(peer_name, peer, &self.script_dirs)?;
        }
        let (enabled_yaml, _) = plan.files().render()?;
        self.prevalidate_config(&enabled_yaml).await?;
        let paths = self.paths.clone();
        tokio::task::spawn_blocking(move || config_edit::apply_restore(&paths, &plan))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))??;
        let paths = self.paths.clone();
        let loaded = tokio::task::spawn_blocking(move || config_edit::load(&paths))
            .await
            .map_err(|error| ConfigError::Io(error.to_string()))??;
        let (applied, generation, warnings) = self.reload_server().await;
        Ok(ApplyReport {
            applied,
            generation,
            etag: loaded.etag(),
            backups: Vec::new(),
            revoked: Vec::new(),
            warnings,
        })
    }

    fn events(&self) -> Vec<EventView> {
        self.events.snapshot()
    }
}

impl From<ctl::Counters> for Counters {
    fn from(value: ctl::Counters) -> Self {
        Self {
            bytes_in: value.bytes_in,
            bytes_out: value.bytes_out,
            payload_in: value.payload_in,
            payload_out: value.payload_out,
            frames_in: value.frames_in,
            frames_out: value.frames_out,
            unauth: value.unauth,
            dup: value.dup,
            heartbeat_recv: value.heartbeat_recv,
            heartbeat_sent: value.heartbeat_sent,
        }
    }
}

impl From<ctl::SessionInfo> for SessionInfo {
    fn from(value: ctl::SessionInfo) -> Self {
        Self {
            session_id: value.session_id,
            peer_id: value.peer_id,
            name: value.name,
            addr: value.addr,
            proto: value.proto,
            mode: value.mode,
            mtu: value.mtu,
            established: value.established,
            started_at_unix: value.started_at_unix,
            last_ping: value.last_ping,
            last_sent: value.last_sent,
            counters: value.counters.into(),
            rate_in_bps: 0,
            rate_out_bps: 0,
        }
    }
}

impl TryFrom<ctl::SessionStarted> for SessionStart {
    type Error = String;

    fn try_from(value: ctl::SessionStarted) -> Result<Self, Self::Error> {
        Ok(Self {
            session_id: value.session_id,
            peer_id: parse_id(&value.peer_id)?,
            name: value.name,
            addr: value.addr,
            proto: value.proto,
            mode: value.mode,
            started_at: value.started_at,
            counters: value.counters.into(),
        })
    }
}

impl TryFrom<ctl::SessionInfo> for SessionStart {
    type Error = String;

    fn try_from(value: ctl::SessionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            session_id: value.session_id,
            peer_id: parse_id(&value.peer_id)?,
            name: value.name,
            addr: value.addr,
            proto: value.proto,
            mode: value.mode,
            started_at: value.started_at_unix,
            counters: value.counters.into(),
        })
    }
}

impl TryFrom<ctl::SessionEnded> for SessionEnd {
    type Error = String;

    fn try_from(value: ctl::SessionEnded) -> Result<Self, Self::Error> {
        Ok(Self {
            session_id: value.session_id,
            peer_id: parse_id(&value.peer_id)?,
            ended_at: value.ended_at,
            reason: value.reason,
            counters: value.counters.into(),
        })
    }
}

impl From<ctl::KickReport> for KickReport {
    fn from(value: ctl::KickReport) -> Self {
        Self {
            kicked: value.kicked,
            session_id: value.session_id,
            addr: value.addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AdminBackend, ApplyRequest, ConfigError, EventLog};
    use crate::store::Store;
    use rustvpn_control::{read_frame, write_frame};
    use std::path::Path;
    use tokio::net::UnixListener;

    fn spawn_fake_control(path: &Path, valid: bool, kick_error: bool) {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let Ok(Some(Request::Hello { version })) =
                        read_frame::<_, Request>(&mut stream).await
                    else {
                        return;
                    };
                    let hello = Response::Hello {
                        version,
                        server_version: "test".into(),
                        server_instance: 1,
                    };
                    if write_frame(&mut stream, &hello).await.is_err() {
                        return;
                    }
                    loop {
                        let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await else {
                            break;
                        };
                        let response = match request {
                            Request::ValidateConfig { .. } => Response::ConfigValidation {
                                valid,
                                errors: if valid {
                                    Vec::new()
                                } else {
                                    vec!["test policy rejection".into()]
                                },
                            },
                            Request::Kick { .. } if kick_error => Response::Error {
                                message: "peer is not online".into(),
                            },
                            _ => Response::Error {
                                message: "unsupported in test".into(),
                            },
                        };
                        if write_frame(&mut stream, &response).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    fn test_backend(dir: &Path, control: std::path::PathBuf) -> Arc<ControlBackend> {
        let paths = ConfigPaths {
            enabled: dir.join("peers.yaml"),
            disabled: dir.join("peers.disabled.yaml"),
            backup_dir: dir.join("backups"),
        };
        std::fs::write(&paths.enabled, "").unwrap();
        let store = Arc::new(Store::open_in_memory().unwrap());
        let history = History::spawn(store.clone());
        ControlBackend::new(
            paths,
            control,
            "127.0.0.1:8080".into(),
            history,
            Arc::new(EventLog::new(10)),
            store,
            Vec::new(),
        )
    }

    fn apply_request() -> ApplyRequest {
        ApplyRequest {
            enabled_yaml: String::new(),
            disabled_yaml: String::new(),
            expected_etag: config_edit::etag("", ""),
            comment: String::new(),
        }
    }

    #[test]
    fn request_timeouts_match_server_limits() {
        assert_eq!(request_timeout(&Request::Status), Duration::from_secs(3));
        assert_eq!(request_timeout(&Request::Sessions), Duration::from_secs(3));
        assert_eq!(
            request_timeout(&Request::Kick {
                id: "00".repeat(16),
                reason: "test".into()
            }),
            Duration::from_secs(10)
        );
        assert_eq!(request_timeout(&Request::Reload), Duration::from_secs(10));
        assert_eq!(
            request_timeout(&Request::ValidateConfig {
                enabled_yaml: String::new()
            }),
            Duration::from_secs(10)
        );
    }

    #[tokio::test]
    async fn apply_refuses_to_write_without_control_plane() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend(dir.path(), dir.path().join("missing.sock"));
        let error = backend.apply_config(apply_request()).await.unwrap_err();
        assert!(matches!(error, ConfigError::Io(_)));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("peers.yaml")).unwrap(),
            ""
        );
        assert!(!dir.path().join("backups").exists());
    }

    #[tokio::test]
    async fn apply_does_not_write_when_preflight_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let control = dir.path().join("control.sock");
        spawn_fake_control(&control, false, false);
        let backend = test_backend(dir.path(), control);
        let error = backend.apply_config(apply_request()).await.unwrap_err();
        assert!(matches!(error, ConfigError::Invalid(_)));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("peers.yaml")).unwrap(),
            ""
        );
        assert!(!dir.path().join("backups").exists());
    }

    #[tokio::test]
    async fn valid_preflight_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let control = dir.path().join("control.sock");
        spawn_fake_control(&control, true, false);
        let backend = test_backend(dir.path(), control);
        backend.prevalidate_config("").await.unwrap();
        assert!(backend.is_online());
    }

    #[tokio::test]
    async fn remote_business_error_keeps_the_control_plane_online() {
        let dir = tempfile::tempdir().unwrap();
        let control = dir.path().join("control.sock");
        spawn_fake_control(&control, true, true);
        let backend = test_backend(dir.path(), control);
        let error = backend.kick([0u8; 16], "test".into()).await.unwrap_err();
        assert!(error.contains("peer is not online"));
        assert!(backend.is_online());
    }
}
