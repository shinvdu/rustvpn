//! Shared admin runtime state.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::auth::{AuthState, LoginLimiter};
use crate::history::History;
use crate::model::{AdminBackend, SessionInfo};
use crate::store::Store;

#[derive(Clone, Debug, Default)]
pub struct AdminOptions {
    /// Set when the admin endpoint is served over TLS (directly or by a
    /// reverse proxy).  `__Host-` cookies require it.
    pub secure_cookies: bool,
    /// Optional allow-list for `up`/`down` paths.
    pub script_dirs: Vec<PathBuf>,
}

pub struct AdminState {
    pub backend: Arc<dyn AdminBackend>,
    pub store: Arc<Store>,
    pub auth: Arc<AuthState>,
    pub history: Arc<History>,
    pub limiter: LoginLimiter,
    pub options: AdminOptions,
    pub started_at: SystemTime,
}

impl AdminState {
    pub fn new(
        backend: Arc<dyn AdminBackend>,
        store: Arc<Store>,
        history: Arc<History>,
        options: AdminOptions,
    ) -> Arc<Self> {
        Arc::new(Self {
            backend,
            store,
            auth: Arc::new(AuthState::new()),
            history,
            limiter: LoginLimiter::new(),
            options,
            started_at: SystemTime::now(),
        })
    }

    /// Start the 10-second traffic sampler.
    pub fn spawn_sampler(self: &Arc<Self>) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last = Instant::now();
            loop {
                tick.tick().await;
                let sessions = state.backend.active_sessions().await;
                let elapsed = last.elapsed().as_secs_f64();
                state.history.record_tick(&sessions, elapsed);
                last = Instant::now();
            }
        });
    }

    pub async fn sessions_with_rates(&self) -> Vec<SessionInfo> {
        let sessions = self.backend.active_sessions().await;
        let rates = self.history.rates();
        sessions
            .into_iter()
            .map(|session| {
                let rate = rates.get(&session.session_id);
                session.with_rate(rate)
            })
            .collect()
    }

    /// Run a blocking SQLite operation off the async runtime.
    pub async fn db<F, T>(&self, operation: F) -> Result<T, String>
    where
        F: FnOnce(&Store) -> Result<T, String> + Send + 'static,
        T: Send + 'static,
    {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || operation(&store))
            .await
            .map_err(|e| format!("database task failed: {e}"))?
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn audit(
        &self,
        user: &str,
        ip: &str,
        action: &str,
        target: &str,
        detail: serde_json::Value,
        result: &str,
    ) {
        let user = user.to_string();
        let ip = ip.to_string();
        let action = action.to_string();
        let target = target.to_string();
        let detail = detail.to_string();
        let result = result.to_string();
        let _ = self
            .db(move |store| store.audit(&user, &ip, &action, &target, &detail, &result))
            .await;
    }

    pub fn uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.started_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
