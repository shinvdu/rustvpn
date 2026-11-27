//! Reconnect engine used by `rustvpn-clientd`.
//!
//! The CLI keeps its historical loop and calls [`crate::session`] directly;
//! the daemon uses this engine for states, traffic samples, logs and
//! exponential backoff.

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ipnet::IpNet;
use rustvpn_client_ipc::{EngineStatus, Event, LogLine, ProfileSpec, TrafficSample};
use rustvpn_net::stats::StatsState;
use rustvpn_net::tap::{Tap, TapConfig};
use rustvpn_proto::{Mode, MAX_BYTES_PER_KEY};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::lock::TunnelLock;
use crate::mtu;
#[cfg(unix)]
use crate::mtu::OuterFamily;
use crate::netcfg::{ConnectionCleanup, FirewallOptions, NetOptions, NetworkGuard};
use crate::profile::ValidatedProfile;
use crate::session::{resolve_endpoints, start_session, Endpoints, Session, SessionEnd};

pub enum Command {
    Connect {
        profile: Box<ProfileSpec>,
        password: Zeroizing<String>,
    },
    Disconnect,
    Shutdown,
}

/// Daemon-wide options that are not part of a profile.
#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// Leave DNS configuration to the caller (network namespace/container).
    pub no_host_dns: bool,
    /// Per-daemon nftables table scope (see [`crate::firewall::instance_scope`]).
    pub firewall_scope: String,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            no_host_dns: false,
            firewall_scope: "rustvpn-clientd".into(),
        }
    }
}

/// Effective MTUs used for this connection.
#[derive(Clone, Copy, Debug)]
struct MtuInfo {
    daemon: usize,
    inner: usize,
    mss_v4: Option<usize>,
    mss_v6: Option<usize>,
}

pub struct Engine;

impl Engine {
    pub fn spawn(
        commands: mpsc::Receiver<Command>,
        events: broadcast::Sender<Event>,
    ) -> JoinHandle<()> {
        Self::spawn_with_options(commands, events, EngineOptions::default())
    }

    pub fn spawn_with_options(
        commands: mpsc::Receiver<Command>,
        events: broadcast::Sender<Event>,
        options: EngineOptions,
    ) -> JoinHandle<()> {
        tokio::spawn(async move { Self::run(commands, events, options).await })
    }

    pub async fn run(
        mut commands: mpsc::Receiver<Command>,
        events: broadcast::Sender<Event>,
        options: EngineOptions,
    ) {
        // Windows crash recovery: a previous daemon that died while connected
        // leaves routes/DNS/NRPT/firewall entries recorded in
        // %ProgramData%\RustVPN\netstate.json.  Remove only those entries before
        // accepting commands.  A live owner (another daemon) is left alone.
        #[cfg(windows)]
        match crate::netcfg::cleanup_stale_network().await {
            Ok(report) if report.skipped_live_owner => emit_log(
                &events,
                "warn",
                "another RustVPN client still owns Windows network state; \
                 crash recovery was skipped",
            ),
            Ok(report) if !report.actions.is_empty() || !report.errors.is_empty() => {
                for action in &report.actions {
                    emit_log(&events, "info", format!("crash recovery: {action}"));
                }
                for error in &report.errors {
                    emit_log(
                        &events,
                        "warn",
                        format!("crash recovery left state for the next retry: {error}"),
                    );
                }
            }
            Ok(_) => {}
            Err(error) => emit_log(
                &events,
                "warn",
                format!("cannot inspect crash-recovery network state: {error:#}"),
            ),
        }

        let mut current: Option<(CancellationToken, JoinHandle<()>)> = None;
        // True once a connection task has completed, i.e. the Wintun adapter
        // may just have been closed.  Windows must not issue a network query
        // immediately after that close; a failed cleanup is retried on the
        // next daemon start instead.
        #[cfg(windows)]
        let mut connection_closed = false;
        loop {
            tokio::select! {
                cmd = commands.recv() => {
                    match cmd {
                        Some(Command::Connect { profile, password }) => {
                            #[cfg(windows)]
                            if current.is_some() {
                                connection_closed = true;
                            }
                            stop_current(&mut current).await;
                            let cancel = CancellationToken::new();
                            let handle = tokio::spawn(run_connection(
                                *profile,
                                password,
                                cancel.clone(),
                                events.clone(),
                                options.clone(),
                            ));
                            current = Some((cancel, handle));
                        }
                        Some(Command::Disconnect) => {
                            // The IPC acknowledgement is sent as soon as the
                            // command is queued, not when teardown completes.
                            // Publish a distinct state so clients can tell the
                            // difference instead of assuming `Ok` means idle.
                            let _ = events.send(Event::State(EngineStatus {
                                state: "disconnecting".into(),
                                ..EngineStatus::default()
                            }));
                            #[cfg(windows)]
                            let was_active = current.is_some();
                            stop_current(&mut current).await;
                            #[cfg(windows)]
                            if was_active {
                                connection_closed = true;
                            }
                            // An explicit disconnect restores connectivity even
                            // when the daemon is idle with a crash-preserved
                            // kill-switch table (no connection guard to remove).
                            #[cfg(unix)]
                            crate::firewall::cleanup_stale(&options.firewall_scope).await;
                            // A crashed Windows daemon may have left state even
                            // when the engine is idle (no guard to remove).
                            //
                            // Only the idle path may query the network here.
                            // When a connection just ended, its adapter has
                            // already been closed; a `Get-Net*` query at this
                            // point is the suspected second trigger of the
                            // Windows hang and must be deferred to the next
                            // daemon start (before any adapter is opened).
                            #[cfg(windows)]
                            if !connection_closed {
                                if let Err(error) = crate::netcfg::cleanup_owned_network().await {
                                    emit_log(
                                        &events,
                                        "warn",
                                        format!("cannot clean Windows network state: {error:#}"),
                                    );
                                }
                            }
                            let _ = events.send(Event::State(EngineStatus {
                                state: "idle".into(),
                                ..EngineStatus::default()
                            }));
                            emit_log(&events, "info", "disconnected");
                        }
                        Some(Command::Shutdown) | None => {
                            #[cfg(windows)]
                            if current.is_some() {
                                connection_closed = true;
                            }
                            stop_current(&mut current).await;
                            break;
                        }
                    }
                }
                _ = async {
                    if let Some((_, handle)) = current.as_mut() {
                        let _ = handle.await;
                    }
                }, if current.is_some() => {
                    current = None;
                    #[cfg(windows)]
                    {
                        connection_closed = true;
                    }
                }
            }
        }

        // Final retry for a daemon that never ran a connection (for example a
        // crash-preserved state found while idle).  If a connection did run,
        // its teardown already handled cleanup; querying the network now would
        // happen right after the adapter close, which is exactly what this
        // contract forbids.  A failed cleanup is retried on the next start.
        #[cfg(windows)]
        if !connection_closed {
            if let Err(error) = crate::netcfg::cleanup_owned_network().await {
                emit_log(
                    &events,
                    "warn",
                    format!("cannot finish Windows network cleanup: {error:#}"),
                );
            }
        }
    }
}

async fn stop_current(current: &mut Option<(CancellationToken, JoinHandle<()>)>) {
    if let Some((cancel, handle)) = current.take() {
        cancel.cancel();
        let _ = handle.await;
    }
}

/// Device half of the teardown contract, fakeable in unit tests.
trait TeardownDevice {
    /// Stop the platform reader thread without closing the device.
    fn stop_reader(&self);
    /// Close the device (Windows: session shutdown + adapter close).
    ///
    /// Returns whether the device really closed.  For [`Arc<Tap>`] this is
    /// false when another strong reference leaked: the Wintun session would
    /// still be live, so post-close address work must not run.
    fn close(self) -> bool;
}

impl TeardownDevice for Arc<Tap> {
    fn stop_reader(&self) {
        Tap::stop_reader(self.as_ref());
    }

    fn close(self) -> bool {
        let last_reference = Arc::strong_count(&self) == 1;
        drop(self);
        last_reference
    }
}

/// Ordered host teardown for a connection.
///
/// The contract, in order:
///
/// 1. stop the platform reader (Windows: join the Wintun shim reader),
/// 2. run the pre-close cleanup closure (Windows: NRPT, DNS, interface metric
///    and IPv6 firewall only - never `Remove-NetRoute`/`Remove-NetIPAddress`
///    against a live Wintun session),
/// 3. close the device (Windows: session shutdown + adapter close, which also
///    removes the address and its connected/default/split routes).
///
/// The caller then publishes the idle status.  Host routes, the address of a
/// pre-existing adapter and the state file are deliberately **not** touched
/// here: the next connect (before opening an adapter) or the next daemon start
/// runs the full cleanup with no Wintun session present.
/// Returns the cleanup value and whether the device really closed.
async fn teardown_connection<D, R, RFut, T>(device: D, remove_network: R) -> (T, bool)
where
    D: TeardownDevice,
    R: FnOnce() -> RFut,
    RFut: Future<Output = T>,
{
    device.stop_reader();
    let cleanup = remove_network().await;
    let closed = device.close();
    // Returned to the caller so it can clear the state file only after close.
    (cleanup, closed)
}

/// Clean previous Windows network state before any adapter is opened.
///
/// This is also the deferred-cleanup point for a normal Disconnect: the
/// anti-loop host route and netstate.json are left in place by the disconnect
/// path and removed here, while this process has no Wintun session open.
///
/// Runs the daemon's own leftover state first, then dead-owner crash state.  A
/// failure (or a state file still owned by another live process) refuses the
/// connection instead of mutating a live Wintun session later.
#[cfg(windows)]
async fn cleanup_before_opening_adapter(events: &broadcast::Sender<Event>) -> anyhow::Result<()> {
    let owned = crate::netcfg::cleanup_owned_network().await?;
    if !owned.errors.is_empty() {
        anyhow::bail!(
            "cannot clean this client's previous network state: {}",
            owned.errors.join("; ")
        );
    }
    let stale = crate::netcfg::cleanup_stale_network().await?;
    if stale.skipped_live_owner {
        anyhow::bail!(
            "another live RustVPN owner still owns Windows network state; refusing to open \
             an adapter"
        );
    }
    if !stale.errors.is_empty() {
        anyhow::bail!(
            "cannot clean previous Windows network state: {}",
            stale.errors.join("; ")
        );
    }
    for action in owned.actions.iter().chain(stale.actions.iter()) {
        emit_log(
            events,
            "info",
            format!("pre-connect network cleanup: {action}"),
        );
    }
    Ok(())
}

/// Whether resolving `host` needs the temporary DNS allowance.
///
/// `lookup_host` parses an IP literal (with an optional port) locally, so the
/// crash bootstrap must not widen the table for an IP-literal remote.  This
/// keeps the DNS hole limited to hostname remotes and preserves the previous
/// behavior for IP literals.
fn lookup_needs_dns(host: &str) -> bool {
    host.parse::<std::net::SocketAddr>().is_err()
}

/// Ordering contract for the kill-switch table preserved across a crash.
///
/// A crash-preserved table keeps its `drop` policy; the engine widens it just
/// enough to reconnect:
///
/// 1. The temporary DNS allowance must be open before a DNS lookup.
/// 2. After a successful lookup the rules are narrowed to the resolved outer
///    endpoint, which closes the allowance again.
/// 3. If the handshake then fails, `endpoints` is cleared and the next loop
///    iteration must re-open the allowance before it can resolve again.
/// 4. A successful handshake replaces the table with the full rule set (or
///    removes it); no bootstrap is needed afterwards.
///
/// Tracking this explicitly instead of a single `stale` bool prevents both
/// the DNS-blocked reconnect loop and a DNS allowance left open by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootstrapState {
    /// A preserved table is still enforcing the kill switch.
    active: bool,
    /// The temporary DNS allowance is currently present in that table.
    dns_open: bool,
}

impl BootstrapState {
    /// No crash-preserved table; the normal path never touches the firewall.
    fn inactive() -> Self {
        Self {
            active: false,
            dns_open: false,
        }
    }

    /// A preserved table exists but its DNS allowance is not confirmed open
    /// (the initial bootstrap has not succeeded yet).
    ///
    /// The crash-preserved kill switch is Unix/nftables-only; Windows keeps
    /// the neutral state machine compiled but does not use this constructor.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    fn pending() -> Self {
        Self {
            active: true,
            dns_open: false,
        }
    }

    /// Whether the preserved table still exists and has not been replaced.
    ///
    /// The crash-preserved table is Unix/nftables-only; Windows keeps the
    /// neutral state machine compiled but never queries this accessor.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    fn active(&self) -> bool {
        self.active
    }

    /// Whether the engine must (re-)open the DNS allowance before resolving.
    fn needs_dns(&self) -> bool {
        self.active && !self.dns_open
    }

    /// Whether the engine must narrow the table before a handshake.
    fn needs_narrow(&self) -> bool {
        self.active
    }

    /// Record the outcome of `bootstrap_kill_switch(scope, None, true)`.
    /// `present == false` means the table vanished; stop claiming fail-closed.
    fn record_dns(&mut self, present: bool) {
        if present {
            self.dns_open = true;
        } else {
            *self = Self::inactive();
        }
    }

    /// Record the outcome of `bootstrap_kill_switch(scope, Some(outer), false)`.
    /// `present == false` means the table vanished; stop claiming fail-closed.
    fn record_narrow(&mut self, present: bool) {
        if present {
            self.dns_open = false;
        } else {
            *self = Self::inactive();
        }
    }

    /// Record a failed bootstrap call.
    ///
    /// `bootstrap_commands` flushes the `output` chain first, so *any* failure
    /// after that flush removes the temporary DNS allowance even if the engine
    /// previously recorded it as open.  In particular a narrow that flushes
    /// successfully but then fails to add a rule would otherwise leave
    /// `dns_open == true`; the handshake failure would clear `endpoints` and
    /// the next lookup would never re-open DNS, recreating the deadlock.
    ///
    /// The table stays `active` (fail-closed) because the chain's `drop`
    /// policy is untouched; a retry re-runs the idempotent bootstrap.
    fn record_error(&mut self) {
        if self.active {
            self.dns_open = false;
        }
    }

    /// A successful handshake installed the full rule set (or removed the
    /// table).  The temporary allowance is gone in either case.
    ///
    /// Unix/nftables-only path; see [`Self::pending`].
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    fn replaced(&mut self) {
        *self = Self::inactive();
    }
}

async fn run_connection(
    spec: ProfileSpec,
    password: Zeroizing<String>,
    cancel: CancellationToken,
    events: broadcast::Sender<Event>,
    options: EngineOptions,
) {
    // Publish `connecting` before validation/key derivation and any network
    // change so the UI never falls back to a stale idle state.
    let mut pending = spec_status(&spec);
    pending.state = "connecting".into();
    let _ = events.send(Event::State(pending));

    let mut validated = match ValidatedProfile::new(&spec) {
        Ok(validated) => validated,
        Err(error) => {
            emit_error(&events, &spec, format!("{error:#}"));
            emit_log(&events, "error", format!("profile rejected: {error:#}"));
            return;
        }
    };

    // The Windows client does not implement a fail-closed kill switch yet.
    // Refuse an opt-in kill-switch profile instead of silently leaving the host
    // fail-open while the profile claims otherwise.
    if cfg!(not(unix)) && spec.kill_switch {
        let message = "kill_switch is not implemented on Windows; refusing to connect \
                       rather than silently leaving the host fail-open (deferred; the \
                       Windows guard still blocks IPv6 for full-tunnel profiles)";
        emit_error(&events, &spec, message.to_string());
        emit_log(&events, "error", message);
        return;
    }

    // Share the tunnel lock with the CLI before touching TAP/routes.
    let _lock = match TunnelLock::acquire(&spec.name, &spec.remote, "daemon") {
        Ok(lock) => lock,
        Err(error) => {
            emit_error(&events, &spec, format!("{error:#}"));
            emit_log(&events, "error", format!("tunnel lock: {error:#}"));
            return;
        }
    };
    emit_log(
        &events,
        "info",
        format!("tunnel lock acquired: {}", _lock.path().display()),
    );
    #[cfg(unix)]
    crate::netcfg::cleanup_stale_ipv6_blackhole().await;

    // Argon2d is intentionally expensive.  Keep it off the async workers so
    // status/Disconnect requests stay responsive while a profile is opened.
    let (validated, signing_key) = match tokio::task::spawn_blocking(move || {
        let key = validated.derive_signing_key(&password)?;
        Ok::<_, anyhow::Error>((validated, key))
    })
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            emit_error(&events, &spec, format!("{error:#}"));
            emit_log(
                &events,
                "error",
                format!("key derivation failed: {error:#}"),
            );
            return;
        }
        Err(error) => {
            let message = format!("key derivation task failed: {error}");
            emit_error(&events, &spec, message.clone());
            emit_log(&events, "error", message);
            return;
        }
    };

    // The daemon start already applied the crash policy: after a clean
    // shutdown all tables are gone, after a crash the kill switch is preserved.
    // Never delete it here, or a crash-restarted daemon would re-open the host.
    // Bootstrap after validation/key derivation so a bad passphrase cannot
    // leave a temporary DNS hole in a preserved table.
    let scope = options.firewall_scope.clone();
    let mut bootstrap = BootstrapState::inactive();
    #[cfg(unix)]
    if crate::firewall::kill_switch_present(&scope).await {
        bootstrap = BootstrapState::pending();
        match crate::firewall::bootstrap_kill_switch(&scope, None, true).await {
            Ok(true) => {
                bootstrap.record_dns(true);
                emit_log(
                    &events,
                    "info",
                    "preserved kill-switch table from a previous run (fail-closed); \
                     bootstrap allows only loopback, DNS and underlay control traffic \
                     until the handshake succeeds.  The temporary DNS allowance is \
                     re-opened before every hostname lookup and narrowed away \
                     before the handshake",
                );
            }
            Ok(false) => {
                // The table disappeared between the probe and the bootstrap.
                // Nothing is preserved, so do not claim fail-closed.
                bootstrap.record_dns(false);
                emit_log(
                    &events,
                    "warn",
                    "preserved kill-switch table is no longer available; continuing \
                     without the crash-preserved kill switch",
                );
            }
            Err(error) => {
                // Keep the table active but leave the allowance unconfirmed:
                // the loop retries the bootstrap before its first lookup.
                bootstrap.record_error();
                emit_log(&events, "warn", format!("kill-switch bootstrap: {error:#}"));
            }
        }
    }

    emit_log(&events, "info", format!("connecting to {}", spec.remote));
    if spec.keepalive > 0 && (spec.noise || spec.encless) {
        emit_log(
            &events,
            "warn",
            format!(
                "keepalive={}s in {} mode is padded to the MTU per packet; \
                 the v1 wire format cannot send a shorter keepalive",
                spec.keepalive,
                spec.mode_name()
            ),
        );
    }

    // v1 treats the numeric MTU as a two-sided wire contract.  Derive only
    // the TAP interface IP MTU and MSS from it; never change `spec.mtu`.
    let mode = validated.mode_enum();
    let wire = match mtu::from_wire(mode, spec.mtu) {
        Ok(value) => value,
        Err(error) => {
            emit_error(&events, &spec, format!("MTU: {error:#}"));
            emit_log(&events, "error", format!("MTU: {error:#}"));
            return;
        }
    };
    emit_log(&events, "info", wire.log_line());
    let daemon_mtu = spec.mtu;
    let link_mtu = wire.inner_ip_mtu;
    let (mss_v4, mss_v6) = if spec.mss_clamp {
        (Some(wire.mss_v4), Some(wire.mss_v6))
    } else {
        (None, None)
    };

    // Encless is the only case where the outer path capacity still matters
    // for a warning.  This never changes the configured wire MTU.  The probe
    // uses Linux `ip`, so it is Unix-only; Windows gets the same v1 MTU
    // contract without a path-MTU check.
    let mut endpoints: Option<Endpoints> = None;
    #[cfg(unix)]
    if spec.encless {
        match resolve_endpoints(&spec.remote, &spec.proxy).await {
            Ok(resolved) => endpoints = Some(resolved),
            Err(error) => emit_log(
                &events,
                "warn",
                format!("cannot resolve outer endpoint for encless capacity check: {error:#}"),
            ),
        }
        if let Some(addr) = endpoints.as_ref().and_then(Endpoints::outer) {
            if let Ok(path) = mtu::detect_path_mtu(addr).await {
                let needed = spec.mtu
                    + rustvpn_proto::ENCLESS_ENLARGE_SIZE
                    + OuterFamily::from_addr(&addr).header_len(validated.proto());
                if path.underlay_mtu < needed {
                    emit_log(
                        &events,
                        "warn",
                        format!(
                            "encless with mtu={} needs ~{} byte outer path but {} ({}) is {}; \
                             expect fragmentation or large-packet loss",
                            spec.mtu, needed, path.dev, path.source, path.underlay_mtu
                        ),
                    );
                }
            }
        }
    }
    let resolved = MtuInfo {
        daemon: daemon_mtu,
        inner: link_mtu,
        mss_v4,
        mss_v6,
    };

    // Build the platform-neutral interface config.  Linux ignores the
    // Windows-only fields; Windows uses the verifier id for a stable synthetic
    // MAC and the derived inner IP MTU (never the wire budget).
    let tap_config = match tap_config_for(&validated, &spec, mode, daemon_mtu, link_mtu) {
        Ok(config) => config,
        Err(error) => {
            emit_error(
                &events,
                &spec,
                format!("configure TAP {}: {error:#}", spec.iface),
            );
            emit_log(
                &events,
                "error",
                format!("configure TAP {}: {error:#}", spec.iface),
            );
            return;
        }
    };
    // Windows: clean any previous RustVPN network state *before* opening the
    // adapter.  This is the only safe time to run crash-recovery commands;
    // install later refuses if state is still recorded, and nothing issues
    // Remove-Net* against a live Wintun session.
    #[cfg(windows)]
    if let Err(error) = cleanup_before_opening_adapter(&events).await {
        emit_error(&events, &spec, format!("Windows network state: {error:#}"));
        emit_log(
            &events,
            "error",
            format!("Windows network state: {error:#}"),
        );
        return;
    }
    let tap = match Tap::open_with_config(&tap_config).await {
        Ok(tap) => Arc::new(tap),
        Err(error) => {
            emit_error(&events, &spec, format!("open TAP {}: {error}", spec.iface));
            emit_log(
                &events,
                "error",
                format!("open TAP {}: {error}", spec.iface),
            );
            return;
        }
    };
    emit_log(&events, "info", format!("TAP {} opened", spec.iface));
    #[cfg(unix)]
    if let Err(error) = crate::netcfg::bring_link_up(&spec.iface, link_mtu).await {
        emit_error(&events, &spec, format!("bring up TAP: {error:#}"));
        emit_log(&events, "error", format!("bring up TAP: {error:#}"));
        return;
    }
    if cfg!(not(unix)) {
        emit_log(
            &events,
            "info",
            format!(
                "Windows Wintun adapter {} opened with interface MTU {}; address, routes, DNS, \
                 NRPT and the IPv6 block are installed after the handshake succeeds",
                spec.iface, link_mtu
            ),
        );
        if spec.mss_clamp {
            emit_log(
                &events,
                "warn",
                "TCP MSS clamping is not implemented on Windows; the tunnel relies on the \
                 configured wire-MTU contract and mss_applied will be false",
            );
        }
    }

    let stats_state = StatsState::new();
    // Endpoints are resolved once the handshake path needs them.  Until the
    // first successful handshake no routes or DNS are installed, so a failed
    // attempt cannot black-hole the host.  After the first success the address
    // is pinned for reconnects (the tunnel may own the default route at that
    // point, which would make a fresh DNS lookup unreliable).
    #[cfg_attr(target_os = "windows", allow(unused_mut))]
    let mut guard: Option<NetworkGuard> = None;
    let mut attempt: u32 = 0;
    let mut last_status = base_status(&validated, resolved, applied_from_guard(guard.as_ref()));

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let proto = validated.proto();
        let remote = spec.remote.as_str();
        let proxy = spec.proxy.as_str();
        let proxy_auth = spec.proxy_auth.as_str();
        let outcome = attempt_connection(
            &mut bootstrap,
            &mut endpoints,
            &scope,
            validated.outer_host(),
            &events,
            || {
                last_status.state = "connecting".into();
                last_status.next_retry_in = None;
                last_status.since_unix = None;
                let _ = events.send(Event::State(last_status.clone()));
                emit_log(
                    &events,
                    "info",
                    format!(
                        "connecting {} over {} ({})",
                        spec.remote,
                        validated.proto(),
                        validated.mode()
                    ),
                );
            },
            || resolve_endpoints(&spec.remote, &spec.proxy),
            |endpoints: Endpoints| {
                let cfg = validated.peer_config_with_mtu(signing_key.clone(), resolved.daemon);
                let signing_key = signing_key.clone();
                let tap = tap.clone();
                let stats_state = stats_state.clone();
                async move {
                    start_session(
                        cfg,
                        signing_key,
                        tap,
                        stats_state,
                        remote,
                        &endpoints,
                        proto,
                        proxy,
                        proxy_auth,
                        "",
                    )
                    .await
                }
            },
        )
        .await;

        let mut planned_rekey = false;
        match outcome {
            Attempt::Succeeded(mut session) => {
                let mut connected_status =
                    base_status(&validated, resolved, applied_from_guard(guard.as_ref()));
                if guard.is_none() {
                    let outer = endpoints.as_ref().and_then(Endpoints::outer);
                    let net_options = NetOptions {
                        firewall: FirewallOptions {
                            mss_v4: resolved.mss_v4,
                            mss_v6: resolved.mss_v6,
                            kill_switch: spec.kill_switch,
                            scope: options.firewall_scope.clone(),
                        },
                        no_host_dns: options.no_host_dns,
                    };
                    match NetworkGuard::install(&spec, outer, resolved.inner, net_options).await {
                        Ok(installed) => {
                            connected_status.mss_applied = Some(installed.mss_applied());
                            connected_status.kill_switch_applied =
                                Some(installed.kill_switch_applied());
                            guard = Some(installed);
                            #[cfg(unix)]
                            if bootstrap.active() {
                                if spec.kill_switch {
                                    // apply_kill_switch replaced the preserved
                                    // table with the full current rule set.
                                    emit_log(
                                        &events,
                                        "info",
                                        "replaced the preserved kill-switch table with the \
                                         current profile's rule set",
                                    );
                                } else {
                                    crate::firewall::remove_kill_switch(&scope).await;
                                    emit_log(
                                        &events,
                                        "info",
                                        "removed the preserved kill-switch table; this \
                                         profile does not request a kill switch",
                                    );
                                }
                                bootstrap.replaced();
                            }
                            emit_log(
                                &events,
                                "info",
                                format!(
                                    "configured {} on {} with {} route(s)",
                                    spec.address,
                                    spec.iface,
                                    spec.routes.len()
                                ),
                            );
                            #[cfg(windows)]
                            emit_log(
                                &events,
                                "info",
                                if spec
                                    .routes
                                    .iter()
                                    .any(|route| rustvpn_net::config::is_default_route(route))
                                {
                                    "Windows full tunnel: default route via Wintun, per-interface \
                                     DNS + NRPT, and global/ULA IPv6 egress blocked for this \
                                     connection (removed on disconnect)"
                                } else {
                                    "Windows split tunnel: profile routes via Wintun only; system \
                                     DNS and IPv6 behaviour are left as configured unless the \
                                     profile specifies DNS"
                                },
                            );
                        }
                        Err(failure) => {
                            // P1-3: stop the data plane before rolling back the
                            // partial network state.  No Remove-Net* command
                            // may run while the peer tasks or shim reader can
                            // still touch the Wintun session.
                            let message = failure.message();
                            session.close(&stats_state).await;
                            tap.stop_reader();
                            let cleanup = failure.rollback().await;
                            let closed = Arc::strong_count(&tap) == 1;
                            drop(tap);
                            // Routes/address and the state file are kept for
                            // the next connect/daemon start, which clean them
                            // with no Wintun session open.
                            cleanup.finish_after_close(closed).await;
                            emit_error(&events, &spec, message.clone());
                            emit_log(&events, "error", message);
                            emit_log(&events, "info", "tunnel stopped");
                            return;
                        }
                    }
                }

                attempt = 0;
                connected_status.state = "connected".into();
                connected_status.since_unix = Some(unix_now());
                let _ = events.send(Event::State(connected_status.clone()));
                emit_log(&events, "info", "session established");

                let end = session_loop(&mut session, &cancel, &events, &mut connected_status).await;
                // Joins every peer task: no task keeps a `Tap` clone after
                // this returns, so the final `drop(tap)` really closes the
                // adapter.
                session.close(&stats_state).await;
                if cancel.is_cancelled() {
                    break;
                }
                planned_rekey = matches!(end, SessionEnd::Rekey);
                let reason = match end {
                    SessionEnd::Timeout => "timeout",
                    SessionEnd::Rehandshake => "rehandshake",
                    SessionEnd::Rekey => "time-based rekey",
                    SessionEnd::TcpClosed => "connection closed",
                    SessionEnd::TapClosed => "TAP closed",
                    SessionEnd::Terminated => "terminated",
                };
                if planned_rekey {
                    // The v1 protocol has no rekey message, so this is a
                    // scheduled reconnect: new handshake immediately, with a
                    // brief packet gap.  It is not zero-loss.
                    emit_log(
                        &events,
                        "info",
                        "planned rekey: reconnecting immediately (no session overlap; \
                         short packet gap possible)",
                    );
                } else {
                    emit_log(&events, "warn", format!("session ended: {reason}"));
                }
                connected_status.state = "reconnecting".into();
                connected_status.since_unix = None;
                connected_status.traffic = TrafficSample::default();
                connected_status.last_error = Some(reason.to_string());
                last_status = connected_status;
            }
            Attempt::ResolveFailed(error) => {
                attempt = attempt.saturating_add(1);
                let message = format!("resolve {}: {error:#}", validated.outer_host());
                emit_log(&events, "error", &message);
                let mut status =
                    base_status(&validated, resolved, applied_from_guard(guard.as_ref()));
                status.state = "reconnecting".into();
                status.last_error = Some(message);
                last_status = status.clone();
                let delay = backoff(attempt);
                status.next_retry_in = Some(delay.as_secs());
                let _ = events.send(Event::State(status));
                emit_log(
                    &events,
                    "info",
                    format!("reconnecting in {}s", delay.as_secs()),
                );
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.cancelled() => break,
                }
                continue;
            }
            Attempt::HandshakeFailed(error) => {
                attempt = attempt.saturating_add(1);
                let message = format!("{error:#}");
                emit_log(&events, "error", format!("session failed: {message}"));
                let mut status =
                    base_status(&validated, resolved, applied_from_guard(guard.as_ref()));
                status.state = "reconnecting".into();
                status.last_error = Some(message);
                last_status = status;
                // Before the first success no routes/DNS are installed; a
                // fresh lookup is safe and picks up DNS changes.
                if guard.is_none() {
                    endpoints = None;
                }
            }
        }

        let delay = if planned_rekey {
            Duration::ZERO
        } else {
            backoff(attempt)
        };
        last_status.next_retry_in = Some(delay.as_secs());
        let _ = events.send(Event::State(last_status.clone()));
        if !(planned_rekey && delay.is_zero()) {
            emit_log(
                &events,
                "info",
                format!("reconnecting in {}s", delay.as_secs()),
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = cancel.cancelled() => break,
        }
    }

    #[cfg(unix)]
    let had_guard = guard.is_some();
    // Every session above was closed by an awaited `session.close()` (which
    // joins the peer tasks), so no task holds a `Tap` clone anymore.  The
    // ordered teardown is:
    //   1. stop the platform reader,
    //   2. remove only non-route state (NRPT/DNS/metric/IPv6) while the Wintun
    //      session is still open,
    //   3. close the adapter as the final `Tap` reference.
    // Routes (including the anti-loop host route), a pre-existing adapter's
    // address and netstate.json are **deferred**: no network command runs after
    // the close.  The next connect (before opening an adapter) or the next
    // daemon start removes them with no Wintun session present.
    let (cleanup, closed) = teardown_connection(tap, || async {
        let cleanup = match guard {
            Some(guard) => guard.begin_connection_teardown().await,
            None => ConnectionCleanup::none(),
        };
        // An explicit disconnect/stop must restore connectivity even if the
        // daemon only ever managed to bootstrap through a preserved crash
        // table.  A failed setup (which returns above without cancellation)
        // deliberately leaves the table installed (fail-closed).
        #[cfg(unix)]
        if !had_guard && bootstrap.active() && cancel.is_cancelled() {
            crate::firewall::remove_kill_switch(&scope).await;
            emit_log(
                &events,
                "info",
                "removed the preserved kill switch on explicit stop; connectivity restored",
            );
        }
        cleanup
    })
    .await;
    // The adapter is closed; this only reports the pre-close cleanup and
    // keeps netstate.json.  No network command may run here.
    cleanup.finish_after_close(closed).await;
    emit_log(&events, "info", "tunnel stopped");
}

/// Build the platform-neutral interface config from a validated profile.
///
/// Only the numeric wire MTU is carried into the transport; the interface MTU
/// is derived by [`TapConfig`] and cross-checked against the engine's own
/// `mtu::from_wire` result so the two can never drift.
fn tap_config_for(
    validated: &ValidatedProfile,
    spec: &ProfileSpec,
    mode: Mode,
    wire_mtu: usize,
    expected_inner_mtu: usize,
) -> anyhow::Result<TapConfig> {
    let address: IpNet = spec
        .address
        .parse()
        .with_context(|| format!("invalid address {:?}", spec.address))?;
    let gateway = if spec.gateway.trim().is_empty() {
        None
    } else {
        Some(
            spec.gateway
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid gateway {:?}", spec.gateway))?,
        )
    };
    let dns = spec
        .dns
        .iter()
        .map(|server| {
            server
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid DNS server {server:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let config = TapConfig::new(&spec.iface, wire_mtu, mode, address)
        .with_gateway(gateway)
        .with_dns(dns)
        .with_verifier_id(validated.verifier().id);
    let derived = config
        .inner_ip_mtu()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if derived != expected_inner_mtu {
        return Err(anyhow::anyhow!(
            "platform interface MTU {derived} disagrees with the engine-derived inner MTU \
             {expected_inner_mtu}"
        ));
    }
    Ok(config)
}

/// Result of one attempt's bootstrap, resolution and handshake phases.
#[derive(Debug)]
enum Attempt<T> {
    /// The outer endpoint could not be resolved; the cached one stays empty.
    ResolveFailed(anyhow::Error),
    /// Resolution and narrowing completed but the handshake failed.
    HandshakeFailed(anyhow::Error),
    /// The handshake succeeded.
    Succeeded(T),
}

/// Drive the production connect ordering for one attempt.
///
/// This is the single implementation of the crash-bootstrap contract used by
/// [`run_connection`], so a reordering bug cannot hide behind tests of the
/// state helper alone:
///
/// 1. While the preserved table is active and the remote needs a lookup, open
///    the temporary DNS allowance *before* resolving.
/// 2. Resolve the outer endpoint when none is cached.
/// 3. Narrow the preserved table to that endpoint *before* the handshake.
/// 4. Run the handshake.
///
/// `before_handshake` runs after narrowing and immediately before the
/// handshake, which is where the engine emits its `connecting` status/log.
#[allow(clippy::too_many_arguments)]
async fn attempt_connection<T, RF, RFut, HF, HFut>(
    bootstrap: &mut BootstrapState,
    endpoints: &mut Option<Endpoints>,
    scope: &str,
    host: &str,
    events: &broadcast::Sender<Event>,
    before_handshake: impl FnOnce(),
    resolve: RF,
    handshake: HF,
) -> Attempt<T>
where
    RF: FnOnce() -> RFut,
    RFut: Future<Output = anyhow::Result<Endpoints>>,
    HF: FnOnce(Endpoints) -> HFut,
    HFut: Future<Output = anyhow::Result<T>>,
{
    if endpoints.is_none() {
        // While a crash-preserved table is active, the temporary DNS
        // allowance must be open before *every* lookup.  A failed handshake
        // clears `endpoints` after the previous iteration narrowed the table
        // to the (now stale) outer endpoint, which drops DNS; without
        // re-opening it the retry — and every retry after it — could never
        // resolve a hostname remote again.  `bootstrap_commands` flushes the
        // chain first, so this is idempotent and never accumulates duplicate
        // rules.  IP-literal remotes are parsed locally, so they keep DNS
        // closed as before.
        if bootstrap.needs_dns() && lookup_needs_dns(host) {
            match crate::firewall::bootstrap_kill_switch(scope, None, true).await {
                Ok(present) => {
                    if !present {
                        emit_log(
                            events,
                            "warn",
                            "preserved kill-switch table is no longer available; \
                             continuing without the crash-preserved kill switch",
                        );
                    }
                    bootstrap.record_dns(present);
                }
                Err(error) => {
                    // The flush may have removed the allowance before the
                    // failure; require a fresh successful bootstrap before the
                    // next lookup.
                    bootstrap.record_error();
                    emit_log(
                        events,
                        "warn",
                        format!("kill-switch DNS bootstrap: {error:#}"),
                    );
                }
            }
        }
        match resolve().await {
            Ok(resolved) => *endpoints = Some(resolved),
            Err(error) => return Attempt::ResolveFailed(error),
        }
    }

    if bootstrap.needs_narrow() {
        // DNS has served its purpose.  Narrow the preserved table to the
        // resolved outer endpoint so the handshake can pass while every other
        // host packet still hits the drop policy.  The temporary DNS allowance
        // is closed here; a failed handshake or a partial narrowing re-opens
        // it before the next lookup.
        if let Some(outer) = endpoints.as_ref().and_then(Endpoints::outer) {
            match crate::firewall::bootstrap_kill_switch(scope, Some(outer), false).await {
                Ok(present) => {
                    if !present {
                        emit_log(
                            events,
                            "warn",
                            "preserved kill-switch table is no longer available; \
                             continuing without the crash-preserved kill switch",
                        );
                    }
                    bootstrap.record_narrow(present);
                }
                Err(error) => {
                    // `bootstrap_commands` flushes first, so a later add
                    // failure means the DNS allowance is gone even though the
                    // state still said it was open.  Record that so the retry
                    // re-opens it instead of looping on blocked DNS.
                    bootstrap.record_error();
                    emit_log(
                        events,
                        "warn",
                        format!("kill-switch bootstrap for {outer}: {error:#}"),
                    );
                }
            }
        }
    }

    before_handshake();
    let endpoints = *endpoints.as_ref().expect("resolved above");
    match handshake(endpoints).await {
        Ok(value) => Attempt::Succeeded(value),
        Err(error) => Attempt::HandshakeFailed(error),
    }
}

async fn session_loop(
    session: &mut Session,
    cancel: &CancellationToken,
    events: &broadcast::Sender<Event>,
    status: &mut EngineStatus,
) -> SessionEnd {
    let start = Instant::now();
    let mut last_at = Instant::now();
    let mut last_rx = session.stats.bytes_in_total();
    let mut last_tx = session.stats.bytes_out_total();
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    timer.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return SessionEnd::Terminated,
            ev = session.handle.events.recv() => {
                return match ev {
                    Some(rustvpn_net::peer::PeerEvent::Timeout) => SessionEnd::Timeout,
                    Some(rustvpn_net::peer::PeerEvent::Rehandshake) => SessionEnd::Rehandshake,
                    Some(rustvpn_net::peer::PeerEvent::Rekey) => SessionEnd::Rekey,
                    Some(rustvpn_net::peer::PeerEvent::TcpClosed) => SessionEnd::TcpClosed,
                    Some(rustvpn_net::peer::PeerEvent::TapClosed) => SessionEnd::TapClosed,
                    None => SessionEnd::TcpClosed,
                };
            }
            _ = timer.tick() => {
                let now = Instant::now();
                let elapsed = now.duration_since(last_at).as_secs_f64().max(0.001);
                let snap = session.stats.snapshot();
                let rx = snap.bytes_in;
                let tx = snap.bytes_out;
                let traffic = TrafficSample {
                    rx_bytes: rx,
                    tx_bytes: tx,
                    rx_payload_bytes: snap.payload_in,
                    tx_payload_bytes: snap.payload_out,
                    rx_bps: ((rx.saturating_sub(last_rx)) as f64 / elapsed) as u64,
                    tx_bps: ((tx.saturating_sub(last_tx)) as f64 / elapsed) as u64,
                    uptime_s: start.elapsed().as_secs(),
                };
                last_rx = rx;
                last_tx = tx;
                last_at = now;
                status.endpoint = Some(snap.addr.clone());
                status.last_handshake_unix = Some(snap.last_ping.timestamp());
                status.heartbeat_sent = Some(snap.heartbeat_sent);
                status.heartbeat_recv = Some(snap.heartbeat_recv);
                status.frames_unauth = Some(snap.unauth);
                status.frames_dup = Some(snap.dup);
                status.rekey_in_sec = rekey_in_sec(rx, tx, traffic.rx_bps, traffic.tx_bps);
                status.rates_available = true;
                status.rate_window_sec = Some(1);
                status.traffic = traffic.clone();
                let _ = events.send(Event::Traffic(traffic));
            }
        }
    }
}

fn backoff(attempt: u32) -> Duration {
    let base = 1u64 << attempt.min(5); // 1, 2, 4, 8, 16, 30 seconds
    let base = base.min(30);
    let mut bytes = [0u8; 8];
    let jitter_ms = if getrandom::getrandom(&mut bytes).is_ok() {
        let max = (base * 200).max(1);
        u64::from_le_bytes(bytes) % max
    } else {
        0
    };
    Duration::from_secs(base) + Duration::from_millis(jitter_ms.min(999))
}

/// Remaining seconds before the 4 GiB per-key limit at the current wire rate.
fn rekey_in_sec(rx: u64, tx: u64, rx_bps: u64, tx_bps: u64) -> Option<u64> {
    let used = rx.saturating_add(tx);
    let remaining = MAX_BYTES_PER_KEY.saturating_sub(used);
    let rate = rx_bps.saturating_add(tx_bps);
    remaining.checked_div(rate)
}

fn base_status(
    validated: &ValidatedProfile,
    mtu: MtuInfo,
    applied: Option<(bool, bool)>,
) -> EngineStatus {
    let mut status = spec_status(validated.spec());
    status.proto = Some(validated.proto().to_string());
    status.mode = Some(validated.mode().to_string());
    status.mtu = Some(mtu.daemon);
    status.inner_mtu = Some(mtu.inner);
    status.mss = mtu.mss_v4;
    status.mss_v6 = mtu.mss_v6;
    status.mtu_source = Some("configured".into());
    status.kill_switch = Some(validated.spec().kill_switch);
    status.keepalive_sec = (validated.spec().keepalive > 0).then_some(validated.spec().keepalive);
    status.rekey_time_sec =
        (validated.spec().rekey_time > 0).then_some(validated.spec().rekey_time);
    // A reconnect keeps the live guard, so the applied flags must be carried
    // into every new status instead of reverting to "unknown".
    if let Some((mss, kill_switch)) = applied {
        status.mss_applied = Some(mss);
        status.kill_switch_applied = Some(kill_switch);
    }
    status
}

/// Applied firewall state of the live guard, if one is still installed.
fn applied_from_guard(guard: Option<&NetworkGuard>) -> Option<(bool, bool)> {
    guard.map(|guard| (guard.mss_applied(), guard.kill_switch_applied()))
}

fn spec_status(spec: &ProfileSpec) -> EngineStatus {
    let proto = if spec.proxy.trim().is_empty() {
        spec.proto.to_ascii_lowercase()
    } else {
        "tcp".into()
    };
    let mode = if spec.encless {
        "encless"
    } else if spec.noise {
        "noise"
    } else {
        "plain"
    };
    EngineStatus {
        state: "idle".into(),
        profile: Some(spec.name.clone()),
        remote: Some(spec.remote.clone()),
        proto: Some(proto),
        mode: Some(mode.into()),
        iface: Some(spec.iface.clone()),
        ..EngineStatus::default()
    }
}

fn emit_error(events: &broadcast::Sender<Event>, spec: &ProfileSpec, message: String) {
    let mut status = spec_status(spec);
    status.state = "error".into();
    status.last_error = Some(message);
    let _ = events.send(Event::State(status));
}

fn emit_log(events: &broadcast::Sender<Event>, level: &str, line: impl Into<String>) {
    let _ = events.send(Event::Log(LogLine {
        ts_ms: unix_now_ms(),
        level: level.into(),
        line: line.into(),
    }));
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::net::SocketAddr;

    struct RecordingDevice {
        log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl TeardownDevice for RecordingDevice {
        fn stop_reader(&self) {
            self.log.lock().unwrap().push("stop-reader");
        }

        fn close(self) -> bool {
            self.log.lock().unwrap().push("close-device");
            true
        }
    }

    #[tokio::test]
    async fn teardown_order_is_reader_then_non_route_then_close_then_defer_cleanup() {
        // Locks in the Windows teardown contract: the reader stops first, the
        // pre-close cleanup removes only non-route state, then the device
        // closes.  Host routes and the state file are deferred: no
        // Remove-NetRoute may run before or after the close in this path.
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let remove_log = log.clone();
        let finalize_log = log.clone();
        let (cleanup, closed) = teardown_connection(RecordingDevice { log: log.clone() }, || {
            let remove_log = remove_log;
            async move {
                remove_log.lock().unwrap().push("cleanup-non-route");
                "state-cleanup-token"
            }
        })
        .await;

        // Mirrors the caller: the post-close cleanup runs after the close.
        assert_eq!(cleanup, "state-cleanup-token");
        assert!(closed, "the recording device reports a real close");
        finalize_log.lock().unwrap().push("defer-host-routes");

        assert_eq!(
            &*log.lock().unwrap(),
            &[
                "stop-reader",
                "cleanup-non-route",
                "close-device",
                "defer-host-routes"
            ]
        );
    }

    #[test]
    fn backoff_is_bounded_and_grows() {
        for attempt in 0..8 {
            let delay = backoff(attempt);
            assert!(delay >= Duration::from_secs(1));
            assert!(delay <= Duration::from_secs(31));
        }
        assert!(backoff(4) >= Duration::from_secs(16));
        assert!(backoff(5) >= Duration::from_secs(30));
    }

    fn validated_profile() -> ValidatedProfile {
        let spec = ProfileSpec {
            name: "office".into(),
            remote: "vpn.example.com:1194".into(),
            proto: "udp".into(),
            verifier: "$argon2d$m=1024,t=4,p=1$AAECAwQFBgcICQoLDA0ODw".into(),
            mtu: 1515,
            timeout: 60,
            iface: "rsvpn0".into(),
            address: "10.88.0.2/24".into(),
            gateway: "10.88.0.1".into(),
            routes: vec!["default".into()],
            dns: vec!["10.88.0.1".into()],
            ..ProfileSpec::default()
        };
        ValidatedProfile::new(&spec).unwrap()
    }

    fn mtu_info() -> MtuInfo {
        MtuInfo {
            daemon: 1515,
            inner: 1500,
            mss_v4: Some(1460),
            mss_v6: Some(1440),
        }
    }

    #[test]
    fn tap_config_from_profile_uses_verifier_id_and_derived_mtu() {
        let validated = validated_profile();
        let cfg = tap_config_for(&validated, validated.spec(), Mode::Plain, 1515, 1500)
            .expect("platform config");
        assert_eq!(cfg.name, "rsvpn0");
        assert_eq!(cfg.wire_mtu, 1515);
        assert_eq!(cfg.inner_ip_mtu().unwrap(), 1500);
        assert_eq!(cfg.verifier_id, validated.verifier().id);
        assert_eq!(cfg.address.to_string(), "10.88.0.2/24");
        assert_eq!(cfg.gateway, Some(Ipv4Addr::new(10, 88, 0, 1)));
        assert_eq!(cfg.dns, vec![Ipv4Addr::new(10, 88, 0, 1)]);

        // A disagreement with the engine's own derivation is rejected instead
        // of silently re-deriving a platform-specific MTU.
        assert!(tap_config_for(&validated, validated.spec(), Mode::Plain, 1515, 1499).is_err());
    }

    #[test]
    fn tap_config_from_noise_profile_reserves_padding() {
        let mut spec = validated_profile().spec().clone();
        spec.noise = true;
        spec.mtu = 1539;
        let validated = ValidatedProfile::new(&spec).unwrap();
        let cfg =
            tap_config_for(&validated, &spec, Mode::Noise, 1539, 1500).expect("platform config");
        assert_eq!(cfg.wire_mtu, 1539);
        assert_eq!(cfg.inner_ip_mtu().unwrap(), 1500);
        assert_eq!(cfg.verifier_id, validated.verifier().id);
    }

    #[test]
    fn reconnect_status_keeps_applied_flags_from_the_live_guard() {
        let validated = validated_profile();
        let mut status = base_status(&validated, mtu_info(), Some((false, true)));
        assert_eq!(status.mss_applied, Some(false));
        assert_eq!(status.kill_switch_applied, Some(true));

        // Simulate the reconnect transition: the guard is still installed, so
        // the flags must survive the status rebuild.
        status.state = "reconnecting".into();
        assert_eq!(status.mss_applied, Some(false));
        assert_eq!(status.kill_switch_applied, Some(true));

        // Without a live guard the applied state is unknown, not false.
        let fresh = base_status(&validated, mtu_info(), None);
        assert_eq!(fresh.mss_applied, None);
        assert_eq!(fresh.kill_switch_applied, None);
    }

    #[test]
    fn applied_flags_reflect_padded_mode_false_values() {
        let validated = validated_profile();
        let status = base_status(&validated, mtu_info(), Some((false, false)));
        assert_eq!(status.mss_applied, Some(false));
        assert_eq!(status.kill_switch_applied, Some(false));
        assert_eq!(applied_from_guard(None), None);
    }

    #[test]
    fn only_hostname_remotes_need_the_dns_allowance() {
        // IP literals (with a port) are parsed locally by `lookup_host`, so
        // they must not widen the preserved table to port 53.
        assert!(!lookup_needs_dns("203.0.113.10:1194"));
        assert!(!lookup_needs_dns("[2001:db8::10]:1194"));
        // Hostnames and malformed inputs need (or attempt) a real lookup.
        assert!(lookup_needs_dns("vpn.example.com:1194"));
        assert!(lookup_needs_dns("203.0.113.10"));
    }

    #[test]
    fn inactive_bootstrap_never_touches_the_firewall() {
        // No crash-preserved table: the normal (and IP-literal) path must not
        // issue bootstrap commands in either direction.
        let bootstrap = BootstrapState::inactive();
        assert!(!bootstrap.active());
        assert!(!bootstrap.needs_dns());
        assert!(!bootstrap.needs_narrow());
    }

    #[test]
    fn bootstrap_reopens_dns_before_resolving_after_a_failed_handshake() {
        // Regression for the hostname-remote deadlock: after a crash the
        // initial bootstrap opens DNS, the lookup narrows the table to the
        // outer endpoint, and a failed handshake clears `endpoints`.  The next
        // lookup must re-open the DNS allowance or it can never resolve again.
        let mut bootstrap = BootstrapState::pending();
        let mut steps: Vec<&str> = Vec::new();

        // Initial bootstrap confirms the preserved table and opens DNS.
        assert!(bootstrap.needs_dns());
        bootstrap.record_dns(true);
        steps.push("open-dns");

        // Iteration 1: resolve succeeds, narrow, handshake fails.
        assert!(!bootstrap.needs_dns());
        assert!(bootstrap.needs_narrow());
        bootstrap.record_narrow(true);
        steps.push("narrow");
        assert!(
            !bootstrap.dns_open,
            "narrowing must close the DNS allowance"
        );

        // Iteration 2: the retry must re-open DNS *before* resolving.  The old
        // code only narrowed here, so the lookup was dropped forever.
        assert!(bootstrap.needs_dns());
        bootstrap.record_dns(true);
        steps.push("open-dns");
        assert!(!bootstrap.needs_dns());

        // The retry resolves, narrows, and this time the handshake succeeds.
        assert!(bootstrap.needs_narrow());
        bootstrap.record_narrow(true);
        steps.push("narrow");
        bootstrap.replaced();
        assert!(!bootstrap.active());
        assert!(!bootstrap.needs_dns());
        assert!(!bootstrap.needs_narrow());
        assert_eq!(steps, ["open-dns", "narrow", "open-dns", "narrow"]);
    }

    #[test]
    fn bootstrap_keeps_reopening_dns_until_a_handshake_succeeds() {
        let mut bootstrap = BootstrapState::pending();
        bootstrap.record_dns(true); // initial bootstrap
        let mut opens = 1;

        // Seven failed handshakes: each retry must re-open DNS exactly once.
        for round in 0..7 {
            if bootstrap.needs_dns() {
                bootstrap.record_dns(true);
                opens += 1;
            }
            assert!(!bootstrap.needs_dns(), "round {round}");
            assert!(bootstrap.needs_narrow(), "round {round}");
            bootstrap.record_narrow(true);
            // Failed handshake: `endpoints` is cleared, loop retries.
        }
        assert_eq!(opens, 7, "the first retry reuses the initial allowance");

        // The eventual success leaves the table to be replaced by the full
        // rule set, and no further DNS is needed.
        if bootstrap.needs_dns() {
            bootstrap.record_dns(true);
            opens += 1;
        }
        bootstrap.record_narrow(true);
        bootstrap.replaced();
        assert_eq!(opens, 8);
        assert!(!bootstrap.active());
    }

    #[test]
    fn narrow_error_reopens_dns_on_the_next_lookup() {
        // Regression: a narrow that flushed the chain and then failed to add
        // a rule used to leave `dns_open == true` even though DNS was blocked,
        // so the next lookup after a failed handshake never re-opened it.
        let mut bootstrap = BootstrapState::pending();
        bootstrap.record_dns(true);
        assert!(!bootstrap.needs_dns());

        bootstrap.record_error();
        assert!(bootstrap.active(), "the drop policy is still in force");
        assert!(!bootstrap.dns_open, "the flushed allowance is gone");
        assert!(bootstrap.needs_dns(), "the retry must re-open DNS");

        // A retry re-opens the allowance; a successful narrow then retires the
        // bootstrap state and leaves no allowance behind.
        bootstrap.record_dns(true);
        assert!(!bootstrap.needs_dns());
        bootstrap.record_narrow(true);
        bootstrap.replaced();
        assert!(!bootstrap.active());
        assert!(!bootstrap.needs_dns());
    }

    #[test]
    fn bootstrap_stops_claiming_fail_closed_when_the_table_vanishes() {
        // A failed bootstrap probe (`Ok(false)`) means no table is left; the
        // engine must not keep treating the host as fail-closed.
        let mut bootstrap = BootstrapState::pending();
        assert!(bootstrap.needs_dns());
        bootstrap.record_dns(false);
        assert!(!bootstrap.active());
        assert!(!bootstrap.needs_dns());
        assert!(!bootstrap.needs_narrow());

        // Same for a narrow call that discovers the table is gone.
        let mut bootstrap = BootstrapState::pending();
        bootstrap.record_dns(true);
        bootstrap.record_narrow(false);
        assert!(!bootstrap.active());
        assert!(!bootstrap.needs_dns());
        assert!(!bootstrap.needs_narrow());
    }

    /// Serializes tests that change the process-global `RUSTVPN_NFT_BIN`.
    #[cfg(unix)]
    static NFT_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Restores the nft-related environment variables when dropped.
    #[cfg(unix)]
    struct NftEnv {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    #[cfg(unix)]
    impl NftEnv {
        fn set(vars: &[(&'static str, String)]) -> Self {
            let saved = vars
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();
            for (key, value) in vars {
                std::env::set_var(key, value);
            }
            Self { saved }
        }
    }

    #[cfg(unix)]
    impl Drop for NftEnv {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// Fake `nft` used through `RUSTVPN_NFT_BIN`; never touches the host.
    #[cfg(unix)]
    struct FakeNft {
        dir: std::path::PathBuf,
        script: std::path::PathBuf,
        log: std::path::PathBuf,
        fail_marker: std::path::PathBuf,
    }

    /// The script always reports the table as present (`list` exits 0) and,
    /// when the one-shot marker exists, fails the first narrowed endpoint rule
    /// after the preceding `flush` succeeded.
    #[cfg(unix)]
    const FAKE_NFT_SCRIPT: &str = r#"#!/bin/sh
log="${RUSTVPN_FAKE_NFT_LOG:?}"
echo "$*" >> "$log"
if [ "$1" = "list" ]; then
    exit 0
fi
if [ -f "${RUSTVPN_FAKE_NFT_FAIL_NARROW:-/nonexistent}" ] && [ "$1" = "add" ] && [ "$2" = "rule" ]; then
    case "$*" in
        *daddr*)
            rm -f "$RUSTVPN_FAKE_NFT_FAIL_NARROW"
            exit 1
            ;;
    esac
fi
exit 0
"#;

    #[cfg(unix)]
    impl FakeNft {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            use std::sync::atomic::{AtomicUsize, Ordering};

            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "rustvpn-fake-nft-{}-{tag}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let script = dir.join("nft");
            let log = dir.join("calls.log");
            let fail_marker = dir.join("fail-narrow");
            std::fs::write(&script, FAKE_NFT_SCRIPT).unwrap();
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
            Self {
                dir,
                script,
                log,
                fail_marker,
            }
        }

        fn env(&self) -> Vec<(&'static str, String)> {
            vec![
                (
                    "RUSTVPN_NFT_BIN",
                    self.script.to_string_lossy().into_owned(),
                ),
                (
                    "RUSTVPN_FAKE_NFT_LOG",
                    self.log.to_string_lossy().into_owned(),
                ),
                (
                    "RUSTVPN_FAKE_NFT_FAIL_NARROW",
                    self.fail_marker.to_string_lossy().into_owned(),
                ),
            ]
        }

        fn arm_narrow_failure(&self) {
            std::fs::write(&self.fail_marker, b"1").unwrap();
        }

        fn mark(&self, label: &str) {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log)
                .unwrap();
            writeln!(file, "MARK {label}").unwrap();
        }

        fn tokens(&self) -> Vec<String> {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(classify_nft_call)
                .collect()
        }
    }

    #[cfg(unix)]
    impl Drop for FakeNft {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(unix)]
    fn classify_nft_call(line: &str) -> String {
        if let Some(mark) = line.strip_prefix("MARK ") {
            return mark.to_string();
        }
        let line = line.trim();
        if line.starts_with("list ") {
            "probe".into()
        } else if line.contains("add chain") {
            "chain".into()
        } else if line.contains("flush chain") {
            "flush".into()
        } else if line.contains("dport 53") {
            "dns".into()
        } else if line.contains("add rule") && line.contains("daddr") {
            "outer".into()
        } else if line.contains("add rule") && line.contains("oifname \"lo\"") {
            "loopback".into()
        } else if line.contains("sport 68") {
            "dhcp".into()
        } else if line.contains("icmpv6") {
            "icmpv6".into()
        } else if line.starts_with("delete ") {
            "delete".into()
        } else {
            format!("other:{line}")
        }
    }

    /// Production-ordering regression test.
    ///
    /// Uses the same [`attempt_connection`] that `run_connection` calls, a
    /// fake `nft` and injected resolver/handshake closures, so it exercises
    /// the real sequence without TAP, root or host firewall changes.
    #[cfg(unix)]
    #[tokio::test]
    async fn production_ordering_reopens_dns_after_partial_narrow_failure() {
        let _serial = NFT_ENV_LOCK.lock().await;
        let fake = FakeNft::new("partial-narrow");
        let _env = NftEnv::set(&fake.env());

        let scope = "test-scope";
        let host = "vpn.example.com:1194";
        let outer: SocketAddr = "203.0.113.10:1194".parse().unwrap();
        let (events, _rx) = broadcast::channel(64);

        // Mirror the engine's initial crash-preserved bootstrap.
        let present = crate::firewall::bootstrap_kill_switch(scope, None, true)
            .await
            .unwrap();
        assert!(present, "fake nft must report the preserved table");
        let mut bootstrap = BootstrapState::pending();
        bootstrap.record_dns(true);
        let mut endpoints: Option<Endpoints> = None;

        // First narrow: `flush` succeeds, the endpoint rule add fails once.
        fake.arm_narrow_failure();

        let mut resolves = 0usize;
        let first: Attempt<()> = attempt_connection(
            &mut bootstrap,
            &mut endpoints,
            scope,
            host,
            &events,
            || fake.mark("before-handshake-1"),
            || {
                resolves += 1;
                fake.mark("resolve-1");
                async {
                    Ok(Endpoints {
                        remote: Some(outer),
                        proxy: None,
                    })
                }
            },
            |_| {
                fake.mark("handshake-fail-1");
                async { Err::<(), _>(anyhow::anyhow!("handshake failed")) }
            },
        )
        .await;
        assert!(matches!(first, Attempt::HandshakeFailed(_)));
        assert!(bootstrap.active(), "the table must stay fail-closed");
        assert!(
            !bootstrap.dns_open,
            "a partial narrow must record that the allowance is gone"
        );

        // Production clears the cached endpoint after a failed handshake.
        endpoints = None;
        assert!(
            bootstrap.needs_dns(),
            "the retry must re-open DNS before resolving"
        );

        let second: Attempt<()> = attempt_connection(
            &mut bootstrap,
            &mut endpoints,
            scope,
            host,
            &events,
            || fake.mark("before-handshake-2"),
            || {
                resolves += 1;
                fake.mark("resolve-2");
                async {
                    Ok(Endpoints {
                        remote: Some(outer),
                        proxy: None,
                    })
                }
            },
            |_| {
                fake.mark("handshake-ok");
                async { Ok::<(), anyhow::Error>(()) }
            },
        )
        .await;
        assert!(matches!(second, Attempt::Succeeded(())));
        // The post-success path installs the full current rule set (or removes
        // the table) through the firewall; exercise that half with the same
        // fake nft.  A full install never contains the port-53 allowance.
        crate::firewall::apply_kill_switch(scope, "rsvpn0", outer, Some("eth0"))
            .await
            .unwrap();
        bootstrap.replaced();

        // A later reconnect with the endpoint pinned must not touch nft.
        let before = fake.tokens().len();
        let third: Attempt<()> = attempt_connection(
            &mut bootstrap,
            &mut endpoints,
            scope,
            host,
            &events,
            || {},
            || async { panic!("a pinned endpoint must be reused") },
            |_| async { Ok::<(), anyhow::Error>(()) },
        )
        .await;
        assert!(matches!(third, Attempt::Succeeded(())));
        assert_eq!(fake.tokens().len(), before, "no bootstrap after success");
        assert_eq!(resolves, 2);

        let tokens = fake.tokens();
        let pos = |needle: &str| {
            tokens
                .iter()
                .position(|token| token == needle)
                .unwrap_or_else(|| panic!("missing {needle} in {tokens:?}"))
        };
        let resolve1 = pos("resolve-1");
        let handshake_fail = pos("handshake-fail-1");
        let resolve2 = pos("resolve-2");
        let handshake_ok = pos("handshake-ok");

        // 1. DNS allowance is open before the first lookup.
        assert!(
            pos("dns") < resolve1,
            "DNS must open before the first resolve: {tokens:?}"
        );
        // 2. The first narrow happened before the handshake and closed DNS.
        let narrow1 = tokens[..handshake_fail]
            .iter()
            .rposition(|token| token == "flush")
            .unwrap();
        assert!(
            narrow1 > resolve1 && narrow1 < handshake_fail,
            "narrow#1 must precede the handshake: {tokens:?}"
        );
        assert!(
            !tokens[narrow1..handshake_fail].contains(&"dns".to_string()),
            "narrow#1 must close the DNS allowance: {tokens:?}"
        );
        // 3. The partial failure re-opened DNS before the retry lookup.
        assert!(
            tokens[handshake_fail..resolve2].contains(&"dns".to_string()),
            "the retry must re-open DNS before resolving again: {tokens:?}"
        );
        // 4. The successful narrow precedes the handshake and has no DNS rule.
        let narrow2 = tokens[..handshake_ok]
            .iter()
            .rposition(|token| token == "flush")
            .unwrap();
        assert!(
            narrow2 > resolve2 && narrow2 < handshake_ok,
            "narrow#2 must precede the handshake: {tokens:?}"
        );
        assert!(
            !tokens[narrow2..handshake_ok].contains(&"dns".to_string()),
            "narrow#2 must close the DNS allowance: {tokens:?}"
        );
        // 5. No allowance leaks after the successful handshake.
        assert!(
            !tokens[handshake_ok..].contains(&"dns".to_string()),
            "no DNS allowance may survive a successful handshake: {tokens:?}"
        );
        // The failing narrow really attempted the outer-endpoint rule.
        assert!(
            tokens[(handshake_fail.saturating_sub(4))..handshake_fail]
                .contains(&"outer".to_string()),
            "the failure must be a later rule, after the narrow flush: {tokens:?}"
        );
    }
}
