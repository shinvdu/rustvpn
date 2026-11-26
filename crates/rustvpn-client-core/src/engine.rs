//! Reconnect engine used by `rustvpn-clientd`.
//!
//! The CLI keeps its historical loop and calls [`crate::session`] directly;
//! the daemon uses this engine for states, traffic samples, logs and
//! exponential backoff.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustvpn_client_ipc::{EngineStatus, Event, LogLine, ProfileSpec, TrafficSample};
use rustvpn_net::stats::StatsState;
use rustvpn_net::tap::Tap;
use rustvpn_proto::MAX_BYTES_PER_KEY;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::lock::TunnelLock;
use crate::mtu::{self, OuterFamily};
use crate::netcfg::{FirewallOptions, NetOptions, NetworkGuard};
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
        let mut current: Option<(CancellationToken, JoinHandle<()>)> = None;
        loop {
            tokio::select! {
                cmd = commands.recv() => {
                    match cmd {
                        Some(Command::Connect { profile, password }) => {
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
                            stop_current(&mut current).await;
                            let _ = events.send(Event::State(EngineStatus {
                                state: "idle".into(),
                                ..EngineStatus::default()
                            }));
                            emit_log(&events, "info", "disconnected");
                        }
                        Some(Command::Shutdown) | None => {
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
                }
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
    crate::netcfg::cleanup_stale_ipv6_blackhole().await;
    crate::netcfg::cleanup_stale_firewall(&options.firewall_scope).await;

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
    // for a warning.  This never changes the configured wire MTU.
    let mut endpoints: Option<Endpoints> = None;
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

    let tap = match Tap::open(&spec.iface, daemon_mtu) {
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
    if let Err(error) = crate::netcfg::bring_link_up(&spec.iface, link_mtu).await {
        emit_error(&events, &spec, format!("bring up TAP: {error:#}"));
        emit_log(&events, "error", format!("bring up TAP: {error:#}"));
        return;
    }

    let stats_state = StatsState::new();
    // Endpoints are resolved once the handshake path needs them.  Until the
    // first successful handshake no routes or DNS are installed, so a failed
    // attempt cannot black-hole the host.  After the first success the address
    // is pinned for reconnects (the tunnel may own the default route at that
    // point, which would make a fresh DNS lookup unreliable).
    let mut guard: Option<NetworkGuard> = None;
    let mut attempt: u32 = 0;
    let mut last_status = base_status(&validated, resolved);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        if endpoints.is_none() {
            match resolve_endpoints(&spec.remote, &spec.proxy).await {
                Ok(resolved) => endpoints = Some(resolved),
                Err(error) => {
                    attempt = attempt.saturating_add(1);
                    let message = format!("resolve {}: {error:#}", validated.outer_host());
                    emit_log(&events, "error", &message);
                    let mut status = base_status(&validated, resolved);
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
            }
        }

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

        let cfg = validated.peer_config_with_mtu(signing_key.clone(), resolved.daemon);
        let started = start_session(
            cfg,
            signing_key.clone(),
            tap.clone(),
            stats_state.clone(),
            &spec.remote,
            endpoints.as_ref().expect("resolved above"),
            validated.proto(),
            &spec.proxy,
            &spec.proxy_auth,
            "",
        )
        .await;

        let mut connected_status = base_status(&validated, resolved);
        let mut planned_rekey = false;
        match started {
            Ok(mut session) => {
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
                        }
                        Err(error) => {
                            session.close(&stats_state);
                            drop(tap);
                            emit_error(&events, &spec, format!("network setup: {error:#}"));
                            emit_log(&events, "error", format!("network setup: {error:#}"));
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
                session.close(&stats_state);
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
            Err(error) => {
                attempt = attempt.saturating_add(1);
                let message = format!("{error:#}");
                emit_log(&events, "error", format!("session failed: {message}"));
                let mut status = base_status(&validated, resolved);
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

    if let Some(guard) = guard {
        guard.remove().await;
    }
    drop(tap);
    emit_log(&events, "info", "tunnel stopped");
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

fn base_status(validated: &ValidatedProfile, mtu: MtuInfo) -> EngineStatus {
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
    status
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
}
