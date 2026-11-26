//! GoVPN 5.7-compatible Rust client.

use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rustvpn_client_core::profile::{KEEPALIVE_MAX, KEEPALIVE_MIN, KEEPALIVE_MIN_PADDED};
use rustvpn_client_core::{resolve_endpoints, start_session, SessionEnd, TunnelLock};
use rustvpn_client_ipc::{Client, ClientStatusV1};
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::PeerConfig;
use rustvpn_net::scripts::{call_down, call_up};
use rustvpn_net::stats::{stats_listener, StatsState};
use rustvpn_net::tap::Tap;
use rustvpn_proto::{Mode, MTU_DEFAULT};
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
    remote: String,
    proto: String,
    iface: String,
    verifier: String,
    key: String,
    up: String,
    down: String,
    stats: String,
    proxy: String,
    proxy_auth: String,
    mtu: usize,
    timeout: u64,
    timesync: i64,
    keepalive: u64,
    rekey_time: u64,
    rekey_jitter: u64,
    noise: bool,
    encless: bool,
    cpr: u32,
    egd: String,
    warranty: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-client:\n\
         \x20 -cpr int\n\
         \x20 -down string\n\
         \x20 -egd string\n\
         \x20 -encless\n\
         \x20 -iface string (default \"tap0\")\n\
         \x20 -keepalive int (idle keepalive seconds; default 0 = timeout/4 heartbeat)\n\
         \x20 -key string\n\
         \x20 -mtu int (default {MTU_DEFAULT})\n\
         \x20 -noise\n\
         \x20 -proto string (default \"udp\")\n\
         \x20 -proxy string\n\
         \x20 -proxy-auth string\n\
         \x20 -remote string\n\
         \x20 -rekey-jitter int (seconds added randomly to rekey-time; default 0)\n\
         \x20 -rekey-time int (time-driven rekey seconds; default 0 = 4 GiB only)\n\
         \x20 -stats string\n\
         \x20 -timeout int\n\
         \x20 -timesync int\n\
         \x20 -up string\n\
         \x20 -verifier string\n\
         \x20 -warranty\n\
         \n\
         Subcommand:\n\
         \x20 status [--json] [--socket PATH]\n\
         \x20   Query the running rustvpn-clientd over its local socket."
    );
    process::exit(2);
}

fn status_usage() -> ! {
    eprintln!(
        "Usage of rustvpn-client status:\n\
         \x20 --json            Print the stable rustvpn.status.v1 document\n\
         \x20 --socket PATH     Override the daemon socket path\n\
         \x20 --help            Show this help"
    );
    process::exit(2);
}

struct StatusArgs {
    json: bool,
    socket: Option<PathBuf>,
}

fn parse_status_args() -> StatusArgs {
    let mut args = StatusArgs {
        json: false,
        socket: None,
    };
    let mut it = std::env::args().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" | "-json" | "-j" => args.json = true,
            "--socket" | "-socket" => {
                let Some(path) = it.next() else {
                    eprintln!("--socket needs an argument");
                    status_usage();
                };
                args.socket = Some(PathBuf::from(path));
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

fn status_command() -> ! {
    let args = parse_status_args();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(error) => {
            eprintln!("runtime: {error}");
            process::exit(1);
        }
    };
    let exit = rt.block_on(async {
        let candidates: Vec<PathBuf> = match &args.socket {
            Some(path) => vec![path.clone()],
            None => rustvpn_client_ipc::candidate_socket_paths(),
        };
        let mut last_error = "client daemon is not reachable".to_string();
        for path in candidates {
            match tokio::time::timeout(Duration::from_secs(2), Client::connect(&path)).await {
                Ok(Ok(mut client)) => {
                    return match client.status().await {
                        Ok(status) => {
                            if args.json {
                                print_json(&ClientStatusV1::from_status(&status));
                            } else {
                                print_human(&status);
                            }
                            0
                        }
                        Err(error) => {
                            if args.json {
                                print_json(&ClientStatusV1::unavailable(format!(
                                    "status request failed: {error}"
                                )));
                            } else {
                                eprintln!("status request failed: {error}");
                            }
                            1
                        }
                    };
                }
                Ok(Err(error)) => last_error = format!("{}: {error}", path.display()),
                Err(_) => last_error = format!("{}: timed out", path.display()),
            }
        }
        if args.json {
            print_json(&ClientStatusV1::unavailable(&last_error));
        } else {
            eprintln!("{last_error}");
        }
        1
    });
    process::exit(exit);
}

fn print_json(status: &ClientStatusV1) {
    match serde_json::to_string_pretty(status) {
        Ok(text) => println!("{text}"),
        Err(error) => {
            eprintln!("serialize status: {error}");
            process::exit(1);
        }
    }
}

fn print_human(status: &rustvpn_client_ipc::EngineStatus) {
    println!("state:    {}", status.state);
    if let Some(name) = &status.profile {
        println!("profile:  {name}");
    }
    if let Some(remote) = &status.remote {
        println!("server:   {remote}");
    }
    if let Some(endpoint) = &status.endpoint {
        println!("endpoint: {endpoint}");
    }
    println!(
        "transport: {} / {}",
        status.proto.as_deref().unwrap_or("?"),
        status.mode.as_deref().unwrap_or("?")
    );
    if let Some(iface) = &status.iface {
        println!("iface:    {iface}");
    }
    if let Some(since) = status.since_unix {
        println!("since:    {}", rfc3339(since));
    }
    if let Some(last) = status.last_handshake_unix {
        println!("handshake:{}", rfc3339(last));
    }
    println!(
        "traffic:  tx={} rx={} ({} B/s down, {} B/s up)",
        status.traffic.tx_bytes,
        status.traffic.rx_bytes,
        status.traffic.rx_bps,
        status.traffic.tx_bps
    );
    if let (Some(sent), Some(recv)) = (status.heartbeat_sent, status.heartbeat_recv) {
        println!("heartbeat: sent={sent} recv={recv}");
    }
    if let (Some(unauth), Some(dup)) = (status.frames_unauth, status.frames_dup) {
        println!("frames:   unauth={unauth} dup={dup}");
    }
    if let Some(keepalive) = status.keepalive_sec {
        println!("keepalive:{keepalive}s");
    }
    if let Some(rekey) = status.rekey_time_sec {
        println!("rekey:    every {rekey}s (4 GiB threshold also applies)");
    }
    if let Some(error) = &status.last_error {
        println!("last_error: {error}");
    }
}

fn rfc3339(seconds: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| seconds.to_string())
}

fn parse_args() -> Args {
    let mut a = Args {
        remote: String::new(),
        proto: "udp".into(),
        iface: "tap0".into(),
        verifier: String::new(),
        key: String::new(),
        up: String::new(),
        down: String::new(),
        stats: String::new(),
        proxy: String::new(),
        proxy_auth: String::new(),
        mtu: MTU_DEFAULT,
        timeout: 60,
        timesync: 0,
        keepalive: 0,
        rekey_time: 0,
        rekey_jitter: 0,
        noise: false,
        encless: false,
        cpr: 0,
        egd: String::new(),
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
            "remote" => a.remote = take("remote"),
            "proto" => a.proto = take("proto"),
            "iface" => a.iface = take("iface"),
            "verifier" => a.verifier = take("verifier"),
            "key" => a.key = take("key"),
            "up" => a.up = take("up"),
            "down" => a.down = take("down"),
            "stats" => a.stats = take("stats"),
            "proxy" => a.proxy = take("proxy"),
            "proxy-auth" => a.proxy_auth = take("proxy-auth"),
            "mtu" => a.mtu = take("mtu").parse().unwrap_or_else(|_| usage()),
            "timeout" => a.timeout = take("timeout").parse().unwrap_or_else(|_| usage()),
            "timesync" => a.timesync = take("timesync").parse().unwrap_or_else(|_| usage()),
            "keepalive" => a.keepalive = take("keepalive").parse().unwrap_or_else(|_| usage()),
            "rekey-time" => a.rekey_time = take("rekey-time").parse().unwrap_or_else(|_| usage()),
            "rekey-jitter" => {
                a.rekey_jitter = take("rekey-jitter").parse().unwrap_or_else(|_| usage())
            }
            "cpr" => a.cpr = take("cpr").parse().unwrap_or_else(|_| usage()),
            "egd" => a.egd = take("egd"),
            "noise" => a.noise = true,
            "encless" => a.encless = true,
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

fn read_password(path: &str) -> Result<String> {
    if path.is_empty() {
        return rpassword::prompt_password("Passphrase:").map_err(Into::into);
    }
    Ok(std::fs::read_to_string(path)?
        .trim_end_matches('\n')
        .to_string())
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

/// Keepalive bounds shared with profile validation.  `0` disables the idle
/// keepalive entirely; padded modes need a longer interval because every
/// keepalive is sent at the MTU.
fn keepalive_error(keepalive: u64, timeout: u64, noise: bool) -> Option<String> {
    if keepalive == 0 {
        return None;
    }
    let minimum = if noise {
        KEEPALIVE_MIN_PADDED
    } else {
        KEEPALIVE_MIN
    };
    if keepalive < minimum {
        return Some(format!(
            "keepalive must be 0 (off) or at least {minimum}s for this mode"
        ));
    }
    if keepalive > KEEPALIVE_MAX || keepalive >= timeout {
        return Some(format!(
            "keepalive must be <= {KEEPALIVE_MAX}s and shorter than timeout"
        ));
    }
    None
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("status") {
        status_command();
    }
    let args = parse_args();
    if args.warranty {
        println!("{WARRANTY}");
        return;
    }
    if args.remote.is_empty() {
        eprintln!("No remote address specified");
        process::exit(1);
    }
    if args.verifier.is_empty() {
        eprintln!("No verifier specified");
        process::exit(1);
    }
    let noise = args.noise || args.encless;
    let mode = if args.encless {
        Mode::Encless
    } else if args.noise {
        Mode::Noise
    } else {
        Mode::Plain
    };
    if let Err(error) = rustvpn_client_core::mtu::from_wire(mode, args.mtu) {
        eprintln!("{error:#}");
        process::exit(1);
    }
    if let Some(message) = keepalive_error(args.keepalive, args.timeout, noise) {
        eprintln!("{message}");
        process::exit(1);
    }
    if args.rekey_time > 0 {
        if !(60..=86_400).contains(&args.rekey_time)
            || args.rekey_jitter > 3600
            || args.rekey_jitter > args.rekey_time
        {
            eprintln!("rekey-time must be 60..=86400s and rekey-jitter 0..=min(rekey-time,3600)");
            process::exit(1);
        }
    } else if args.rekey_jitter > 0 {
        eprintln!("rekey-jitter requires -rekey-time");
        process::exit(1);
    }
    if args.keepalive > 0 && noise {
        eprintln!(
            "warning: keepalive packets are padded to the MTU in noise/encless mode \
             ({} bytes per interval)",
            args.mtu
        );
    }
    let proto = if args.proxy.is_empty() {
        args.proto.clone()
    } else {
        "tcp".to_string()
    };
    if proto != "udp" && proto != "tcp" {
        eprintln!("Unknown protocol specified");
        process::exit(1);
    }
    if args.encless && proto != "tcp" {
        eprintln!("Currently encryptionless mode works only with TCP");
        process::exit(1);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(run(args, proto)) {
        eprintln!("{e:#}");
        process::exit(1);
    }
}

async fn run(args: Args, proto: String) -> Result<()> {
    // The daemon and CLI share one tunnel lock so routing state is never
    // installed by two processes at once.
    let _lock = TunnelLock::acquire("cli", &args.remote, "cli")?;
    rustvpn_client_core::netcfg::cleanup_stale_ipv6_blackhole().await;
    let mut verifier =
        Verifier::from_string(&args.verifier).map_err(|e| anyhow!("invalid verifier: {e}"))?;
    let password = read_password(&args.key)?;
    if password.is_empty() {
        return Err(anyhow!("Empty passphrase submitted"));
    }
    let signing_key = verifier.password_apply(&password)?;
    let cfg = Arc::new(PeerConfig {
        id: verifier.id,
        name: "client".into(),
        iface: args.iface.clone(),
        mtu: args.mtu,
        up: args.up.clone(),
        down: args.down.clone(),
        timeout: Duration::from_secs(args.timeout.max(1)),
        noise: args.noise || args.encless,
        cpr: args.cpr,
        encless: args.encless,
        time_sync: args.timesync,
        keepalive: Duration::from_secs(args.keepalive),
        rekey_time: Duration::from_secs(args.rekey_time),
        rekey_jitter: Duration::from_secs(args.rekey_jitter),
        network: None,
        verifier,
        signing_key: Some(signing_key.clone()),
    });

    let tap = Arc::new(Tap::open(&cfg.iface, cfg.mtu)?);
    let stats_state = StatsState::new();
    if !args.stats.is_empty() {
        let listener = tokio::net::TcpListener::bind(&args.stats).await?;
        let state = stats_state.clone();
        tokio::spawn(async move { stats_listener(listener, state).await });
    }
    let remote = args.remote.clone();
    let proxy = args.proxy.clone();
    let proxy_auth = args.proxy_auth.clone();
    let egd = args.egd.clone();
    let mut first_up = true;
    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            wait_signal().await;
            shutdown.cancel();
        });
    }
    loop {
        let end = run_once(
            cfg.clone(),
            signing_key.clone(),
            tap.clone(),
            stats_state.clone(),
            remote.clone(),
            proto.clone(),
            proxy.clone(),
            proxy_auth.clone(),
            egd.clone(),
            &mut first_up,
            shutdown.clone(),
        )
        .await;
        match end {
            Ok(SessionEnd::Terminated) => break,
            // Time-driven rekey reconnects immediately; the protocol has no
            // make-before-break message, so a short packet gap is expected.
            Ok(SessionEnd::Rekey) => {}
            Ok(
                SessionEnd::Timeout
                | SessionEnd::Rehandshake
                | SessionEnd::TcpClosed
                | SessionEnd::TapClosed,
            ) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => {
                eprintln!("session failed: {e:#}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    call_down(&cfg.down, &cfg.iface, &args.remote).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_once(
    cfg: Arc<PeerConfig>,
    signing_key: ed25519_dalek::SigningKey,
    tap: Arc<Tap>,
    stats_state: Arc<StatsState>,
    remote_str: String,
    proto: String,
    proxy: String,
    proxy_auth: String,
    egd: String,
    first_up: &mut bool,
    shutdown: CancellationToken,
) -> Result<SessionEnd> {
    let endpoints = resolve_endpoints(&remote_str, &proxy).await?;
    let mut session = start_session(
        cfg.clone(),
        signing_key,
        tap,
        stats_state.clone(),
        &remote_str,
        &endpoints,
        &proto,
        &proxy,
        &proxy_auth,
        &egd,
    )
    .await?;
    if *first_up {
        let _ = call_up(&cfg.up, &cfg.iface, &remote_str).await;
        *first_up = false;
    }
    let end = session.wait(&shutdown).await;
    session.close(&stats_state);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_uses_the_shared_profile_bounds() {
        // Plain mode: 10s floor, 3600s cap, and shorter than timeout.
        assert!(keepalive_error(0, 60, false).is_none());
        assert!(keepalive_error(5, 60, false).is_some());
        assert!(keepalive_error(10, 60, false).is_none());
        assert!(keepalive_error(3600, 7200, false).is_none());
        assert!(keepalive_error(3601, 7200, false).is_some());
        assert!(keepalive_error(60, 60, false).is_some());

        // Noise/encless are padded to the MTU and use the 25s floor.
        assert!(keepalive_error(15, 60, true).is_some());
        assert!(keepalive_error(24, 60, true).is_some());
        assert!(keepalive_error(25, 60, true).is_none());
    }

    #[test]
    fn keepalive_errors_quote_the_shared_limits() {
        let error = keepalive_error(5, 60, false).unwrap();
        assert!(error.contains("10s"), "{error}");
        let error = keepalive_error(15, 60, true).unwrap();
        assert!(error.contains("25s"), "{error}");
        let error = keepalive_error(3601, 7200, false).unwrap();
        assert!(error.contains("3600s"), "{error}");
    }
}
