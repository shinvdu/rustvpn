//! GoVPN 5.7-compatible Rust client.

use std::process;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rustvpn_client_core::{resolve_endpoints, start_session, SessionEnd, TunnelLock};
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::PeerConfig;
use rustvpn_net::scripts::{call_down, call_up};
use rustvpn_net::stats::{stats_listener, StatsState};
use rustvpn_net::tap::Tap;
use rustvpn_proto::{MTU_DEFAULT, MTU_MAX, MTU_MIN, MTU_MIN_NOISE};
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
         \x20 -key string\n\
         \x20 -mtu int (default {MTU_DEFAULT})\n\
         \x20 -noise\n\
         \x20 -proto string (default \"udp\")\n\
         \x20 -proxy string\n\
         \x20 -proxy-auth string\n\
         \x20 -remote string\n\
         \x20 -stats string\n\
         \x20 -timeout int\n\
         \x20 -timesync int\n\
         \x20 -up string\n\
         \x20 -verifier string\n\
         \x20 -warranty"
    );
    process::exit(2);
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

fn main() {
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
    if args.mtu < MTU_MIN || args.mtu > MTU_MAX {
        eprintln!("MTU must be between {MTU_MIN} and {MTU_MAX}");
        process::exit(1);
    }
    let noise = args.noise || args.encless;
    if noise && args.mtu < MTU_MIN_NOISE {
        eprintln!("Minimum permissible MTU for noise mode is {MTU_MIN_NOISE}");
        process::exit(1);
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
