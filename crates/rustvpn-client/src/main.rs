//! GoVPN 5.7-compatible Rust client.

use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rand_core::{OsRng, RngCore};
use rustvpn_crypto::egd::EgDRng;
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::PeerConfig;
use rustvpn_net::peer::{spawn_tcp, spawn_udp_dispatch, spawn_udp_peer, PeerEvent, WireWriter};
use rustvpn_net::scripts::{call_down, call_up};
use rustvpn_net::stats::{stats_listener, LiveStats, StatsState};
use rustvpn_net::tap::Tap;
use rustvpn_proto::{
    ClientHandshake, ClientOutput, HandshakeConfig, Mode, ENCLESS_ENLARGE_SIZE, MTU_DEFAULT,
    MTU_MAX, MTU_MIN, MTU_MIN_NOISE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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

enum Rng {
    Os(OsRng),
    Egd(EgDRng),
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

fn server_msg2_len(mode: Mode, mtu: usize) -> usize {
    match mode {
        Mode::Encless => 2 * (ENCLESS_ENLARGE_SIZE + mtu),
        Mode::Noise => mtu,
        Mode::Plain => 80,
    }
}

fn server_msg4_len(mode: Mode, mtu: usize) -> usize {
    match mode {
        Mode::Encless => ENCLESS_ENLARGE_SIZE + mtu,
        Mode::Noise => mtu,
        Mode::Plain => 16,
    }
}

async fn connect_remote(remote: &str, proxy: &str, auth: &str) -> Result<TcpStream> {
    if proxy.is_empty() {
        return TcpStream::connect(remote)
            .await
            .with_context(|| format!("connect {remote}"));
    }
    let mut stream = TcpStream::connect(proxy)
        .await
        .with_context(|| format!("connect proxy {proxy}"))?;
    let mut req = format!("CONNECT {remote} HTTP/1.1\r\nHost: {remote}\r\n");
    if !auth.is_empty() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&STANDARD.encode(auth));
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut hdr = Vec::new();
    let mut b = [0u8; 512];
    loop {
        let n = stream.read(&mut b).await?;
        if n == 0 {
            return Err(anyhow!("proxy closed during CONNECT"));
        }
        hdr.extend_from_slice(&b[..n]);
        if hdr.windows(4).any(|w| w == b"\r\n\r\n") || hdr.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if hdr.len() > 8192 {
            return Err(anyhow!("proxy response too large"));
        }
    }
    let status = String::from_utf8_lossy(&hdr);
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(anyhow!(
            "proxy CONNECT failed: {}",
            status.lines().next().unwrap_or("")
        ));
    }
    Ok(stream)
}

async fn handshake_tcp(
    stream: &mut TcpStream,
    cfg: &PeerConfig,
    signing_key: ed25519_dalek::SigningKey,
    rng: &mut Rng,
) -> Result<[u8; 32]> {
    let mode = cfg.mode();
    let hcfg = HandshakeConfig::client(
        cfg.id,
        cfg.mtu,
        cfg.noise,
        cfg.encless,
        cfg.time_sync,
        signing_key,
    );
    let (mut hs, msg1) = ClientHandshake::start(hcfg, rng)?;
    stream.write_all(&msg1).await?;
    let mut b2 = vec![0u8; server_msg2_len(mode, cfg.mtu)];
    tokio::time::timeout(cfg.timeout, stream.read_exact(&mut b2)).await??;
    let msg3 = match hs.client(&b2, rng)? {
        ClientOutput::Reply(m) => m,
        ClientOutput::Complete(_) => return Err(anyhow!("handshake completed too early")),
    };
    stream.write_all(&msg3).await?;
    let mut b4 = vec![0u8; server_msg4_len(mode, cfg.mtu)];
    tokio::time::timeout(cfg.timeout, stream.read_exact(&mut b4)).await??;
    match hs.client(&b4, rng)? {
        ClientOutput::Complete(key) => Ok(key),
        ClientOutput::Reply(_) => Err(anyhow!("handshake did not complete")),
    }
}

async fn handshake_udp(
    socket: &UdpSocket,
    cfg: &PeerConfig,
    signing_key: ed25519_dalek::SigningKey,
    rng: &mut Rng,
) -> Result<[u8; 32]> {
    let hcfg = HandshakeConfig::client(
        cfg.id,
        cfg.mtu,
        cfg.noise,
        cfg.encless,
        cfg.time_sync,
        signing_key,
    );
    let (mut hs, msg1) = ClientHandshake::start(hcfg, rng)?;
    socket.send(&msg1).await?;
    let mut buf = vec![0u8; ENCLESS_ENLARGE_SIZE + MTU_MAX + 64];
    // Bound the handshake so a lost packet leads to a fresh attempt instead
    // of a full `timeout` (60 s) outage.  Retransmit the last flight with
    // exponential backoff in the meantime.
    let deadline = Instant::now()
        + cfg
            .timeout
            .min(Duration::from_secs(10))
            .max(Duration::from_secs(3));
    let mut last = msg1;
    let mut wait = Duration::from_secs(1);
    loop {
        let recv = tokio::time::timeout(wait, socket.recv(&mut buf)).await;
        match recv {
            Err(_) => {
                if Instant::now() >= deadline {
                    return Err(anyhow!("handshake timeout"));
                }
                socket.send(&last).await?;
                wait = (wait * 2).min(Duration::from_secs(5));
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(n)) => match hs.client(&buf[..n], rng)? {
                ClientOutput::Reply(m) => {
                    last = m.clone();
                    socket.send(&m).await?;
                    wait = Duration::from_secs(1);
                }
                ClientOutput::Complete(key) => return Ok(key),
            },
        }
    }
}

enum SessionEnd {
    Timeout,
    Rehandshake,
    TcpClosed,
    Terminated,
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
            Ok(SessionEnd::Timeout | SessionEnd::Rehandshake | SessionEnd::TcpClosed) => {
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
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&remote_str).await?.collect();
    let remote = *addrs.first().ok_or_else(|| anyhow!("no remote address"))?;
    let mut rng = if egd.is_empty() {
        Rng::Os(OsRng)
    } else {
        Rng::Egd(EgDRng::new(egd))
    };

    let (stats_state, handle) = if proto == "tcp" {
        let mut stream = connect_remote(&remote_str, &proxy, &proxy_auth).await?;
        let key = handshake_tcp(&mut stream, &cfg, signing_key.clone(), &mut rng).await?;
        let stats = LiveStats::new(
            remote_str.clone(),
            cfg.id,
            cfg.noise,
            cfg.cpr,
            cfg.encless,
            cfg.mtu,
        );
        stats_state.insert(stats.clone());
        if *first_up {
            let _ = call_up(&cfg.up, &cfg.iface, &remote_str).await;
            *first_up = false;
        }
        let (read, write) = stream.into_split();
        let handle = spawn_tcp(read, write, cfg.clone(), tap.clone(), key, true, stats);
        (stats_state, handle)
    } else {
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        socket.connect(remote).await?;
        let key = handshake_udp(&socket, &cfg, signing_key.clone(), &mut rng).await?;
        let stats = LiveStats::new(
            remote_str.clone(),
            cfg.id,
            cfg.noise,
            cfg.cpr,
            cfg.encless,
            cfg.mtu,
        );
        stats_state.insert(stats.clone());
        if *first_up {
            let _ = call_up(&cfg.up, &cfg.iface, &remote_str).await;
            *first_up = false;
        }
        let tx = rustvpn_net::udp_batch::spawn_udp_batcher(socket.clone());
        let writer = WireWriter::UdpBatch { tx, remote };
        let handle = spawn_udp_peer(cfg.clone(), tap.clone(), key, true, stats, writer);
        if let Some(inbound) = handle.inbound.clone() {
            spawn_udp_dispatch(socket, inbound, handle.cancel.clone());
        }
        (stats_state, handle)
    };
    let mut handle = handle;
    let addr = handle.stats.addr.clone();
    let end = tokio::select! {
        ev = handle.events.recv() => match ev {
            Some(PeerEvent::Timeout) => SessionEnd::Timeout,
            Some(PeerEvent::Rehandshake) => SessionEnd::Rehandshake,
            Some(PeerEvent::TcpClosed) | Some(PeerEvent::TapClosed) | None => {
                SessionEnd::TcpClosed
            }
        },
        _ = shutdown.cancelled() => SessionEnd::Terminated,
    };
    handle.cancel.cancel();
    stats_state.remove(&addr);
    Ok(end)
}
