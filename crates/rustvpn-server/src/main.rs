//! GoVPN 5.7-compatible Rust server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use rand_core::{OsRng, RngCore};
use rustvpn_crypto::egd::EgDRng;
use rustvpn_crypto::xtea::Xtea;
use rustvpn_net::config::{add_time_sync, ConfigSet, PeerConfig};
use rustvpn_net::peer::{spawn_tcp, spawn_udp_peer, PeerEvent, WireWriter};
use rustvpn_net::scripts::{call_down, run_script};
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
    let old = ctx.registry.remove_addr(&old_addr)?;
    old.cancel.cancel();
    ctx.stats.remove(&old.stats.addr);
    // Give the old reader/writer tasks a moment to observe cancellation
    // before the replacement starts using the same TAP.
    tokio::time::sleep(Duration::from_millis(10)).await;
    Some(old.tap.clone())
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
    });
    ctx.registry.insert(entry);
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
        if let Some(old) = ctx.registry.remove_addr(&addr) {
            old.cancel.cancel();
            ctx.stats.remove(&old.stats.addr);
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
    if handshakes.len() >= 4096 {
        return;
    }
    if handshakes.keys().filter(|a| a.ip() == addr.ip()).count() >= 16 {
        return;
    }
    let ip = addr.ip();
    if !ctx.hs_limit.lock().unwrap().allow(ip) || !ctx.hs_global.lock().unwrap().allow_global() {
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
        Err(e) => eprintln!("handshake error from {addr}: {e}"),
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
    });
    ctx.registry.insert(entry);
    eprintln!("peer created: {addr}");
    Ok(())
}

async fn tcp_listener_loop(listener: TcpListener, ctx: ServerContext) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = ctx.tcp_limit.clone().try_acquire_owned() else {
                    eprintln!("tcp connection limit reached, dropping {stream:?}");
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_tcp_conn(stream, ctx).await {
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

async fn run(args: Args) -> Result<()> {
    if args.proto != "udp" && args.proto != "tcp" && args.proto != "all" {
        return Err(anyhow!("Unknown protocol specified"));
    }
    let set = ConfigSet::from_file(std::path::Path::new(&args.conf))?;
    let configs: ConfigStore = Arc::new(RwLock::new(set));
    let registry = Arc::new(Registry::default());
    let stats = StatsState::new();
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let (requests_tx, mut requests_rx) = mpsc::channel(64);
    let egd = Arc::new(args.egd.clone());
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
        let path = args.conf.clone();
        let configs = configs.clone();
        let requests = ctx.requests.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                match ConfigSet::from_file(std::path::Path::new(&path)) {
                    Ok(new_set) => {
                        let fingerprints = new_set
                            .peers
                            .iter()
                            .map(|p| (p.id, config_fingerprint(p)))
                            .collect();
                        *configs.write().await = new_set;
                        let _ = requests
                            .send(MainRequest::ConfigReloaded { fingerprints })
                            .await;
                    }
                    Err(e) => eprintln!("config refresh failed: {e:#}"),
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
                        registry.remove_addr(&addr);
                        entry.cancel.cancel();
                        stats.remove(&entry.stats.addr);
                        call_down(&entry.cfg.down, entry.tap.name(), &entry.addr.to_string()).await;
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
                            if stale && registry.remove_addr(&entry.addr).is_some() {
                                entry.cancel.cancel();
                                stats.remove(&entry.stats.addr);
                                call_down(
                                    &entry.cfg.down,
                                    entry.tap.name(),
                                    &entry.addr.to_string(),
                                )
                                .await;
                                eprintln!("peer revoked by config reload: {}", entry.addr);
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }

    for entry in registry.snapshot() {
        entry.cancel.cancel();
        call_down(&entry.cfg.down, entry.tap.name(), &entry.addr.to_string()).await;
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
