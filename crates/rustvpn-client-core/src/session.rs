//! One tunnel session: handshake, peer tasks and clean cancellation.
//!
//! This is the logic that used to live inside `rustvpn-client`'s
//! `run_once()`; the CLI now calls it directly and the daemon drives it from
//! the reconnect engine.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rand_core::{OsRng, RngCore};
use rustvpn_crypto::egd::EgDRng;
use rustvpn_net::config::PeerConfig;
use rustvpn_net::peer::{
    spawn_tcp, spawn_udp_dispatch, spawn_udp_peer, PeerEvent, PeerHandle, WireWriter,
};
use rustvpn_net::stats::{LiveStats, StatsState};
use rustvpn_net::tap::Tap;
use rustvpn_proto::{
    ClientHandshake, ClientOutput, HandshakeConfig, Mode, ENCLESS_ENLARGE_SIZE, MTU_MAX,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

pub enum SessionEnd {
    Timeout,
    Rehandshake,
    /// Time-driven rekey initiated by this client.
    Rekey,
    TcpClosed,
    TapClosed,
    Terminated,
}

pub struct Session {
    pub stats: Arc<LiveStats>,
    pub handle: PeerHandle,
}

impl Session {
    /// Stop the peer tasks, wait until every task has released its `Tap`
    /// clone, and remove the live stats entry.
    ///
    /// Joining here is part of the teardown contract: the caller may close the
    /// TAP/Wintun device immediately after this returns, so no task may still
    /// be inside `tap.recv()` or `tap.send()`.
    pub async fn close(&mut self, stats_state: &StatsState) {
        self.handle.shutdown().await;
        stats_state.remove(&self.stats.addr);
    }

    /// Wait for the session to end or for the caller to cancel it.
    pub async fn wait(&mut self, shutdown: &CancellationToken) -> SessionEnd {
        tokio::select! {
            ev = self.handle.events.recv() => match ev {
                Some(PeerEvent::Timeout) => SessionEnd::Timeout,
                Some(PeerEvent::Rehandshake) => SessionEnd::Rehandshake,
                Some(PeerEvent::Rekey) => SessionEnd::Rekey,
                Some(PeerEvent::TcpClosed) => SessionEnd::TcpClosed,
                Some(PeerEvent::TapClosed) => SessionEnd::TapClosed,
                None => SessionEnd::TcpClosed,
            },
            _ = shutdown.cancelled() => SessionEnd::Terminated,
        }
    }
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

#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    /// Resolved target; `None` when a proxy resolves the CONNECT target.
    pub remote: Option<SocketAddr>,
    pub proxy: Option<SocketAddr>,
}

impl Endpoints {
    pub fn outer(&self) -> Option<SocketAddr> {
        self.proxy.or(self.remote)
    }
}

pub async fn resolve_endpoints(remote: &str, proxy: &str) -> Result<Endpoints> {
    if !proxy.trim().is_empty() {
        Ok(Endpoints {
            remote: None,
            proxy: Some(resolve_first(proxy).await?),
        })
    } else {
        Ok(Endpoints {
            remote: Some(resolve_first(remote).await?),
            proxy: None,
        })
    }
}

async fn resolve_first(host: &str) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(host)
        .await
        .with_context(|| format!("resolve {host}"))?
        .collect();
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no address for {host}"))
}

pub async fn connect_remote(
    remote: &str,
    proxy: &str,
    auth: &str,
    endpoints: &Endpoints,
) -> Result<TcpStream> {
    if proxy.is_empty() {
        let addr = endpoints
            .remote
            .ok_or_else(|| anyhow!("remote address was not resolved"))?;
        return TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect {remote}"));
    }
    let addr = endpoints
        .proxy
        .ok_or_else(|| anyhow!("proxy address was not resolved"))?;
    let mut stream = TcpStream::connect(addr)
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

/// Establish one session over an already-open TAP device.
#[allow(clippy::too_many_arguments)]
pub async fn start_session(
    cfg: Arc<PeerConfig>,
    signing_key: ed25519_dalek::SigningKey,
    tap: Arc<Tap>,
    stats_state: Arc<StatsState>,
    remote_str: &str,
    endpoints: &Endpoints,
    proto: &str,
    proxy: &str,
    proxy_auth: &str,
    egd: &str,
) -> Result<Session> {
    let mut rng = if egd.is_empty() {
        Rng::Os(OsRng)
    } else {
        Rng::Egd(EgDRng::new(egd))
    };

    let (stats, handle) = if proto == "tcp" {
        let mut stream = connect_remote(remote_str, proxy, proxy_auth, endpoints).await?;
        let key = handshake_tcp(&mut stream, &cfg, signing_key.clone(), &mut rng).await?;
        let stats = LiveStats::new(
            remote_str.to_string(),
            cfg.id,
            cfg.noise,
            cfg.cpr,
            cfg.encless,
            cfg.mtu,
        );
        stats_state.insert(stats.clone());
        let (read, write) = stream.into_split();
        let handle = spawn_tcp(
            read,
            write,
            cfg.clone(),
            tap.clone(),
            key,
            true,
            stats.clone(),
        );
        (stats, handle)
    } else {
        let remote = endpoints
            .remote
            .ok_or_else(|| anyhow!("proxy mode requires TCP"))?;
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        socket.connect(remote).await?;
        let key = handshake_udp(&socket, &cfg, signing_key.clone(), &mut rng).await?;
        let stats = LiveStats::new(
            remote_str.to_string(),
            cfg.id,
            cfg.noise,
            cfg.cpr,
            cfg.encless,
            cfg.mtu,
        );
        stats_state.insert(stats.clone());
        let tx = rustvpn_net::udp_batch::spawn_udp_batcher(socket.clone());
        let writer = WireWriter::UdpBatch { tx, remote };
        let handle = spawn_udp_peer(cfg.clone(), tap.clone(), key, true, stats.clone(), writer);
        if let Some(inbound) = handle.inbound.clone() {
            spawn_udp_dispatch(socket, inbound, handle.cancel.clone());
        }
        (stats, handle)
    };
    Ok(Session { stats, handle })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_endpoint_resolves_but_proxy_leaves_target_to_proxy() {
        let direct = resolve_endpoints("127.0.0.1:1", "").await.unwrap();
        assert!(direct.remote.is_some());
        assert!(direct.proxy.is_none());

        // The CONNECT target must not be resolved locally when a proxy is used.
        let proxied =
            resolve_endpoints("name-that-must-not-resolve.invalid:1194", "127.0.0.1:8080")
                .await
                .unwrap();
        assert!(proxied.remote.is_none());
        assert!(proxied.proxy.is_some());
    }
}
