//! Per-peer runtime: TAP <-> transport pump, heartbeat/CPR and timeout.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use rustvpn_proto::{Decoder, Encoder, Ordering as PktOrdering, TransportError, MAX_BYTES_PER_KEY};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::PeerConfig;
use crate::stats::LiveStats;
use crate::tap::Tap;

const OUTBOUND_QUEUE: usize = 256;
const INBOUND_QUEUE: usize = 512;

#[derive(Debug)]
pub enum Outbound {
    Payload(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerEvent {
    Timeout,
    Rehandshake,
    TcpClosed,
    /// The TAP backend failed fatally (io_uring/ring death, ENODEV, ...).
    TapClosed,
}

pub enum WireWriter {
    Udp {
        socket: Arc<UdpSocket>,
        remote: std::net::SocketAddr,
    },
    UdpBatch {
        tx: crate::udp_batch::UdpBatchSender,
        remote: std::net::SocketAddr,
    },
    Tcp(tokio::net::tcp::OwnedWriteHalf),
}

impl WireWriter {
    async fn send(&mut self, data: Vec<u8>) -> std::io::Result<()> {
        match self {
            WireWriter::Udp { socket, remote } => {
                socket.send_to(&data, *remote).await?;
                Ok(())
            }
            WireWriter::UdpBatch { tx, remote } => tx
                .send((data, *remote))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            WireWriter::Tcp(w) => {
                use tokio::io::AsyncWriteExt;
                w.write_all(&data).await
            }
        }
    }

    /// Batched writers take ownership of the buffer so the sendmmsg task
    /// can keep it alive until the syscall completes.
    fn needs_owned(&self) -> bool {
        matches!(self, WireWriter::UdpBatch { .. })
    }

    async fn send_slice(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            WireWriter::Udp { socket, remote } => {
                socket.send_to(data, *remote).await?;
                Ok(())
            }
            WireWriter::UdpBatch { .. } => {
                Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
            }
            WireWriter::Tcp(w) => {
                use tokio::io::AsyncWriteExt;
                w.write_all(data).await
            }
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self, WireWriter::Tcp(_))
    }
}

pub struct PeerHandle {
    pub tap: Arc<Tap>,
    pub stats: Arc<LiveStats>,
    pub cancel: CancellationToken,
    pub outbound: mpsc::Sender<Outbound>,
    pub inbound: Option<mpsc::Sender<Vec<u8>>>,
    pub events: mpsc::Receiver<PeerEvent>,
}

fn event(tx: &mpsc::Sender<PeerEvent>, ev: PeerEvent) {
    let _ = tx.try_send(ev);
}

#[allow(clippy::too_many_arguments)]
async fn send_payload(
    writer: &mut WireWriter,
    encoder: &mut Encoder,
    cfg: &PeerConfig,
    stats: &LiveStats,
    payload: &[u8],
    last_sent: &mut Instant,
    wire: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
) -> Result<()> {
    let mode = cfg.mode();
    let wire_len = if writer.needs_owned() {
        let mut owned = Vec::new();
        encoder.encode_into(payload, mode, cfg.mtu, &mut owned, scratch)?;
        let len = owned.len();
        writer.send(owned).await?;
        len
    } else {
        encoder.encode_into(payload, mode, cfg.mtu, wire, scratch)?;
        let len = wire.len();
        writer.send_slice(wire).await?;
        len
    };
    stats.add_wire_out(wire_len);
    if payload.is_empty() {
        stats.add_heartbeat_sent();
    } else {
        stats.add_payload_out(payload.len());
    }
    *last_sent = Instant::now();
    stats.touch_sent();
    Ok(())
}

async fn sender_task(
    mut writer: WireWriter,
    mut encoder: Encoder,
    cfg: Arc<PeerConfig>,
    stats: Arc<LiveStats>,
    mut outbound: mpsc::Receiver<Outbound>,
    cancel: CancellationToken,
    events: mpsc::Sender<PeerEvent>,
) {
    let mode = cfg.mode();
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut wire: Vec<u8> = Vec::new();
    let mut scratch: Vec<u8> = Vec::new();
    let mut last_sent = Instant::now();
    let tick = if cfg.cpr > 0 {
        cfg.cpr_cycle()
    } else {
        cfg.heartbeat_interval()
    };
    let mut ticker = tokio::time::interval(tick.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let payload = if cfg.cpr > 0 {
                    queue.pop_front().unwrap_or_default()
                } else if last_sent.elapsed() >= cfg.peer_timeout() {
                    Vec::new()
                } else {
                    continue;
                };
                if let Err(e) = send_payload(&mut writer, &mut encoder, &cfg, &stats, &payload, &mut last_sent, &mut wire, &mut scratch).await {
                    eprintln!("send failed: {e}");
                    if writer.is_tcp() {
                        event(&events, PeerEvent::TcpClosed);
                        break;
                    }
                }
            }
            msg = outbound.recv() => {
                let Some(Outbound::Payload(payload)) = msg else { break };
                if cfg.cpr > 0 {
                    if queue.len() >= OUTBOUND_QUEUE {
                        queue.pop_front();
                    }
                    queue.push_back(payload);
                } else if let Err(e) = send_payload(&mut writer, &mut encoder, &cfg, &stats, &payload, &mut last_sent, &mut wire, &mut scratch).await {
                    eprintln!("send failed: {e}");
                    if writer.is_tcp() {
                        event(&events, PeerEvent::TcpClosed);
                        break;
                    }
                }
            }
        }
    }
    let _ = mode;
}

async fn tap_reader_task(
    tap: Arc<Tap>,
    cfg: Arc<PeerConfig>,
    outbound: mpsc::Sender<Outbound>,
    cancel: CancellationToken,
    events: mpsc::Sender<PeerEvent>,
) {
    let mut buf = vec![0u8; cfg.mtu.max(1)];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = tap.recv(&mut buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("TAP read failed: {e}");
                        // A broken/closed TAP backend never recovers; tell
                        // the peer/session instead of faking liveness.
                        if !matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::TimedOut
                        ) {
                            event(&events, PeerEvent::TapClosed);
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                if n > cfg.max_payload() {
                    eprintln!("TAP frame {n} exceeds effective maximum {}", cfg.max_payload());
                    continue;
                }
                if outbound
                    .send(Outbound::Payload(buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

fn classify_error(err: &TransportError, stats: &LiveStats) {
    match err {
        TransportError::Replay => stats.add_dup(),
        TransportError::Authenticator | TransportError::Padding => stats.add_unauth(),
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn udp_receiver_task(
    mut decoder: Decoder,
    tap: Arc<Tap>,
    cfg: Arc<PeerConfig>,
    stats: Arc<LiveStats>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
    events: mpsc::Sender<PeerEvent>,
    client: bool,
) {
    let mut rekey = false;
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            pkt = inbound.recv() => {
                let Some(pkt) = pkt else { break };
                let result = decoder.decode_into(
                    &pkt,
                    cfg.mode(),
                    cfg.mtu,
                    PktOrdering::Reorderable,
                    &mut payload,
                    &mut scratch,
                );
                match result {
                    Ok(()) => {
                        stats.add_wire_in(pkt.len());
                        if payload.is_empty() {
                            stats.add_heartbeat_recv();
                        } else {
                            stats.add_payload_in(payload.len());
                            if let Err(e) = tap.send(&payload).await {
                                eprintln!("TAP write failed: {e}");
                            }
                        }
                        if client && wire_total(&stats) > MAX_BYTES_PER_KEY {
                            rekey = true;
                        }
                    }
                    Err(e) => classify_error(&e, &stats),
                }
            }
        }
        if rekey {
            event(&events, PeerEvent::Rehandshake);
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_receiver_task(
    mut decoder: Decoder,
    mut read: tokio::net::tcp::OwnedReadHalf,
    tap: Arc<Tap>,
    cfg: Arc<PeerConfig>,
    stats: Arc<LiveStats>,
    cancel: CancellationToken,
    events: mpsc::Sender<PeerEvent>,
    client: bool,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let max_buf = 4 * cfg.mtu + 2 * rustvpn_proto::ENCLESS_ENLARGE_SIZE + 64;
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = read.read_buf(&mut buf) => {
                let n = match r { Ok(0) => { event(&events, PeerEvent::TcpClosed); break; }, Ok(n) => n, Err(_) => { event(&events, PeerEvent::TcpClosed); break; } };
                let _ = n;
                loop {
                    let nonce = decoder.expected_nonce();
                    let pos = buf.windows(8).position(|w| w == nonce);
                    let Some(idx) = pos else {
                        if buf.len() > max_buf {
                            event(&events, PeerEvent::TcpClosed);
                            return;
                        }
                        break;
                    };
                    let end = idx + 8;
                    let result = decoder.decode_into(
                        &buf[..end],
                        cfg.mode(),
                        cfg.mtu,
                        PktOrdering::Exact,
                        &mut payload,
                        &mut scratch,
                    );
                    match result {
                        Ok(()) => {
                            stats.add_wire_in(end);
                            if payload.is_empty() {
                                stats.add_heartbeat_recv();
                            } else {
                                stats.add_payload_in(payload.len());
                                if let Err(e) = tap.send(&payload).await {
                                    eprintln!("TAP write failed: {e}");
                                }
                            }
                            if client && wire_total(&stats) > MAX_BYTES_PER_KEY {
                                event(&events, PeerEvent::Rehandshake);
                                return;
                            }
                        }
                        Err(e) => {
                            classify_error(&e, &stats);
                            event(&events, PeerEvent::TcpClosed);
                            return;
                        }
                    }
                    buf.drain(..end);
                }
            }
        }
    }
}

fn wire_total(stats: &LiveStats) -> u64 {
    stats.bytes_in_total() + stats.bytes_out_total()
}

async fn monitor_task(
    stats: Arc<LiveStats>,
    cfg: Arc<PeerConfig>,
    cancel: CancellationToken,
    events: mpsc::Sender<PeerEvent>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {
                if stats.last_ping().elapsed().unwrap_or_default() > cfg.timeout {
                    event(&events, PeerEvent::Timeout);
                    break;
                }
            }
        }
    }
}

pub fn spawn_udp(
    socket: Arc<UdpSocket>,
    remote: std::net::SocketAddr,
    cfg: Arc<PeerConfig>,
    tap: Arc<Tap>,
    key: [u8; 32],
    is_client: bool,
    stats: Arc<LiveStats>,
) -> PeerHandle {
    let writer = WireWriter::Udp { socket, remote };
    spawn_udp_peer(cfg, tap, key, is_client, stats, writer)
}

pub fn spawn_udp_peer(
    cfg: Arc<PeerConfig>,
    tap: Arc<Tap>,
    key: [u8; 32],
    is_client: bool,
    stats: Arc<LiveStats>,
    writer: WireWriter,
) -> PeerHandle {
    let cancel = CancellationToken::new();
    let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let (events_tx, events_rx) = mpsc::channel(4);
    tokio::spawn(sender_task(
        writer,
        Encoder::new(key, is_client),
        cfg.clone(),
        stats.clone(),
        outbound_rx,
        cancel.clone(),
        events_tx.clone(),
    ));
    tokio::spawn(tap_reader_task(
        tap.clone(),
        cfg.clone(),
        outbound_tx.clone(),
        cancel.clone(),
        events_tx.clone(),
    ));
    tokio::spawn(udp_receiver_task(
        Decoder::new(key, is_client),
        tap.clone(),
        cfg.clone(),
        stats.clone(),
        inbound_rx,
        cancel.clone(),
        events_tx.clone(),
        is_client,
    ));
    tokio::spawn(monitor_task(stats.clone(), cfg, cancel.clone(), events_tx));
    PeerHandle {
        tap,
        stats,
        cancel,
        outbound: outbound_tx,
        inbound: Some(inbound_tx),
        events: events_rx,
    }
}

pub fn spawn_tcp(
    read: tokio::net::tcp::OwnedReadHalf,
    write: tokio::net::tcp::OwnedWriteHalf,
    cfg: Arc<PeerConfig>,
    tap: Arc<Tap>,
    key: [u8; 32],
    is_client: bool,
    stats: Arc<LiveStats>,
) -> PeerHandle {
    let cancel = CancellationToken::new();
    let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE);
    let (events_tx, events_rx) = mpsc::channel(4);
    tokio::spawn(sender_task(
        WireWriter::Tcp(write),
        Encoder::new(key, is_client),
        cfg.clone(),
        stats.clone(),
        outbound_rx,
        cancel.clone(),
        events_tx.clone(),
    ));
    tokio::spawn(tap_reader_task(
        tap.clone(),
        cfg.clone(),
        outbound_tx.clone(),
        cancel.clone(),
        events_tx.clone(),
    ));
    tokio::spawn(tcp_receiver_task(
        Decoder::new(key, is_client),
        read,
        tap.clone(),
        cfg.clone(),
        stats.clone(),
        cancel.clone(),
        events_tx.clone(),
        is_client,
    ));
    tokio::spawn(monitor_task(stats.clone(), cfg, cancel.clone(), events_tx));
    PeerHandle {
        tap,
        stats,
        cancel,
        outbound: outbound_tx,
        inbound: None,
        events: events_rx,
    }
}

/// Number of bytes sent for a peer (used by tests/diagnostics).
pub struct PeerByteCounter(pub AtomicU64);

impl PeerByteCounter {
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Feed a connected UDP socket into a peer's inbound channel (client side).
pub fn spawn_udp_dispatch(
    socket: Arc<UdpSocket>,
    inbound: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        use crate::udp_batch;
        let buf_size = rustvpn_proto::ENCLESS_ENLARGE_SIZE + rustvpn_proto::MTU_MAX + 64;
        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; buf_size]).collect();
        let mut lens = vec![0usize; 32];
        let mut addrs = vec![std::net::SocketAddr::from(([0u8, 0, 0, 0], 0)); 32];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                r = udp_batch::recv_batch(&socket, &mut bufs, &mut lens, &mut addrs) => {
                    match r {
                        Ok(n) => {
                            for i in 0..n {
                                if lens[i] == 0 {
                                    continue;
                                }
                                if inbound.try_send(bufs[i][..lens[i]].to_vec()).is_err() {
                                    // bounded queue: drop under overload
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("udp receive failed: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    });
}
