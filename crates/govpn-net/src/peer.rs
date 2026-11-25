//! Per-peer runtime: TAP <-> transport pump, heartbeat/CPR and timeout.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use govpn_proto::{Decoder, Encoder, Ordering as PktOrdering, TransportError, MAX_BYTES_PER_KEY};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

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
}

pub enum WireWriter {
    Udp {
        socket: Arc<UdpSocket>,
        remote: std::net::SocketAddr,
    },
    Tcp(tokio::net::tcp::OwnedWriteHalf),
}

impl WireWriter {
    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            WireWriter::Udp { socket, remote } => {
                socket.send_to(data, *remote).await?;
                Ok(())
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

async fn send_payload(
    writer: &mut WireWriter,
    encoder: &mut Encoder,
    cfg: &PeerConfig,
    stats: &LiveStats,
    payload: &[u8],
    last_sent: &mut Instant,
) -> Result<()> {
    let mode = cfg.mode();
    let wire = encoder.encode(payload, mode, cfg.mtu)?;
    writer.send(&wire).await?;
    stats.add_wire_out(wire.len());
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
                if let Err(e) = send_payload(&mut writer, &mut encoder, &cfg, &stats, &payload, &mut last_sent).await {
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
                } else if let Err(e) = send_payload(&mut writer, &mut encoder, &cfg, &stats, &payload, &mut last_sent).await {
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
    socket: Arc<UdpSocket>,
    tap: Arc<Tap>,
    cfg: Arc<PeerConfig>,
    stats: Arc<LiveStats>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
    events: mpsc::Sender<PeerEvent>,
    client: bool,
) {
    let mut rekey = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            pkt = inbound.recv() => {
                let Some(pkt) = pkt else { break };
                match decoder.decode(&pkt, cfg.mode(), cfg.mtu, PktOrdering::Reorderable) {
                    Ok(payload) => {
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
        let _ = &socket;
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
    let max_buf = 4 * cfg.mtu + 2 * govpn_proto::ENCLESS_ENLARGE_SIZE + 64;
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
                    let packet = buf[..idx + 8].to_vec();
                    match decoder.decode(&packet, cfg.mode(), cfg.mtu, PktOrdering::Exact) {
                        Ok(payload) => {
                            stats.add_wire_in(packet.len());
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
                    buf.drain(..idx + 8);
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
    let cancel = CancellationToken::new();
    let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let (events_tx, events_rx) = mpsc::channel(4);
    let writer = WireWriter::Udp {
        socket: socket.clone(),
        remote,
    };
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
    ));
    tokio::spawn(udp_receiver_task(
        Decoder::new(key, is_client),
        socket,
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
        let mut buf = vec![0u8; govpn_proto::ENCLESS_ENLARGE_SIZE + govpn_proto::MTU_MAX + 64];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                r = socket.recv(&mut buf) => {
                    match r {
                        Ok(n) => {
                            if inbound.try_send(buf[..n].to_vec()).is_err() {
                                // bounded queue: drop under overload
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
