//! Per-peer runtime: TAP <-> transport pump, heartbeat/CPR and timeout.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use rustvpn_proto::{Decoder, Encoder, Ordering as PktOrdering, TransportError, MAX_BYTES_PER_KEY};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::PeerConfig;
use crate::stats::LiveStats;
use crate::tap::Tap;

const OUTBOUND_QUEUE: usize = 256;
const INBOUND_QUEUE: usize = 512;
/// Upper bound for joining cancelled peer tasks before they are aborted.
///
/// All peer tasks are cancel-aware, so a healthy task exits immediately.  The
/// timeout only matters if a transport write is wedged; aborting it is safe
/// because the task owns no state the teardown needs, and it guarantees that
/// no task keeps an `Arc<Tap>` alive after [`PeerHandle::shutdown`] returns.
const TASK_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum Outbound {
    Payload(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerEvent {
    Timeout,
    /// Transport reached the 4 GiB per-key limit.
    Rehandshake,
    /// Time-driven rekey; only emitted by the original initiator (client).
    Rekey,
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
    pub stats: Arc<LiveStats>,
    pub cancel: CancellationToken,
    pub outbound: mpsc::Sender<Outbound>,
    pub inbound: Option<mpsc::Sender<Vec<u8>>>,
    pub events: mpsc::Receiver<PeerEvent>,
    /// Every task spawned for this peer.  The handle owns the only strong
    /// reference to their join handles so [`Self::shutdown`] can join (or
    /// abort) them before the caller closes the shared TAP/Wintun device.
    tasks: Vec<JoinHandle<()>>,
}

impl PeerHandle {
    /// Stop every peer task and wait until each one has released its `Tap`
    /// clone.  Cancel-aware tasks exit on the cancellation token; a task that
    /// does not finish within [`TASK_JOIN_TIMEOUT`] is aborted and joined, so
    /// this never returns while a task still holds the device.
    ///
    /// This is idempotent: a second call finds no tasks left.
    pub async fn shutdown(&mut self) {
        join_tasks_after_cancel(&self.cancel, &mut self.tasks, TASK_JOIN_TIMEOUT).await;
    }
}

/// Cancel `cancel`, then join every task, aborting any task that does not
/// finish within `timeout`.  Aborting still drops the task's `Tap` clone, so
/// this guarantees the device has no task readers/writers once it returns.
async fn join_tasks_after_cancel(
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
    timeout: Duration,
) {
    cancel.cancel();
    for mut task in tasks.drain(..) {
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(_) => {}
            Err(_) => {
                task.abort();
                let _ = task.await;
            }
        }
    }
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
    // `send_interval` is timeout/4 when keepalive is disabled (historical
    // heartbeat), the configured keepalive otherwise, and the CPR cycle when
    // constant-rate mode is active.
    let send_interval = cfg.send_interval();
    let mut ticker = tokio::time::interval(send_interval.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let payload = if cfg.cpr > 0 {
                    queue.pop_front().unwrap_or_default()
                } else if last_sent.elapsed() >= send_interval {
                    // Empty payload.  In noise/encless mode the transport
                    // codec pads this to the MTU; the wire format cannot
                    // carry a shorter packet, so keepalive cost is documented.
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
                        if client && bytes_rekey_due(&stats) {
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
                            if client && bytes_rekey_due(&stats) {
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

/// 4 GiB per-key threshold, evaluated only on the client (initiator).
fn bytes_rekey_due(stats: &LiveStats) -> bool {
    wire_total(stats) > MAX_BYTES_PER_KEY
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

/// Randomized time-driven rekey delay.  Returns `None` for servers (only the
/// original initiator may rekey) and when `rekey_time` is disabled.
fn rekey_delay(cfg: &PeerConfig, is_client: bool) -> Option<Duration> {
    if !is_client || cfg.rekey_time.is_zero() {
        return None;
    }
    let jitter_secs = cfg.rekey_jitter.as_secs();
    let jitter = if jitter_secs == 0 {
        0
    } else {
        let mut bytes = [0u8; 8];
        if getrandom::getrandom(&mut bytes).is_ok() {
            u64::from_le_bytes(bytes) % jitter_secs.saturating_add(1)
        } else {
            0
        }
    };
    cfg.rekey_time
        .checked_add(Duration::from_secs(jitter))
        .or(Some(Duration::MAX))
}

async fn rekey_task(delay: Duration, cancel: CancellationToken, events: mpsc::Sender<PeerEvent>) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(delay) => event(&events, PeerEvent::Rekey),
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
    let mut tasks = Vec::with_capacity(5);
    if let Some(delay) = rekey_delay(&cfg, is_client) {
        tasks.push(tokio::spawn(rekey_task(
            delay,
            cancel.clone(),
            events_tx.clone(),
        )));
    }
    tasks.push(tokio::spawn(sender_task(
        writer,
        Encoder::new(key, is_client),
        cfg.clone(),
        stats.clone(),
        outbound_rx,
        cancel.clone(),
        events_tx.clone(),
    )));
    tasks.push(tokio::spawn(tap_reader_task(
        tap.clone(),
        cfg.clone(),
        outbound_tx.clone(),
        cancel.clone(),
        events_tx.clone(),
    )));
    tasks.push(tokio::spawn(udp_receiver_task(
        Decoder::new(key, is_client),
        tap,
        cfg.clone(),
        stats.clone(),
        inbound_rx,
        cancel.clone(),
        events_tx.clone(),
        is_client,
    )));
    tasks.push(tokio::spawn(monitor_task(
        stats.clone(),
        cfg,
        cancel.clone(),
        events_tx,
    )));
    PeerHandle {
        stats,
        cancel,
        outbound: outbound_tx,
        inbound: Some(inbound_tx),
        events: events_rx,
        tasks,
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
    let mut tasks = Vec::with_capacity(5);
    if let Some(delay) = rekey_delay(&cfg, is_client) {
        tasks.push(tokio::spawn(rekey_task(
            delay,
            cancel.clone(),
            events_tx.clone(),
        )));
    }
    tasks.push(tokio::spawn(sender_task(
        WireWriter::Tcp(write),
        Encoder::new(key, is_client),
        cfg.clone(),
        stats.clone(),
        outbound_rx,
        cancel.clone(),
        events_tx.clone(),
    )));
    tasks.push(tokio::spawn(tap_reader_task(
        tap.clone(),
        cfg.clone(),
        outbound_tx.clone(),
        cancel.clone(),
        events_tx.clone(),
    )));
    tasks.push(tokio::spawn(tcp_receiver_task(
        Decoder::new(key, is_client),
        read,
        tap,
        cfg.clone(),
        stats.clone(),
        cancel.clone(),
        events_tx.clone(),
        is_client,
    )));
    tasks.push(tokio::spawn(monitor_task(
        stats.clone(),
        cfg,
        cancel.clone(),
        events_tx,
    )));
    PeerHandle {
        stats,
        cancel,
        outbound: outbound_tx,
        inbound: None,
        events: events_rx,
        tasks,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustvpn_crypto::verifier::Verifier;

    fn cfg(rekey_time: u64, rekey_jitter: u64) -> PeerConfig {
        PeerConfig {
            id: [1u8; 16],
            name: "test".into(),
            iface: "tap0".into(),
            mtu: 1515,
            up: String::new(),
            down: String::new(),
            timeout: Duration::from_secs(60),
            noise: false,
            cpr: 0,
            encless: false,
            time_sync: 0,
            keepalive: Duration::ZERO,
            rekey_time: Duration::from_secs(rekey_time),
            rekey_jitter: Duration::from_secs(rekey_jitter),
            network: None,
            verifier: Verifier::new(1, 1, 1, [1u8; 16]),
            signing_key: None,
        }
    }

    #[test]
    fn rekey_is_client_only_and_off_by_default() {
        assert!(rekey_delay(&cfg(0, 0), true).is_none());
        assert!(rekey_delay(&cfg(1800, 30), false).is_none());
    }

    #[test]
    fn rekey_delay_respects_interval_and_jitter() {
        let base = Duration::from_secs(1800);
        let max = Duration::from_secs(1830);
        for _ in 0..64 {
            let delay = rekey_delay(&cfg(1800, 30), true).unwrap();
            assert!(delay >= base && delay <= max, "{delay:?}");
        }
        assert_eq!(
            rekey_delay(&cfg(1800, 0), true).unwrap(),
            Duration::from_secs(1800)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rekey_task_fires_once_and_honours_cancel() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        tokio::spawn(rekey_task(Duration::from_secs(30), cancel.clone(), tx));
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(rx.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(rx.recv().await, Some(PeerEvent::Rekey));

        let (tx, mut rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        tokio::spawn(rekey_task(Duration::from_secs(30), cancel.clone(), tx));
        cancel.cancel();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn shutdown_joins_cancelled_tasks_and_aborts_wedged_ones() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let cancel = CancellationToken::new();
        let stopped = Arc::new(AtomicUsize::new(0));

        let token = cancel.clone();
        let flag = stopped.clone();
        let cancelled = tokio::spawn(async move {
            token.cancelled().await;
            flag.fetch_add(1, AtomicOrdering::SeqCst);
        });
        let token = cancel.clone();
        let flag = stopped.clone();
        let also_cancelled = tokio::spawn(async move {
            token.cancelled().await;
            flag.fetch_add(1, AtomicOrdering::SeqCst);
        });
        // Ignores cancellation forever: the join timeout must abort it.
        let wedged = tokio::spawn(async { std::future::pending::<()>().await });

        let mut tasks = vec![cancelled, also_cancelled, wedged];
        join_tasks_after_cancel(&cancel, &mut tasks, Duration::from_millis(25)).await;

        assert!(
            tasks.is_empty(),
            "every handle must be drained after shutdown"
        );
        assert_eq!(stopped.load(AtomicOrdering::SeqCst), 2);
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_reports_no_remaining_tasks() {
        let cancel = CancellationToken::new();
        let (outbound, _rx) = mpsc::channel(1);
        let (_events_tx, events) = mpsc::channel(1);
        let stats = LiveStats::new("test".into(), [1u8; 16], false, 0, false, 1515);
        let mut handle = PeerHandle {
            stats,
            cancel,
            outbound,
            inbound: None,
            events,
            tasks: Vec::new(),
        };
        handle.shutdown().await;
        // A second call is a no-op and must not panic or block.
        handle.shutdown().await;
    }

    async fn spawn_sender_for_test(
        cfg: PeerConfig,
    ) -> (
        Arc<LiveStats>,
        mpsc::Sender<Outbound>,
        tokio::net::UdpSocket,
    ) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = LiveStats::new("test".into(), cfg.id, false, 0, false, cfg.mtu);
        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::channel(4);
        tokio::spawn(sender_task(
            WireWriter::Udp {
                socket,
                remote: remote.local_addr().unwrap(),
            },
            Encoder::new([9u8; 32], true),
            Arc::new(cfg),
            stats.clone(),
            outbound_rx,
            CancellationToken::new(),
            events_tx,
        ));
        // Let the sender create its interval timer before the test advances
        // the paused clock.
        tokio::task::yield_now().await;
        (stats, outbound_tx, remote)
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_disabled_keeps_legacy_timeout_quarter() {
        let mut cfg = cfg(0, 0);
        cfg.timeout = Duration::from_secs(60);
        let (stats, _outbound, _remote) = spawn_sender_for_test(cfg).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(stats.snapshot().heartbeat_sent, 0);
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert!(stats.snapshot().heartbeat_sent >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_uses_configured_interval() {
        let mut cfg = cfg(0, 0);
        cfg.timeout = Duration::from_secs(60);
        cfg.keepalive = Duration::from_secs(25);
        let (stats, _outbound, _remote) = spawn_sender_for_test(cfg).await;
        tokio::time::advance(Duration::from_secs(24)).await;
        tokio::task::yield_now().await;
        assert_eq!(stats.snapshot().heartbeat_sent, 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(stats.snapshot().heartbeat_sent >= 1);
    }

    #[test]
    fn bytes_rekey_threshold_is_client_side_budget() {
        let stats = LiveStats::new("1.2.3.4:5".into(), [1u8; 16], false, 0, false, 1515);
        assert!(!bytes_rekey_due(&stats));
        stats.add_wire_out(MAX_BYTES_PER_KEY as usize);
        assert!(!bytes_rekey_due(&stats));
        stats.add_wire_out(1);
        assert!(bytes_rekey_due(&stats));
    }
}
