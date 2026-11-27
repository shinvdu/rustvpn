//! Platform-independent Ethernet shim in front of an L3 adapter.
//!
//! RustVPN's wire protocol carries complete Ethernet frames.  Windows clients
//! use a Wintun **L3** adapter, so this module supplies the missing L2 pieces:
//!
//! * IPv4 <-> Ethernet frame codec (Ethernet padding stripped via
//!   `total_length`).
//! * A bounded ARP state machine that synthesizes the next-hop MAC.
//! * The [`ShimPump`] concurrency wrapper: one dedicated blocking reader
//!   thread feeds a bounded Tokio channel, while the shim state is only locked
//!   for short, non-blocking bookkeeping.
//!
//! Everything here is platform-neutral and unit-tested on Linux.  The Wintun
//! device itself lives under `#[cfg(target_os = "windows")]` in the `windows`
//! submodule.
//!
//! ## Direction map
//!
//! `rustvpn-net`'s [`crate::tap::Tap::recv`] is the **OS -> tunnel** direction.
//! The Windows tap therefore drains this shim's internal outbound queue first
//! (ARP requests/replies and packets released from ARP pending state), then
//! reads an IP packet from Wintun, wraps it in Ethernet, and returns it.
//!
//! [`crate::tap::Tap::send`] is **tunnel -> OS**: IPv4 frames are written to
//! Wintun; ARP frames are consumed locally and any reply is queued for the
//! next `recv()`.

pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod mac;
pub mod safety;

/// Deterministic fuzz-style parser tests (no external property-test crate).
#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod fuzz_tests;

/// Windows Wintun adapter + [`crate::tap::Tap`] implementation.
///
/// Public so the M2 Windows service and diagnostics can reuse the adapter and
/// its close/persistence probe; the shim core does not depend on them.
#[cfg(target_os = "windows")]
pub mod windows;

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex as AsyncMutex;

use rustvpn_proto::{Mode, MTU_MAX};

use arp::{ArpConfig, ArpState, ArpStats, ResolveOutcome};
use ethernet::{build_ipv4_frame, classify_inbound, Inbound, InboundError, ETH_HEADER_LEN};
use ipv4::{
    in_same_subnet, is_limited_broadcast, is_multicast, multicast_mac, subnet_broadcast, Ipv4Error,
    Ipv4Header,
};
use mac::MacAddr;

/// Smallest inner IP MTU the shim itself accepts. It is below the Windows
/// adapter's 576-byte policy but still leaves room for a minimal IPv4 header
/// plus a small transport header.
pub const MIN_INNER_IP_MTU: usize = 42;

/// Bounded OS -> tunnel channel used by [`ShimPump`].
pub const DEFAULT_INBOUND_CAPACITY: usize = 64;
/// Bounded "toward tunnel" queue inside [`EthernetShim`].
pub const DEFAULT_OUTBOUND_CAPACITY: usize = 64;
/// How long the blocking reader waits for an OS packet before re-checking the
/// stop flag.
const READER_POLL: Duration = Duration::from_millis(50);
/// Reader buffer is the inner MTU plus headroom for an OS-generated packet
/// that exceeds the interface MTU.
const READER_HEADROOM: usize = 128;

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Plain => "plain",
        Mode::Noise => "noise",
        Mode::Encless => "encless",
    }
}

#[derive(Clone, Debug)]
pub struct ShimConfig {
    pub arp: ArpConfig,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    /// IP MTU configured on Wintun (`wire.max_payload - 14`).
    pub inner_ip_mtu: usize,
    /// Bound for the internal "toward tunnel" frame queue.
    pub outbound_capacity: usize,
    /// Numeric two-sided wire MTU contract (`Mode::max_payload` input).
    pub wire_mtu: usize,
    /// Transport mode whose payload budget the wire MTU is checked against.
    pub mode: Mode,
}

impl ShimConfig {
    pub fn new(our_ip: Ipv4Addr, our_mac: MacAddr) -> Self {
        Self {
            arp: ArpConfig::new(our_ip, our_mac),
            prefix_len: 24,
            gateway: None,
            inner_ip_mtu: 1500,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            wire_mtu: 1515,
            mode: Mode::Plain,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.prefix_len > 32 {
            return Err(format!(
                "prefix length {} is invalid (must be 0..=32)",
                self.prefix_len
            ));
        }
        if self.wire_mtu < self.mode.min_mtu() || self.wire_mtu > MTU_MAX {
            return Err(format!(
                "wire MTU {} is outside the supported {} range {}..={}",
                self.wire_mtu,
                mode_name(self.mode),
                self.mode.min_mtu(),
                MTU_MAX
            ));
        }
        let wire_budget = self.mode.max_payload(self.wire_mtu);
        if self.inner_ip_mtu < MIN_INNER_IP_MTU {
            return Err(format!(
                "inner IP MTU {} is below the minimum {MIN_INNER_IP_MTU}",
                self.inner_ip_mtu
            ));
        }
        let framed = self
            .inner_ip_mtu
            .checked_add(ETH_HEADER_LEN)
            .ok_or_else(|| "inner IP MTU overflows the frame budget".to_string())?;
        if framed > wire_budget {
            return Err(format!(
                "inner IP MTU {} + {ETH_HEADER_LEN}-byte Ethernet header = {framed} exceeds the \
                 {} wire budget {} for wire MTU {} (inner IP MTU must be at most {})",
                self.inner_ip_mtu,
                mode_name(self.mode),
                wire_budget,
                self.wire_mtu,
                wire_budget.saturating_sub(ETH_HEADER_LEN)
            ));
        }
        if self.outbound_capacity == 0 {
            return Err("outbound queue capacity must be non-zero".into());
        }
        if self.arp.pending_capacity == 0 || self.arp.pending_per_target == 0 {
            return Err("ARP pending queue bounds must be non-zero".into());
        }
        if self.arp.cache_capacity == 0 {
            return Err("ARP cache capacity must be non-zero".into());
        }
        if self.gateway == Some(Ipv4Addr::UNSPECIFIED) {
            return Err("gateway must not be 0.0.0.0 (use None for none)".into());
        }
        Ok(())
    }

    pub fn our_ip(&self) -> Ipv4Addr {
        self.arp.our_ip
    }

    pub fn our_mac(&self) -> MacAddr {
        self.arp.our_mac
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShimStats {
    pub ip_from_os: u64,
    pub ip_to_os: u64,
    pub frames_from_tunnel: u64,
    pub frames_to_tunnel: u64,
    pub arp_from_tunnel: u64,
    pub arp_to_tunnel: u64,
    pub outbound_dropped: u64,
    pub drop_short: u64,
    pub drop_not_for_us: u64,
    pub drop_vlan: u64,
    pub drop_ipv6: u64,
    pub drop_other_ethertype: u64,
    pub drop_short_arp: u64,
    pub drop_malformed_ip: u64,
    pub drop_oversized: u64,
    pub drop_no_route: u64,
    pub drop_pending_full: u64,
    pub drop_ipv6_os: u64,
    pub drop_self_addressed: u64,
}

impl ShimStats {
    /// Total input frames/packets that were discarded.
    pub fn dropped_total(&self) -> u64 {
        self.drop_short
            + self.drop_not_for_us
            + self.drop_vlan
            + self.drop_ipv6
            + self.drop_other_ethertype
            + self.drop_short_arp
            + self.drop_malformed_ip
            + self.drop_oversized
            + self.drop_no_route
            + self.drop_pending_full
            + self.drop_ipv6_os
            + self.drop_self_addressed
            + self.outbound_dropped
    }
}

impl fmt::Display for ShimStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "os_ip={} os_to_ip={} tunnel_frames={} tunnel_to_os_frames={} \
             arp_in={} arp_out={} drops={}",
            self.ip_from_os,
            self.ip_to_os,
            self.frames_from_tunnel,
            self.frames_to_tunnel,
            self.arp_from_tunnel,
            self.arp_to_tunnel,
            self.dropped_total()
        )
    }
}

pub struct EthernetShim {
    cfg: ShimConfig,
    arp: ArpState,
    outbound: VecDeque<Vec<u8>>,
    stats: ShimStats,
}

impl EthernetShim {
    pub fn new(cfg: ShimConfig) -> Result<Self, String> {
        cfg.validate()?;
        Ok(Self {
            arp: ArpState::new(cfg.arp.clone()),
            cfg,
            outbound: VecDeque::new(),
            stats: ShimStats::default(),
        })
    }

    pub fn config(&self) -> &ShimConfig {
        &self.cfg
    }

    pub fn stats(&self) -> &ShimStats {
        &self.stats
    }

    pub fn arp_stats(&self) -> &ArpStats {
        self.arp.stats()
    }

    pub fn arp(&mut self) -> &mut ArpState {
        &mut self.arp
    }

    pub fn outbound_len(&self) -> usize {
        self.outbound.len()
    }

    /// Drain one frame that must be delivered to the tunnel.
    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// Feed one L3 IPv4 packet from the OS side (Wintun).
    ///
    /// Returns the number of Ethernet frames enqueued toward the tunnel.
    pub fn ingest_os_ip(&mut self, ip: &[u8], now: Instant) -> usize {
        self.stats.ip_from_os += 1;
        let header = match Ipv4Header::parse(ip) {
            Ok(header) => header,
            Err(Ipv4Error::NotIpv4(6)) => {
                self.stats.drop_ipv6_os += 1;
                return 0;
            }
            Err(_) => {
                self.stats.drop_malformed_ip += 1;
                return 0;
            }
        };
        if header.total_length > self.cfg.inner_ip_mtu {
            self.stats.drop_oversized += 1;
            return 0;
        }
        let packet = header.packet();
        let dst = header.dst;

        // The OS should never hand us a packet addressed to our own interface,
        // but if it does, never ARP-queue or tunnel it (that would leak a
        // self-addressed loop into the peer).
        if dst == self.cfg.our_ip() {
            self.stats.drop_self_addressed += 1;
            return 0;
        }

        // Broadcast and multicast never use ARP.
        let directed_broadcast = subnet_broadcast(self.cfg.our_ip(), self.cfg.prefix_len);
        if is_limited_broadcast(dst) || directed_broadcast == Some(dst) {
            let frame = build_ipv4_frame(MacAddr::BROADCAST, self.cfg.our_mac(), packet);
            self.enqueue(frame);
            return 1;
        }
        if is_multicast(dst) {
            let frame = build_ipv4_frame(multicast_mac(dst), self.cfg.our_mac(), packet);
            self.enqueue(frame);
            return 1;
        }

        let Some(next_hop) = self.next_hop(dst) else {
            self.stats.drop_no_route += 1;
            return 0;
        };

        match self.arp.resolve_or_queue(next_hop, packet, now) {
            ResolveOutcome::Ready(frame) => {
                self.enqueue(frame);
                1
            }
            ResolveOutcome::Queued { request, dropped } => {
                if dropped {
                    self.stats.drop_pending_full += 1;
                }
                if let Some(request) = request {
                    self.stats.arp_to_tunnel += 1;
                    self.enqueue(request);
                    1
                } else {
                    0
                }
            }
        }
    }

    /// Feed one Ethernet frame from the tunnel.
    ///
    /// Returns an IPv4 packet to write to Wintun, or `None` when the frame was
    /// dropped or handled locally (ARP).
    pub fn ingest_tunnel_frame(&mut self, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.stats.frames_from_tunnel += 1;
        match classify_inbound(frame, self.cfg.our_mac(), self.cfg.inner_ip_mtu) {
            Ok(Inbound::Ipv4(header)) => {
                self.stats.ip_to_os += 1;
                Some(header.packet().to_vec())
            }
            Ok(Inbound::Arp(payload)) => {
                self.stats.arp_from_tunnel += 1;
                let handling = self.arp.handle_payload(payload, now);
                if let Some(reply) = handling.reply {
                    self.stats.arp_to_tunnel += 1;
                    self.enqueue(reply);
                }
                for released in handling.flushed {
                    self.enqueue(released);
                }
                None
            }
            Err(error) => {
                self.count_drop(error);
                None
            }
        }
    }

    /// Queue an optional gratuitous ARP request (connection setup).
    pub fn announce_gratuitous_arp(&mut self, _now: Instant) -> bool {
        let frame = self.arp.gratuitous_request();
        self.stats.arp_to_tunnel += 1;
        self.enqueue(frame);
        true
    }

    pub fn next_hop(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        if in_same_subnet(dst, self.cfg.our_ip(), self.cfg.prefix_len) {
            Some(dst)
        } else {
            self.cfg.gateway
        }
    }

    fn enqueue(&mut self, frame: Vec<u8>) {
        if frame.len() > self.cfg.inner_ip_mtu + ETH_HEADER_LEN {
            self.stats.outbound_dropped += 1;
            return;
        }
        if self.outbound.len() >= self.cfg.outbound_capacity {
            self.outbound.pop_front();
            self.stats.outbound_dropped += 1;
        }
        self.stats.frames_to_tunnel += 1;
        self.outbound.push_back(frame);
    }

    fn count_drop(&mut self, error: InboundError) {
        match error {
            InboundError::TooShort => self.stats.drop_short += 1,
            InboundError::NotForUs(_) => self.stats.drop_not_for_us += 1,
            InboundError::Vlan => self.stats.drop_vlan += 1,
            InboundError::Ipv6 => self.stats.drop_ipv6 += 1,
            InboundError::OtherEtherType(_) => self.stats.drop_other_ethertype += 1,
            InboundError::ShortArp => self.stats.drop_short_arp += 1,
            InboundError::MalformedIpv4(_) => self.stats.drop_malformed_ip += 1,
            InboundError::OversizedIpv4 { .. } => self.stats.drop_oversized += 1,
        }
    }
}

/// A blocking L3 packet device (Wintun on Windows, a fake in tests).
///
/// `recv_packet` may block for a short, bounded period and return
/// `Ok(None)` when no packet is ready. It must never hold a lock that the
/// shim needs.
pub trait L3Device: Send + Sync + 'static {
    fn recv_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    fn send_packet(&self, packet: &[u8]) -> io::Result<usize>;
}

/// What [`ShimPump::send`] did with a tunnel frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// The frame carried an IPv4 packet that was written to the L3 device.
    Written(usize),
    /// The frame was handled locally (ARP) or dropped; any reply is queued for
    /// the next `recv()`.
    Consumed,
}

/// Concurrency-safe async wrapper around [`EthernetShim`] and an [`L3Device`].
///
/// The naive `Mutex<EthernetShim>` design deadlocks or stalls: `recv()` would
/// hold the shim lock across a blocking Wintun read, so `send()` could not make
/// progress, and a Tokio worker would be blocked.  `ShimPump` instead:
///
/// 1. runs L3 reads on a dedicated blocking thread that feeds a bounded Tokio
///    channel using `blocking_send` (backpressure, no busy loop);
/// 2. locks the shim only briefly for `take_outbound()` / `ingest_os_ip()` /
///    `ingest_tunnel_frame()` (never across a Wintun read/write and never
///    across an `.await` in `send`);
/// 3. writes the L3 device outside the shim lock.
///
/// Idle `recv()` awaits the bounded channel and only returns `Ok(None)` after
/// [`Self::shutdown`] or a reader exit; it never spins on `Ok(0)`.
pub struct ShimPump {
    shim: Mutex<EthernetShim>,
    rx: Mutex<Option<Receiver<Vec<u8>>>>,
    recv_gate: AsyncMutex<()>,
    device: Arc<dyn L3Device>,
    stop: Arc<AtomicBool>,
    reader_error: Arc<Mutex<Option<String>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

/// Owns the single inbound receiver while [`ShimPump::recv`] awaits on it.
///
/// If the `recv` future is cancelled (the peer task is joined/aborted during a
/// reconnect), the receiver is put back so a reused adapter keeps working.
/// During shutdown the receiver is dropped instead, which closes the channel
/// and wakes a reader parked in `blocking_send`.
struct ReceiverLease<'a> {
    rx: Option<Receiver<Vec<u8>>>,
    slot: &'a Mutex<Option<Receiver<Vec<u8>>>>,
    stop: &'a AtomicBool,
}

impl Drop for ReceiverLease<'_> {
    fn drop(&mut self) {
        let Some(rx) = self.rx.take() else {
            return;
        };
        if self.stop.load(AtomicOrdering::SeqCst) {
            // Shutdown: closing the channel unblocks the reader.
            drop(rx);
            return;
        }
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if slot.is_none() {
            *slot = Some(rx);
        }
    }
}

impl ShimPump {
    /// Start the pump. `inbound_capacity` bounds the OS->tunnel channel;
    /// `max_packet_size` must be at least the configured inner IP MTU.
    pub fn new(
        cfg: ShimConfig,
        device: Arc<dyn L3Device>,
        inbound_capacity: usize,
        max_packet_size: usize,
    ) -> Result<Self, String> {
        if inbound_capacity == 0 {
            return Err("inbound channel capacity must be non-zero".into());
        }
        if max_packet_size < cfg.inner_ip_mtu || max_packet_size == 0 {
            return Err(format!(
                "reader buffer {max_packet_size} is smaller than the inner IP MTU {}",
                cfg.inner_ip_mtu
            ));
        }
        let shim = EthernetShim::new(cfg)?;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(inbound_capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let reader_error = Arc::new(Mutex::new(None));

        let thread_device = Arc::clone(&device);
        let thread_stop = Arc::clone(&stop);
        let thread_error = Arc::clone(&reader_error);
        let reader = thread::Builder::new()
            .name("rustvpn-wintun-l3-reader".into())
            .spawn(move || {
                let mut buf = vec![0u8; max_packet_size];
                while !thread_stop.load(AtomicOrdering::Relaxed) {
                    match thread_device.recv_packet(&mut buf) {
                        Ok(Some(n)) if n > 0 && n <= max_packet_size => {
                            if tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => {}
                        Err(error) => {
                            if !thread_stop.load(AtomicOrdering::SeqCst) {
                                *thread_error
                                    .lock()
                                    .unwrap_or_else(|poison| poison.into_inner()) =
                                    Some(error.to_string());
                            }
                            break;
                        }
                    }
                }
            })
            .map_err(|e| format!("spawn L3 reader thread: {e}"))?;

        Ok(Self {
            shim: Mutex::new(shim),
            rx: Mutex::new(Some(rx)),
            recv_gate: AsyncMutex::new(()),
            device,
            stop,
            reader_error,
            reader: Mutex::new(Some(reader)),
        })
    }

    /// OS -> tunnel. Awaits a frame. Returns `Ok(None)` only after
    /// [`Self::shutdown`] or when the reader exits cleanly.
    pub async fn recv(&self) -> io::Result<Option<Vec<u8>>> {
        let _gate = self.recv_gate.lock().await;
        loop {
            if let Some(frame) = self.take_outbound() {
                return Ok(Some(frame));
            }
            if let Some(message) = self.take_reader_error() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, message));
            }
            if self.stop.load(AtomicOrdering::SeqCst) {
                return Ok(None);
            }

            // Move the receiver into a lease for the await so a std mutex is never
            // held across `.await`.  The gate serializes concurrent `recv`
            // callers.  The lease restores the receiver if this future is
            // cancelled (reconnect), and closes the channel on shutdown.
            let mut lease = {
                let mut guard = self.rx.lock().unwrap_or_else(|poison| poison.into_inner());
                match guard.take() {
                    Some(rx) => ReceiverLease {
                        rx: Some(rx),
                        slot: &self.rx,
                        stop: self.stop.as_ref(),
                    },
                    None => return Ok(None),
                }
            };
            let received = lease
                .rx
                .as_mut()
                .expect("receiver present in the lease")
                .recv()
                .await;
            drop(lease);

            match received {
                Some(packet) => {
                    let produced = {
                        let mut shim = self
                            .shim
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        shim.ingest_os_ip(&packet, Instant::now())
                    };
                    if produced == 0 {
                        // Dropped locally; keep waiting instead of returning an
                        // empty frame (which would spin the caller).
                        continue;
                    }
                    // The loop drains the resulting outbound frames.
                }
                None => {
                    if let Some(message) = self.take_reader_error() {
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, message));
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// Tunnel -> OS. The shim lock is dropped before writing to the device, so
    /// this can progress while another task waits in [`Self::recv`].
    pub fn send(&self, frame: &[u8]) -> io::Result<SendOutcome> {
        let packet = {
            let mut shim = self
                .shim
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            shim.ingest_tunnel_frame(frame, Instant::now())
        };
        match packet {
            Some(packet) => {
                let written = self.device.send_packet(&packet)?;
                Ok(SendOutcome::Written(written))
            }
            None => Ok(SendOutcome::Consumed),
        }
    }

    /// Queue one gratuitous ARP request toward the tunnel.
    pub fn announce_gratuitous_arp(&self) -> bool {
        self.with_shim(|shim| shim.announce_gratuitous_arp(Instant::now()))
    }

    pub fn outbound_len(&self) -> usize {
        self.with_shim(|shim| shim.outbound_len())
    }

    pub fn stats(&self) -> ShimStats {
        self.with_shim(|shim| *shim.stats())
    }

    pub fn arp_stats(&self) -> ArpStats {
        self.with_shim(|shim| *shim.arp_stats())
    }

    pub fn config(&self) -> ShimConfig {
        self.with_shim(|shim| shim.config().clone())
    }

    /// Stop the reader and join it. Safe to call more than once and from a
    /// thread other than the one blocked in `recv()`.
    pub fn shutdown(&self) {
        self.stop.store(true, AtomicOrdering::SeqCst);
        // Disconnect an idle reader parked in `blocking_send`.  If a `recv`
        // future currently owns the receiver it will observe the channel
        // closing / stop flag itself.
        if let Ok(mut guard) = self.rx.lock() {
            guard.take();
        }
        let handle = self
            .reader
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    fn take_outbound(&self) -> Option<Vec<u8>> {
        self.with_shim(|shim| shim.take_outbound())
    }

    fn take_reader_error(&self) -> Option<String> {
        self.reader_error
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
    }

    fn with_shim<T>(&self, action: impl FnOnce(&mut EthernetShim) -> T) -> T {
        let mut shim = self
            .shim
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        action(&mut shim)
    }
}

impl Drop for ShimPump {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The reader poll interval, exposed for diagnostics/tests.
pub fn reader_poll_interval() -> Duration {
    READER_POLL
}

/// Reader buffer size for an inner IP MTU.
pub fn reader_buffer_size(inner_ip_mtu: usize) -> usize {
    inner_ip_mtu.saturating_add(READER_HEADROOM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;

    use arp::{build_arp_frame, ArpOp, ArpPacket, ARP_PAYLOAD_LEN};
    use ethernet::{build_frame, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN};

    const OUR_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 1, 2, 3]);
    const PEER_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 9, 8, 7]);
    const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 9);

    fn shim_config() -> ShimConfig {
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.prefix_len = 24;
        cfg.inner_ip_mtu = 1500;
        cfg.arp.pending_capacity = 8;
        cfg.arp.pending_per_target = 4;
        cfg.arp.cache_ttl = Duration::from_secs(60);
        cfg.arp.pending_ttl = Duration::from_secs(5);
        cfg.arp.retry_interval = Duration::from_secs(1);
        cfg.outbound_capacity = 8;
        cfg
    }

    fn shim() -> EthernetShim {
        EthernetShim::new(shim_config()).unwrap()
    }

    fn ipv4(dst: Ipv4Addr, payload: usize) -> Vec<u8> {
        let total = 20 + payload;
        let mut buf = vec![0u8; total];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        buf[8] = 64;
        buf[9] = 17;
        buf[12..16].copy_from_slice(&OUR_IP.octets());
        buf[16..20].copy_from_slice(&dst.octets());
        buf
    }

    fn arp_reply_frame() -> Vec<u8> {
        let packet = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: OUR_MAC,
            target_ip: OUR_IP,
        };
        build_arp_frame(OUR_MAC, PEER_MAC, &packet)
    }

    #[test]
    fn outbound_miss_emits_arp_then_flush_produces_data_frame() {
        let now = Instant::now();
        let mut shim = shim();
        let packet = ipv4(PEER_IP, 20);
        assert_eq!(shim.ingest_os_ip(&packet, now), 1);

        let request_frame = shim.take_outbound().expect("ARP request");
        let request = ArpPacket::parse(&request_frame[14..]).unwrap();
        assert_eq!(request.op, ArpOp::Request);
        assert_eq!(request.target_ip, PEER_IP);
        assert_eq!(shim.outbound_len(), 0);

        assert!(shim.ingest_tunnel_frame(&arp_reply_frame(), now).is_none());
        let data_frame = shim.take_outbound().expect("pending packet flushed");
        assert_eq!(data_frame.len(), 14 + packet.len());
        assert_eq!(&data_frame[0..6], &PEER_MAC.octets());
        assert_eq!(&data_frame[6..12], &OUR_MAC.octets());
        assert_eq!(&data_frame[12..14], &[0x08, 0x00]);
        assert_eq!(&data_frame[14..], &packet[..]);
    }

    #[test]
    fn inbound_ipv4_frame_is_stripped_to_total_length() {
        let now = Instant::now();
        let mut shim = shim();
        let packet = ipv4(Ipv4Addr::new(10, 88, 0, 1), 8);
        let mut frame = build_ipv4_frame(OUR_MAC, PEER_MAC, &packet);
        frame.extend_from_slice(&[0xee; 30]);
        let out = shim.ingest_tunnel_frame(&frame, now).unwrap();
        assert_eq!(out.len(), packet.len());
        assert_eq!(out, packet);
    }

    #[test]
    fn inbound_arp_request_for_us_is_answered_into_outbound_queue() {
        let now = Instant::now();
        let mut shim = shim();
        let request = ArpPacket {
            op: ArpOp::Request,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: MacAddr::ZERO,
            target_ip: OUR_IP,
        };
        let frame = build_arp_frame(MacAddr::BROADCAST, PEER_MAC, &request);
        assert!(shim.ingest_tunnel_frame(&frame, now).is_none());
        let reply_frame = shim.take_outbound().expect("ARP reply");
        assert_eq!(reply_frame.len(), 14 + ARP_PAYLOAD_LEN);
        assert_eq!(&reply_frame[0..6], &PEER_MAC.octets());
        let reply = ArpPacket::parse(&reply_frame[14..]).unwrap();
        assert_eq!(reply.op, ArpOp::Reply);
        assert_eq!(reply.sender_ip, OUR_IP);
        assert_eq!(reply.sender_mac, OUR_MAC);
        assert_eq!(reply.target_ip, PEER_IP);
    }

    #[test]
    fn broadcast_and_multicast_are_framed_without_arp() {
        let now = Instant::now();
        let mut shim = shim();

        let broadcast = ipv4(Ipv4Addr::BROADCAST, 4);
        assert_eq!(shim.ingest_os_ip(&broadcast, now), 1);
        let frame = shim.take_outbound().unwrap();
        assert_eq!(&frame[0..6], &MacAddr::BROADCAST.octets());

        let group = Ipv4Addr::new(224, 0, 1, 2);
        let multicast = ipv4(group, 4);
        assert_eq!(shim.ingest_os_ip(&multicast, now), 1);
        let frame = shim.take_outbound().unwrap();
        assert_eq!(&frame[0..6], &[0x01, 0x00, 0x5e, 0x00, 0x01, 0x02]);
        assert_eq!(shim.outbound_len(), 0);
    }

    #[test]
    fn directed_broadcast_uses_broadcast_mac() {
        let now = Instant::now();
        let mut shim = shim();
        let packet = ipv4(Ipv4Addr::new(10, 88, 0, 255), 4);
        assert_eq!(shim.ingest_os_ip(&packet, now), 1);
        let frame = shim.take_outbound().unwrap();
        assert_eq!(&frame[0..6], &MacAddr::BROADCAST.octets());
    }

    #[test]
    fn off_subnet_without_gateway_is_dropped() {
        let now = Instant::now();
        let mut shim = shim();
        let packet = ipv4(Ipv4Addr::new(192, 0, 2, 1), 4);
        assert_eq!(shim.ingest_os_ip(&packet, now), 0);
        assert_eq!(shim.stats().drop_no_route, 1);
    }

    #[test]
    fn off_subnet_uses_gateway_for_arp() {
        let now = Instant::now();
        let mut shim = shim();
        shim.cfg.gateway = Some(Ipv4Addr::new(10, 88, 0, 1));
        let packet = ipv4(Ipv4Addr::new(192, 0, 2, 1), 4);
        assert_eq!(shim.ingest_os_ip(&packet, now), 1);
        let frame = shim.take_outbound().unwrap();
        let request = ArpPacket::parse(&frame[14..]).unwrap();
        assert_eq!(request.target_ip, Ipv4Addr::new(10, 88, 0, 1));
    }

    #[test]
    fn drop_counters_cover_vlan_ipv6_ethtype_and_malformed() {
        let now = Instant::now();
        let mut shim = shim();

        assert!(shim
            .ingest_tunnel_frame(
                &build_frame(OUR_MAC, PEER_MAC, ETHERTYPE_VLAN, &[0u8; 20]),
                now
            )
            .is_none());
        assert!(shim
            .ingest_tunnel_frame(
                &build_frame(OUR_MAC, PEER_MAC, ETHERTYPE_IPV6, &[0x60; 40]),
                now
            )
            .is_none());
        assert!(shim
            .ingest_tunnel_frame(&build_frame(OUR_MAC, PEER_MAC, 0x88cc, &[0u8; 32]), now)
            .is_none());
        assert!(shim.ingest_tunnel_frame(&[0u8; 10], now).is_none());
        assert!(shim
            .ingest_tunnel_frame(
                &build_frame(PEER_MAC, PEER_MAC, ETHERTYPE_ARP, &[0u8; 28]),
                now
            )
            .is_none());

        let stats = shim.stats();
        assert_eq!(stats.drop_vlan, 1);
        assert_eq!(stats.drop_ipv6, 1);
        assert_eq!(stats.drop_other_ethertype, 1);
        assert_eq!(stats.drop_short, 1);
        assert_eq!(stats.drop_not_for_us, 1);
    }

    #[test]
    fn oversized_os_packet_is_dropped() {
        let now = Instant::now();
        let mut shim = shim();
        let packet = ipv4(PEER_IP, 1501);
        assert_eq!(shim.ingest_os_ip(&packet, now), 0);
        assert_eq!(shim.stats().drop_oversized, 1);
    }

    #[test]
    fn self_addressed_os_packet_is_dropped_without_arp() {
        let now = Instant::now();
        let mut shim = shim();
        let packet = ipv4(OUR_IP, 8);
        assert_eq!(shim.ingest_os_ip(&packet, now), 0);
        assert_eq!(shim.stats().drop_self_addressed, 1);
        assert_eq!(shim.outbound_len(), 0);
        assert_eq!(shim.arp_stats().requests_sent, 0);
    }

    #[test]
    fn ipv6_from_os_is_dropped_by_version() {
        let now = Instant::now();
        let mut shim = shim();
        let mut packet = ipv4(PEER_IP, 0);
        packet[0] = 0x60;
        assert_eq!(shim.ingest_os_ip(&packet, now), 0);
        assert_eq!(shim.stats().drop_ipv6_os, 1);
    }

    #[test]
    fn outbound_queue_is_bounded() {
        let now = Instant::now();
        let mut shim = shim();
        shim.cfg.outbound_capacity = 2;
        for _ in 0..5 {
            let packet = ipv4(Ipv4Addr::BROADCAST, 4);
            assert_eq!(shim.ingest_os_ip(&packet, now), 1);
        }
        assert_eq!(shim.outbound_len(), 2);
        assert_eq!(shim.stats().outbound_dropped, 3);
    }

    #[test]
    fn gratuitous_arp_is_queued() {
        let now = Instant::now();
        let mut shim = shim();
        assert!(shim.announce_gratuitous_arp(now));
        let frame = shim.take_outbound().unwrap();
        assert_eq!(&frame[0..6], &MacAddr::BROADCAST.octets());
        let packet = ArpPacket::parse(&frame[14..]).unwrap();
        assert_eq!(packet.op, ArpOp::Request);
        assert_eq!(packet.target_ip, OUR_IP);
    }

    #[test]
    fn invalid_config_is_rejected() {
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.prefix_len = 33;
        assert!(EthernetShim::new(cfg).is_err());

        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.outbound_capacity = 0;
        assert!(EthernetShim::new(cfg).is_err());

        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.gateway = Some(Ipv4Addr::UNSPECIFIED);
        assert!(EthernetShim::new(cfg).is_err());
    }

    #[test]
    fn wire_budget_validation_rejects_nonsensical_mtu_combinations() {
        // 1500 + 14 = 1514, but plain wire 1514 only budgets 1513.
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.wire_mtu = 1514;
        cfg.inner_ip_mtu = 1500;
        let error = EthernetShim::new(cfg).err().unwrap();
        assert!(error.contains("exceeds"), "{error}");

        // Noise mode reserves 25 bytes: 1515 -> 1490 payload -> 1476 inner.
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.mode = Mode::Noise;
        cfg.wire_mtu = 1515;
        cfg.inner_ip_mtu = 1500;
        assert!(EthernetShim::new(cfg).is_err());

        // Encless 1515 -> 1506 payload -> 1492 inner.
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.mode = Mode::Encless;
        cfg.wire_mtu = 1515;
        cfg.inner_ip_mtu = 1500;
        assert!(EthernetShim::new(cfg).is_err());

        // Matching values are accepted.
        for (mode, wire, inner) in [
            (Mode::Plain, 1515, 1500),
            (Mode::Noise, 1515, 1476),
            (Mode::Encless, 1515, 1492),
            (Mode::Plain, 83, 68),
        ] {
            let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
            cfg.mode = mode;
            cfg.wire_mtu = wire;
            cfg.inner_ip_mtu = inner;
            assert!(EthernetShim::new(cfg).is_ok(), "{mode:?} {wire} -> {inner}");
        }

        // Too-small inner MTUs and impossible wire values are rejected.
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.inner_ip_mtu = MIN_INNER_IP_MTU - 1;
        assert!(EthernetShim::new(cfg).is_err());

        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.inner_ip_mtu = 0;
        assert!(EthernetShim::new(cfg).is_err());

        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.wire_mtu = 0;
        assert!(EthernetShim::new(cfg).is_err());

        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.wire_mtu = MTU_MAX + 1;
        assert!(EthernetShim::new(cfg).is_err());

        // An absurd inner MTU cannot fit any wire budget.
        let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
        cfg.inner_ip_mtu = MTU_MAX;
        assert!(EthernetShim::new(cfg).is_err());
    }

    struct FakeDevice {
        inbound: Mutex<VecDeque<Vec<u8>>>,
        ready: Condvar,
        outbound: Mutex<Vec<Vec<u8>>>,
        closed: AtomicBool,
    }

    impl FakeDevice {
        fn new() -> Self {
            Self {
                inbound: Mutex::new(VecDeque::new()),
                ready: Condvar::new(),
                outbound: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            }
        }

        fn push(&self, packet: Vec<u8>) {
            self.inbound
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push_back(packet);
            self.ready.notify_all();
        }

        fn written(&self) -> Vec<Vec<u8>> {
            self.outbound
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
        }
    }

    impl L3Device for FakeDevice {
        fn recv_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
            let mut queue = self
                .inbound
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            loop {
                if let Some(packet) = queue.pop_front() {
                    if packet.len() > buf.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "fake packet exceeds the reader buffer",
                        ));
                    }
                    buf[..packet.len()].copy_from_slice(&packet);
                    return Ok(Some(packet.len()));
                }
                if self.closed.load(AtomicOrdering::SeqCst) {
                    return Ok(None);
                }
                let (guard, timeout) = self
                    .ready
                    .wait_timeout(queue, Duration::from_millis(25))
                    .unwrap_or_else(|poison| poison.into_inner());
                queue = guard;
                if timeout.timed_out() {
                    return Ok(None);
                }
            }
        }

        fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
            self.outbound
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(packet.to_vec());
            Ok(packet.len())
        }
    }

    #[tokio::test]
    async fn pump_send_progresses_while_recv_is_blocked() {
        let device = Arc::new(FakeDevice::new());
        let pump = Arc::new(ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump"));

        let recv_pump = Arc::clone(&pump);
        let mut recv_task = tokio::spawn(async move { recv_pump.recv().await });

        // Idle recv() must await the channel rather than spin.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut recv_task)
                .await
                .is_err()
        );

        // Tunnel -> OS must complete while recv() is waiting.
        let inbound = build_ipv4_frame(OUR_MAC, PEER_MAC, &ipv4(OUR_IP, 8));
        assert_eq!(
            pump.send(&inbound)
                .expect("send must not block behind recv"),
            SendOutcome::Written(28)
        );
        assert_eq!(device.written(), vec![ipv4(OUR_IP, 8)]);
        // send() did not satisfy the pending recv().
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut recv_task)
                .await
                .is_err()
        );

        // An OS packet on a cache miss produces one ARP request frame.
        device.push(ipv4(PEER_IP, 20));
        let frame = tokio::time::timeout(Duration::from_secs(2), &mut recv_task)
            .await
            .expect("recv completes")
            .expect("join")
            .expect("not closed")
            .expect("frame");
        assert_eq!(frame.len(), ETH_HEADER_LEN + ARP_PAYLOAD_LEN);

        pump.shutdown();
    }

    #[tokio::test]
    async fn pump_idle_recv_returns_none_only_after_shutdown() {
        let device = Arc::new(FakeDevice::new());
        let pump = Arc::new(ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump"));

        let recv_pump = Arc::clone(&pump);
        let mut recv_task = tokio::spawn(async move { recv_pump.recv().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut recv_task)
                .await
                .is_err()
        );

        pump.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(2), &mut recv_task)
            .await
            .expect("shutdown wakes recv")
            .expect("join");
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn pump_shutdown_joins_the_dedicated_reader_thread() {
        let device = Arc::new(FakeDevice::new());
        let pump = ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump");

        // Let the blocking reader enter the device before shutting down.
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            pump.reader
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .is_some(),
            "the reader thread must be running before shutdown"
        );

        pump.shutdown();

        // `shutdown` takes and joins the handle: the thread cannot still be
        // inside Wintun when the caller closes the session/adapter.
        assert!(
            pump.reader
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .is_none(),
            "shutdown must take and join the reader handle"
        );
        assert!(pump.stop.load(AtomicOrdering::SeqCst));
    }

    #[tokio::test]
    async fn cancelled_recv_restores_the_receiver_for_the_next_call() {
        // A reconnect joins the old peer task, which cancels a parked
        // `recv()` future.  The receiver must survive that so the reused
        // adapter still delivers OS packets.
        let device = Arc::new(FakeDevice::new());
        let pump = Arc::new(ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump"));

        let recv_pump = Arc::clone(&pump);
        let task = tokio::spawn(async move { recv_pump.recv().await });
        // Let the task take the receiver and park on the channel.
        tokio::time::sleep(Duration::from_millis(25)).await;
        task.abort();
        let _ = task.await;

        device.push(ipv4(PEER_IP, 20));
        let frame = tokio::time::timeout(Duration::from_secs(1), pump.recv())
            .await
            .expect("recv after cancel must complete")
            .expect("pump must not report closed")
            .expect("frame");
        // First packet to an unknown peer is an ARP request.
        assert_eq!(frame.len(), ETH_HEADER_LEN + ARP_PAYLOAD_LEN);
        pump.shutdown();
    }

    #[tokio::test]
    async fn pump_drains_outbound_before_waiting_for_os_packets() {
        let device = Arc::new(FakeDevice::new());
        let pump = ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump");
        assert!(pump.announce_gratuitous_arp());

        // No OS packet is available, yet recv() must yield the queued ARP
        // request immediately.
        let frame = tokio::time::timeout(Duration::from_millis(200), pump.recv())
            .await
            .expect("outbound queue drained without waiting")
            .expect("not closed")
            .expect("frame");
        assert_eq!(&frame[0..6], &MacAddr::BROADCAST.octets());
        assert_eq!(frame.len(), ETH_HEADER_LEN + ARP_PAYLOAD_LEN);
        assert_eq!(pump.outbound_len(), 0);
    }

    #[tokio::test]
    async fn pump_arp_reply_from_send_is_returned_by_the_next_recv() {
        let device = Arc::new(FakeDevice::new());
        let pump = ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump");

        let request = ArpPacket {
            op: ArpOp::Request,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: MacAddr::ZERO,
            target_ip: OUR_IP,
        };
        let frame = build_arp_frame(MacAddr::BROADCAST, PEER_MAC, &request);
        assert_eq!(pump.send(&frame).unwrap(), SendOutcome::Consumed);
        assert!(device.written().is_empty(), "ARP must not reach the OS");

        let reply = tokio::time::timeout(Duration::from_millis(200), pump.recv())
            .await
            .expect("queued reply")
            .expect("not closed")
            .expect("frame");
        assert_eq!(&reply[0..6], &PEER_MAC.octets());
        let parsed = ArpPacket::parse(&reply[14..]).unwrap();
        assert_eq!(parsed.op, ArpOp::Reply);
        assert_eq!(parsed.sender_ip, OUR_IP);
    }

    #[tokio::test]
    async fn pump_reader_error_is_reported() {
        struct BrokenDevice;
        impl L3Device for BrokenDevice {
            fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<Option<usize>> {
                Err(io::Error::other("driver failure"))
            }
            fn send_packet(&self, _packet: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
        }

        let pump = ShimPump::new(shim_config(), Arc::new(BrokenDevice), 4, 2048).unwrap();
        let error = pump.recv().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("driver failure"));

        // Subsequent calls do not busy-loop: the reader is gone, so recv()
        // returns Ok(None) once the error has been consumed.
        assert!(matches!(pump.recv().await, Ok(None)));
    }

    #[test]
    fn pump_rejects_invalid_parameters() {
        let device = Arc::new(FakeDevice::new());
        assert!(ShimPump::new(shim_config(), device.clone(), 0, 2048).is_err());
        assert!(ShimPump::new(shim_config(), device, 4, 100).is_err());
    }

    #[test]
    fn reader_buffer_is_covered_by_the_platform_floor() {
        assert!(reader_buffer_size(1500) > 1500);
        assert!(reader_poll_interval() > Duration::ZERO);
    }
}
