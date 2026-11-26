//! The platform-independent Ethernet shim core.
//!
//! The real Windows `Tap` adapter will own three pieces:
//!
//! * the Wintun session (`OS -> L3 IP packet`),
//! * this shim (`L3 IP packet <-> L2 Ethernet frame`),
//! * an internal outbound queue for frames that must go **toward** the tunnel
//!   (ARP requests/replies and packets released from the ARP pending queue).
//!
//! `recv()` in `rustvpn-net` is the OS -> tunnel direction, so it always
//! drains this queue first and only then reads the Wintun session. `send()` is
//! the tunnel -> OS direction: IPv4 frames are written to Wintun, while ARP
//! frames are consumed locally and their replies enqueued for the next
//! `recv()`.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::arp::{ArpConfig, ArpState, ArpStats, ResolveOutcome};
use crate::ethernet::{build_ipv4_frame, classify_inbound, Inbound, InboundError, ETH_HEADER_LEN};
use crate::ipv4::{
    in_same_subnet, is_limited_broadcast, is_multicast, multicast_mac, subnet_broadcast, Ipv4Error,
    Ipv4Header,
};
use crate::mac::MacAddr;
use crate::mtu::{Mode, MTU_MAX};

/// Smallest inner IP MTU the shim itself accepts. It is below the Windows
/// adapter's 576-byte policy but still leaves room for a minimal IPv4 header
/// plus a small transport header.
pub const MIN_INNER_IP_MTU: usize = 42;

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
            outbound_capacity: 32,
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
                self.mode,
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
                self.mode,
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
    /// Total input frames/ packets that were discarded.
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

/// What `ShimPump::send` did with a tunnel frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// The frame carried an IPv4 packet that was written to the L3 device.
    Written(usize),
    /// The frame was handled locally (ARP) or dropped; any reply is queued for
    /// the next `recv()`.
    Consumed,
}

/// Concurrency-safe wrapper around [`EthernetShim`] and an [`L3Device`].
///
/// The naive `Mutex<EthernetShim>` design deadlocks or stalls: `recv()` would
/// hold the shim lock across a blocking Wintun read, so `send()` could not make
/// progress. `ShimPump` instead:
///
/// 1. runs L3 reads on a dedicated blocking thread that feeds a bounded
///    channel;
/// 2. locks the shim only briefly for `take_outbound()` / `ingest_os_ip()` /
///    `ingest_tunnel_frame()` (never across a blocking read or write);
/// 3. writes the L3 device outside the shim lock.
///
/// Idle `recv()` blocks on the bounded channel and only returns `Ok(None)`
/// after `shutdown()`; it never spins on `Ok(0)`.
pub struct ShimPump {
    shim: Mutex<EthernetShim>,
    rx: Mutex<Receiver<Vec<u8>>>,
    device: Arc<dyn L3Device>,
    stop: Arc<AtomicBool>,
    reader_error: Arc<Mutex<Option<String>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
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

        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(inbound_capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let reader_error = Arc::new(Mutex::new(None));

        let thread_device = Arc::clone(&device);
        let thread_stop = Arc::clone(&stop);
        let thread_error = Arc::clone(&reader_error);
        let reader = thread::Builder::new()
            .name("rustvpn-shim-l3-reader".into())
            .spawn(move || {
                let mut buf = vec![0u8; max_packet_size];
                while !thread_stop.load(AtomicOrdering::Relaxed) {
                    match thread_device.recv_packet(&mut buf) {
                        Ok(Some(n)) if n > 0 && n <= max_packet_size => {
                            if tx.send(buf[..n].to_vec()).is_err() {
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
            rx: Mutex::new(rx),
            device,
            stop,
            reader_error,
            reader: Mutex::new(Some(reader)),
        })
    }

    /// OS -> tunnel. Blocks until a frame is available. Returns `Ok(None)`
    /// only after [`Self::shutdown`] or when the reader reports closure.
    pub fn recv(&self) -> io::Result<Option<Vec<u8>>> {
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

            let received = {
                let rx = self.rx.lock().unwrap_or_else(|poison| poison.into_inner());
                rx.recv_timeout(Duration::from_millis(100))
            };
            match received {
                Ok(packet) => {
                    let produced = {
                        let mut shim = self
                            .shim
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        shim.ingest_os_ip(&packet, Instant::now())
                    };
                    if produced == 0 {
                        // Dropped locally; keep waiting instead of returning
                        // an empty frame (which would spin the caller).
                        continue;
                    }
                    // The loop drains the resulting outbound frames.
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    if let Some(message) = self.take_reader_error() {
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, message));
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// Tunnel -> OS. The shim lock is dropped before writing to the device, so
    /// this can progress while another thread waits in [`Self::recv`].
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
        // A reader may be parked on a full bounded channel; release one slot
        // so it can observe the stop flag.
        if let Ok(rx) = self.rx.lock() {
            let _ = rx.try_recv();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;

    use crate::arp::{build_arp_frame, ArpOp, ArpPacket, ARP_PAYLOAD_LEN};
    use crate::ethernet::{build_frame, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN};

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
        assert_eq!(shim.ingest_tunnel_frame(&frame, now), Some(packet));
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
            (Mode::Plain, 68, 53),
        ] {
            let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
            cfg.mode = mode;
            cfg.wire_mtu = wire;
            cfg.inner_ip_mtu = inner;
            assert!(EthernetShim::new(cfg).is_ok(), "{mode} {wire} -> {inner}");
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

    #[test]
    fn pump_send_progresses_while_recv_is_blocked() {
        let device = Arc::new(FakeDevice::new());
        let pump = Arc::new(ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump"));

        let (result_tx, result_rx) = mpsc::channel();
        let recv_pump = Arc::clone(&pump);
        let recv_thread = thread::spawn(move || {
            let result = recv_pump.recv().map(|frame| frame.map(|f| f.len()));
            let _ = result_tx.send(result);
        });

        // Idle recv() must block on the channel rather than spin.
        assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());

        // Tunnel -> OS must complete while recv() is blocked.
        let inbound = build_ipv4_frame(OUR_MAC, PEER_MAC, &ipv4(OUR_IP, 8));
        assert_eq!(
            pump.send(&inbound)
                .expect("send must not block behind recv"),
            SendOutcome::Written(28)
        );
        assert_eq!(device.written(), vec![ipv4(OUR_IP, 8)]);
        // send() did not satisfy the pending recv().
        assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());

        // An OS packet on a cache miss produces one ARP request frame.
        device.push(ipv4(PEER_IP, 20));
        let frame_len = result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv completes")
            .expect("not closed")
            .expect("frame");
        assert_eq!(frame_len, ETH_HEADER_LEN + ARP_PAYLOAD_LEN);

        recv_thread.join().unwrap();
        pump.shutdown();
    }

    #[test]
    fn pump_idle_recv_returns_none_only_after_shutdown() {
        let device = Arc::new(FakeDevice::new());
        let pump = Arc::new(ShimPump::new(shim_config(), device.clone(), 8, 2048).expect("pump"));

        let (result_tx, result_rx) = mpsc::channel();
        let recv_pump = Arc::clone(&pump);
        let recv_thread = thread::spawn(move || {
            let result = recv_pump.recv();
            let _ = result_tx.send(result);
        });

        assert!(result_rx.recv_timeout(Duration::from_millis(200)).is_err());
        pump.shutdown();
        let result = result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("shutdown wakes recv");
        assert!(matches!(result, Ok(None)));
        recv_thread.join().unwrap();
    }

    #[test]
    fn pump_reader_error_is_reported() {
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
        let error = pump.recv().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("driver failure"));

        // Subsequent calls do not busy-loop: the reader is gone, so recv()
        // returns Ok(None) once the error has been consumed.
        assert!(matches!(pump.recv(), Ok(None)));
    }

    #[test]
    fn pump_rejects_invalid_parameters() {
        let device = Arc::new(FakeDevice::new());
        assert!(ShimPump::new(shim_config(), device.clone(), 0, 2048).is_err());
        assert!(ShimPump::new(shim_config(), device, 4, 100).is_err());
    }
}
