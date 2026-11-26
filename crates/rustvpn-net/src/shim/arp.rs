//! Bounded ARP state machine for the synthetic Ethernet shim.
//!
//! The shim must answer ARP for its own IP, learn the next-hop MAC from ARP
//! replies, and hold a small bounded queue of IP packets while a resolution is
//! in flight. Queues are bounded so a malicious or broken peer cannot grow
//! memory without limit.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::ethernet::{build_frame, build_ipv4_frame, ETHERTYPE_ARP};
use super::mac::MacAddr;

pub const ARP_PAYLOAD_LEN: usize = 28;
pub const ARP_FRAME_LEN: usize = super::ethernet::ETH_HEADER_LEN + ARP_PAYLOAD_LEN;

const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
}

impl ArpOp {
    pub fn code(self) -> u16 {
        match self {
            ArpOp::Request => 1,
            ArpOp::Reply => 2,
        }
    }

    fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(ArpOp::Request),
            2 => Some(ArpOp::Reply),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ArpOp::Request => "request",
            ArpOp::Reply => "reply",
        }
    }
}

/// The 28-byte IPv4-over-Ethernet ARP body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpParseError {
    TooShort,
    UnsupportedHardware { htype: u16, hlen: u8 },
    UnsupportedProtocol { ptype: u16, plen: u8 },
    UnknownOp(u16),
}

impl fmt::Display for ArpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpParseError::TooShort => write!(f, "ARP payload shorter than 28 bytes"),
            ArpParseError::UnsupportedHardware { htype, hlen } => {
                write!(f, "unsupported ARP hardware {htype}/{hlen}")
            }
            ArpParseError::UnsupportedProtocol { ptype, plen } => {
                write!(f, "unsupported ARP protocol 0x{ptype:04x}/{plen}")
            }
            ArpParseError::UnknownOp(op) => write!(f, "unsupported ARP opcode {op}"),
        }
    }
}

impl ArpPacket {
    pub fn parse(payload: &[u8]) -> Result<Self, ArpParseError> {
        if payload.len() < ARP_PAYLOAD_LEN {
            return Err(ArpParseError::TooShort);
        }
        let htype = u16::from_be_bytes([payload[0], payload[1]]);
        let ptype = u16::from_be_bytes([payload[2], payload[3]]);
        let hlen = payload[4];
        let plen = payload[5];
        if htype != HTYPE_ETHERNET || hlen != 6 {
            return Err(ArpParseError::UnsupportedHardware { htype, hlen });
        }
        if ptype != PTYPE_IPV4 || plen != 4 {
            return Err(ArpParseError::UnsupportedProtocol { ptype, plen });
        }
        let opcode = u16::from_be_bytes([payload[6], payload[7]]);
        let op = ArpOp::from_code(opcode).ok_or(ArpParseError::UnknownOp(opcode))?;
        let sender_mac = MacAddr::from_slice(&payload[8..14]).ok_or(ArpParseError::TooShort)?;
        let target_mac = MacAddr::from_slice(&payload[18..24]).ok_or(ArpParseError::TooShort)?;
        Ok(Self {
            op,
            sender_mac,
            sender_ip: Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]),
            target_mac,
            target_ip: Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
        })
    }

    pub fn encode(&self) -> [u8; ARP_PAYLOAD_LEN] {
        let mut out = [0u8; ARP_PAYLOAD_LEN];
        out[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&self.op.code().to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac.octets());
        out[14..18].copy_from_slice(&self.sender_ip.octets());
        out[18..24].copy_from_slice(&self.target_mac.octets());
        out[24..28].copy_from_slice(&self.target_ip.octets());
        out
    }
}

/// Build a 42-byte Ethernet/ARP frame (no Ethernet padding).
pub fn build_arp_frame(dst: MacAddr, src: MacAddr, packet: &ArpPacket) -> Vec<u8> {
    build_frame(dst, src, ETHERTYPE_ARP, &packet.encode())
}

fn sane_ip(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST
}

fn sane_mac(mac: MacAddr) -> bool {
    !mac.is_zero() && mac.is_unicast()
}

#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    mac: MacAddr,
    expires: Instant,
}

/// A bounded ARP cache with a fixed TTL.
#[derive(Debug)]
pub struct ArpCache {
    capacity: usize,
    entries: HashMap<Ipv4Addr, CacheEntry>,
}

impl ArpCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Look up a MAC, lazily evicting the entry if it has expired.
    pub fn lookup(&mut self, ip: Ipv4Addr, now: Instant) -> Option<MacAddr> {
        match self.entries.get(&ip) {
            Some(entry) if entry.expires > now => Some(entry.mac),
            Some(_) => {
                self.entries.remove(&ip);
                None
            }
            None => None,
        }
    }

    /// Insert or refresh an entry. When full, the earliest-expiring entry is
    /// evicted.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr, now: Instant, ttl: Duration) {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&ip) {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(ip, _)| *ip)
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            ip,
            CacheEntry {
                mac,
                expires: now + ttl,
            },
        );
    }

    pub fn remove(&mut self, ip: Ipv4Addr) {
        self.entries.remove(&ip);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Debug)]
struct Pending {
    target: Ipv4Addr,
    ip: Vec<u8>,
    added: Instant,
}

/// Bounded global + per-target FIFO of IP packets awaiting ARP resolution.
#[derive(Debug)]
pub struct PendingQueue {
    total_capacity: usize,
    per_target_capacity: usize,
    entries: VecDeque<Pending>,
    dropped: u64,
}

impl PendingQueue {
    pub fn new(total_capacity: usize, per_target_capacity: usize) -> Self {
        Self {
            total_capacity,
            per_target_capacity,
            entries: VecDeque::new(),
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn count_for(&self, target: Ipv4Addr) -> usize {
        self.entries
            .iter()
            .filter(|pending| pending.target == target)
            .count()
    }

    /// Enqueue a packet. Returns `false` if a bound caused the packet to be
    /// dropped. Per-target overflow drops the *new* packet (the queue is a
    /// per-flow bound); global overflow evicts the oldest packet.
    pub fn enqueue(&mut self, target: Ipv4Addr, ip: Vec<u8>, now: Instant) -> bool {
        if self.total_capacity == 0
            || self.per_target_capacity == 0
            || self.count_for(target) >= self.per_target_capacity
        {
            self.dropped += 1;
            return false;
        }
        while self.entries.len() >= self.total_capacity {
            self.entries.pop_front();
            self.dropped += 1;
        }
        self.entries.push_back(Pending {
            target,
            ip,
            added: now,
        });
        true
    }

    /// Remove all entries for `target`, preserving arrival order.
    pub fn drain_target(&mut self, target: Ipv4Addr) -> Vec<Vec<u8>> {
        let mut kept = VecDeque::with_capacity(self.entries.len());
        let mut out = Vec::new();
        while let Some(pending) = self.entries.pop_front() {
            if pending.target == target {
                out.push(pending.ip);
            } else {
                kept.push_back(pending);
            }
        }
        self.entries = kept;
        out
    }

    /// Drop entries older than `max_age`; returns the number dropped.
    pub fn expire(&mut self, now: Instant, max_age: Duration) -> usize {
        let mut kept = VecDeque::with_capacity(self.entries.len());
        let mut expired = 0;
        while let Some(pending) = self.entries.pop_front() {
            if now.saturating_duration_since(pending.added) >= max_age {
                expired += 1;
            } else {
                kept.push_back(pending);
            }
        }
        self.entries = kept;
        self.dropped += u64::try_from(expired).unwrap_or(u64::MAX);
        expired
    }
}

#[derive(Clone, Debug)]
pub struct ArpConfig {
    pub our_ip: Ipv4Addr,
    pub our_mac: MacAddr,
    pub cache_capacity: usize,
    pub pending_capacity: usize,
    pub pending_per_target: usize,
    pub cache_ttl: Duration,
    pub pending_ttl: Duration,
    pub retry_interval: Duration,
    pub max_retries: u8,
}

impl ArpConfig {
    pub fn new(our_ip: Ipv4Addr, our_mac: MacAddr) -> Self {
        Self {
            our_ip,
            our_mac,
            cache_capacity: 64,
            pending_capacity: 64,
            pending_per_target: 8,
            cache_ttl: Duration::from_secs(60),
            pending_ttl: Duration::from_secs(5),
            retry_interval: Duration::from_secs(1),
            max_retries: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ArpStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub requests_sent: u64,
    pub replies_sent: u64,
    pub requests_received: u64,
    pub replies_received: u64,
    pub learned: u64,
    pub pending_enqueued: u64,
    pub pending_dropped: u64,
    pub pending_flushed: u64,
    pub parse_errors: u64,
    pub ignored: u64,
}

#[derive(Debug, Clone, Copy)]
struct Attempt {
    last: Instant,
    count: u8,
}

/// Result of trying to resolve or queue an outbound IP packet.
#[derive(Debug)]
pub enum ResolveOutcome {
    /// The MAC was known; this is a ready Ethernet frame for the tunnel.
    Ready(Vec<u8>),
    /// The packet was (or could not be) queued; `request` is an ARP request
    /// that should be sent to the tunnel when present.
    Queued {
        request: Option<Vec<u8>>,
        dropped: bool,
    },
}

/// The result of feeding an inbound ARP payload through the state machine.
#[derive(Debug, Default)]
pub struct ArpHandling {
    /// An ARP reply that must be returned toward the tunnel.
    pub reply: Option<Vec<u8>>,
    /// IP frames released from the pending queue after learning a MAC.
    pub flushed: Vec<Vec<u8>>,
}

pub struct ArpState {
    cfg: ArpConfig,
    cache: ArpCache,
    pending: PendingQueue,
    attempts: HashMap<Ipv4Addr, Attempt>,
    stats: ArpStats,
}

impl ArpState {
    pub fn new(cfg: ArpConfig) -> Self {
        Self {
            cache: ArpCache::new(cfg.cache_capacity),
            pending: PendingQueue::new(cfg.pending_capacity, cfg.pending_per_target),
            cfg,
            attempts: HashMap::new(),
            stats: ArpStats::default(),
        }
    }

    pub fn stats(&self) -> &ArpStats {
        &self.stats
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_dropped(&self) -> u64 {
        self.pending.dropped()
    }

    pub fn cache(&mut self) -> &mut ArpCache {
        &mut self.cache
    }

    /// Resolve `next_hop` and encapsulate `ip_packet`, or queue the packet and
    /// emit an ARP request.
    pub fn resolve_or_queue(
        &mut self,
        next_hop: Ipv4Addr,
        ip_packet: &[u8],
        now: Instant,
    ) -> ResolveOutcome {
        if let Some(mac) = self.cache.lookup(next_hop, now) {
            self.stats.cache_hits += 1;
            // A cache hit still has to age out stale pending packets and their
            // retry state; otherwise an idle flow could keep them forever.
            self.expire_pending(now);
            return ResolveOutcome::Ready(build_ipv4_frame(mac, self.cfg.our_mac, ip_packet));
        }
        self.stats.cache_misses += 1;
        self.expire_pending(now);

        let enqueued = self.pending.enqueue(next_hop, ip_packet.to_vec(), now);
        if enqueued {
            self.stats.pending_enqueued += 1;
        } else {
            self.stats.pending_dropped += 1;
        }

        let should_request = enqueued
            && match self.attempts.get(&next_hop) {
                None => true,
                Some(attempt) => {
                    attempt.count < self.cfg.max_retries.max(1)
                        && now.saturating_duration_since(attempt.last) >= self.cfg.retry_interval
                }
            };
        let request = if should_request {
            let count = self
                .attempts
                .get(&next_hop)
                .map(|attempt| attempt.count.saturating_add(1))
                .unwrap_or(1);
            self.attempts.insert(next_hop, Attempt { last: now, count });
            self.stats.requests_sent += 1;
            Some(self.build_request(next_hop))
        } else {
            None
        };

        ResolveOutcome::Queued {
            request,
            dropped: !enqueued,
        }
    }

    /// Handle an inbound 28-byte ARP payload.
    pub fn handle_payload(&mut self, payload: &[u8], now: Instant) -> ArpHandling {
        let mut handling = ArpHandling::default();
        self.expire_pending(now);

        let packet = match ArpPacket::parse(payload) {
            Ok(packet) => packet,
            Err(_) => {
                self.stats.parse_errors += 1;
                return handling;
            }
        };

        match packet.op {
            ArpOp::Request => {
                self.stats.requests_received += 1;
                // Any successful learn (not only a reply for our own IP)
                // releases packets waiting for that sender.
                if let Some((ip, mac)) = self.maybe_learn(&packet, now) {
                    self.flush_into(&mut handling, ip, mac);
                }

                if packet.target_ip == self.cfg.our_ip {
                    if !sane_mac(packet.sender_mac) || !sane_ip(packet.sender_ip) {
                        self.stats.ignored += 1;
                        return handling;
                    }
                    let reply = ArpPacket {
                        op: ArpOp::Reply,
                        sender_mac: self.cfg.our_mac,
                        sender_ip: self.cfg.our_ip,
                        target_mac: packet.sender_mac,
                        target_ip: packet.sender_ip,
                    };
                    handling.reply =
                        Some(build_arp_frame(packet.sender_mac, self.cfg.our_mac, &reply));
                    self.stats.replies_sent += 1;
                } else if !is_gratuitous(&packet) {
                    self.stats.ignored += 1;
                }
            }
            ArpOp::Reply => {
                self.stats.replies_received += 1;
                if (packet.target_ip == self.cfg.our_ip || is_gratuitous(&packet))
                    && sane_ip(packet.sender_ip)
                    && packet.sender_ip != self.cfg.our_ip
                    && sane_mac(packet.sender_mac)
                {
                    self.learn(packet.sender_ip, packet.sender_mac, now);
                    // Gratuitous replies update an entry too, and any learn
                    // must release packets pending for that sender.
                    self.flush_into(&mut handling, packet.sender_ip, packet.sender_mac);
                } else {
                    self.stats.ignored += 1;
                }
            }
        }
        handling
    }

    /// Build an optional gratuitous ARP request advertising our IP/MAC.
    pub fn gratuitous_request(&mut self) -> Vec<u8> {
        self.stats.requests_sent += 1;
        let packet = ArpPacket {
            op: ArpOp::Request,
            sender_mac: self.cfg.our_mac,
            sender_ip: self.cfg.our_ip,
            target_mac: MacAddr::ZERO,
            target_ip: self.cfg.our_ip,
        };
        build_arp_frame(MacAddr::BROADCAST, self.cfg.our_mac, &packet)
    }

    fn build_request(&self, target_ip: Ipv4Addr) -> Vec<u8> {
        let packet = ArpPacket {
            op: ArpOp::Request,
            sender_mac: self.cfg.our_mac,
            sender_ip: self.cfg.our_ip,
            target_mac: MacAddr::ZERO,
            target_ip,
        };
        build_arp_frame(MacAddr::BROADCAST, self.cfg.our_mac, &packet)
    }

    fn maybe_learn(&mut self, packet: &ArpPacket, now: Instant) -> Option<(Ipv4Addr, MacAddr)> {
        if (packet.target_ip == self.cfg.our_ip || is_gratuitous(packet))
            && sane_ip(packet.sender_ip)
            && packet.sender_ip != self.cfg.our_ip
            && sane_mac(packet.sender_mac)
        {
            self.learn(packet.sender_ip, packet.sender_mac, now);
            Some((packet.sender_ip, packet.sender_mac))
        } else {
            None
        }
    }

    fn learn(&mut self, ip: Ipv4Addr, mac: MacAddr, now: Instant) {
        self.cache.insert(ip, mac, now, self.cfg.cache_ttl);
        self.stats.learned += 1;
    }

    fn flush_into(&mut self, handling: &mut ArpHandling, target: Ipv4Addr, mac: MacAddr) {
        let flushed = self.flush(target, mac);
        self.stats.pending_flushed += u64::try_from(flushed.len()).unwrap_or(u64::MAX);
        handling.flushed.extend(flushed);
    }

    fn flush(&mut self, target: Ipv4Addr, mac: MacAddr) -> Vec<Vec<u8>> {
        self.attempts.remove(&target);
        self.pending
            .drain_target(target)
            .into_iter()
            .map(|ip| build_ipv4_frame(mac, self.cfg.our_mac, &ip))
            .collect()
    }

    fn expire_pending(&mut self, now: Instant) {
        let expired = self.pending.expire(now, self.cfg.pending_ttl);
        self.stats.pending_dropped += u64::try_from(expired).unwrap_or(u64::MAX);
        let pending = &self.pending;
        self.attempts.retain(|ip, _| pending.count_for(*ip) > 0);
    }
}

fn is_gratuitous(packet: &ArpPacket) -> bool {
    packet.sender_ip == packet.target_ip && sane_ip(packet.sender_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 1, 2, 3]);
    const PEER_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 9, 8, 7]);
    const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 9);

    fn state() -> ArpState {
        ArpState::new(ArpConfig::new(OUR_IP, OUR_MAC))
    }

    fn request(from_mac: MacAddr, from_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        ArpPacket {
            op: ArpOp::Request,
            sender_mac: from_mac,
            sender_ip: from_ip,
            target_mac: MacAddr::ZERO,
            target_ip,
        }
        .encode()
        .to_vec()
    }

    fn reply(from_mac: MacAddr, from_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        ArpPacket {
            op: ArpOp::Reply,
            sender_mac: from_mac,
            sender_ip: from_ip,
            target_mac: OUR_MAC,
            target_ip,
        }
        .encode()
        .to_vec()
    }

    #[test]
    fn packet_round_trip_and_frame_size() {
        let packet = ArpPacket {
            op: ArpOp::Request,
            sender_mac: OUR_MAC,
            sender_ip: OUR_IP,
            target_mac: MacAddr::ZERO,
            target_ip: PEER_IP,
        };
        let encoded = packet.encode();
        assert_eq!(encoded.len(), ARP_PAYLOAD_LEN);
        assert_eq!(ArpPacket::parse(&encoded).unwrap(), packet);
        let frame = build_arp_frame(MacAddr::BROADCAST, OUR_MAC, &packet);
        assert_eq!(frame.len(), ARP_FRAME_LEN);
        assert_eq!(&frame[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        assert_eq!(
            ArpPacket::parse(&[0u8; 27]).unwrap_err(),
            ArpParseError::TooShort
        );

        let mut bad_hw = [0u8; 28];
        bad_hw[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        bad_hw[4] = 6;
        bad_hw[5] = 4;
        bad_hw[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            ArpPacket::parse(&bad_hw).unwrap_err(),
            ArpParseError::UnsupportedHardware { htype: 0, hlen: 6 }
        ));

        let mut bad_proto = [0u8; 28];
        bad_proto[0..2].copy_from_slice(&1u16.to_be_bytes());
        bad_proto[2..4].copy_from_slice(&0x86ddu16.to_be_bytes());
        bad_proto[4] = 6;
        bad_proto[5] = 4;
        bad_proto[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            ArpPacket::parse(&bad_proto).unwrap_err(),
            ArpParseError::UnsupportedProtocol {
                ptype: 0x86dd,
                plen: 4
            }
        ));

        let mut bad_op = [0u8; 28];
        bad_op[0..2].copy_from_slice(&1u16.to_be_bytes());
        bad_op[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        bad_op[4] = 6;
        bad_op[5] = 4;
        bad_op[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            ArpPacket::parse(&bad_op).unwrap_err(),
            ArpParseError::UnknownOp(3)
        );
    }

    #[test]
    fn request_for_us_produces_reply_toward_requester() {
        let now = Instant::now();
        let mut arp = state();
        let handling = arp.handle_payload(&request(PEER_MAC, PEER_IP, OUR_IP), now);
        let reply_frame = handling.reply.expect("reply");
        assert_eq!(reply_frame.len(), ARP_FRAME_LEN);
        assert_eq!(&reply_frame[0..6], &PEER_MAC.octets());
        assert_eq!(&reply_frame[6..12], &OUR_MAC.octets());
        let reply = ArpPacket::parse(&reply_frame[14..]).unwrap();
        assert_eq!(reply.op, ArpOp::Reply);
        assert_eq!(reply.sender_mac, OUR_MAC);
        assert_eq!(reply.sender_ip, OUR_IP);
        assert_eq!(reply.target_mac, PEER_MAC);
        assert_eq!(reply.target_ip, PEER_IP);
        assert_eq!(arp.cache().lookup(PEER_IP, now), Some(PEER_MAC));
    }

    #[test]
    fn miss_queues_packet_and_emits_one_request() {
        let now = Instant::now();
        let mut arp = state();
        let ip = vec![0x45u8; 28];
        let first = arp.resolve_or_queue(PEER_IP, &ip, now);
        let ResolveOutcome::Queued {
            request: Some(frame),
            dropped: false,
        } = first
        else {
            panic!("expected a queued packet with a request");
        };
        assert_eq!(&frame[0..6], &MacAddr::BROADCAST.octets());
        let request = ArpPacket::parse(&frame[14..]).unwrap();
        assert_eq!(request.op, ArpOp::Request);
        assert_eq!(request.target_ip, PEER_IP);
        assert_eq!(arp.pending_len(), 1);

        // A second packet to the same target must not flood requests.
        let second = arp.resolve_or_queue(PEER_IP, &ip, now);
        assert!(matches!(
            second,
            ResolveOutcome::Queued {
                request: None,
                dropped: false
            }
        ));
        assert_eq!(arp.pending_len(), 2);
    }

    #[test]
    fn reply_flushes_pending_in_order() {
        let now = Instant::now();
        let mut arp = state();
        let first_ip = vec![0x45u8; 28];
        let second_ip = vec![0x46u8; 28];
        let _ = arp.resolve_or_queue(PEER_IP, &first_ip, now);
        let _ = arp.resolve_or_queue(PEER_IP, &second_ip, now);

        let handling = arp.handle_payload(&reply(PEER_MAC, PEER_IP, OUR_IP), now);
        assert!(handling.reply.is_none());
        assert_eq!(handling.flushed.len(), 2);
        assert_eq!(&handling.flushed[0][0..6], &PEER_MAC.octets());
        assert_eq!(&handling.flushed[0][14..], &first_ip[..]);
        assert_eq!(&handling.flushed[1][14..], &second_ip[..]);
        assert_eq!(arp.pending_len(), 0);
        assert_eq!(arp.cache().lookup(PEER_IP, now), Some(PEER_MAC));
    }

    #[test]
    fn cache_expiry_is_enforced() {
        let now = Instant::now();
        let mut cache = ArpCache::new(4);
        cache.insert(PEER_IP, PEER_MAC, now, Duration::from_secs(60));
        assert_eq!(
            cache.lookup(PEER_IP, now + Duration::from_secs(59)),
            Some(PEER_MAC)
        );
        assert_eq!(cache.lookup(PEER_IP, now + Duration::from_secs(61)), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_is_bounded() {
        let now = Instant::now();
        let mut cache = ArpCache::new(2);
        cache.insert(
            Ipv4Addr::new(10, 88, 0, 3),
            PEER_MAC,
            now,
            Duration::from_secs(60),
        );
        cache.insert(
            Ipv4Addr::new(10, 88, 0, 4),
            PEER_MAC,
            now,
            Duration::from_secs(60),
        );
        cache.insert(
            Ipv4Addr::new(10, 88, 0, 5),
            PEER_MAC,
            now,
            Duration::from_secs(60),
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn pending_queue_honors_per_target_and_global_bounds() {
        let now = Instant::now();
        let mut queue = PendingQueue::new(5, 3);
        for _ in 0..5 {
            let _ = queue.enqueue(PEER_IP, vec![1], now);
        }
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.dropped(), 2);

        let mut queue = PendingQueue::new(2, 8);
        assert!(queue.enqueue(Ipv4Addr::new(10, 88, 0, 3), vec![1], now));
        assert!(queue.enqueue(Ipv4Addr::new(10, 88, 0, 4), vec![2], now));
        assert!(queue.enqueue(Ipv4Addr::new(10, 88, 0, 5), vec![3], now));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.drain_target(Ipv4Addr::new(10, 88, 0, 3)).len(), 0);
        assert_eq!(queue.drain_target(Ipv4Addr::new(10, 88, 0, 5)).len(), 1);
    }

    #[test]
    fn gratuitous_reply_updates_cache_and_flushes_pending() {
        let now = Instant::now();
        let mut arp = state();
        let ip = vec![0x45u8; 28];
        let _ = arp.resolve_or_queue(PEER_IP, &ip, now);
        assert_eq!(arp.pending_len(), 1);

        let gratuitous = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: PEER_MAC,
            target_ip: PEER_IP,
        }
        .encode();
        let handling = arp.handle_payload(&gratuitous, now);
        assert!(handling.reply.is_none());
        // P2-3: *any* successful learn flushes pending frames for that
        // sender, including a gratuitous (unsolicited) reply.
        assert_eq!(handling.flushed.len(), 1);
        assert_eq!(&handling.flushed[0][0..6], &PEER_MAC.octets());
        assert_eq!(&handling.flushed[0][14..], &ip[..]);
        assert_eq!(arp.pending_len(), 0);
        assert_eq!(arp.cache().lookup(PEER_IP, now), Some(PEER_MAC));
    }

    #[test]
    fn request_from_sender_flushes_pending_for_that_sender() {
        let now = Instant::now();
        let mut arp = state();
        let ip = vec![0x45u8; 28];
        let _ = arp.resolve_or_queue(PEER_IP, &ip, now);
        assert_eq!(arp.pending_len(), 1);

        // A request addressed to us is a learn for the sender; the pending
        // frame must be released even though the reply target is us.
        let handling = arp.handle_payload(&request(PEER_MAC, PEER_IP, OUR_IP), now);
        assert!(handling.reply.is_some());
        assert_eq!(handling.flushed.len(), 1);
        assert_eq!(&handling.flushed[0][0..6], &PEER_MAC.octets());
        assert_eq!(arp.pending_len(), 0);
    }

    #[test]
    fn cache_hit_expires_stale_pending_entries() {
        let now = Instant::now();
        let mut cfg = ArpConfig::new(OUR_IP, OUR_MAC);
        cfg.pending_capacity = 8;
        cfg.pending_per_target = 4;
        cfg.pending_ttl = Duration::from_secs(5);
        let mut arp = ArpState::new(cfg);
        let ip = vec![0x45u8; 28];
        let other = Ipv4Addr::new(10, 88, 0, 4);

        arp.cache()
            .insert(PEER_IP, PEER_MAC, now, Duration::from_secs(60));
        let _ = arp.resolve_or_queue(other, &ip, now);
        assert_eq!(arp.pending_len(), 1);

        // A cache hit still ages the pending queue; 6s > the 5s TTL.
        assert!(matches!(
            arp.resolve_or_queue(PEER_IP, &ip, now + Duration::from_secs(6)),
            ResolveOutcome::Ready(_)
        ));
        assert_eq!(arp.pending_len(), 0);
    }

    #[test]
    fn pending_ttl_expiry_drops_packets_and_clears_retry_state() {
        let now = Instant::now();
        let mut cfg = ArpConfig::new(OUR_IP, OUR_MAC);
        cfg.pending_capacity = 8;
        cfg.pending_per_target = 4;
        cfg.pending_ttl = Duration::from_secs(5);
        cfg.retry_interval = Duration::from_secs(1);
        cfg.max_retries = 3;
        let mut arp = ArpState::new(cfg);
        let ip = vec![0x45u8; 28];

        assert!(matches!(
            arp.resolve_or_queue(PEER_IP, &ip, now),
            ResolveOutcome::Queued {
                request: Some(_),
                dropped: false
            }
        ));
        assert_eq!(arp.pending_len(), 1);

        // Any miss expires the queue; 6s > 5s TTL.
        let other = Ipv4Addr::new(10, 88, 0, 4);
        let late = now + Duration::from_secs(6);
        assert!(matches!(
            arp.resolve_or_queue(other, &ip, late),
            ResolveOutcome::Queued {
                request: Some(_),
                ..
            }
        ));
        assert_eq!(arp.pending_len(), 1);
        assert!(arp.pending_dropped() >= 1);

        // The expired target lost its retry state: a fresh packet issues a
        // fresh request immediately instead of being rate-limited by the old
        // attempt counter.
        assert!(matches!(
            arp.resolve_or_queue(PEER_IP, &ip, late + Duration::from_millis(10)),
            ResolveOutcome::Queued {
                request: Some(_),
                dropped: false
            }
        ));
    }

    #[test]
    fn retry_exhaustion_stops_requesting_the_same_target() {
        let now = Instant::now();
        let mut cfg = ArpConfig::new(OUR_IP, OUR_MAC);
        cfg.pending_capacity = 8;
        cfg.pending_per_target = 8;
        cfg.max_retries = 2;
        cfg.retry_interval = Duration::from_secs(1);
        let mut arp = ArpState::new(cfg);
        let ip = vec![0x45u8; 28];

        // First packet: request #1; second after the interval: request #2.
        assert!(matches!(
            arp.resolve_or_queue(PEER_IP, &ip, now),
            ResolveOutcome::Queued {
                request: Some(_),
                ..
            }
        ));
        assert!(matches!(
            arp.resolve_or_queue(PEER_IP, &ip, now + Duration::from_secs(2)),
            ResolveOutcome::Queued {
                request: Some(_),
                ..
            }
        ));
        // max_retries=2 is exhausted: no further requests.
        for step in [4u64, 6u64] {
            assert!(matches!(
                arp.resolve_or_queue(PEER_IP, &ip, now + Duration::from_secs(step)),
                ResolveOutcome::Queued {
                    request: None,
                    dropped: false
                }
            ));
        }
        assert_eq!(arp.stats().requests_sent, 2);
    }

    #[test]
    fn global_fifo_eviction_does_not_keep_per_target_attempt_state() {
        let now = Instant::now();
        let mut cfg = ArpConfig::new(OUR_IP, OUR_MAC);
        cfg.pending_capacity = 2;
        cfg.pending_per_target = 8;
        cfg.pending_ttl = Duration::from_secs(60);
        cfg.retry_interval = Duration::from_secs(1);
        cfg.max_retries = 3;
        let mut arp = ArpState::new(cfg);
        let ip = vec![0x45u8; 28];
        let a = Ipv4Addr::new(10, 88, 0, 3);
        let b = Ipv4Addr::new(10, 88, 0, 4);
        let c = Ipv4Addr::new(10, 88, 0, 5);

        let _ = arp.resolve_or_queue(a, &ip, now);
        let _ = arp.resolve_or_queue(b, &ip, now);
        // Enqueueing `c` evicts the oldest (`a`) from the global FIFO.
        let _ = arp.resolve_or_queue(c, &ip, now);
        assert_eq!(arp.pending_len(), 2);
        let other = Ipv4Addr::new(10, 88, 0, 6);
        let _ = arp.resolve_or_queue(other, &ip, now);
        // The next miss prunes retry state for the evicted target, so `a`
        // can issue a fresh request despite the earlier attempt record.
        assert!(matches!(
            arp.resolve_or_queue(a, &ip, now + Duration::from_millis(1)),
            ResolveOutcome::Queued {
                request: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn pending_queue_expire_respects_per_entry_age() {
        let now = Instant::now();
        let mut queue = PendingQueue::new(4, 4);
        let a = Ipv4Addr::new(10, 88, 0, 3);
        let b = Ipv4Addr::new(10, 88, 0, 4);
        assert!(queue.enqueue(a, vec![1], now));
        assert!(queue.enqueue(b, vec![2], now + Duration::from_secs(3)));

        // At t=6s only `a` (6s old) exceeds the 5s age; `b` is 3s old.
        assert_eq!(
            queue.expire(now + Duration::from_secs(6), Duration::from_secs(5)),
            1
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.count_for(a), 0);
        assert_eq!(queue.count_for(b), 1);
        assert_eq!(queue.dropped(), 1);
    }

    #[test]
    fn pending_queue_global_eviction_is_fifo_and_independent_of_per_target() {
        let now = Instant::now();
        let mut queue = PendingQueue::new(2, 8);
        let a = Ipv4Addr::new(10, 88, 0, 3);
        let b = Ipv4Addr::new(10, 88, 0, 4);
        let c = Ipv4Addr::new(10, 88, 0, 5);
        assert!(queue.enqueue(a, vec![1], now));
        assert!(queue.enqueue(b, vec![2], now));
        assert!(queue.enqueue(c, vec![3], now));
        assert_eq!(queue.len(), 2);
        // The oldest entry is evicted even though the per-target bound (8)
        // would have allowed another packet for `a`.
        assert_eq!(queue.count_for(a), 0);
        assert_eq!(queue.count_for(b), 1);
        assert_eq!(queue.count_for(c), 1);
        assert_eq!(queue.dropped(), 1);
    }

    #[test]
    fn gratuitous_request_frame_is_broadcast() {
        let mut arp = state();
        let frame = arp.gratuitous_request();
        assert_eq!(&frame[0..6], &MacAddr::BROADCAST.octets());
        let packet = ArpPacket::parse(&frame[14..]).unwrap();
        assert_eq!(packet.op, ArpOp::Request);
        assert_eq!(packet.sender_ip, OUR_IP);
        assert_eq!(packet.target_ip, OUR_IP);
    }

    #[test]
    fn retry_is_rate_limited() {
        let now = Instant::now();
        let mut arp = state();
        let ip = vec![0x45u8; 28];
        let _ = arp.resolve_or_queue(PEER_IP, &ip, now);
        let retry_early = arp.resolve_or_queue(PEER_IP, &ip, now + Duration::from_millis(100));
        assert!(matches!(
            retry_early,
            ResolveOutcome::Queued { request: None, .. }
        ));
        let retry_late = arp.resolve_or_queue(PEER_IP, &ip, now + Duration::from_secs(2));
        assert!(matches!(
            retry_late,
            ResolveOutcome::Queued {
                request: Some(_),
                ..
            }
        ));
    }
}
