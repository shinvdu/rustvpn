//! Deterministic fuzz-style tests for the untrusted Ethernet/IPv4/ARP parsers.
//!
//! These tests deliberately use a tiny built-in xorshift generator instead of
//! a property-testing crate: the shim is parsing attacker-controlled frames in
//! the tunnel direction, so the important property is "never panic, never
//! index out of bounds, and every accepted frame satisfies the documented
//! length bounds", which a large fixed corpus of mutated inputs covers without
//! adding dependencies or build time.
//!
//! Every generator is seeded deterministically so a failure is reproducible.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rustvpn_proto::Mode;

use super::arp::{ArpOp, ArpPacket, ARP_PAYLOAD_LEN};
use super::ethernet::{
    build_frame, classify_inbound, Inbound, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6,
    ETHERTYPE_VLAN, ETH_HEADER_LEN,
};
use super::ipv4::{
    checksum, in_same_subnet, multicast_mac, prefix_to_mask, subnet_broadcast, udp_checksum,
    Ipv4Header,
};
use super::mac::MacAddr;
use super::{EthernetShim, ShimConfig};

/// Small deterministic xorshift64* generator; no external dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, upper: usize) -> usize {
        if upper == 0 {
            0
        } else {
            (self.next() % upper as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf {
            *byte = self.byte();
        }
    }

    fn mac(&mut self) -> MacAddr {
        let mut octets = [0u8; 6];
        self.fill(&mut octets);
        // Locally administered unicast: valid as a sender/target MAC.
        octets[0] = (octets[0] & 0xfe) | 0x02;
        MacAddr::from(octets)
    }

    fn sane_ip(&mut self) -> Ipv4Addr {
        // Avoid unspecified/multicast/broadcast so ARP's sanity filters are
        // exercised both ways.
        let first = (self.byte() % 223) + 1;
        Ipv4Addr::new(first, self.byte(), self.byte(), self.byte())
    }

    fn ipv4_packet(&mut self, dst: Ipv4Addr, payload: usize) -> Vec<u8> {
        let total = 20 + payload;
        let mut buf = vec![0u8; total];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        buf[8] = 64;
        buf[9] = 17;
        buf[12..16].copy_from_slice(&[10, 99, 0, 2]);
        buf[16..20].copy_from_slice(&dst.octets());
        self.fill(&mut buf[20..]);
        buf
    }
}

const OUR_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 1, 2, 3]);
const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);

fn shim() -> EthernetShim {
    let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
    cfg.prefix_len = 24;
    cfg.gateway = Some(Ipv4Addr::new(10, 99, 0, 1));
    cfg.inner_ip_mtu = 1500;
    cfg.outbound_capacity = 8;
    cfg.arp.pending_capacity = 8;
    cfg.arp.pending_per_target = 3;
    cfg.arp.cache_capacity = 16;
    cfg.arp.cache_ttl = Duration::from_secs(60);
    cfg.arp.pending_ttl = Duration::from_secs(5);
    cfg.arp.retry_interval = Duration::from_secs(1);
    cfg.mode = Mode::Plain;
    cfg.wire_mtu = 1515;
    EthernetShim::new(cfg).unwrap()
}

#[test]
fn fuzz_ipv4_parser_bounds_and_no_panic() {
    let mut rng = Rng::new(0x4950_7634_0000_0001);
    for _ in 0..40_000 {
        let len = rng.below(96);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        if let Ok(header) = Ipv4Header::parse(&buf) {
            assert!(header.header_len >= 20);
            assert!(header.header_len <= buf.len());
            assert!(header.total_length >= header.header_len);
            assert!(header.total_length <= buf.len());
            assert_eq!(header.packet().len(), header.total_length);
            assert_eq!(
                header.payload().len(),
                header.total_length - header.header_len
            );
        }
    }

    // Start from a structurally valid packet and mutate one byte: this
    // explores IHL/length/version edge cases much more densely than random
    // bytes alone.
    for _ in 0..40_000 {
        let dst = rng.sane_ip();
        let payload = rng.below(80);
        let mut packet = rng.ipv4_packet(dst, payload);
        let index = rng.below(packet.len());
        packet[index] = rng.byte();
        if let Ok(header) = Ipv4Header::parse(&packet) {
            assert!(header.total_length <= packet.len());
            assert!(header.header_len <= header.total_length);
        }
    }
}

#[test]
fn fuzz_arp_parser_round_trips_and_never_panics() {
    let mut rng = Rng::new(0x4152_5000_0000_0002);
    for _ in 0..40_000 {
        let len = rng.below(40);
        let mut payload = vec![0u8; len];
        rng.fill(&mut payload);
        if let Ok(packet) = ArpPacket::parse(&payload) {
            let encoded = packet.encode();
            assert_eq!(encoded.len(), ARP_PAYLOAD_LEN);
            assert_eq!(ArpPacket::parse(&encoded).unwrap(), packet);
        }
    }

    for _ in 0..10_000 {
        let packet = ArpPacket {
            op: if rng.byte() & 1 == 0 {
                ArpOp::Request
            } else {
                ArpOp::Reply
            },
            sender_mac: rng.mac(),
            sender_ip: rng.sane_ip(),
            target_mac: rng.mac(),
            target_ip: rng.sane_ip(),
        };
        let encoded = packet.encode();
        assert_eq!(ArpPacket::parse(&encoded).unwrap(), packet);
        // Short prefixes of a valid payload are accepted only if they still
        // contain a full 28-byte body.
        let short = rng.below(ARP_PAYLOAD_LEN);
        assert!(ArpPacket::parse(&encoded[..short]).is_err());
    }
}

#[test]
fn fuzz_inbound_classifier_only_accepts_well_bounded_frames() {
    let mut rng = Rng::new(0x434C_4153_0000_0003);
    for _ in 0..40_000 {
        let dst = match rng.below(4) {
            0 => OUR_MAC,
            1 => MacAddr::BROADCAST,
            2 => MacAddr::from([0x01, 0x00, 0x5e, rng.byte(), rng.byte(), rng.byte()]),
            _ => rng.mac(),
        };
        let ethertype = match rng.below(6) {
            0 => ETHERTYPE_IPV4,
            1 => ETHERTYPE_ARP,
            2 => ETHERTYPE_VLAN,
            3 => ETHERTYPE_IPV6,
            _ => u16::from_be_bytes([rng.byte(), rng.byte()]),
        };
        let len = rng.below(200);
        let mut payload = vec![0u8; len];
        rng.fill(&mut payload);
        let frame = build_frame(dst, rng.mac(), ethertype, &payload);
        let max_ip = 68 + rng.below(1500);
        match classify_inbound(&frame, OUR_MAC, max_ip) {
            Ok(Inbound::Ipv4(header)) => {
                assert!(header.total_length <= max_ip, "total_length over budget");
                assert!(header.total_length <= frame.len() - ETH_HEADER_LEN);
                assert_eq!(header.packet().len(), header.total_length);
            }
            Ok(Inbound::Arp(payload)) => {
                assert_eq!(payload.len(), ARP_PAYLOAD_LEN);
                assert!(frame.len() >= ETH_HEADER_LEN + ARP_PAYLOAD_LEN);
            }
            Err(_) => {}
        }
    }
}

#[test]
fn fuzz_shim_inbound_keeps_queues_and_arp_state_bounded() {
    let mut rng = Rng::new(0x5348_494D_0000_0004);
    let mut shim = shim();
    let cap = shim.config().outbound_capacity;
    let arp_cfg = shim.config().arp.clone();
    let base = Instant::now();

    for i in 0..30_000 {
        let now = base + Duration::from_millis(i as u64);
        let frame = match rng.below(6) {
            0 => {
                // A well-formed IPv4 frame for us with a random total length,
                // including values above the inner MTU.
                let dst = [OUR_MAC, MacAddr::BROADCAST, rng.mac()][rng.below(3)];
                let payload = rng.below(1600);
                let target = rng.sane_ip();
                let packet = rng.ipv4_packet(target, payload);
                build_frame(dst, rng.mac(), ETHERTYPE_IPV4, &packet)
            }
            1 => {
                // A valid ARP request/reply for or about our address.
                let packet = ArpPacket {
                    op: if rng.byte() & 1 == 0 {
                        ArpOp::Request
                    } else {
                        ArpOp::Reply
                    },
                    sender_mac: rng.mac(),
                    sender_ip: if rng.below(2) == 0 {
                        OUR_IP
                    } else {
                        rng.sane_ip()
                    },
                    target_mac: if rng.below(2) == 0 {
                        OUR_MAC
                    } else {
                        rng.mac()
                    },
                    target_ip: if rng.below(2) == 0 {
                        OUR_IP
                    } else {
                        rng.sane_ip()
                    },
                };
                super::arp::build_arp_frame(MacAddr::BROADCAST, packet.sender_mac, &packet)
            }
            _ => {
                let len = rng.below(300);
                let mut frame = vec![0u8; len];
                rng.fill(&mut frame);
                frame
            }
        };
        let _ = shim.ingest_tunnel_frame(&frame, now);
        assert!(shim.outbound_len() <= cap);
        assert!(shim.arp().cache_len() <= arp_cfg.cache_capacity);
        assert!(shim.arp().pending_len() <= arp_cfg.pending_capacity);
        while shim.take_outbound().is_some() {}
    }
    // The counters must have observed traffic without panicking; no exact
    // counts are asserted because the corpus is intentionally mixed.
    assert!(shim.stats().frames_from_tunnel > 0);
}

#[test]
fn fuzz_shim_outbound_never_exceeds_the_frame_budget() {
    let mut rng = Rng::new(0x4F53_4950_0000_0005);
    let mut shim = shim();
    let cap = shim.config().outbound_capacity;
    let max_frame = shim.config().inner_ip_mtu + ETH_HEADER_LEN;
    let base = Instant::now();

    for i in 0..30_000 {
        let now = base + Duration::from_millis(i as u64);
        let packet = if rng.below(8) == 0 {
            // Random bytes, including malformed IPv4.
            let len = rng.below(1600);
            let mut raw = vec![0u8; len];
            rng.fill(&mut raw);
            raw
        } else {
            let dst = match rng.below(6) {
                0 => OUR_IP,
                1 => Ipv4Addr::BROADCAST,
                2 => Ipv4Addr::new(224, 0, 0, rng.byte()),
                3 => Ipv4Addr::new(10, 99, 0, rng.byte()),
                4 => Ipv4Addr::new(10, 99, 1, rng.byte()),
                _ => rng.sane_ip(),
            };
            // Occasionally exceed the inner MTU so the oversized path runs.
            let payload = if rng.below(16) == 0 {
                1501 + rng.below(100)
            } else {
                rng.below(1501)
            };
            rng.ipv4_packet(dst, payload)
        };
        let produced = shim.ingest_os_ip(&packet, now);
        assert!(produced <= 1);
        assert!(shim.outbound_len() <= cap);
        while let Some(frame) = shim.take_outbound() {
            assert!(frame.len() >= ETH_HEADER_LEN);
            assert!(
                frame.len() <= max_frame,
                "frame {} exceeds budget {}",
                frame.len(),
                max_frame
            );
        }
    }
}

#[test]
fn fuzz_checksum_and_address_helpers_are_total() {
    let mut rng = Rng::new(0x4348_4B53_0000_0006);
    for _ in 0..4_000 {
        let len = rng.below(2048);
        let mut data = vec![0u8; len];
        rng.fill(&mut data);
        // Deterministic and total for arbitrary inputs.
        let first = checksum(&data);
        let second = checksum(&data);
        assert_eq!(first, second);
        let src = rng.sane_ip();
        let dst = rng.sane_ip();
        let udp_first = udp_checksum(src, dst, &data);
        let udp_second = udp_checksum(src, dst, &data);
        assert_eq!(udp_first, udp_second);
    }

    for _ in 0..4_000 {
        let a = rng.sane_ip();
        let b = rng.sane_ip();
        let prefix = rng.byte() % 40; // includes invalid > 32
        let _ = in_same_subnet(a, b, prefix);
        let _ = subnet_broadcast(a, prefix);
        let mask = prefix_to_mask(prefix);
        if prefix <= 32 {
            assert!(mask.is_some());
        } else {
            assert!(mask.is_none());
        }
        let group = Ipv4Addr::new(224, rng.byte(), rng.byte(), rng.byte());
        let mapped = multicast_mac(group);
        assert!(mapped.is_multicast());
    }
}
