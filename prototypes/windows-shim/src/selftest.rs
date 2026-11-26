//! Pure self-test used by `windows-shim-spike --self-test`.
//!
//! It exercises codec, ARP, MTU and queue logic only, so it runs on Linux and
//! on Windows without a Wintun adapter.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::arp::{
    build_arp_frame, ArpCache, ArpConfig, ArpOp, ArpPacket, ArpState, PendingQueue, ARP_PAYLOAD_LEN,
};
use crate::ethernet::{build_frame, build_ipv4_frame, ETHERTYPE_VLAN};
use crate::ipv4;
use crate::mac::{self, MacAddr};
use crate::mtu::{self, Mode};
use crate::safety;
use crate::shim::{EthernetShim, ShimConfig};
use crate::wintun_verify;

const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 9);
const OUR_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 1, 2, 3]);
const PEER_MAC: MacAddr = MacAddr([0x02, 0x52, 0x56, 9, 8, 7]);

#[derive(Debug, Default)]
pub struct SelfTestReport {
    pub passed: Vec<String>,
    pub failed: Vec<String>,
}

impl SelfTestReport {
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }
}

#[derive(Default)]
struct Checks {
    report: SelfTestReport,
}

impl Checks {
    fn ok(&mut self, name: &str, condition: bool) {
        if condition {
            self.report.passed.push(name.to_string());
        } else {
            self.report.failed.push(name.to_string());
        }
    }

    fn eq<T: PartialEq + fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        if got == want {
            self.report.passed.push(name.to_string());
        } else {
            self.report
                .failed
                .push(format!("{name}: got {got:?}, want {want:?}"));
        }
    }

    fn contains(&mut self, name: &str, haystack: &str, needle: &str) {
        self.ok(
            &format!("{name} (contains {needle:?})"),
            haystack.contains(needle),
        );
    }
}

pub fn run() -> SelfTestReport {
    let mut checks = Checks::default();
    mtu_checks(&mut checks);
    mac_checks(&mut checks);
    codec_checks(&mut checks);
    arp_checks(&mut checks);
    shim_checks(&mut checks);
    safety_checks(&mut checks);
    wire_contract_checks(&mut checks);
    pin_checks(&mut checks);
    checks.report
}

fn mtu_checks(checks: &mut Checks) {
    let plain = mtu::from_wire(Mode::Plain, 1515).expect("plain 1515");
    checks.eq("plain 1515 -> inner IP MTU 1500", plain.inner_ip_mtu, 1500);
    checks.eq("plain 1515 -> IPv4 MSS 1460", plain.mss_v4, 1460);
    checks.eq("plain 1515 -> IPv6 MSS 1440", plain.mss_v6, 1440);

    let noise = mtu::from_wire(Mode::Noise, 1515).expect("noise 1515");
    checks.eq("noise 1515 -> inner IP MTU 1476", noise.inner_ip_mtu, 1476);
    checks.eq("noise 1515 -> IPv4 MSS 1436", noise.mss_v4, 1436);
    checks.eq("noise 1515 -> IPv6 MSS 1416", noise.mss_v6, 1416);

    let encless = mtu::from_wire(Mode::Encless, 1515).expect("encless 1515");
    checks.eq(
        "encless 1515 -> inner IP MTU 1492",
        encless.inner_ip_mtu,
        1492,
    );
    checks.eq("encless 1515 -> IPv4 MSS 1452", encless.mss_v4, 1452);
    checks.eq("encless 1515 -> IPv6 MSS 1432", encless.mss_v6, 1432);
    checks.eq(
        "encless expansion constant is 4128",
        mtu::ENCLESS_ENLARGE_SIZE,
        4128,
    );

    let warning = mtu::encless_capacity_warning(
        Mode::Encless,
        1515,
        1500,
        mtu::OuterFamily::V4,
        mtu::OuterTransport::Udp,
    )
    .unwrap_or_default();
    checks.contains(
        "encless 1515 warning names ~5671 outer bytes",
        &warning,
        "5671",
    );
    checks.contains(
        "encless 1515 warning mentions fragmentation",
        &warning,
        "fragmentation",
    );
    checks.ok(
        "plain mode does not warn about outer capacity",
        mtu::encless_capacity_warning(
            Mode::Plain,
            1515,
            1500,
            mtu::OuterFamily::V4,
            mtu::OuterTransport::Udp,
        )
        .is_none(),
    );

    checks.ok(
        "wire MTU 0 is rejected",
        mtu::from_wire(Mode::Plain, 0).is_err(),
    );
    checks.ok(
        "wire MTU below mode minimum is rejected",
        mtu::from_wire(Mode::Noise, 119).is_err(),
    );
    checks.ok(
        "wire MTU above maximum is rejected",
        mtu::from_wire(Mode::Plain, mtu::MTU_MAX + 1).is_err(),
    );
}

fn mac_checks(checks: &mut Checks) {
    let a = mac::derive(b"verifier-42");
    let b = mac::derive(b"verifier-42");
    checks.eq("synthetic MAC is stable", a, b);
    checks.ok("synthetic MAC is locally administered", a.is_local());
    checks.ok("synthetic MAC is unicast", a.is_unicast());
    checks.eq(
        "synthetic MAC prefix is 02:52:56",
        &a.octets()[..3],
        &[0x02, 0x52, 0x56],
    );
    checks.ok(
        "different verifier ids produce different MACs",
        mac::derive(b"a") != mac::derive(b"b"),
    );
}

fn codec_checks(checks: &mut Checks) {
    let ip = ipv4(PEER_IP, 8);
    let frame = build_ipv4_frame(PEER_MAC, OUR_MAC, &ip);
    checks.eq(
        "outbound frame length is 14 + IP length",
        frame.len(),
        14 + ip.len(),
    );
    checks.eq("outbound dst MAC", &frame[0..6], &PEER_MAC.octets());
    checks.eq("outbound src MAC", &frame[6..12], &OUR_MAC.octets());
    checks.eq(
        "outbound EtherType is 0x0800",
        &frame[12..14],
        &[0x08, 0x00],
    );

    let mut padded = build_ipv4_frame(OUR_MAC, PEER_MAC, &ip);
    padded.extend_from_slice(&[0xaa; 18]);
    match crate::ethernet::classify_inbound(&padded, OUR_MAC, 1500) {
        Ok(crate::ethernet::Inbound::Ipv4(header)) => {
            checks.eq(
                "inbound total_length strips 18 bytes of padding",
                header.packet().len(),
                ip.len(),
            );
        }
        other => checks.ok(&format!("inbound padding frame failed: {other:?}"), false),
    }

    checks.ok(
        "inbound frame shorter than 14 bytes is dropped",
        crate::ethernet::classify_inbound(&[0u8; 13], OUR_MAC, 1500).is_err(),
    );
    let not_us = build_ipv4_frame(PEER_MAC, PEER_MAC, &ipv4(OUR_IP, 4));
    checks.ok(
        "unknown unicast destination MAC is dropped",
        crate::ethernet::classify_inbound(&not_us, OUR_MAC, 1500).is_err(),
    );
    let vlan = build_frame(OUR_MAC, PEER_MAC, ETHERTYPE_VLAN, &[0u8; 20]);
    checks.ok(
        "VLAN frame is dropped",
        crate::ethernet::classify_inbound(&vlan, OUR_MAC, 1500).is_err(),
    );
    let ipv6 = build_frame(OUR_MAC, PEER_MAC, 0x86dd, &[0x60; 40]);
    checks.ok(
        "IPv6 frame is dropped",
        crate::ethernet::classify_inbound(&ipv6, OUR_MAC, 1500).is_err(),
    );
    let oversized = build_ipv4_frame(OUR_MAC, PEER_MAC, &ipv4(OUR_IP, 1500));
    checks.ok(
        "IPv4 packet above inner MTU is dropped",
        crate::ethernet::classify_inbound(&oversized, OUR_MAC, 1500).is_err(),
    );
}

fn arp_checks(checks: &mut Checks) {
    let packet = ArpPacket {
        op: ArpOp::Request,
        sender_mac: OUR_MAC,
        sender_ip: OUR_IP,
        target_mac: MacAddr::ZERO,
        target_ip: PEER_IP,
    };
    let encoded = packet.encode();
    checks.eq("ARP payload is 28 bytes", encoded.len(), ARP_PAYLOAD_LEN);
    checks.eq(
        "ARP request parse round-trips",
        ArpPacket::parse(&encoded).ok(),
        Some(packet),
    );
    let frame = build_arp_frame(MacAddr::BROADCAST, OUR_MAC, &packet);
    checks.eq("ARP Ethernet frame is 42 bytes", frame.len(), 42);
    checks.eq("ARP EtherType is 0x0806", &frame[12..14], &[0x08, 0x06]);
    checks.ok(
        "truncated ARP payload is rejected",
        ArpPacket::parse(&[0u8; 27]).is_err(),
    );

    let now = Instant::now();
    let mut cache = ArpCache::new(4);
    cache.insert(PEER_IP, PEER_MAC, now, Duration::from_secs(60));
    checks.eq(
        "ARP cache hit before TTL",
        cache.lookup(PEER_IP, now + Duration::from_secs(59)),
        Some(PEER_MAC),
    );
    checks.ok(
        "ARP cache entry expires after TTL",
        cache
            .lookup(PEER_IP, now + Duration::from_secs(61))
            .is_none(),
    );

    let mut pending = PendingQueue::new(4, 2);
    let _ = pending.enqueue(PEER_IP, vec![1, 2, 3], now);
    let _ = pending.enqueue(PEER_IP, vec![4, 5, 6], now);
    let accepted = pending.enqueue(PEER_IP, vec![7, 8, 9], now);
    checks.ok(
        "per-target pending bound drops the newest packet",
        !accepted,
    );
    checks.eq("per-target pending bound keeps 2 packets", pending.len(), 2);

    let request_frame = build_arp_frame(
        MacAddr::BROADCAST,
        PEER_MAC,
        &ArpPacket {
            op: ArpOp::Request,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: MacAddr::ZERO,
            target_ip: OUR_IP,
        },
    );
    checks.eq(
        "ARP request frame for us parses as a request",
        ArpPacket::parse(&request_frame[14..]).map(|p| p.op).ok(),
        Some(ArpOp::Request),
    );

    // P2-3: any successful learn flushes pending frames for that sender, not
    // only a reply addressed to us.
    let mut arp = ArpState::new(ArpConfig::new(OUR_IP, OUR_MAC));
    let _ = arp.resolve_or_queue(PEER_IP, &ipv4(PEER_IP, 8), now);
    let gratuitous = ArpPacket {
        op: ArpOp::Reply,
        sender_mac: PEER_MAC,
        sender_ip: PEER_IP,
        target_mac: PEER_MAC,
        target_ip: PEER_IP,
    }
    .encode();
    let handling = arp.handle_payload(&gratuitous, now);
    checks.eq(
        "gratuitous ARP reply flushes pending frames",
        handling.flushed.len(),
        1,
    );
    checks.ok(
        "learned MAC is cached",
        arp.cache().lookup(PEER_IP, now) == Some(PEER_MAC),
    );

    let mut arp = ArpState::new(ArpConfig::new(OUR_IP, OUR_MAC));
    let _ = arp.resolve_or_queue(PEER_IP, &ipv4(PEER_IP, 8), now);
    let late = now + Duration::from_secs(30);
    // A cache miss at t+30s ages out the pending packet (TTL 5s) and its
    // retry state.
    let _ = arp.resolve_or_queue(Ipv4Addr::new(10, 88, 0, 4), &ipv4(PEER_IP, 8), late);
    checks.eq(
        "pending ARP packet expires after its TTL",
        arp.pending_len(),
        1,
    );
}

fn shim_checks(checks: &mut Checks) {
    let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
    cfg.prefix_len = 24;
    cfg.inner_ip_mtu = 1500;
    cfg.outbound_capacity = 8;
    cfg.arp.pending_capacity = 8;
    cfg.arp.pending_per_target = 4;
    let mut shim = EthernetShim::new(cfg).expect("shim");

    let now = Instant::now();
    let packet = ipv4(PEER_IP, 20);
    checks.eq(
        "shim enqueues an ARP request on cache miss",
        shim.ingest_os_ip(&packet, now),
        1,
    );
    let request_frame = shim.take_outbound().expect("ARP request");
    let request = ArpPacket::parse(&request_frame[14..]).expect("parse request");
    checks.eq("shim ARP request opcode", request.op, ArpOp::Request);
    checks.eq("shim ARP request target", request.target_ip, PEER_IP);

    let reply_frame = build_arp_frame(
        OUR_MAC,
        PEER_MAC,
        &ArpPacket {
            op: ArpOp::Reply,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: OUR_MAC,
            target_ip: OUR_IP,
        },
    );
    checks.ok(
        "shim consumes the ARP reply locally",
        shim.ingest_tunnel_frame(&reply_frame, now).is_none(),
    );
    let data_frame = shim.take_outbound().expect("flushed IP frame");
    checks.eq(
        "shim flushes the pending IP packet after learning the MAC",
        &data_frame[0..6],
        &PEER_MAC.octets(),
    );
    checks.eq(
        "flushed IP frame carries the original packet",
        &data_frame[14..],
        &packet[..],
    );

    checks.eq(
        "cache hit encodes directly without another ARP request",
        shim.ingest_os_ip(&packet, now),
        1,
    );
    let direct = shim.take_outbound().expect("cached frame");
    checks.eq("cached frame dst MAC", &direct[0..6], &PEER_MAC.octets());

    let mut inbound = build_ipv4_frame(OUR_MAC, PEER_MAC, &ipv4(OUR_IP, 8));
    inbound.extend_from_slice(&[0xbb; 20]);
    let out = shim.ingest_tunnel_frame(&inbound, now);
    checks.eq(
        "shim inbound frame strips Ethernet padding",
        out.map(|p| p.len()),
        Some(28),
    );

    let arp_request = build_arp_frame(
        MacAddr::BROADCAST,
        PEER_MAC,
        &ArpPacket {
            op: ArpOp::Request,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: MacAddr::ZERO,
            target_ip: OUR_IP,
        },
    );
    checks.ok(
        "shim handles inbound ARP request for our IP",
        shim.ingest_tunnel_frame(&arp_request, now).is_none(),
    );
    let reply = shim.take_outbound().expect("ARP reply");
    let reply = ArpPacket::parse(&reply[14..]).expect("parse reply");
    checks.eq("shim ARP reply opcode", reply.op, ArpOp::Reply);
    checks.eq("shim ARP reply sender IP", reply.sender_ip, OUR_IP);
    checks.eq("shim ARP reply target IP", reply.target_ip, PEER_IP);

    let vlan = build_frame(OUR_MAC, PEER_MAC, ETHERTYPE_VLAN, &[0u8; 20]);
    checks.ok(
        "shim drops VLAN frames",
        shim.ingest_tunnel_frame(&vlan, now).is_none() && shim.stats().drop_vlan == 1,
    );

    checks.ok(
        "shim queues gratuitous ARP on demand",
        shim.announce_gratuitous_arp(now) && shim.outbound_len() > 0,
    );
}

fn safety_checks(checks: &mut Checks) {
    let good = Ipv4Addr::new(10, 88, 0, 2);
    checks.ok(
        "test address 10.88.0.2/24 is accepted",
        safety::validate_adapter_address(good, 24).is_ok(),
    );
    checks.ok(
        "prefix /8 is rejected",
        safety::validate_adapter_address(good, 8).is_err(),
    );
    checks.ok(
        "prefix /1 is rejected",
        safety::validate_adapter_address(good, 1).is_err(),
    );
    checks.ok(
        "address outside 10.88.0.0/24 is rejected",
        safety::validate_adapter_address(Ipv4Addr::new(192, 168, 1, 2), 24).is_err(),
    );
    checks.ok(
        "peer inside the test subnet is accepted",
        safety::validate_peer(Ipv4Addr::new(10, 88, 0, 3), good).is_ok(),
    );
    checks.ok(
        "peer outside the test subnet is rejected",
        safety::validate_peer(Ipv4Addr::new(8, 8, 8, 8), good).is_err(),
    );
    checks.ok(
        "peer equal to the adapter address is rejected",
        safety::validate_peer(good, good).is_err(),
    );
    checks.ok(
        "adapter inner IP MTU 575 is rejected",
        safety::validate_adapter_mtu(575).is_err(),
    );
    checks.ok(
        "adapter inner IP MTU 1500 is accepted",
        safety::validate_adapter_mtu(1500).is_ok(),
    );
    checks.ok(
        "ring capacity 4 MiB is accepted",
        safety::validate_ring_capacity(4 * 1024 * 1024).is_ok(),
    );
    checks.ok(
        "non-power-of-two ring capacity is rejected",
        safety::validate_ring_capacity(3 * 1024 * 1024).is_err(),
    );
    checks.ok(
        "adapter name with whitespace is rejected",
        safety::validate_adapter_name("bad name").is_err(),
    );
    checks.ok(
        "adapter-not-found OS codes are classified narrowly",
        safety::is_adapter_not_found(Some(1168))
            && safety::is_adapter_not_found(Some(2))
            && !safety::is_adapter_not_found(Some(5))
            && !safety::is_adapter_not_found(None),
    );
    checks.ok(
        "deterministic adapter GUIDs differ per name",
        safety::adapter_guid("RustVPN-Spike") == safety::adapter_guid("RustVPN-Spike")
            && safety::adapter_guid("RustVPN-Spike") != safety::adapter_guid("RustVPN-Other"),
    );
    #[cfg(windows)]
    let system_root = Path::new(r"C:\Windows");
    #[cfg(not(windows))]
    let system_root = Path::new("/windows-root");
    let netsh = safety::resolve_system32_tool(system_root, "netsh.exe");
    checks.ok(
        "System32 tool path is absolute and under the system root",
        netsh
            .as_ref()
            .map(|path| path.is_absolute() && path.starts_with(system_root))
            .unwrap_or(false),
    );
    checks.ok(
        "relative system root is rejected",
        safety::resolve_system32_tool(Path::new("relative-root"), "netsh.exe").is_err(),
    );
}

fn wire_contract_checks(checks: &mut Checks) {
    let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
    cfg.inner_ip_mtu = 1500;
    checks.ok(
        "shim config accepts plain 1515 -> 1500",
        cfg.validate().is_ok(),
    );

    cfg.mode = Mode::Noise;
    checks.ok(
        "shim config rejects 1500 inner under noise 1515",
        cfg.validate().is_err(),
    );
    cfg.mode = Mode::Encless;
    checks.ok(
        "shim config rejects 1500 inner under encless 1515",
        cfg.validate().is_err(),
    );

    let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
    cfg.inner_ip_mtu = 42;
    cfg.wire_mtu = 56 + 14;
    checks.ok(
        "shim config accepts the smallest inner MTU with a matching budget",
        cfg.validate().is_ok(),
    );

    let mut cfg = ShimConfig::new(OUR_IP, OUR_MAC);
    cfg.inner_ip_mtu = 41;
    checks.ok("shim config rejects inner MTU 41", cfg.validate().is_err());

    let big = vec![0xab; 400 * 1024];
    let mut reference = 0u64;
    let (pairs, remainder) = big.as_chunks::<2>();
    for pair in pairs {
        reference += u64::from(u16::from_be_bytes(*pair));
    }
    if let Some(&last) = remainder.first() {
        reference += u64::from(last) << 8;
    }
    while reference >> 16 != 0 {
        reference = (reference & 0xffff) + (reference >> 16);
    }
    checks.eq(
        "large-buffer checksum folds a 64-bit accumulator",
        ipv4::checksum(&big),
        !(reference as u16),
    );
}

fn pin_checks(checks: &mut Checks) {
    let parsed = wintun_verify::parse_sha256_hex(wintun_verify::DEFAULT_WINTUN_SHA256_HEX);
    checks.ok(
        "default wintun SHA-256 parses",
        parsed == Ok(wintun_verify::DEFAULT_WINTUN_SHA256),
    );
    checks.ok(
        "short SHA-256 is rejected",
        wintun_verify::parse_sha256_hex("abcd").is_err(),
    );
    checks.ok(
        "non-hex SHA-256 is rejected",
        wintun_verify::parse_sha256_hex(&format!("{}zz", "0".repeat(62))).is_err(),
    );
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

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        let report = super::run();
        assert!(report.is_ok(), "self-test failures: {:#?}", report.failed);
    }
}
