//! Golden test: the prototype's wire-MTU arithmetic must stay consistent with
//! the repository's real `rustvpn-proto` constants. This is a dev-dependency
//! only, so the prototype itself remains standalone.
//!
//! Unix-only because `rustvpn-crypto` (a `rustvpn-proto` dependency) currently
//! uses `std::os::unix`; the rest of the prototype still builds and tests on
//! Windows.
#![cfg(unix)]

use std::net::Ipv4Addr;

use rustvpn_proto::Mode as ProtoMode;
use rustvpn_windows_shim::mac::MacAddr;
use rustvpn_windows_shim::mtu::{self, Mode};
use rustvpn_windows_shim::shim::ShimConfig;

fn proto_mode(mode: Mode) -> ProtoMode {
    match mode {
        Mode::Plain => ProtoMode::Plain,
        Mode::Noise => ProtoMode::Noise,
        Mode::Encless => ProtoMode::Encless,
    }
}

#[test]
fn constants_match_rustvpn_proto() {
    assert_eq!(mtu::MTU_MIN, rustvpn_proto::MTU_MIN);
    assert_eq!(mtu::MTU_MIN_NOISE, rustvpn_proto::MTU_MIN_NOISE);
    assert_eq!(mtu::MTU_MAX, rustvpn_proto::MTU_MAX);
    assert_eq!(mtu::TAG_SIZE, rustvpn_proto::TAG_SIZE);
    assert_eq!(mtu::NONCE_SIZE, rustvpn_proto::NONCE_SIZE);
    assert_eq!(mtu::ETH_HEADER, 14);
    assert_eq!(
        mtu::ENCLESS_ENLARGE_SIZE,
        rustvpn_proto::ENCLESS_ENLARGE_SIZE
    );
}

#[test]
fn inner_mtu_plus_ethernet_header_equals_proto_max_payload() {
    for mode in [Mode::Plain, Mode::Noise, Mode::Encless] {
        let proto = proto_mode(mode);
        let wires = [
            proto.min_mtu(),
            proto.min_mtu() + 1,
            576,
            1200,
            1515,
            9001,
            mtu::MTU_MAX,
        ];
        for wire in wires {
            if wire > mtu::MTU_MAX {
                continue;
            }
            let ours = mtu::from_wire(mode, wire)
                .unwrap_or_else(|error| panic!("{mode} wire {wire}: {error}"));
            assert_eq!(
                ours.inner_ip_mtu + mtu::ETH_HEADER,
                proto.max_payload(wire),
                "{mode} wire {wire}: inner MTU {} + 14 must equal the proto payload budget",
                ours.inner_ip_mtu
            );
        }
        assert_eq!(mode.min_mtu(), proto.min_mtu());
    }
}

#[test]
fn every_from_wire_value_is_accepted_by_shim_config_validation() {
    let our_ip = Ipv4Addr::new(10, 88, 0, 2);
    let our_mac = MacAddr([0x02, 0x52, 0x56, 1, 2, 3]);
    for mode in [Mode::Plain, Mode::Noise, Mode::Encless] {
        for wire in [mode.min_mtu(), 1515, mtu::MTU_MAX] {
            let wire_mtu = mtu::from_wire(mode, wire).unwrap();
            let mut cfg = ShimConfig::new(our_ip, our_mac);
            cfg.mode = mode;
            cfg.wire_mtu = wire;
            cfg.inner_ip_mtu = wire_mtu.inner_ip_mtu;
            cfg.validate()
                .unwrap_or_else(|error| panic!("{mode} wire {wire}: {error}"));
        }
    }
}
