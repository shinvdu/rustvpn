//! Ethernet frame codec for the L3 Wintun <-> L2 tunnel shim.
//!
//! GoVPN transports complete Ethernet frames. Wintun gives the OS an L3 IP
//! interface, so outbound IP packets get a synthetic 14-byte header and
//! inbound frames are validated, stripped and (for ARP) handled locally.

use std::fmt;

use crate::ipv4::{Ipv4Error, Ipv4Header};
use crate::mac::MacAddr;

pub const ETH_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Build an Ethernet frame with an arbitrary EtherType.
pub fn build_frame(dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + payload.len());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Build the outbound `[dst][src][0x0800][IPv4 packet]` frame.
pub fn build_ipv4_frame(dst: MacAddr, src: MacAddr, ip_packet: &[u8]) -> Vec<u8> {
    build_frame(dst, src, ETHERTYPE_IPV4, ip_packet)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundError {
    TooShort,
    NotForUs(MacAddr),
    Vlan,
    Ipv6,
    OtherEtherType(u16),
    ShortArp,
    MalformedIpv4(Ipv4Error),
    OversizedIpv4 {
        total_length: usize,
        max_ip_payload: usize,
    },
}

impl fmt::Display for InboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InboundError::TooShort => write!(f, "frame shorter than {ETH_HEADER_LEN} bytes"),
            InboundError::NotForUs(mac) => {
                write!(f, "destination MAC {mac} is not ours/broadcast/multicast")
            }
            InboundError::Vlan => write!(f, "VLAN-tagged frames are unsupported"),
            InboundError::Ipv6 => write!(f, "IPv6 frames are unsupported"),
            InboundError::OtherEtherType(t) => write!(f, "unsupported EtherType 0x{t:04x}"),
            InboundError::ShortArp => write!(f, "ARP frame shorter than 42 bytes"),
            InboundError::MalformedIpv4(e) => write!(f, "malformed IPv4 packet: {e}"),
            InboundError::OversizedIpv4 {
                total_length,
                max_ip_payload,
            } => write!(
                f,
                "IPv4 packet {total_length} bytes exceeds inner IP MTU {max_ip_payload}"
            ),
        }
    }
}

/// A validated inbound tunnel frame.
#[derive(Clone, Copy, Debug)]
pub enum Inbound<'a> {
    /// An IPv4 packet with `total_length` already applied (padding stripped
    /// by [`Ipv4Header::packet`]).
    Ipv4(Ipv4Header<'a>),
    /// The 28-byte ARP payload (frame padding ignored).
    Arp(&'a [u8]),
}

/// Validate an inbound tunnel frame.
///
/// Order of checks matches the design doc: length, destination MAC, then
/// EtherType. IPv4 uses `total_length` rather than the frame length so
/// Ethernet padding from the server bridge is harmless.
pub fn classify_inbound<'a>(
    frame: &'a [u8],
    our_mac: MacAddr,
    max_ip_payload: usize,
) -> Result<Inbound<'a>, InboundError> {
    if frame.len() < ETH_HEADER_LEN {
        return Err(InboundError::TooShort);
    }
    let Some(dst) = MacAddr::from_slice(&frame[0..6]) else {
        return Err(InboundError::TooShort);
    };
    if dst != our_mac && !dst.is_broadcast() && !dst.is_multicast() {
        return Err(InboundError::NotForUs(dst));
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        ETHERTYPE_IPV4 => {
            let header =
                Ipv4Header::parse(&frame[ETH_HEADER_LEN..]).map_err(InboundError::MalformedIpv4)?;
            if header.total_length > max_ip_payload {
                return Err(InboundError::OversizedIpv4 {
                    total_length: header.total_length,
                    max_ip_payload,
                });
            }
            Ok(Inbound::Ipv4(header))
        }
        ETHERTYPE_ARP => {
            if frame.len() < ETH_HEADER_LEN + crate::arp::ARP_PAYLOAD_LEN {
                return Err(InboundError::ShortArp);
            }
            Ok(Inbound::Arp(
                &frame[ETH_HEADER_LEN..ETH_HEADER_LEN + crate::arp::ARP_PAYLOAD_LEN],
            ))
        }
        ETHERTYPE_VLAN => Err(InboundError::Vlan),
        ETHERTYPE_IPV6 => Err(InboundError::Ipv6),
        other => Err(InboundError::OtherEtherType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR: MacAddr = MacAddr([0x02, 0x52, 0x56, 1, 2, 3]);
    const PEER: MacAddr = MacAddr([0x02, 0x52, 0x56, 9, 8, 7]);

    fn ipv4(total_length: u16) -> Vec<u8> {
        let mut buf = vec![0u8; usize::from(total_length)];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&total_length.to_be_bytes());
        buf[8] = 64;
        buf[9] = 17;
        buf[12..16].copy_from_slice(&[10, 88, 0, 2]);
        buf[16..20].copy_from_slice(&[10, 88, 0, 1]);
        buf
    }

    #[test]
    fn outbound_frame_layout() {
        let packet = ipv4(28);
        let frame = build_ipv4_frame(PEER, OUR, &packet);
        assert_eq!(frame.len(), 14 + 28);
        assert_eq!(&frame[0..6], &PEER.octets());
        assert_eq!(&frame[6..12], &OUR.octets());
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(&frame[14..], &packet[..]);
    }

    #[test]
    fn inbound_strips_padding_using_total_length() {
        let packet = ipv4(28);
        let mut frame = build_ipv4_frame(OUR, PEER, &packet);
        frame.extend_from_slice(&[0xaa; 18]);
        let Inbound::Ipv4(header) = classify_inbound(&frame, OUR, 1500).unwrap() else {
            panic!("expected IPv4");
        };
        assert_eq!(header.total_length, 28);
        assert_eq!(header.packet().len(), 28);
    }

    #[test]
    fn rejects_short_not_for_us_and_non_ip() {
        assert_eq!(
            classify_inbound(&[0u8; 13], OUR, 1500).unwrap_err(),
            InboundError::TooShort
        );

        let frame = build_ipv4_frame(PEER, OUR, &ipv4(20));
        assert_eq!(
            classify_inbound(&frame, OUR, 1500).unwrap_err(),
            InboundError::NotForUs(PEER)
        );

        let vlan = build_frame(OUR, PEER, ETHERTYPE_VLAN, &[0u8; 20]);
        assert_eq!(
            classify_inbound(&vlan, OUR, 1500).unwrap_err(),
            InboundError::Vlan
        );

        let v6 = build_frame(OUR, PEER, ETHERTYPE_IPV6, &[0x60; 40]);
        assert_eq!(
            classify_inbound(&v6, OUR, 1500).unwrap_err(),
            InboundError::Ipv6
        );

        let other = build_frame(OUR, PEER, 0x88cc, &[0u8; 32]);
        assert_eq!(
            classify_inbound(&other, OUR, 1500).unwrap_err(),
            InboundError::OtherEtherType(0x88cc)
        );
    }

    #[test]
    fn broadcast_and_multicast_are_accepted() {
        for dst in [MacAddr::BROADCAST, MacAddr([0x01, 0x00, 0x5e, 0, 0, 1])] {
            let frame = build_ipv4_frame(dst, PEER, &ipv4(20));
            assert!(classify_inbound(&frame, OUR, 1500).is_ok());
        }
    }

    #[test]
    fn rejects_oversized_and_malformed_ipv4() {
        let big = build_ipv4_frame(OUR, PEER, &ipv4(1501));
        assert!(matches!(
            classify_inbound(&big, OUR, 1500).unwrap_err(),
            InboundError::OversizedIpv4 {
                total_length: 1501,
                ..
            }
        ));

        let mut packet = ipv4(28);
        packet[0] = 0x44; // IHL 4 -> 16 bytes
        let frame = build_ipv4_frame(OUR, PEER, &packet);
        assert!(matches!(
            classify_inbound(&frame, OUR, 1500).unwrap_err(),
            InboundError::MalformedIpv4(Ipv4Error::BadIhl(16))
        ));

        let mut packet = ipv4(20);
        packet[2..4].copy_from_slice(&9000u16.to_be_bytes());
        let frame = build_ipv4_frame(OUR, PEER, &packet);
        assert!(matches!(
            classify_inbound(&frame, OUR, 1500).unwrap_err(),
            InboundError::MalformedIpv4(Ipv4Error::BadTotalLength { .. })
        ));
    }

    #[test]
    fn short_arp_frame_is_rejected() {
        let frame = build_frame(OUR, PEER, ETHERTYPE_ARP, &[0u8; 27]);
        assert_eq!(
            classify_inbound(&frame, OUR, 1500).unwrap_err(),
            InboundError::ShortArp
        );
    }
}
