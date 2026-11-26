//! Minimal IPv4 header parsing used by the Ethernet codec and the shim.
//!
//! Only the fields needed for L3->L2 framing are validated. Header checksums
//! and upper-layer checksums are deliberately not verified in this Phase 0
//! prototype; the tunnel is already authenticated by RustVPN/GoVPN.

use std::fmt;
use std::net::Ipv4Addr;

use crate::mac::MacAddr;

pub const IPV4_MIN_HEADER: usize = 20;
pub const UDP_HEADER: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Error {
    TooShort,
    NotIpv4(u8),
    BadIhl(usize),
    BadTotalLength {
        total: usize,
        header: usize,
        available: usize,
    },
}

impl fmt::Display for Ipv4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv4Error::TooShort => write!(f, "shorter than a 20-byte IPv4 header"),
            Ipv4Error::NotIpv4(version) => write!(f, "IP version {version}, expected 4"),
            Ipv4Error::BadIhl(ihl) => write!(f, "invalid IHL {ihl} (header bytes)"),
            Ipv4Error::BadTotalLength {
                total,
                header,
                available,
            } => write!(
                f,
                "total_length {total} out of range (header {header}, buffer {available})"
            ),
        }
    }
}

/// A validated IPv4 header view.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4Header<'a> {
    /// The whole buffer that was parsed. May include Ethernet padding.
    pub bytes: &'a [u8],
    /// Header length in bytes (`IHL * 4`).
    pub header_len: usize,
    /// IPv4 `total_length` in bytes, including the header.
    pub total_length: usize,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl<'a> Ipv4Header<'a> {
    /// Parse and validate an IPv4 packet.
    ///
    /// `total_length` is the authoritative packet size; any bytes after it in
    /// `buf` are Ethernet padding and are ignored by [`Self::packet`].
    pub fn parse(buf: &'a [u8]) -> Result<Self, Ipv4Error> {
        if buf.len() < IPV4_MIN_HEADER {
            return Err(Ipv4Error::TooShort);
        }
        let version = buf[0] >> 4;
        if version != 4 {
            return Err(Ipv4Error::NotIpv4(version));
        }
        let header_len = usize::from(buf[0] & 0x0f) * 4;
        if header_len < IPV4_MIN_HEADER || header_len > buf.len() {
            return Err(Ipv4Error::BadIhl(header_len));
        }
        let total_length = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if total_length < header_len || total_length > buf.len() {
            return Err(Ipv4Error::BadTotalLength {
                total: total_length,
                header: header_len,
                available: buf.len(),
            });
        }
        Ok(Self {
            bytes: buf,
            header_len,
            total_length,
            protocol: buf[9],
            src: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            dst: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
        })
    }

    /// The packet with Ethernet padding stripped (`total_length` bytes).
    pub fn packet(&self) -> &'a [u8] {
        &self.bytes[..self.total_length]
    }

    /// Upper-layer payload (`total_length - header_len` bytes).
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..self.total_length]
    }
}

pub fn is_multicast(ip: Ipv4Addr) -> bool {
    ip.octets()[0] & 0xf0 == 0xe0
}

pub fn is_limited_broadcast(ip: Ipv4Addr) -> bool {
    ip == Ipv4Addr::BROADCAST
}

pub fn in_same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return a == b;
    }
    let mask = u32::MAX << (32 - u32::from(prefix_len));
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Directed broadcast address for a prefix, if one exists (/0../30).
pub fn subnet_broadcast(ip: Ipv4Addr, prefix_len: u8) -> Option<Ipv4Addr> {
    if prefix_len >= 31 || prefix_len > 32 {
        return None;
    }
    let mask = u32::MAX << (32 - u32::from(prefix_len));
    Some(Ipv4Addr::from(u32::from(ip) | !mask))
}

/// Convert a prefix length to a dotted-quad netmask.
pub fn prefix_to_mask(prefix_len: u8) -> Option<Ipv4Addr> {
    if prefix_len > 32 {
        return None;
    }
    if prefix_len == 0 {
        return Some(Ipv4Addr::UNSPECIFIED);
    }
    Some(Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix_len))))
}

/// RFC 1112 mapping: low 23 bits of the group address.
pub fn multicast_mac(group: Ipv4Addr) -> MacAddr {
    let octets = group.octets();
    MacAddr([0x01, 0x00, 0x5e, octets[1] & 0x7f, octets[2], octets[3]])
}

fn fold_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn sum_words(mut sum: u64, data: &[u8]) -> u64 {
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u64::from(u16::from_be_bytes(*pair));
    }
    if let Some(&last) = remainder.first() {
        sum += u64::from(last) << 8;
    }
    sum
}

/// Internet checksum (RFC 1071) over `data`.
///
/// The accumulator is 64-bit so arbitrarily large buffers cannot overflow it
/// before the final one's-complement fold.
pub fn checksum(data: &[u8]) -> u16 {
    fold_checksum(sum_words(0, data))
}

/// Compute the UDP checksum for an IPv4 datagram.
pub fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = sum_words(0, &src.octets());
    sum = sum_words(sum, &dst.octets());
    sum = sum_words(sum, &[0, 17]);
    sum += udp.len() as u64;
    let folded = fold_checksum(sum_words(sum, udp));
    if folded == 0 {
        0xffff
    } else {
        folded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(total_length: u16, protocol: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&total_length.to_be_bytes());
        buf[8] = 64;
        buf[9] = protocol;
        buf[12..16].copy_from_slice(&[10, 88, 0, 2]);
        buf[16..20].copy_from_slice(&[10, 88, 0, 1]);
        buf
    }

    #[test]
    fn parses_and_strips_trailing_padding() {
        let mut buf = header(28, 17);
        buf.extend_from_slice(&[0u8; 18]); // Ethernet padding to 46 bytes
        let parsed = Ipv4Header::parse(&buf).unwrap();
        assert_eq!(parsed.header_len, 20);
        assert_eq!(parsed.total_length, 28);
        assert_eq!(parsed.packet().len(), 28);
        assert_eq!(parsed.payload().len(), 8);
        assert_eq!(parsed.dst, Ipv4Addr::new(10, 88, 0, 1));
    }

    #[test]
    fn rejects_malformed_headers() {
        assert_eq!(
            Ipv4Header::parse(&[0u8; 19]).unwrap_err(),
            Ipv4Error::TooShort
        );

        let mut v6 = header(20, 6);
        v6[0] = 0x60;
        assert_eq!(Ipv4Header::parse(&v6).unwrap_err(), Ipv4Error::NotIpv4(6));

        let mut ihl4 = header(20, 6);
        ihl4[0] = 0x44;
        assert_eq!(Ipv4Header::parse(&ihl4).unwrap_err(), Ipv4Error::BadIhl(16));

        let mut short_total = header(20, 6);
        short_total[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert!(matches!(
            Ipv4Header::parse(&short_total).unwrap_err(),
            Ipv4Error::BadTotalLength { total: 19, .. }
        ));

        let mut over_total = header(20, 6);
        over_total[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert!(matches!(
            Ipv4Header::parse(&over_total).unwrap_err(),
            Ipv4Error::BadTotalLength { total: 21, .. }
        ));
    }

    #[test]
    fn subnet_and_broadcast_helpers() {
        let a = Ipv4Addr::new(10, 88, 0, 2);
        assert!(in_same_subnet(a, Ipv4Addr::new(10, 88, 0, 200), 24));
        assert!(!in_same_subnet(a, Ipv4Addr::new(10, 88, 1, 2), 24));
        assert_eq!(subnet_broadcast(a, 24), Some(Ipv4Addr::new(10, 88, 0, 255)));
        assert_eq!(prefix_to_mask(24), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(prefix_to_mask(33), None);
        assert_eq!(
            multicast_mac(Ipv4Addr::new(224, 0, 1, 2)),
            MacAddr([0x01, 0x00, 0x5e, 0x00, 0x01, 0x02])
        );
        assert!(is_multicast(Ipv4Addr::new(239, 1, 2, 3)));
        assert!(!is_multicast(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_limited_broadcast(Ipv4Addr::BROADCAST));
    }

    #[test]
    fn checksum_large_input_does_not_overflow_the_accumulator() {
        // 400 KiB of 0xFF would overflow a 32-bit accumulator (each word adds
        // 65535), which previously wrapped silently in release builds.
        let data = vec![0xffu8; 400 * 1024];
        let mut reference = 0u64;
        for pair in data.as_chunks::<2>().0 {
            reference += u64::from(u16::from_be_bytes(*pair));
        }
        while reference >> 16 != 0 {
            reference = (reference & 0xffff) + (reference >> 16);
        }
        assert_eq!(checksum(&data), !(reference as u16));

        // Odd-length buffers exercise the trailing-byte path as well.
        let odd = vec![0xab; 400 * 1024 + 1];
        let _ = checksum(&odd);
    }

    #[test]
    fn udp_checksum_large_payload_is_stable() {
        let src = Ipv4Addr::new(10, 88, 0, 3);
        let dst = Ipv4Addr::new(10, 88, 0, 2);
        let udp = vec![0xffu8; 64 * 1024];
        let sum = udp_checksum(src, dst, &udp);
        assert_ne!(sum, 0);
    }

    #[test]
    fn checksums_round_trip() {
        let mut h = header(28, 17);
        h[10..12].copy_from_slice(&[0, 0]);
        let sum = checksum(&h);
        h[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(checksum(&h), 0);

        let src = Ipv4Addr::new(10, 88, 0, 3);
        let dst = Ipv4Addr::new(10, 88, 0, 2);
        let mut udp = vec![0u8; 8 + 4];
        udp[0..2].copy_from_slice(&45123u16.to_be_bytes());
        udp[2..4].copy_from_slice(&5555u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        udp[8..].copy_from_slice(b"pong");
        let sum = udp_checksum(src, dst, &udp);
        assert_eq!(sum, 0x4654);
        udp[6..8].copy_from_slice(&sum.to_be_bytes());
        // RFC 768 maps a zero checksum to all ones; verification therefore
        // yields 0xffff for a valid datagram.
        assert_eq!(udp_checksum(src, dst, &udp), 0xffff);
    }
}
