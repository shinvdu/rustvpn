//! MAC address helpers and deterministic synthetic-MAC derivation.

use std::fmt;

/// A 48-bit Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const ZERO: Self = Self([0; 6]);
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    /// The group bit (bit 0 of the first octet) is set for multicast/broadcast.
    pub fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_unicast(self) -> bool {
        !self.is_multicast()
    }

    pub fn is_broadcast(self) -> bool {
        self == Self::BROADCAST
    }

    /// The locally administered bit (bit 1 of the first octet).
    pub fn is_local(self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let octets: [u8; 6] = bytes.get(..6)?.try_into().ok()?;
        Some(Self(octets))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// Derive the shim's synthetic MAC from the verifier id.
///
/// The prefix `02:52:56` is stable ("R", "V" in the locally administered
/// `02:` space); the low 24 bits come from a fixed FNV-1a hash so the same
/// verifier id always maps to the same address across reconnects and
/// processes. 24 bits are enough for a synthetic peer MAC; this is not a
/// security boundary.
pub fn derive(verifier_id: &[u8]) -> MacAddr {
    let mut hash = fnv1a64(b"rustvpn-windows-shim\0");
    hash = fnv1a64_seeded(hash, verifier_id);
    MacAddr([
        0x02,
        0x52,
        0x56,
        (hash >> 16) as u8,
        (hash >> 8) as u8,
        hash as u8,
    ])
}

fn fnv1a64(data: &[u8]) -> u64 {
    fnv1a64_seeded(0xcbf2_9ce4_8422_2325, data)
}

fn fnv1a64_seeded(mut hash: u64, data: &[u8]) -> u64 {
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_stable_and_locally_administered_unicast() {
        let a = derive(b"verifier-123");
        let b = derive(b"verifier-123");
        assert_eq!(a, b);
        assert_eq!(a.octets()[0], 0x02);
        assert!(a.is_local());
        assert!(a.is_unicast());
        assert!(!a.is_broadcast());
        assert!(!a.is_multicast());
    }

    #[test]
    fn different_ids_produce_different_macs() {
        assert_ne!(derive(b"verifier-a"), derive(b"verifier-b"));
        assert_ne!(derive(b""), derive(b"x"));
    }

    #[test]
    fn display_is_colon_separated() {
        let mac = MacAddr([0x02, 0x52, 0x56, 0xab, 0xcd, 0xef]);
        assert_eq!(mac.to_string(), "02:52:56:ab:cd:ef");
    }

    #[test]
    fn classification() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::BROADCAST.is_unicast());
        assert!(MacAddr([0x01, 0x00, 0x5e, 1, 2, 3]).is_multicast());
        assert!(MacAddr([0x02, 0, 0, 0, 0, 1]).is_unicast());
        assert!(MacAddr([0x02, 0, 0, 0, 0, 1]).is_local());
        assert!(MacAddr::ZERO.is_zero());
        assert!(MacAddr::from_slice(&[1, 2, 3]).is_none());
    }
}
