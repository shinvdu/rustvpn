//! Wire-MTU -> inner-IP-MTU / MSS arithmetic.
//!
//! The configured `mtu` is a **two-sided numeric wire contract** shared with
//! the peer. This prototype deliberately does not implement automatic/path
//! wire-MTU detection: only the local interface MTU and the TCP MSS clamp are
//! derived from the numeric value.
//!
//! ```text
//! inner_ip_mtu = Mode::max_payload(wire_mtu) - 14   (Ethernet header)
//! ipv4_mss     = inner_ip_mtu - 40                  (IPv4 + TCP headers)
//! ipv6_mss     = inner_ip_mtu - 60                  (IPv6 + TCP headers)
//! ```
//!
//! Per-mode payload budgets (mirrors `rustvpn-proto::transport::Mode`):
//!
//! | mode    | payload for wire 1515 | inner IP MTU |
//! |---------|-----------------------|--------------|
//! | plain   | 1514                  | 1500         |
//! | noise   | 1490                  | 1476         |
//! | encless | 1506                  | 1492         |
//!
//! Encless is special: each encoded packet grows by ~4128 bytes on the wire,
//! so a 1515-byte tunnel MTU cannot fit a 1500-byte outer path. The shim keeps
//! the numeric contract unchanged and only warns.

use std::fmt;
use std::str::FromStr;

pub const ETH_HEADER: usize = 14;
pub const TCP_HEADER: usize = 20;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 8;
pub const PAD_BYTE: usize = 1;
pub const MTU_MIN: usize = 68;
pub const MTU_MIN_NOISE: usize = 120;
pub const MTU_MAX: usize = 9000 + ETH_HEADER + 1;
/// `aont::H_SIZE + aont::R_SIZE * cnw::ENLARGE_FACTOR` = 32 + 16 * 256.
pub const ENCLESS_ENLARGE_SIZE: usize = 4128;
/// Windows clients should warn (or reject) below the classic IPv4 minimum.
pub const WINDOWS_MIN_IP_MTU: usize = 576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Plain,
    Noise,
    Encless,
}

impl Mode {
    /// Maximal payload accepted by the transport for this configured MTU.
    pub fn max_payload(self, wire_mtu: usize) -> usize {
        match self {
            Mode::Plain => wire_mtu.saturating_sub(PAD_BYTE),
            Mode::Noise => wire_mtu.saturating_sub(TAG_SIZE + NONCE_SIZE + PAD_BYTE),
            Mode::Encless => wire_mtu.saturating_sub(NONCE_SIZE + PAD_BYTE),
        }
    }

    /// Bytes added to the payload by the transport envelope.
    pub fn overhead(self) -> usize {
        match self {
            Mode::Plain => PAD_BYTE,
            Mode::Noise => TAG_SIZE + NONCE_SIZE + PAD_BYTE,
            Mode::Encless => NONCE_SIZE + PAD_BYTE,
        }
    }

    pub fn min_mtu(self) -> usize {
        match self {
            Mode::Plain => MTU_MIN,
            Mode::Noise | Mode::Encless => MTU_MIN_NOISE,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Plain => "plain",
            Mode::Noise => "noise",
            Mode::Encless => "encless",
        }
    }

    pub fn is_padded(self) -> bool {
        matches!(self, Mode::Noise | Mode::Encless)
    }

    pub fn is_encless(self) -> bool {
        matches!(self, Mode::Encless)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "plain" => Ok(Mode::Plain),
            "noise" => Ok(Mode::Noise),
            "encless" => Ok(Mode::Encless),
            other => Err(format!(
                "unknown mode {other:?}; expected plain, noise or encless"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OuterFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OuterTransport {
    Udp,
    Tcp,
}

impl OuterFamily {
    pub fn header_len(self, transport: OuterTransport) -> usize {
        match (self, transport) {
            (OuterFamily::V4, OuterTransport::Tcp) => 20 + TCP_HEADER,
            (OuterFamily::V6, OuterTransport::Tcp) => 40 + TCP_HEADER,
            (OuterFamily::V4, OuterTransport::Udp) => 20 + 8,
            (OuterFamily::V6, OuterTransport::Udp) => 40 + 8,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            OuterFamily::V4 => "IPv4",
            OuterFamily::V6 => "IPv6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireMtu {
    pub wire_mtu: usize,
    pub mode: Mode,
    /// IP MTU to configure on the Wintun/TAP interface.
    pub inner_ip_mtu: usize,
    pub mss_v4: usize,
    pub mss_v6: usize,
}

impl WireMtu {
    /// Max Ethernet frame payload the transport accepts (also the inner IP
    /// MTU plus the 14-byte synthetic header).
    pub fn max_frame_len(self) -> usize {
        self.mode.max_payload(self.wire_mtu)
    }

    pub fn log_line(&self) -> String {
        format!(
            "mtu: wire={} mode={} -> inner_ip_mtu={} mss_v4={} mss_v6={} max_frame={} \
             (numeric two-sided contract; auto/path-MTU is not implemented)",
            self.wire_mtu,
            self.mode,
            self.inner_ip_mtu,
            self.mss_v4,
            self.mss_v6,
            self.max_frame_len()
        )
    }

    /// Windows guidance: an interface below 576 bytes is not useful.
    pub fn windows_recommendation(&self) -> Option<String> {
        if self.inner_ip_mtu < WINDOWS_MIN_IP_MTU {
            Some(format!(
                "inner IP MTU {} is below the Windows minimum {}; warn or refuse the connection",
                self.inner_ip_mtu, WINDOWS_MIN_IP_MTU
            ))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtuError {
    Zero,
    TooSmall {
        mode: Mode,
        wire_mtu: usize,
        min: usize,
    },
    TooLarge {
        wire_mtu: usize,
        max: usize,
    },
}

impl fmt::Display for MtuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MtuError::Zero => write!(
                f,
                "mtu: 0 is invalid; configure a numeric wire MTU shared by both peers (for example 1515)"
            ),
            MtuError::TooSmall {
                mode,
                wire_mtu,
                min,
            } => write!(
                f,
                "wire MTU {wire_mtu} is below the {min}-byte minimum for {mode} mode"
            ),
            MtuError::TooLarge { wire_mtu, max } => {
                write!(f, "wire MTU {wire_mtu} exceeds the maximum {max}")
            }
        }
    }
}

impl std::error::Error for MtuError {}

/// Derive the interface IP MTU and TCP MSS clamp from a numeric wire MTU.
pub fn from_wire(mode: Mode, wire_mtu: usize) -> Result<WireMtu, MtuError> {
    if wire_mtu == 0 {
        return Err(MtuError::Zero);
    }
    let min = mode.min_mtu();
    if wire_mtu < min {
        return Err(MtuError::TooSmall {
            mode,
            wire_mtu,
            min,
        });
    }
    if wire_mtu > MTU_MAX {
        return Err(MtuError::TooLarge {
            wire_mtu,
            max: MTU_MAX,
        });
    }
    let inner_ip_mtu = mode.max_payload(wire_mtu).saturating_sub(ETH_HEADER);
    Ok(WireMtu {
        wire_mtu,
        mode,
        inner_ip_mtu,
        mss_v4: inner_ip_mtu.saturating_sub(20 + TCP_HEADER),
        mss_v6: inner_ip_mtu.saturating_sub(40 + TCP_HEADER),
    })
}

/// Outer bytes needed for an encless packet with this numeric wire MTU.
pub fn encless_outer_needed(
    wire_mtu: usize,
    family: OuterFamily,
    transport: OuterTransport,
) -> usize {
    wire_mtu
        .saturating_add(ENCLESS_ENLARGE_SIZE)
        .saturating_add(family.header_len(transport))
}

/// Best-effort encless capacity warning. Returns `None` for non-encless modes
/// or when the underlay is large enough.
pub fn encless_capacity_warning(
    mode: Mode,
    wire_mtu: usize,
    underlay_mtu: usize,
    family: OuterFamily,
    transport: OuterTransport,
) -> Option<String> {
    if !mode.is_encless() {
        return None;
    }
    let needed = encless_outer_needed(wire_mtu, family, transport);
    if underlay_mtu < needed {
        Some(format!(
            "encless with mtu={wire_mtu} needs ~{needed} bytes of {}-{} outer path, but the \
             underlay is {underlay_mtu}; expect fragmentation or large-packet loss (wire contract \
             is unchanged)",
            family.label(),
            match transport {
                OuterTransport::Udp => "UDP",
                OuterTransport::Tcp => "TCP",
            }
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_1515_matches_a_standard_ethernet_mtu() {
        let mtu = from_wire(Mode::Plain, 1515).unwrap();
        assert_eq!(mtu.inner_ip_mtu, 1500);
        assert_eq!(mtu.mss_v4, 1460);
        assert_eq!(mtu.mss_v6, 1440);
        assert_eq!(mtu.max_frame_len(), 1514);
    }

    #[test]
    fn noise_1515_reserves_padding_and_tag() {
        let mtu = from_wire(Mode::Noise, 1515).unwrap();
        assert_eq!(mtu.inner_ip_mtu, 1476);
        assert_eq!(mtu.mss_v4, 1436);
        assert_eq!(mtu.mss_v6, 1416);
        assert_eq!(mtu.max_frame_len(), 1490);
    }

    #[test]
    fn encless_1515_values_and_expansion_warning() {
        let mtu = from_wire(Mode::Encless, 1515).unwrap();
        assert_eq!(mtu.inner_ip_mtu, 1492);
        assert_eq!(mtu.mss_v4, 1452);
        assert_eq!(mtu.mss_v6, 1432);
        assert_eq!(mtu.max_frame_len(), 1506);

        assert_eq!(ENCLESS_ENLARGE_SIZE, 4128);
        assert_eq!(
            encless_outer_needed(1515, OuterFamily::V4, OuterTransport::Udp),
            1515 + 4128 + 28
        );
        let warning = encless_capacity_warning(
            Mode::Encless,
            1515,
            1500,
            OuterFamily::V4,
            OuterTransport::Udp,
        )
        .expect("1515 encless cannot fit a 1500-byte underlay");
        assert!(warning.contains("~5671"));
        assert!(warning.contains("fragmentation"));

        assert!(encless_capacity_warning(
            Mode::Encless,
            1515,
            9000,
            OuterFamily::V4,
            OuterTransport::Tcp
        )
        .is_none());
        assert!(encless_capacity_warning(
            Mode::Plain,
            1515,
            1500,
            OuterFamily::V4,
            OuterTransport::Udp
        )
        .is_none());
    }

    #[test]
    fn zero_and_tiny_and_huge_mtus_are_rejected() {
        assert_eq!(from_wire(Mode::Plain, 0).unwrap_err(), MtuError::Zero);
        assert!(matches!(
            from_wire(Mode::Plain, 67).unwrap_err(),
            MtuError::TooSmall { .. }
        ));
        assert!(matches!(
            from_wire(Mode::Noise, 119).unwrap_err(),
            MtuError::TooSmall { .. }
        ));
        assert!(matches!(
            from_wire(Mode::Plain, MTU_MAX + 1).unwrap_err(),
            MtuError::TooLarge { .. }
        ));
    }

    #[test]
    fn small_inner_mtu_triggers_the_windows_warning() {
        let mtu = from_wire(Mode::Plain, 595).unwrap();
        assert_eq!(mtu.inner_ip_mtu, 580);
        assert!(mtu.windows_recommendation().is_none());

        let mtu = from_wire(Mode::Plain, 590).unwrap();
        assert_eq!(mtu.inner_ip_mtu, 575);
        assert!(mtu.windows_recommendation().unwrap().contains("below"));
    }

    #[test]
    fn log_line_records_the_contract() {
        let line = from_wire(Mode::Noise, 1515).unwrap().log_line();
        assert!(line.contains("wire=1515"));
        assert!(line.contains("inner_ip_mtu=1476"));
        assert!(line.contains("mss_v4=1436"));
        assert!(line.contains("mss_v6=1416"));
        assert!(line.contains("two-sided contract"));
    }

    #[test]
    fn mode_parsing_and_overheads() {
        assert_eq!("plain".parse::<Mode>().unwrap(), Mode::Plain);
        assert_eq!("noise".parse::<Mode>().unwrap(), Mode::Noise);
        assert_eq!("encless".parse::<Mode>().unwrap(), Mode::Encless);
        assert!("other".parse::<Mode>().is_err());
        assert_eq!(Mode::Plain.overhead(), 1);
        assert_eq!(Mode::Noise.overhead(), 25);
        assert_eq!(Mode::Encless.overhead(), 9);
        assert_eq!(Mode::Plain.min_mtu(), 68);
        assert_eq!(Mode::Noise.min_mtu(), 120);
    }
}
