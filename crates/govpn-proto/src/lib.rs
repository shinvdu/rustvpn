//! GoVPN 5.7 wire-compatible protocol primitives.
//!
//! This first milestone contains the transport packet codec (classic,
//! noise and encless modes) and the anti-replay window.  Handshake,
//! networking and TAP handling are the next milestones.

pub mod handshake;
pub mod transport;

pub use handshake::{
    ClientHandshake, ClientOutput, HandshakeConfig, HandshakeError, ServerHandshake, ServerOutput,
};
pub use transport::{Decoder, Encoder, Mode, Ordering, Session, TransportError};

pub const NONCE_SIZE: usize = 8;
pub const TAG_SIZE: usize = 16;
pub const S20_BS: usize = 64;
pub const PAD_BYTE: u8 = 0x80;
pub const MIN_PKT_LENGTH: usize = 1 + TAG_SIZE + NONCE_SIZE;
pub const MTU_DEFAULT: usize = 1500 + 14 + 1;
pub const MTU_MIN: usize = 68;
pub const MTU_MIN_NOISE: usize = 120;
pub const MTU_MAX: usize = 9000 + 14 + 1;
pub const MAX_BYTES_PER_KEY: u64 = 1 << 32;
pub const ENCLESS_ENLARGE_SIZE: usize = govpn_crypto::encless::ENCLESS_ENLARGE_SIZE;
