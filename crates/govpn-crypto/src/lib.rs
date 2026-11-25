//! Wire-compatible cryptographic primitives for GoVPN 5.7.
//!
//! This crate intentionally implements the *existing* protocol algorithms:
//! Salsa20/XSalsa20, Poly1305, XTEA-as-PRP, chaffing-and-winnowing, the
//! SAEP/OAEP-style AONT, Argon2d v1.3 and Ed25519.  It is not a new
//! protocol.

pub mod aont;
pub mod blake2b;
pub mod cnw;
pub mod egd;
pub mod elligator;
pub mod encless;
mod field;
pub mod poly1305;
pub mod salsa;
pub mod verifier;
pub mod xtea;

pub use thiserror::Error;

pub const NONCE_SIZE: usize = 8;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const PAD_BYTE: u8 = 0x80;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("input too short")]
    TooShort,
    #[error("input too large")]
    TooLarge,
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid authenticator")]
    InvalidAuthenticator,
    #[error("random source failed")]
    Random,
    #[error("argon2: {0}")]
    Argon2(String),
    #[error("invalid verifier")]
    InvalidVerifier,
    #[error("invalid base64")]
    Base64,
}
