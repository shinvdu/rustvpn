//! Poly1305 one-time authenticator.

use poly1305::universal_hash::KeyInit;
use poly1305::{Key, Poly1305};
use subtle::ConstantTimeEq;

pub fn tag(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mac = Poly1305::new(Key::from_slice(key));
    let tag = mac.compute_unpadded(message);
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

pub fn verify(key: &[u8; 32], message: &[u8], expected: &[u8; 16]) -> bool {
    let actual = tag(key, message);
    bool::from(actual.ct_eq(expected))
}
