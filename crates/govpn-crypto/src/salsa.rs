//! Salsa20 and XSalsa20 wrappers matching `golang.org/x/crypto/salsa20`.
//!
//! GoVPN uses Salsa20 with an 8-byte nonce for the transport/AONT and
//! XSalsa20 (24-byte nonce) for chaffing keys.

use salsa20::cipher::generic_array::GenericArray;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::{Salsa20, XSalsa20};

pub fn salsa20_xor(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8]) {
    let mut cipher = Salsa20::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );
    cipher.apply_keystream(data);
}

pub fn xsalsa20_xor(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) {
    let mut cipher = XSalsa20::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );
    cipher.apply_keystream(data);
}

pub fn salsa20_keystream(key: &[u8; 32], nonce: &[u8; 8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    salsa20_xor(key, nonce, &mut out);
    out
}

pub fn xsalsa20_keystream(key: &[u8; 32], nonce: &[u8; 24], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    xsalsa20_xor(key, nonce, &mut out);
    out
}

/// HSalsa20 with the Salsa20/20 core, as used to derive an XSalsa20 subkey.
pub fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let subkey = salsa20::hsalsa::<salsa20::cipher::consts::U10>(
        GenericArray::from_slice(key),
        GenericArray::from_slice(input),
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(subkey.as_slice());
    out
}
