//! Salsa20 / XSalsa20 wrappers matching `golang.org/x/crypto/salsa20`.
//!
//! On x86-64 with AVX2 the Salsa20 core runs eight blocks (or eight
//! independent streams) at once; otherwise the RustCrypto scalar backend
//! is used.  Both produce identical keystreams.

use salsa20::cipher::generic_array::GenericArray;
use salsa20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use salsa20::Salsa20;

use zeroize::Zeroizing;

use crate::salsa_simd;

fn scalar_salsa20_xor(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8], offset: usize) {
    let mut cipher = Salsa20::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );
    if offset != 0 {
        cipher.seek(offset as u64);
    }
    cipher.apply_keystream(data);
}

pub fn salsa20_xor(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= 512 && std::is_x86_feature_detected!("avx2") {
            let consumed = unsafe { salsa_simd::xor_blocks(key, nonce, data) };
            if consumed < data.len() {
                scalar_salsa20_xor(key, nonce, &mut data[consumed..], consumed);
            }
            return;
        }
    }
    scalar_salsa20_xor(key, nonce, data, 0);
}

pub fn xsalsa20_xor(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) {
    // XSalsa20 = HSalsa20(first 16 nonce bytes) + Salsa20(last 8 bytes).
    let mut hnonce = [0u8; 16];
    hnonce.copy_from_slice(&nonce[..16]);
    let subkey = Zeroizing::new(hsalsa20(key, &hnonce));
    let mut n8 = [0u8; 8];
    n8.copy_from_slice(&nonce[16..24]);
    salsa20_xor(&subkey, &n8, data);
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

/// Generate eight independent 512-byte keystreams for eight 8-byte
/// nonces under one key (used by cnw's SIMD batch path).
pub(crate) fn keystream8_512(key: &[u8; 32], nonces: &[[u8; 8]; 8]) -> [[u8; 512]; 8] {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return unsafe { salsa_simd::keystream8_512(key, nonces) };
        }
    }
    let mut out = [[0u8; 512]; 8];
    for (i, nonce) in nonces.iter().enumerate() {
        out[i].copy_from_slice(&salsa20_keystream(key, nonce, 512));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use salsa20::XSalsa20;

    fn scalar_reference(key: &[u8; 32], nonce: &[u8; 8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut cipher = Salsa20::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(nonce),
        );
        cipher.apply_keystream(&mut out);
        out
    }

    #[test]
    fn simd_stream_matches_scalar() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 8];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(9).wrapping_add(1);
        }
        nonce.copy_from_slice(&key[..8]);
        for len in [0usize, 1, 63, 64, 65, 511, 512, 513, 1000, 2048, 4096] {
            let want = scalar_reference(&key, &nonce, len);
            let got = salsa20_keystream(&key, &nonce, len);
            assert_eq!(got, want, "len {len}");
        }
    }

    #[test]
    fn simd_multi_stream_matches_scalar() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(3);
        }
        let mut nonces = [[0u8; 8]; 8];
        for (i, n) in nonces.iter_mut().enumerate() {
            n.copy_from_slice(&[i as u8, 0, 0, 0, 0, 0, 0, 0]);
        }
        let got = keystream8_512(&key, &nonces);
        for (i, nonce) in nonces.iter().enumerate() {
            assert_eq!(
                got[i].as_slice(),
                scalar_reference(&key, nonce, 512).as_slice()
            );
        }
    }

    #[test]
    fn xsalsa_matches_crate() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(7);
        }
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(4).wrapping_add(2);
        }
        let data = vec![0x5au8; 2000];
        let mut want = data.clone();
        let mut cipher = XSalsa20::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce),
        );
        cipher.apply_keystream(&mut want);
        let mut got = data;
        xsalsa20_xor(&key, &nonce, &mut got);
        assert_eq!(got, want);
    }
}
