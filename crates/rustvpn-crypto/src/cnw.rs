//! Chaffing-and-Winnowing (CnW), byte-identical to GoVPN 5.7.
//!
//! AONT headers are 16 bytes = 128 bits.  For every bit two Poly1305
//! one-byte MACs are emitted: one over `"0"` and one over `"1"`, in an
//! order determined by the secret bit.  Winnow checks both candidates.
//!
//! The one-byte Poly1305 is computed with the specialised formula:
//!
//! ```text
//! block("0") = 0x130, block("1") = 0x131   (Poly1305 final-block 0x01)
//! h0 = 0x130 * r mod 2^130-5
//! tag0 = low128(h0 + s)
//! tag1 = low128((h0 + r) mod 2^130-5 + s)
//! ```

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::salsa;
use crate::salsa::hsalsa20;
use crate::CryptoError;

pub const TAG_SIZE: usize = 16;
pub const ENLARGE_FACTOR: usize = 16 * TAG_SIZE;

fn mul64(a: u64, b: u64) -> (u64, u64) {
    let p = a as u128 * b as u128;
    ((p >> 64) as u64, p as u64)
}

fn add64(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let s = a as u128 + b as u128 + carry as u128;
    (s as u64, (s >> 64) as u64)
}

fn sub64(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let (d, b1) = a.overflowing_sub(b);
    let (d, b2) = d.overflowing_sub(borrow);
    (d, (b1 || b2) as u64)
}

fn sub_p(h0: u64, h1: u64, h2: u64) -> (u64, u64, u64) {
    const P0: u64 = 0xFFFF_FFFF_FFFF_FFFB;
    const P1: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    const P2: u64 = 3;
    let (d0, b) = sub64(h0, P0, 0);
    let (d1, b) = sub64(h1, P1, b);
    let (d2, b) = sub64(h2, P2, b);
    let mask = b.wrapping_sub(1);
    (
        h0 ^ ((h0 ^ d0) & mask),
        h1 ^ ((h1 ^ d1) & mask),
        h2 ^ ((h2 ^ d2) & mask),
    )
}

/// Returns the two tags for the one-byte messages `"0"` and `"1"` as
/// `(tag0_lo, tag0_hi, tag1_lo, tag1_hi)`, little-endian limbs.
pub(crate) fn tags1(key: &[u8]) -> (u64, u64, u64, u64) {
    debug_assert!(key.len() >= 32);
    let r0 = u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0FFF_FFFC_0FFF_FFFF;
    let r1 = u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0FFF_FFFC_0FFF_FFFC;
    let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
    let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

    let (hi, lo) = mul64(0x130, r0);
    let (p1hi, p1lo) = mul64(0x130, r1);
    let c0 = lo;
    let (c1, carry) = add64(hi, p1lo, 0);
    let c2 = p1hi.wrapping_add(carry);

    let k = c2 >> 2;
    let (h0, c1c) = add64(c0, 5 * k, 0);
    let (h1, c2c) = add64(c1, 0, c1c);
    let h2 = (c2 & 3) + c2c;
    let (h0, h1, h2) = sub_p(h0, h1, h2);

    let (t0lo, c) = add64(h0, s0, 0);
    let (t0hi, _) = add64(h1, s1, c);

    let (r0h, rc) = add64(h0, r0, 0);
    let (r1h, rc2) = add64(h1, r1, rc);
    let r2h = h2 + rc2;
    let (r0h, r1h, _) = sub_p(r0h, r1h, r2h);
    let (t1lo, c) = add64(r0h, s0, 0);
    let (t1hi, _) = add64(r1h, s1, c);

    (t0lo, t0hi, t1lo, t1hi)
}

#[inline]
fn ceq(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    ((x | x.wrapping_neg()) >> 63) ^ 1
}

#[inline]
fn ceq128(alo: u64, ahi: u64, blo: u64, bhi: u64) -> u64 {
    ceq(alo, blo) & ceq(ahi, bhi)
}

/// Derive the XSalsa20 subkey for a packet and the eight 64-byte key
/// blocks for input byte `n`.
fn keys_for(subkey: &[u8; 32], n: u64) -> [u8; 512] {
    let mut keys = [0u8; 512];
    let nonce = n.to_be_bytes();
    salsa::salsa20_xor(subkey, &nonce, &mut keys);
    keys
}

fn subkey_for(auth_key: &[u8; 32], nonce_prfx: &[u8; 8]) -> [u8; 32] {
    let mut hnonce = [0u8; 16];
    hnonce[..8].copy_from_slice(nonce_prfx);
    hsalsa20(auth_key, &hnonce)
}

/// Chaff `input`; output is `input.len() * 256` bytes.
pub fn chaff(auth_key: &[u8; 32], nonce_prfx: &[u8; 8], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len() * ENLARGE_FACTOR];
    chaff_into(auth_key, nonce_prfx, input, &mut out);
    out
}

pub fn chaff_into(auth_key: &[u8; 32], nonce_prfx: &[u8; 8], input: &[u8], out: &mut [u8]) {
    assert_eq!(out.len(), input.len() * ENLARGE_FACTOR);
    let subkey = Zeroizing::new(subkey_for(auth_key, nonce_prfx));
    let mut n = 0;
    while n + 8 <= input.len() {
        let mut nonces = [[0u8; 8]; 8];
        for (j, nonce) in nonces.iter_mut().enumerate() {
            nonce.copy_from_slice(&((n + j) as u64).to_be_bytes());
        }
        let mut streams = crate::salsa::keystream8_512(&subkey, &nonces);
        for lane in 0..8 {
            chaff_byte(&streams[lane], input[n + lane], n + lane, out);
        }
        for stream in &mut streams {
            stream.zeroize();
        }
        n += 8;
    }
    while n < input.len() {
        let mut keys = keys_for(&subkey, n as u64);
        chaff_byte(&keys, input[n], n, out);
        keys.zeroize();
        n += 1;
    }
}

fn chaff_byte(keys: &[u8; 512], b: u8, n: usize, out: &mut [u8]) {
    for i in 0..8 {
        let v = ((b >> i) & 1) as u64;
        let mask = 0u64.wrapping_sub(v);
        let (a0lo, a0hi, a1lo, a1hi) = tags1(&keys[64 * i..64 * i + 32]);
        let (b0lo, b0hi, b1lo, b1hi) = tags1(&keys[64 * i + 32..64 * i + 64]);
        let off = n * 256 + i * 32;
        let first_lo = a1lo ^ ((a0lo ^ a1lo) & mask);
        let first_hi = a1hi ^ ((a0hi ^ a1hi) & mask);
        let second_lo = b0lo ^ ((b0lo ^ b1lo) & mask);
        let second_hi = b0hi ^ ((b0hi ^ b1hi) & mask);
        out[off..off + 8].copy_from_slice(&first_lo.to_le_bytes());
        out[off + 8..off + 16].copy_from_slice(&first_hi.to_le_bytes());
        out[off + 16..off + 24].copy_from_slice(&second_lo.to_le_bytes());
        out[off + 24..off + 32].copy_from_slice(&second_hi.to_le_bytes());
    }
}

/// Winnow `input` (a multiple of 256 bytes) into one byte per 256-byte
/// block.
pub fn winnow(
    auth_key: &[u8; 32],
    nonce_prfx: &[u8; 8],
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if input.len() % ENLARGE_FACTOR != 0 {
        return Err(CryptoError::TooShort);
    }
    let mut out = vec![0u8; input.len() / ENLARGE_FACTOR];
    winnow_into(auth_key, nonce_prfx, input, &mut out)?;
    Ok(out)
}

pub fn winnow_into(
    auth_key: &[u8; 32],
    nonce_prfx: &[u8; 8],
    input: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if input.len() % ENLARGE_FACTOR != 0 || out.len() != input.len() / ENLARGE_FACTOR {
        return Err(CryptoError::TooShort);
    }
    let subkey = Zeroizing::new(subkey_for(auth_key, nonce_prfx));
    let mut n = 0;
    while n + 8 <= out.len() {
        let mut nonces = [[0u8; 8]; 8];
        for (j, nonce) in nonces.iter_mut().enumerate() {
            nonce.copy_from_slice(&((n + j) as u64).to_be_bytes());
        }
        let mut streams = crate::salsa::keystream8_512(&subkey, &nonces);
        for lane in 0..8 {
            match winnow_byte(&streams[lane], input, n + lane) {
                Ok(v) => out[n + lane] = v,
                Err(e) => {
                    for stream in &mut streams {
                        stream.zeroize();
                    }
                    return Err(e);
                }
            }
        }
        for stream in &mut streams {
            stream.zeroize();
        }
        n += 8;
    }
    while n < out.len() {
        let mut keys = keys_for(&subkey, n as u64);
        let result = winnow_byte(&keys, input, n);
        keys.zeroize();
        out[n] = result?;
        n += 1;
    }
    Ok(())
}

fn winnow_byte(keys: &[u8; 512], input: &[u8], n: usize) -> Result<u8, CryptoError> {
    let mut v = 0u8;
    for i in 0..8 {
        let (a0lo, a0hi, a1lo, a1hi) = tags1(&keys[64 * i..64 * i + 32]);
        let (b0lo, b0hi, b1lo, b1hi) = tags1(&keys[64 * i + 32..64 * i + 64]);
        let off = n * 256 + i * 32;
        let s1lo = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        let s1hi = u64::from_le_bytes(input[off + 8..off + 16].try_into().unwrap());
        let s2lo = u64::from_le_bytes(input[off + 16..off + 24].try_into().unwrap());
        let s2hi = u64::from_le_bytes(input[off + 24..off + 32].try_into().unwrap());
        let is01 = ceq128(s1lo, s1hi, a1lo, a1hi);
        let is00 = ceq128(s1lo, s1hi, a0lo, a0hi);
        let is11 = ceq128(s2lo, s2hi, b1lo, b1hi);
        let is10 = ceq128(s2lo, s2hi, b0lo, b0hi);
        if ((is01 & is10) | (is00 & is11)) == 0 {
            return Err(CryptoError::InvalidAuthenticator);
        }
        v |= (is11 as u8) << i;
    }
    Ok(v)
}

/// Constant-time comparison helper for tests.
pub fn ct_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [3u8; 32];
        let nonce = [9u8; 8];
        let input = b"0123456789abcdef";
        let chaffed = chaff(&key, &nonce, input);
        assert_eq!(chaffed.len(), input.len() * ENLARGE_FACTOR);
        let plain = winnow(&key, &nonce, &chaffed).unwrap();
        assert_eq!(plain, input);
    }

    #[test]
    fn rejects_corruption() {
        let key = [3u8; 32];
        let nonce = [9u8; 8];
        let input = b"0123456789abcdef";
        let mut chaffed = chaff(&key, &nonce, input);
        chaffed[17] ^= 0x80;
        assert!(winnow(&key, &nonce, &chaffed).is_err());
    }
}
