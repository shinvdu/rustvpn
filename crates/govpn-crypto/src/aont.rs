//! All-Or-Nothing-Transform used by encless mode.
//!
//! `PKG = P1 || P2`, `P1 = Salsa20(key=r, nonce=0) XOR (M || BLAKE2b(r||M))`,
//! `P2 = BLAKE2b(P1) XOR r`.

use subtle::ConstantTimeEq;

use crate::blake2b::{hash, hash_parts, Hasher};
use crate::salsa::salsa20_xor;
use crate::CryptoError;

pub const H_SIZE: usize = 32;
pub const R_SIZE: usize = 16;

pub fn encode(r: &[u8; R_SIZE], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; input.len() + H_SIZE + R_SIZE];
    out[..input.len()].copy_from_slice(input);

    let checksum = {
        let mut h = Hasher::new();
        h.update(r);
        h.update(input);
        h.finalize()
    };
    out[input.len()..input.len() + H_SIZE].copy_from_slice(&checksum);

    let mut salsa_key = [0u8; 32];
    salsa_key[..R_SIZE].copy_from_slice(r);
    let zero_nonce = [0u8; 8];
    salsa20_xor(&salsa_key, &zero_nonce, &mut out);

    let h = hash(&out[..input.len() + H_SIZE]);
    for i in 0..R_SIZE {
        out[input.len() + H_SIZE + i] = h[i] ^ r[i];
    }
    Ok(out)
}

pub fn decode(input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if input.len() < H_SIZE + R_SIZE {
        return Err(CryptoError::TooShort);
    }
    let mut salsa_key = [0u8; 32];
    let h = hash(&input[..input.len() - R_SIZE]);
    let tail = &input[input.len() - R_SIZE..];
    for i in 0..R_SIZE {
        salsa_key[i] = h[i] ^ tail[i];
    }
    let zero_nonce = [0u8; 8];
    let mut out = input[..input.len() - R_SIZE].to_vec();
    salsa20_xor(&salsa_key, &zero_nonce, &mut out);

    let expected = hash_parts(&[&salsa_key[..R_SIZE], &out[..out.len() - H_SIZE]]);
    if expected.ct_eq(&out[out.len() - H_SIZE..]).unwrap_u8() != 1 {
        return Err(CryptoError::InvalidChecksum);
    }
    out.truncate(out.len() - H_SIZE);
    Ok(out)
}

/// Decode a package split as `first || second` without concatenating the
/// two parts first.  `first` is the recovered 16-byte `r`, `second` is
/// the rest of the AONT package.
pub fn decode_parts(first: &[u8], second: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if first.len() + second.len() < H_SIZE + R_SIZE || second.len() < R_SIZE {
        return Err(CryptoError::TooShort);
    }
    let mut salsa_key = [0u8; 32];
    let digest = hash_parts(&[first, &second[..second.len() - R_SIZE]]);
    let tail = &second[second.len() - R_SIZE..];
    for i in 0..R_SIZE {
        salsa_key[i] = digest[i] ^ tail[i];
    }
    let zero_nonce = [0u8; 8];
    let mut out = Vec::with_capacity(first.len() + second.len() - R_SIZE);
    out.extend_from_slice(first);
    out.extend_from_slice(&second[..second.len() - R_SIZE]);
    salsa20_xor(&salsa_key, &zero_nonce, &mut out);

    let expected = hash_parts(&[&salsa_key[..R_SIZE], &out[..out.len() - H_SIZE]]);
    if expected.ct_eq(&out[out.len() - H_SIZE..]).unwrap_u8() != 1 {
        return Err(CryptoError::InvalidChecksum);
    }
    out.truncate(out.len() - H_SIZE);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r = [5u8; R_SIZE];
        let input = b"hello world, this is AONT";
        let encoded = encode(&r, input).unwrap();
        assert_eq!(decode(&encoded).unwrap(), input);
        assert_eq!(
            decode_parts(&encoded[..R_SIZE], &encoded[R_SIZE..]).unwrap(),
            input
        );
    }
}
