//! Encryptionless confidentiality-preserving encoding:
//! `CnW(AONT(data))`, with a fixed 4128-byte expansion.

use crate::aont;
use crate::cnw;
use crate::CryptoError;

/// `aont.HSize + aont.RSize * cnw.EnlargeFactor`
pub const ENCLESS_ENLARGE_SIZE: usize = aont::H_SIZE + aont::R_SIZE * cnw::ENLARGE_FACTOR;

/// The smallest valid decoded input: chaffed `r` plus the AONT checksum.
pub const MIN_ENCODED_SIZE: usize = aont::R_SIZE * cnw::ENLARGE_FACTOR + aont::H_SIZE;

/// Encode with a caller-provided AONT `r` (useful for deterministic tests).
pub fn encode_with_r(
    auth_key: &[u8; 32],
    nonce: &[u8; 8],
    r: &[u8; aont::R_SIZE],
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aonted = aont::encode(r, input)?;
    let chaff_len = aont::R_SIZE * cnw::ENLARGE_FACTOR;
    let mut out = Vec::with_capacity(chaff_len + aonted.len() - aont::R_SIZE);
    out.resize(chaff_len, 0);
    cnw::chaff_into(
        auth_key,
        nonce,
        &aonted[..aont::R_SIZE],
        &mut out[..chaff_len],
    );
    out.extend_from_slice(&aonted[aont::R_SIZE..]);
    Ok(out)
}

pub fn encode(auth_key: &[u8; 32], nonce: &[u8; 8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut r = [0u8; aont::R_SIZE];
    getrandom::getrandom(&mut r).map_err(|_| CryptoError::Random)?;
    encode_with_r(auth_key, nonce, &r, input)
}

pub fn decode(auth_key: &[u8; 32], nonce: &[u8; 8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if input.len() < MIN_ENCODED_SIZE {
        return Err(CryptoError::TooShort);
    }
    let chaff_len = aont::R_SIZE * cnw::ENLARGE_FACTOR;
    let mut winnowed = [0u8; aont::R_SIZE];
    cnw::winnow_into(auth_key, nonce, &input[..chaff_len], &mut winnowed)?;
    aont::decode_parts(&winnowed, &input[chaff_len..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let nonce = [1u8; 8];
        let input = vec![0x42u8; 1500];
        let encoded = encode(&key, &nonce, &input).unwrap();
        assert_eq!(encoded.len(), input.len() + ENCLESS_ENLARGE_SIZE);
        assert_eq!(decode(&key, &nonce, &encoded).unwrap(), input);
    }

    #[test]
    fn short_input_rejected() {
        let key = [0u8; 32];
        let nonce = [0u8; 8];
        for n in [0usize, 1, 4095, 4127] {
            assert!(decode(&key, &nonce, &vec![0u8; n]).is_err());
        }
    }
}
