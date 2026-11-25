//! Negative and boundary tests for CnW, AONT, encless and Poly1305.

use rustvpn_crypto::{aont, cnw, encless, poly1305};

const KEY: [u8; 32] = [0x33; 32];
const NONCE: [u8; 8] = [7u8; 8];

#[test]
fn cnw_roundtrip_across_batch_boundaries() {
    // 8-byte SIMD batches mixed with the scalar tail, plus empty input.
    for len in [0usize, 1, 7, 8, 9, 10, 15, 16, 17, 33, 64, 100] {
        let input: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
        let chaffed = cnw::chaff(&KEY, &NONCE, &input);
        assert_eq!(chaffed.len(), len * 256, "chaff len {len}");
        let out = cnw::winnow(&KEY, &NONCE, &chaffed).unwrap();
        assert_eq!(out, input, "winnow len {len}");
    }
}

#[test]
fn cnw_rejects_tampering_and_bad_lengths() {
    let input = vec![0x5au8; 16];
    let mut chaffed = cnw::chaff(&KEY, &NONCE, &input);
    chaffed[0] ^= 1;
    assert!(cnw::winnow(&KEY, &NONCE, &chaffed).is_err());

    // Not a multiple of the 256-byte block size.
    for len in [1usize, 100, 255, 257] {
        assert!(cnw::winnow(&KEY, &NONCE, &vec![0u8; len]).is_err());
    }
}

#[test]
fn aont_rejects_corruption_and_short_input() {
    let r = [9u8; 16];
    let data = vec![0x42u8; 200];
    let encoded = aont::encode(&r, &data).unwrap();
    assert_eq!(aont::decode(&encoded).unwrap(), data);

    let mut bad = encoded.clone();
    bad[0] ^= 1;
    assert!(aont::decode(&bad).is_err());

    assert!(aont::decode(&[0u8; 10]).is_err());
    assert!(aont::decode_parts(&[], &[]).is_err());
    assert!(aont::decode_parts(&[0u8; 16], &[0u8; 15]).is_err());
}

#[test]
fn encless_rejects_corruption_and_short_input() {
    let r = [5u8; 16];
    for len in [0usize, 1, 128, 1506] {
        let data = vec![0x5au8; len];
        let encoded = encless::encode_with_r(&KEY, &NONCE, &r, &data).unwrap();
        assert_eq!(
            encless::decode(&KEY, &NONCE, &encoded).unwrap(),
            data,
            "len {len}"
        );

        let mut bad = encoded.clone();
        bad[0] ^= 1;
        assert!(encless::decode(&KEY, &NONCE, &bad).is_err(), "len {len}");
    }

    // Below MIN_ENCODED_SIZE and around it.
    for len in [0usize, 1, 4095, 4127, 4128] {
        assert!(encless::decode(&KEY, &NONCE, &vec![0u8; len]).is_err());
    }
}

#[test]
fn poly1305_empty_and_tamper() {
    let key = [7u8; 32];
    let tag = poly1305::tag(&key, &[]);
    assert!(poly1305::verify(&key, &[], &tag));

    let mut bad = tag;
    bad[0] ^= 1;
    assert!(!poly1305::verify(&key, &[], &bad));

    let msg = vec![0x5au8; 798];
    let tag = poly1305::tag(&key, &msg);
    assert!(poly1305::verify(&key, &msg, &tag));
    let mut tampered = msg;
    tampered[400] ^= 1;
    assert!(!poly1305::verify(&key, &tampered, &tag));
}
