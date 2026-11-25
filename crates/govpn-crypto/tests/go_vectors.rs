use std::fs;
use std::path::Path;

use govpn_crypto::{aont, blake2b, cnw, elligator, poly1305, salsa, verifier, xtea::Xtea};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    xtea: Vec<XteaVec>,
    salsa20: Vec<StreamVec>,
    xsalsa20: Vec<StreamVec>,
    poly1305: Vec<PolyVec>,
    blake2b256: Vec<HashVec>,
    cnw: Vec<CnwVec>,
    aont: Vec<AontVec>,
    verifier: Vec<VerifierVec>,
    elligator: Vec<ElligatorVec>,
    elligator_flags: Vec<ElligatorFlagVec>,
    #[allow(dead_code)]
    transport: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct XteaVec {
    key: String,
    plain: String,
    cipher: String,
}

#[derive(Deserialize)]
struct StreamVec {
    key: String,
    nonce: String,
    input: String,
    output: String,
}

#[derive(Deserialize)]
struct PolyVec {
    key: String,
    msg: String,
    tag: String,
}

#[derive(Deserialize)]
struct HashVec {
    input: String,
    digest: String,
}

#[derive(Deserialize)]
struct CnwVec {
    key: String,
    nonce: String,
    input: String,
    chaff: String,
    winnow: String,
}

#[derive(Deserialize)]
struct AontVec {
    r: String,
    input: String,
    encoded: String,
}

#[derive(Deserialize)]
struct ElligatorFlagVec {
    private: String,
    ok: bool,
    public: Option<String>,
    repr: Option<String>,
}

#[derive(Deserialize)]
struct ElligatorVec {
    private: String,
    public: String,
    repr: String,
}

#[derive(Deserialize)]
struct VerifierVec {
    password: String,
    id: String,
    m: u32,
    t: u32,
    p: u32,
    seed: String,
    public: String,
    short_form: String,
    long_form: String,
}

fn vectors() -> Vectors {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/go_vectors.json");
    let data = fs::read_to_string(path).expect("read go_vectors.json");
    serde_json::from_str(&data).expect("parse go_vectors.json")
}

fn bytes<const N: usize>(hex: &str, what: &str) -> [u8; N] {
    let raw = hex::decode(hex).unwrap_or_else(|_| panic!("bad hex in {what}"));
    raw.try_into()
        .unwrap_or_else(|_| panic!("bad length in {what}"))
}

#[test]
fn xtea_matches_go() {
    for v in vectors().xtea {
        let key = bytes::<16>(&v.key, "xtea key");
        let mut block = bytes::<8>(&v.plain, "xtea plain");
        let expected = bytes::<8>(&v.cipher, "xtea cipher");
        let cipher = Xtea::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, bytes::<8>(&v.plain, "xtea plain"));
    }
}

#[test]
fn salsa_matches_go() {
    for v in vectors().salsa20 {
        let key = bytes::<32>(&v.key, "salsa key");
        let nonce = bytes::<8>(&v.nonce, "salsa nonce");
        let input = hex::decode(&v.input).unwrap();
        let expected = hex::decode(&v.output).unwrap();
        let mut data = input;
        salsa::salsa20_xor(&key, &nonce, &mut data);
        assert_eq!(data, expected);
    }
}

#[test]
fn xsalsa_matches_go() {
    for v in vectors().xsalsa20 {
        let key = bytes::<32>(&v.key, "xsalsa key");
        let nonce = bytes::<24>(&v.nonce, "xsalsa nonce");
        let input = hex::decode(&v.input).unwrap();
        let expected = hex::decode(&v.output).unwrap();
        let mut data = input;
        salsa::xsalsa20_xor(&key, &nonce, &mut data);
        assert_eq!(data, expected);
    }
}

#[test]
fn poly1305_matches_go() {
    for v in vectors().poly1305 {
        let key = bytes::<32>(&v.key, "poly key");
        let msg = hex::decode(&v.msg).unwrap();
        let expected = bytes::<16>(&v.tag, "poly tag");
        assert_eq!(poly1305::tag(&key, &msg), expected);
        assert!(poly1305::verify(&key, &msg, &expected));
    }
}

#[test]
fn blake2b_matches_go() {
    for v in vectors().blake2b256 {
        let input = hex::decode(&v.input).unwrap();
        assert_eq!(blake2b::hash(&input), bytes::<32>(&v.digest, "blake2b"));
    }
}

#[test]
fn cnw_matches_go() {
    for v in vectors().cnw {
        let key = bytes::<32>(&v.key, "cnw key");
        let nonce = bytes::<8>(&v.nonce, "cnw nonce");
        let input = hex::decode(&v.input).unwrap();
        let expected_chaff = hex::decode(&v.chaff).unwrap();
        let expected_winnow = hex::decode(&v.winnow).unwrap();
        let chaffed = cnw::chaff(&key, &nonce, &input);
        assert_eq!(chaffed, expected_chaff);
        let winnowed = cnw::winnow(&key, &nonce, &chaffed).unwrap();
        assert_eq!(winnowed, expected_winnow);
        assert_eq!(winnowed, input);
    }
}

#[test]
fn aont_matches_go() {
    for v in vectors().aont {
        let r = bytes::<16>(&v.r, "aont r");
        let input = hex::decode(&v.input).unwrap();
        let expected = hex::decode(&v.encoded).unwrap();
        assert_eq!(aont::encode(&r, &input).unwrap(), expected);
        assert_eq!(aont::decode(&expected).unwrap(), input);
        assert_eq!(
            aont::decode_parts(&expected[..aont::R_SIZE], &expected[aont::R_SIZE..]).unwrap(),
            input
        );
    }
}

#[test]
fn elligator_matches_go() {
    for v in vectors().elligator {
        let private = bytes::<32>(&v.private, "elligator private");
        let public = bytes::<32>(&v.public, "elligator public");
        let repr = bytes::<32>(&v.repr, "elligator repr");
        let (got_public, got_repr) =
            elligator::scalar_base_mult(&private).expect("Go vector must be representable");
        assert_eq!(got_public, public, "private {}", hex::encode(private));
        assert_eq!(got_repr, repr, "private {}", hex::encode(private));
        assert_eq!(
            elligator::representative_to_public_key(&repr),
            public,
            "public recovery"
        );
    }
}

#[test]
fn elligator_representability_matches_go() {
    for v in vectors().elligator_flags {
        let private = bytes::<32>(&v.private, "elligator private");
        let got = elligator::scalar_base_mult(&private);
        assert_eq!(got.is_some(), v.ok, "private {}", v.private);
        if let Some((got_public, got_repr)) = got {
            assert_eq!(
                got_public,
                bytes::<32>(v.public.as_ref().unwrap(), "flag public"),
                "private {}",
                v.private
            );
            assert_eq!(
                got_repr,
                bytes::<32>(v.repr.as_ref().unwrap(), "flag repr"),
                "private {}",
                v.private
            );
        }
    }
}

#[test]
fn verifier_matches_go() {
    for v in vectors().verifier {
        let id = bytes::<16>(&v.id, "verifier id");
        let mut ver = verifier::Verifier::new(v.m, v.t, v.p, id);
        let key = ver.password_apply(&v.password).unwrap();
        assert_eq!(key.to_bytes(), bytes::<32>(&v.seed, "verifier seed"));
        assert_eq!(
            key.verifying_key().to_bytes(),
            bytes::<32>(&v.public, "verifier public")
        );
        assert_eq!(ver.short_form(), v.short_form);
        assert_eq!(ver.long_form().unwrap(), v.long_form);
        let parsed = verifier::Verifier::from_string(&v.long_form).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(
            parsed.public,
            Some(bytes::<32>(&v.public, "verifier public"))
        );
    }
}
