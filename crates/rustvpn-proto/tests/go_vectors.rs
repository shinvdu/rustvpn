use std::fs;
use std::path::Path;

use rand_core::RngCore;
use rustvpn_crypto::{blake2b, cnw, encless};
use rustvpn_proto::{
    ClientHandshake, ClientOutput, HandshakeConfig, Mode, Ordering, ServerHandshake, ServerOutput,
    Session, ENCLESS_ENLARGE_SIZE,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Vectors {
    handshake: Vec<HandshakeVec>,
    transport: Vec<TransportVec>,
}

#[derive(Deserialize)]
struct HandshakeVec {
    mode: String,
    seed: u64,
    mtu: usize,
    password: String,
    id: String,
    m: u32,
    t: u32,
    p: u32,
    seed_priv: String,
    public: String,
    messages: Vec<String>,
    key: String,
    rand_pos: Vec<usize>,
}

#[derive(Deserialize)]
struct TransportVec {
    mode: String,
    side: String,
    mtu: usize,
    key: String,
    payload: String,
    wire: String,
    serial: u64,
}

fn vectors() -> Vectors {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/go_vectors.json");
    let data = fs::read_to_string(path).expect("read go_vectors.json");
    serde_json::from_str(&data).expect("parse go_vectors.json")
}

fn mode(name: &str) -> Mode {
    match name {
        "plain" => Mode::Plain,
        "noise" => Mode::Noise,
        "encless" => Mode::Encless,
        other => panic!("unknown mode {other}"),
    }
}

struct DetRand {
    seed: u64,
    counter: u64,
    block: [u8; 32],
    pos: usize,
    consumed: usize,
}

impl DetRand {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0u8; 32],
            pos: 32,
            consumed: 0,
        }
    }
}

impl RngCore for DetRand {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.consumed += dest.len();
        let mut off = 0;
        while off < dest.len() {
            if self.pos == 32 {
                let mut h = Sha256::new();
                h.update(self.seed.to_be_bytes());
                h.update(self.counter.to_be_bytes());
                self.block.copy_from_slice(&h.finalize());
                self.pos = 0;
                self.counter += 1;
            }
            let n = (32 - self.pos).min(dest.len() - off);
            dest[off..off + n].copy_from_slice(&self.block[self.pos..self.pos + n]);
            self.pos += n;
            off += n;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn assert_bytes(label: &str, got: &[u8], want: &[u8]) {
    if got == want {
        return;
    }
    let pos = got
        .iter()
        .zip(want)
        .position(|(a, b)| a != b)
        .unwrap_or(got.len().min(want.len()));
    let lo = pos.saturating_sub(8);
    let hi = (pos + 8).min(got.len().max(want.len()));
    panic!(
        "{label}: len got={} want={}, first diff at {pos}; got[{lo}..{hi}]={:02x?} want={:02x?}",
        got.len(),
        want.len(),
        &got[lo.min(got.len())..hi.min(got.len())],
        &want[lo.min(want.len())..hi.min(want.len())],
    );
}

fn rnonce_next(r: &[u8; 8], count: u64) -> [u8; 8] {
    let mut current = 0u64;
    let mut shift = 0u32;
    let mut ok = false;
    for &b in r {
        if b < 0x80 {
            current |= (b as u64) << shift;
            ok = true;
            break;
        }
        current |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    let value = if ok {
        current.wrapping_add(count)
    } else {
        count
    };
    let mut out = [0u8; 8];
    let mut x = value;
    let mut i = 0;
    while x >= 0x80 && i < 8 {
        out[i] = (x as u8) | 0x80;
        x >>= 7;
        i += 1;
    }
    out[i] = x as u8;
    out
}

fn key(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn handshake_matches_go() {
    for v in vectors().handshake {
        let m = mode(&v.mode);
        let id: [u8; 16] = hex::decode(&v.id).unwrap().try_into().unwrap();
        let expected_public = key(&v.public);
        let seed_priv = key(&v.seed_priv);

        let mut verifier = rustvpn_crypto::verifier::Verifier::new(v.m, v.t, v.p, id);
        let signing_key = verifier.password_apply(&v.password).unwrap();
        assert_eq!(signing_key.to_bytes(), seed_priv);
        assert_eq!(signing_key.verifying_key().to_bytes(), expected_public);

        let client_cfg = HandshakeConfig::client(
            id,
            v.mtu,
            m != Mode::Plain,
            m == Mode::Encless,
            0,
            signing_key,
        );
        let server_cfg = HandshakeConfig::server(
            id,
            v.mtu,
            m != Mode::Plain,
            m == Mode::Encless,
            0,
            expected_public,
        );

        let mut rng = DetRand::new(v.seed);
        let (mut client, msg1) = ClientHandshake::start(client_cfg, &mut rng).unwrap();
        assert_eq!(rng.consumed, v.rand_pos[0], "{} rand after start", v.mode);
        assert_bytes(
            &format!("{} msg1", v.mode),
            &msg1,
            &hex::decode(&v.messages[0]).unwrap(),
        );

        let mut server = ServerHandshake::new(server_cfg);
        let expected_msg2 = hex::decode(&v.messages[1]).unwrap();
        let msg2 = match server.server(&msg1, &mut rng).unwrap() {
            ServerOutput::Reply(reply) => reply,
            _ => panic!("server completed too early"),
        };
        if m == Mode::Encless {
            let e = ENCLESS_ENLARGE_SIZE + v.mtu;
            let dsa = blake2b::hash(&expected_public);
            let r: [u8; 8] = msg1[..8].try_into().unwrap();
            let nonce1 = rnonce_next(&r, 1);
            let go_plain = encless::decode(&dsa, &nonce1, &expected_msg2[..e]).unwrap();
            let rust_plain = encless::decode(&dsa, &nonce1, &msg2[..e]).unwrap();
            assert_bytes("encless encPub plaintext", &rust_plain, &go_plain);
            let go_hdr = cnw::winnow(&dsa, &nonce1, &expected_msg2[..4096]).unwrap();
            let rust_hdr = cnw::winnow(&dsa, &nonce1, &msg2[..4096]).unwrap();
            assert_bytes("encless encPub AONT header", &rust_hdr, &go_hdr);
        }
        assert_eq!(rng.consumed, v.rand_pos[1], "{} rand after server1", v.mode);
        assert_bytes(
            &format!("{} msg2", v.mode),
            &msg2,
            &hex::decode(&v.messages[1]).unwrap(),
        );

        let msg3 = match client.client(&msg2, &mut rng).unwrap() {
            ClientOutput::Reply(reply) => reply,
            _ => panic!("client completed too early"),
        };
        assert_eq!(rng.consumed, v.rand_pos[2], "{} rand after client2", v.mode);
        assert_bytes(
            &format!("{} msg3", v.mode),
            &msg3,
            &hex::decode(&v.messages[2]).unwrap(),
        );

        let (msg4, server_key) = match server.server(&msg3, &mut rng).unwrap() {
            ServerOutput::Complete { reply, session_key } => (reply, session_key),
            _ => panic!("server did not complete"),
        };
        assert_eq!(rng.consumed, v.rand_pos[3], "{} rand after server3", v.mode);
        assert_bytes(
            &format!("{} msg4", v.mode),
            &msg4,
            &hex::decode(&v.messages[3]).unwrap(),
        );
        assert_eq!(server_key, key(&v.key), "{} server key", v.mode);

        let client_key = match client.client(&msg4, &mut rng).unwrap() {
            ClientOutput::Complete(session_key) => session_key,
            _ => panic!("client did not complete"),
        };
        assert_eq!(client_key, key(&v.key), "{} client key", v.mode);
        assert_eq!(rng.consumed, v.rand_pos[4], "{} rand after client4", v.mode);
    }
}

#[test]
fn transport_decode_matches_go() {
    for v in vectors().transport {
        let m = mode(&v.mode);
        let wire = hex::decode(&v.wire).unwrap();
        let payload = hex::decode(&v.payload).unwrap();
        // The receiving side is the opposite of the sender.
        let receiver_is_client = v.side == "server";
        let mut session = Session::new(key(&v.key), receiver_is_client);
        let decoded = session
            .decode(&wire, m, v.mtu, Ordering::Reorderable)
            .unwrap_or_else(|e| panic!("{} {} decode failed: {e}", v.mode, v.side));
        assert_eq!(decoded, payload, "{} {} payload", v.mode, v.side);
    }
}

#[test]
fn transport_encode_matches_go() {
    for v in vectors().transport {
        let m = mode(&v.mode);
        if m == Mode::Encless {
            // Encless encoding consumes fresh OS randomness for the AONT
            // nonce, so byte equality is not expected; decoding is
            // covered above and roundtrip below.
            continue;
        }
        let payload = hex::decode(&v.payload).unwrap();
        let expected = hex::decode(&v.wire).unwrap();
        let mut session = Session::new(key(&v.key), v.side == "client");
        assert_eq!(
            session.serial() + 2,
            v.serial,
            "{} {} serial",
            v.mode,
            v.side
        );
        let wire = session.encode(&payload, m, v.mtu).unwrap();
        assert_eq!(wire, expected, "{} {} wire", v.mode, v.side);
    }
}

#[test]
fn transport_encless_roundtrip() {
    let k = [42u8; 32];
    let mut client = Session::new(k, true);
    let mut server = Session::new(k, false);
    let payload = vec![0x77u8; Mode::Encless.max_payload(1515)];
    let wire = client.encode(&payload, Mode::Encless, 1515).unwrap();
    assert_eq!(
        server
            .decode(&wire, Mode::Encless, 1515, Ordering::Reorderable)
            .unwrap(),
        payload
    );
}
