//! Negative and boundary tests for the replay window, transport codec, and
//! handshake state machine.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use rustvpn_proto::transport::ReplayWindow;
use rustvpn_proto::{
    ClientHandshake, ClientOutput, HandshakeConfig, Mode, Ordering, ServerHandshake, ServerOutput,
    Session, TransportError,
};

const KEY: [u8; 32] = [0x42; 32];
const ID: [u8; 16] = [0x11; 16];

fn sessions() -> (Session, Session) {
    (Session::new(KEY, true), Session::new(KEY, false))
}

fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    SigningKey::from_bytes(&seed)
}

fn configs() -> (HandshakeConfig, HandshakeConfig) {
    let sk = signing_key();
    let vk = sk.verifying_key().to_bytes();
    (
        HandshakeConfig::client(ID, 1515, false, false, 0, sk),
        HandshakeConfig::server(ID, 1515, false, false, 0, vk),
    )
}

#[test]
fn replay_window_boundaries() {
    let mut w = ReplayWindow::default();
    assert!(w.accept(1000));
    assert!(!w.accept(1000), "duplicate rejected");
    assert!(w.accept(1001), "newer accepted");
    assert!(w.accept(999), "older inside window accepted");
    assert!(!w.accept(999), "duplicate inside window rejected");
    // Span is 256: diff 256 is in-window, 257 is out.
    assert!(w.accept(1001 - 256));
    assert!(!w.accept(1001 - 257));
}

#[test]
fn replay_window_jump_resets_bitmap() {
    let mut w = ReplayWindow::default();
    assert!(w.accept(10));
    assert!(w.accept(20));
    assert!(w.accept(5000), "far-ahead jump accepted");
    assert!(!w.accept(4743), "just outside the new window");
    assert!(w.accept(4744), "boundary of the new window");
}

#[test]
fn exact_ordering_rejects_reorder() {
    let (mut client, mut server) = sessions();
    let a = client.encode(b"a", Mode::Plain, 1515).unwrap();
    let b = client.encode(b"b", Mode::Plain, 1515).unwrap();
    // Server expects the first serial; feeding the second one is reordered.
    assert_eq!(
        server.decode(&b, Mode::Plain, 1515, Ordering::Exact),
        Err(TransportError::Replay)
    );
    assert_eq!(
        server
            .decode(&a, Mode::Plain, 1515, Ordering::Exact)
            .unwrap(),
        b"a"
    );
    assert_eq!(
        server
            .decode(&b, Mode::Plain, 1515, Ordering::Exact)
            .unwrap(),
        b"b"
    );
}

#[test]
fn transport_rejects_truncation_and_tampering() {
    let (mut client, _) = sessions();
    let wire = client.encode(b"hello", Mode::Plain, 1515).unwrap();

    // Truncated packet.
    let mut server = Session::new(KEY, false);
    assert!(server
        .decode(
            &wire[..wire.len() - 1],
            Mode::Plain,
            1515,
            Ordering::Reorderable
        )
        .is_err());

    // Flipped tag.
    let mut bad = wire.clone();
    bad[0] ^= 1;
    let mut server = Session::new(KEY, false);
    assert_eq!(
        server.decode(&bad, Mode::Plain, 1515, Ordering::Reorderable),
        Err(TransportError::Authenticator)
    );

    // Flipped trailing nonce.
    let mut bad = wire.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let mut server = Session::new(KEY, false);
    assert_eq!(
        server.decode(&bad, Mode::Plain, 1515, Ordering::Reorderable),
        Err(TransportError::Authenticator)
    );
}

#[test]
fn transport_rejects_wrong_padded_length_and_oversize() {
    let (mut client, _) = sessions();
    let wire = client
        .encode(
            &vec![0x5a; Mode::Noise.max_payload(1515)],
            Mode::Noise,
            1515,
        )
        .unwrap();
    let mut server = Session::new(KEY, false);
    assert_eq!(
        server.decode(
            &wire[..wire.len() - 1],
            Mode::Noise,
            1515,
            Ordering::Reorderable
        ),
        Err(TransportError::TooLarge)
    );

    let mut client = Session::new(KEY, true);
    assert_eq!(
        client.encode(&vec![0u8; 1515], Mode::Plain, 1515),
        Err(TransportError::TooLarge)
    );
}

#[test]
fn transport_replay_rejected() {
    let (mut client, mut server) = sessions();
    let wire = client.encode(b"x", Mode::Plain, 1515).unwrap();
    assert!(server
        .decode(&wire, Mode::Plain, 1515, Ordering::Reorderable)
        .is_ok());
    assert_eq!(
        server.decode(&wire, Mode::Plain, 1515, Ordering::Reorderable),
        Err(TransportError::Replay)
    );
}

#[test]
fn handshake_rejects_truncated_messages() {
    let (cc, sc) = configs();
    let mut rng = OsRng;
    let (mut client, msg1) = ClientHandshake::start(cc.clone(), &mut rng).unwrap();
    let mut server = ServerHandshake::new(sc.clone());

    assert!(server.server(&msg1[..msg1.len() - 1], &mut rng).is_err());

    let msg2 = match server.server(&msg1, &mut rng).unwrap() {
        ServerOutput::Reply(m) => m,
        _ => panic!("expected reply"),
    };
    assert!(client.client(&msg2[..msg2.len() - 1], &mut rng).is_err());

    let msg3 = match client.client(&msg2, &mut rng).unwrap() {
        ClientOutput::Reply(m) => m,
        _ => panic!("expected reply"),
    };
    // A duplicate msg1 at stage 2 must not be accepted as msg3.
    assert!(server.server(&msg1, &mut rng).is_err());

    // Flipping the signature (plaintext bytes 48..112) must be rejected.
    let mut bad = msg3.clone();
    bad[50] ^= 1;
    assert!(server.server(&bad, &mut rng).is_err());

    // The untouched msg3 still completes (the failed attempt did not advance).
    match server.server(&msg3, &mut rng).unwrap() {
        ServerOutput::Complete { .. } => {}
        _ => panic!("expected completion"),
    }
}

#[test]
fn handshake_rejects_wrong_stage() {
    let (cc, _) = configs();
    let mut rng = OsRng;
    let (mut client, _msg1) = ClientHandshake::start(cc, &mut rng).unwrap();
    // Stage 0 expects msg2; a short/garbage message is rejected.
    assert!(client.client(&[0u8; 8], &mut rng).is_err());
}
