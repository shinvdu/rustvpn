//! GoVPN 5.7 transport packet codec.
//!
//! Classic packet layout:
//!
//! ```text
//! TAG(16) || SALSA20(KEY, PRP(SERIAL)) XOR (PAYLOAD || 0x80 || ZEROS) || PRP(SERIAL)(8)
//! ```
//!
//! The first 32 bytes of Salsa20 keystream are the Poly1305 one-time
//! key; bytes 32..64 are discarded.  The MAC covers the ciphertext,
//! including the trailing encrypted serial.
//!
//! Encless packets are:
//!
//! ```text
//! ENCLESS(AONT(PAYLOAD || 0x80 || ZEROS)) || PRP(SERIAL)(8)
//! ```

use std::fmt;

use rustvpn_crypto::encless::{self, ENCLESS_ENLARGE_SIZE, MIN_ENCODED_SIZE};
use rustvpn_crypto::{poly1305, salsa, xtea::Xtea};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{MIN_PKT_LENGTH, MTU_MIN, MTU_MIN_NOISE, NONCE_SIZE, PAD_BYTE, S20_BS, TAG_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// No padding, exact-length packets.
    Plain,
    /// Pad every outgoing packet to the configured MTU.
    Noise,
    /// Noise + encryptionless encoding.
    Encless,
}

impl Mode {
    /// Maximal payload for a given configured MTU.  Mirrors Go's
    /// `Peer.maxPayload()`; the extra bytes are the trailing nonce and,
    /// in classic mode, the Poly1305 tag plus pad byte.
    pub fn max_payload(self, mtu: usize) -> usize {
        match self {
            Mode::Plain => mtu.saturating_sub(1),
            Mode::Noise => mtu.saturating_sub(TAG_SIZE + NONCE_SIZE + 1),
            Mode::Encless => mtu.saturating_sub(NONCE_SIZE + 1),
        }
    }

    /// Smallest accepted configured MTU for this mode.
    pub fn min_mtu(self) -> usize {
        match self {
            Mode::Plain => MTU_MIN,
            Mode::Noise | Mode::Encless => MTU_MIN_NOISE,
        }
    }

    fn is_encless(self) -> bool {
        matches!(self, Mode::Encless)
    }

    fn padded(self) -> bool {
        matches!(self, Mode::Noise | Mode::Encless)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ordering {
    /// UDP: accept out-of-order serials within a 257-serial window.
    Reorderable,
    /// TCP: accept exactly the next expected serial.
    Exact,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("packet too short")]
    TooShort,
    #[error("payload too large for MTU")]
    TooLarge,
    #[error("invalid authenticator")]
    Authenticator,
    #[error("invalid padding")]
    Padding,
    #[error("replayed or out-of-window serial")]
    Replay,
    #[error("configured MTU is too small for this mode")]
    BadMtu,
}

/// The 257-bit sliding replay window used for UDP.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    bits: [u64; 5],
    latest: u64,
    init: bool,
}

const WINDOW_SPAN: u64 = 256;

impl ReplayWindow {
    pub fn accept(&mut self, serial: u64) -> bool {
        if !self.init {
            self.init = true;
            self.latest = serial;
            self.bits = [1, 0, 0, 0, 0];
            return true;
        }
        if serial > self.latest {
            let diff = serial - self.latest;
            if diff > WINDOW_SPAN {
                self.bits = [0; 5];
            } else {
                self.shift(diff as usize);
            }
            self.latest = serial;
            self.bits[0] |= 1;
            return true;
        }
        let diff = self.latest - serial;
        if diff > WINDOW_SPAN {
            return false;
        }
        let word = (diff / 64) as usize;
        let bit = diff % 64;
        let mask = 1u64 << bit;
        if self.bits[word] & mask != 0 {
            return false;
        }
        self.bits[word] |= mask;
        true
    }

    fn shift(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        if n > WINDOW_SPAN as usize {
            self.bits = [0; 5];
            return;
        }
        let word = n / 64;
        let bit = (n % 64) as u32;
        let mut tmp = [0u64; 5];
        if bit == 0 {
            tmp[word..].copy_from_slice(&self.bits[..5 - word]);
        } else {
            for (i, out) in tmp.iter_mut().enumerate().skip(word + 1) {
                *out = (self.bits[i - word] << bit) | (self.bits[i - word - 1] >> (64 - bit));
            }
            tmp[word] = self.bits[0] << bit;
        }
        self.bits = tmp;
    }
}

pub struct Session {
    key: [u8; 32],
    prp: Xtea,
    serial: u64,
    expect: u64,
    window: ReplayWindow,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("serial", &self.serial)
            .field("expect", &self.expect)
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Session {
    pub fn new(key: [u8; 32], is_client: bool) -> Self {
        let prp_key = salsa::salsa20_keystream(&key, &[0u8; NONCE_SIZE], 16);
        let mut pk = [0u8; 16];
        pk.copy_from_slice(&prp_key);
        Self {
            key,
            prp: Xtea::new(&pk),
            serial: if is_client { 1 } else { 0 },
            expect: if is_client { 2 } else { 3 },
            window: ReplayWindow::default(),
        }
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn encode(
        &mut self,
        payload: &[u8],
        mode: Mode,
        mtu: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        self.encode_into(payload, mode, mtu, &mut out, &mut scratch)?;
        Ok(out)
    }

    /// Encode into caller-owned buffers.  With reused `out`/`scratch`
    /// this performs no heap allocation in steady state.
    pub fn encode_into(
        &mut self,
        payload: &[u8],
        mode: Mode,
        mtu: usize,
        out: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        if mtu < mode.min_mtu() {
            return Err(TransportError::BadMtu);
        }
        if payload.len() > mode.max_payload(mtu) {
            return Err(TransportError::TooLarge);
        }
        self.serial = self.serial.wrapping_add(2);
        let serial = self.serial;
        let nonce_ct = self.prp.encrypt_u64(serial);
        out.clear();

        if mode.is_encless() {
            // encless still owns its internal buffers.  The frame is
            // payload || pad || zeros; the nonce follows the encoding.
            let frame_len = mtu - NONCE_SIZE;
            scratch.clear();
            scratch.reserve(frame_len);
            scratch.extend_from_slice(payload);
            scratch.push(PAD_BYTE);
            scratch.resize(frame_len, 0);
            let encoded = encless::encode(&self.key, &nonce_ct, scratch)
                .map_err(|_| TransportError::TooLarge)?;
            out.reserve(encoded.len() + NONCE_SIZE);
            out.extend_from_slice(&encoded);
            out.extend_from_slice(&nonce_ct);
            return Ok(());
        }

        let frame_len = if mode.padded() {
            mtu - TAG_SIZE
        } else {
            payload.len() + 1 + NONCE_SIZE
        };
        let buf_len = S20_BS + frame_len - NONCE_SIZE;
        // Only the 64-byte Salsa scratch needs zeroing; the frame region
        // is fully written below, and the zeroed tail is the protocol's
        // padding.  The trailing nonce is appended to `out`.
        scratch.clear();
        scratch.reserve(buf_len);
        scratch.extend_from_slice(&[0u8; S20_BS]);
        scratch.extend_from_slice(payload);
        scratch.push(PAD_BYTE);
        scratch.resize(buf_len, 0);
        salsa::salsa20_xor(&self.key, &nonce_ct, scratch);

        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&scratch[..32]);
        out.reserve(TAG_SIZE + frame_len);
        out.extend_from_slice(&[0u8; TAG_SIZE]);
        out.extend_from_slice(&scratch[S20_BS..]);
        out.extend_from_slice(&nonce_ct);
        let tag = poly1305::tag(&auth_key, &out[TAG_SIZE..]);
        auth_key.zeroize();
        out[..TAG_SIZE].copy_from_slice(&tag);
        Ok(())
    }

    pub fn decode(
        &mut self,
        packet: &[u8],
        mode: Mode,
        mtu: usize,
        ordering: Ordering,
    ) -> Result<Vec<u8>, TransportError> {
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        self.decode_into(packet, mode, mtu, ordering, &mut out, &mut scratch)?;
        Ok(out)
    }

    /// Decode into caller-owned buffers.  With reused `out`/`scratch`
    /// this performs no heap allocation in steady state (except the
    /// encless path, which still owns its internal buffers).
    pub fn decode_into(
        &mut self,
        packet: &[u8],
        mode: Mode,
        mtu: usize,
        ordering: Ordering,
        out: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        if mtu < mode.min_mtu() {
            return Err(TransportError::BadMtu);
        }
        if packet.len() < MIN_PKT_LENGTH {
            return Err(TransportError::TooShort);
        }
        let max_wire = match mode {
            Mode::Plain => mtu.saturating_add(TAG_SIZE + NONCE_SIZE),
            Mode::Noise => mtu,
            Mode::Encless => mtu.saturating_add(ENCLESS_ENLARGE_SIZE),
        };
        let exact_wire = matches!(mode, Mode::Noise | Mode::Encless);
        if packet.len() > max_wire || (exact_wire && packet.len() != max_wire) {
            return Err(TransportError::TooLarge);
        }

        if mode.is_encless() {
            if packet.len() < MIN_ENCODED_SIZE + NONCE_SIZE {
                return Err(TransportError::TooShort);
            }
            let nonce_ct: [u8; 8] = packet[packet.len() - NONCE_SIZE..].try_into().unwrap();
            let plain = encless::decode(&self.key, &nonce_ct, &packet[..packet.len() - NONCE_SIZE])
                .map_err(|_| TransportError::Authenticator)?;
            let serial = self.prp.decrypt_u64(&nonce_ct);
            self.check_replay(serial, ordering)?;
            let idx = split_padding_len(&plain).ok_or(TransportError::Padding)?;
            out.clear();
            out.extend_from_slice(&plain[..idx]);
            return Ok(());
        }

        let tag: [u8; TAG_SIZE] = packet[..TAG_SIZE].try_into().unwrap();
        let frame = &packet[TAG_SIZE..];
        if frame.len() < 1 + NONCE_SIZE {
            return Err(TransportError::TooShort);
        }
        let nonce_ct: [u8; 8] = frame[frame.len() - NONCE_SIZE..].try_into().unwrap();
        scratch.clear();
        scratch.reserve(S20_BS + frame.len() - NONCE_SIZE);
        scratch.extend_from_slice(&[0u8; S20_BS]);
        scratch.extend_from_slice(&frame[..frame.len() - NONCE_SIZE]);
        salsa::salsa20_xor(&self.key, &nonce_ct, scratch);

        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&scratch[..32]);
        let ok = poly1305::verify(&auth_key, frame, &tag);
        auth_key.zeroize();
        if !ok {
            return Err(TransportError::Authenticator);
        }

        let serial = self.prp.decrypt_u64(&nonce_ct);
        self.check_replay(serial, ordering)?;

        // Padding search must not include the trailing nonce: a random
        // 0x80 in the nonce would otherwise be mistaken for the pad byte.
        let idx = split_padding_len(&scratch[S20_BS..]).ok_or(TransportError::Padding)?;
        out.clear();
        out.extend_from_slice(&scratch[S20_BS..S20_BS + idx]);
        Ok(())
    }

    fn check_replay(&mut self, serial: u64, ordering: Ordering) -> Result<(), TransportError> {
        match ordering {
            Ordering::Exact => {
                if serial != self.expect {
                    return Err(TransportError::Replay);
                }
                self.expect = self.expect.wrapping_add(2);
            }
            Ordering::Reorderable => {
                if !self.window.accept(serial) {
                    return Err(TransportError::Replay);
                }
            }
        }
        Ok(())
    }
}

fn split_padding_len(frame: &[u8]) -> Option<usize> {
    let idx = frame.iter().rposition(|&b| b == PAD_BYTE)?;
    if frame[idx + 1..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(idx)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn classic_roundtrip() {
        let key = [11u8; 32];
        let mut client = Session::new(key, true);
        let mut server = Session::new(key, false);
        let payload = b"hello transport";
        let wire = client.encode(payload, Mode::Plain, 1515).unwrap();
        assert_eq!(wire.len(), TAG_SIZE + payload.len() + 1 + NONCE_SIZE);
        assert_eq!(
            server
                .decode(&wire, Mode::Plain, 1515, Ordering::Reorderable)
                .unwrap(),
            payload
        );
        let wire = server.encode(b"back", Mode::Plain, 1515).unwrap();
        assert_eq!(
            client
                .decode(&wire, Mode::Plain, 1515, Ordering::Exact)
                .unwrap(),
            b"back"
        );
    }

    #[test]
    fn noise_roundtrip() {
        let key = [12u8; 32];
        let mut client = Session::new(key, true);
        let mut server = Session::new(key, false);
        let payload = vec![0x5au8; Mode::Noise.max_payload(1515)];
        let wire = client.encode(&payload, Mode::Noise, 1515).unwrap();
        assert_eq!(wire.len(), 1515);
        assert_eq!(
            server
                .decode(&wire, Mode::Noise, 1515, Ordering::Reorderable)
                .unwrap(),
            payload
        );
    }

    #[test]
    fn encless_roundtrip() {
        let key = [13u8; 32];
        let mut client = Session::new(key, true);
        let mut server = Session::new(key, false);
        let payload = vec![0x33u8; Mode::Encless.max_payload(1515)];
        let wire = client.encode(&payload, Mode::Encless, 1515).unwrap();
        assert_eq!(wire.len(), 1515 + ENCLESS_ENLARGE_SIZE);
        assert_eq!(
            server
                .decode(&wire, Mode::Encless, 1515, Ordering::Reorderable)
                .unwrap(),
            payload
        );
    }

    /// Regression for the v1 MTU contract: the client and server must agree on
    /// the numeric wire MTU.  A locally derived value (for example 1472) makes the
    /// peer reject otherwise valid handshake/transport packets with `TooLarge`.
    #[test]
    fn same_numeric_mtu_is_required_on_both_sides() {
        for mode in [Mode::Plain, Mode::Noise, Mode::Encless] {
            let key = [21u8; 32];
            let payload = vec![0x44u8; mode.max_payload(1515)];
            let mut client = Session::new(key, true);
            let wire = client.encode(&payload, mode, 1515).unwrap();

            let mut matching = Session::new(key, false);
            assert_eq!(
                matching
                    .decode(&wire, mode, 1515, Ordering::Reorderable)
                    .unwrap(),
                payload,
                "{mode:?} must decode at the shared wire MTU"
            );

            let mut mismatched = Session::new(key, false);
            assert_eq!(
                mismatched.decode(&wire, mode, 1472, Ordering::Reorderable),
                Err(TransportError::TooLarge),
                "{mode:?} must reject a different wire MTU"
            );
        }
    }

    #[test]
    fn replay_rejected() {
        let key = [14u8; 32];
        let mut client = Session::new(key, true);
        let mut server = Session::new(key, false);
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
    fn small_mtu_rejected() {
        let key = [31u8; 32];
        let mut enc = Session::new(key, true);
        let mut dec = Session::new(key, false);
        for (mode, mtu) in [
            (Mode::Plain, MTU_MIN - 1),
            (Mode::Noise, MTU_MIN_NOISE - 1),
            (Mode::Encless, MTU_MIN_NOISE - 1),
        ] {
            assert_eq!(
                enc.encode(&[], mode, mtu),
                Err(TransportError::BadMtu),
                "encode {mode:?}"
            );
            assert_eq!(
                dec.decode(&[0u8; 64], mode, mtu, Ordering::Reorderable),
                Err(TransportError::BadMtu),
                "decode {mode:?}"
            );
        }
    }

    #[test]
    fn in_place_matches_allocating() {
        let key = [21u8; 32];
        let mut enc_ref = Session::new(key, true);
        let mut enc_ip = Session::new(key, true);
        let mut dec_ref = Session::new(key, false);
        let mut dec_ip = Session::new(key, false);

        // Deliberately dirty buffers reused across every packet, as the
        // production peer path does.
        let mut wire = vec![0xAAu8; 3];
        let mut enc_scratch = vec![0x55u8; 37];
        let mut out = vec![0xCCu8; 11];
        let mut dec_scratch = vec![0x99u8; 5];

        let cases = [
            (Mode::Plain, 0usize),
            (Mode::Plain, 1),
            (Mode::Plain, 789),
            (Mode::Plain, 1514),
            (Mode::Noise, 0),
            (Mode::Noise, 64),
            (Mode::Noise, 1490),
            (Mode::Encless, 1),
            (Mode::Encless, 1506),
        ];
        for (mode, len) in cases {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let want_wire = enc_ref.encode(&payload, mode, 1515).unwrap();
            enc_ip
                .encode_into(&payload, mode, 1515, &mut wire, &mut enc_scratch)
                .unwrap();
            // encless draws a fresh random AONT `r` per packet, so only
            // the deterministic modes are byte-comparable.
            if !matches!(mode, Mode::Encless) {
                assert_eq!(wire, want_wire, "encode {mode:?} len {len}");
            }

            // Decode the in-place output with dirty, reused buffers and
            // require the same plaintext as the reference encode.
            let want = dec_ref
                .decode(&want_wire, mode, 1515, Ordering::Reorderable)
                .unwrap();
            dec_ip
                .decode_into(
                    &wire,
                    mode,
                    1515,
                    Ordering::Reorderable,
                    &mut out,
                    &mut dec_scratch,
                )
                .unwrap();
            assert_eq!(out, want, "decode {mode:?} len {len}");
            assert_eq!(out, payload, "payload {mode:?} len {len}");
        }
    }
}

/// One direction of a transport session (TAP -> network).
pub struct Encoder {
    inner: Session,
}

impl fmt::Debug for Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

impl Encoder {
    pub fn new(key: [u8; 32], is_client: bool) -> Self {
        Self {
            inner: Session::new(key, is_client),
        }
    }

    pub fn encode(
        &mut self,
        payload: &[u8],
        mode: Mode,
        mtu: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let wire = self.inner.encode(payload, mode, mtu)?;
        Ok(wire)
    }

    pub fn encode_into(
        &mut self,
        payload: &[u8],
        mode: Mode,
        mtu: usize,
        out: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        self.inner.encode_into(payload, mode, mtu, out, scratch)
    }

    pub fn serial(&self) -> u64 {
        self.inner.serial()
    }
}

/// The other direction of a transport session (network -> TAP).
pub struct Decoder {
    inner: Session,
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

impl Decoder {
    pub fn new(key: [u8; 32], is_client: bool) -> Self {
        Self {
            inner: Session::new(key, is_client),
        }
    }

    pub fn decode(
        &mut self,
        packet: &[u8],
        mode: Mode,
        mtu: usize,
        ordering: Ordering,
    ) -> Result<Vec<u8>, TransportError> {
        self.inner.decode(packet, mode, mtu, ordering)
    }

    pub fn decode_into(
        &mut self,
        packet: &[u8],
        mode: Mode,
        mtu: usize,
        ordering: Ordering,
        out: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        self.inner
            .decode_into(packet, mode, mtu, ordering, out, scratch)
    }

    /// The encrypted serial expected next, used to delimit TCP packets.
    pub fn expected_nonce(&self) -> [u8; 8] {
        self.inner.prp.encrypt_u64(self.inner.expect)
    }
}
