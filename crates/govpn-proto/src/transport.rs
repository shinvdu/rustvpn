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

use govpn_crypto::encless::{self, ENCLESS_ENLARGE_SIZE, MIN_ENCODED_SIZE};
use govpn_crypto::{poly1305, salsa, xtea::Xtea};
use thiserror::Error;

use crate::{MIN_PKT_LENGTH, NONCE_SIZE, PAD_BYTE, S20_BS, TAG_SIZE};

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

#[derive(Clone, Debug)]
pub struct Session {
    key: [u8; 32],
    prp: Xtea,
    serial: u64,
    expect: u64,
    window: ReplayWindow,
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
        if payload.len() > mode.max_payload(mtu) {
            return Err(TransportError::TooLarge);
        }
        self.serial = self.serial.wrapping_add(2);
        let serial = self.serial;
        let nonce_ct = self.prp.encrypt_u64(serial);

        if mode.is_encless() {
            let mut frame = vec![0u8; mtu];
            frame[..payload.len()].copy_from_slice(payload);
            frame[payload.len()] = PAD_BYTE;
            frame[mtu - NONCE_SIZE..].copy_from_slice(&nonce_ct);
            let encoded = encless::encode(&self.key, &nonce_ct, &frame[..mtu - NONCE_SIZE])
                .map_err(|_| TransportError::TooLarge)?;
            let mut out = Vec::with_capacity(encoded.len() + NONCE_SIZE);
            out.extend_from_slice(&encoded);
            out.extend_from_slice(&nonce_ct);
            return Ok(out);
        }

        let frame_len = if mode.padded() {
            mtu - TAG_SIZE
        } else {
            payload.len() + 1 + NONCE_SIZE
        };
        let mut frame = vec![0u8; frame_len];
        frame[..payload.len()].copy_from_slice(payload);
        frame[payload.len()] = PAD_BYTE;
        frame[frame_len - NONCE_SIZE..].copy_from_slice(&nonce_ct);

        let mut buf = vec![0u8; S20_BS + frame_len - NONCE_SIZE];
        buf[S20_BS..].copy_from_slice(&frame[..frame_len - NONCE_SIZE]);
        salsa::salsa20_xor(&self.key, &nonce_ct, &mut buf);

        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&buf[..32]);
        let mut ciphertext = Vec::with_capacity(frame_len);
        ciphertext.extend_from_slice(&buf[S20_BS..]);
        ciphertext.extend_from_slice(&nonce_ct);
        let tag = poly1305::tag(&auth_key, &ciphertext);

        let mut out = Vec::with_capacity(TAG_SIZE + frame_len);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decode(
        &mut self,
        packet: &[u8],
        mode: Mode,
        mtu: usize,
        ordering: Ordering,
    ) -> Result<Vec<u8>, TransportError> {
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
            return split_padding(&plain).ok_or(TransportError::Padding);
        }

        let tag: [u8; TAG_SIZE] = packet[..TAG_SIZE].try_into().unwrap();
        let frame = &packet[TAG_SIZE..];
        if frame.len() < 1 + NONCE_SIZE {
            return Err(TransportError::TooShort);
        }
        let nonce_ct: [u8; 8] = frame[frame.len() - NONCE_SIZE..].try_into().unwrap();
        let mut buf = vec![0u8; S20_BS + frame.len() - NONCE_SIZE];
        buf[S20_BS..].copy_from_slice(&frame[..frame.len() - NONCE_SIZE]);
        salsa::salsa20_xor(&self.key, &nonce_ct, &mut buf);

        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&buf[..32]);
        if !poly1305::verify(&auth_key, frame, &tag) {
            return Err(TransportError::Authenticator);
        }

        let serial = self.prp.decrypt_u64(&nonce_ct);
        self.check_replay(serial, ordering)?;

        // Padding search must not include the trailing nonce: a random
        // 0x80 in the nonce would otherwise be mistaken for the pad byte.
        split_padding(&buf[S20_BS..]).ok_or(TransportError::Padding)
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

fn split_padding(frame: &[u8]) -> Option<Vec<u8>> {
    let idx = frame.iter().rposition(|&b| b == PAD_BYTE)?;
    if frame[idx + 1..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(frame[..idx].to_vec())
}

#[cfg(test)]
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
}

/// One direction of a transport session (TAP -> network).
#[derive(Clone, Debug)]
pub struct Encoder {
    inner: Session,
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

    pub fn serial(&self) -> u64 {
        self.inner.serial()
    }
}

/// The other direction of a transport session (network -> TAP).
#[derive(Clone, Debug)]
pub struct Decoder {
    inner: Session,
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

    /// The encrypted serial expected next, used to delimit TCP packets.
    pub fn expected_nonce(&self) -> [u8; 8] {
        self.inner.prp.encrypt_u64(self.inner.expect)
    }
}
