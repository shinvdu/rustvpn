//! GoVPN 5.7 PAKE handshake (DH A-EKE, extra25519, Ed25519).
//!
//! The state machine and message layouts mirror the Go implementation
//! exactly, including the sizes of noise/encless padded messages.  All
//! message bytes, including the trailing XTEA `IDtag`, are produced
//! byte-for-byte.

use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;

use rustvpn_crypto::{blake2b, elligator, encless, salsa, xtea::Xtea};

use crate::ENCLESS_ENLARGE_SIZE;

const R_SIZE: usize = 8;
const S_SIZE: usize = 32;
const ID_SIZE: usize = 16;
const XTEA_BLOCK: usize = 8;
const SIGNATURE_SIZE: usize = 64;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HandshakeError {
    #[error("bad handshake stage")]
    Stage,
    #[error("message too short")]
    TooShort,
    #[error("bad message size")]
    BadSize,
    #[error("crypto operation failed")]
    Crypto,
    #[error("authentication failed")]
    Authenticator,
    #[error("signature verification failed")]
    Signature,
    #[error("random number mismatch")]
    Mismatch,
    #[error("no signing key for client handshake")]
    MissingSigningKey,
    #[error("invalid (low-order) DH point")]
    InvalidDh,
}

#[derive(Clone, Debug)]
pub struct HandshakeConfig {
    pub id: [u8; ID_SIZE],
    pub mtu: usize,
    pub noise: bool,
    pub encless: bool,
    pub time_sync: i64,
    pub verifier_public: [u8; 32],
    pub signing_key: Option<SigningKey>,
}

impl HandshakeConfig {
    pub fn client(
        id: [u8; ID_SIZE],
        mtu: usize,
        noise: bool,
        encless: bool,
        time_sync: i64,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            id,
            mtu,
            noise: noise || encless,
            encless,
            time_sync,
            verifier_public: signing_key.verifying_key().to_bytes(),
            signing_key: Some(signing_key),
        }
    }

    pub fn server(
        id: [u8; ID_SIZE],
        mtu: usize,
        noise: bool,
        encless: bool,
        time_sync: i64,
        verifier_public: [u8; 32],
    ) -> Self {
        Self {
            id,
            mtu,
            noise: noise || encless,
            encless,
            time_sync,
            verifier_public,
            signing_key: None,
        }
    }

    fn dsa_pub_h(&self) -> [u8; 32] {
        blake2b::hash(&self.verifier_public)
    }
}

pub enum ServerOutput {
    Reply(Vec<u8>),
    Complete {
        reply: Vec<u8>,
        session_key: [u8; 32],
    },
}

pub enum ClientOutput {
    Reply(Vec<u8>),
    Complete([u8; 32]),
}

fn dh_keypair_gen<R: RngCore + ?Sized>(rng: &mut R) -> ([u8; 32], [u8; 32]) {
    loop {
        let mut private = [0u8; 32];
        rng.fill_bytes(&mut private);
        if let Some((_public, repr)) = elligator::scalar_base_mult(&private) {
            return (private, repr);
        }
    }
}

/// Derive the handshake key from a peer representative.  Low-order points
/// (order 1/2/4/8) collapse to the all-zero shared secret after clamping,
/// which would make the derived key a public constant; reject them.
fn dh_key_gen(private: &[u8; 32], peer_repr: &[u8; 32]) -> Result<[u8; 32], HandshakeError> {
    let public = elligator::representative_to_public_key(peer_repr);
    let shared = MontgomeryPoint(public).mul_clamped(*private).to_bytes();
    if shared.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        return Err(HandshakeError::InvalidDh);
    }
    Ok(blake2b::hash(&shared))
}

fn r_nonce_next(r_nonce: &[u8; R_SIZE], count: u64) -> [u8; R_SIZE] {
    // Mirrors binary.Uvarint / binary.PutUvarint on the fixed 8-byte R.
    let mut current = 0u64;
    let mut shift = 0u32;
    let mut ok = false;
    for &b in r_nonce {
        if b < 0x80 {
            current |= (b as u64) << shift;
            ok = true;
            break;
        }
        current |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    let value = if ok {
        current.wrapping_add(count)
    } else {
        count
    };
    let mut out = [0u8; R_SIZE];
    let mut x = value;
    let mut i = 0;
    while x >= 0x80 && i < R_SIZE {
        out[i] = (x as u8) | 0x80;
        x >>= 7;
        i += 1;
    }
    if i < R_SIZE {
        out[i] = x as u8;
    }
    out
}

fn time_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn id_tag(id: &[u8; ID_SIZE], time_sync: i64, data: &[u8]) -> [u8; 8] {
    let mut block = [0u8; 8];
    block.copy_from_slice(&data[..8]);
    if time_sync > 0 {
        let ts = time_sync as u64;
        let now = time_now_unix() / ts * ts;
        let bytes = now.to_be_bytes();
        for i in 0..8 {
            block[i] ^= bytes[i];
        }
    }
    let cipher = Xtea::new(id);
    cipher.encrypt_u64(u64::from_be_bytes(block))
}

fn encode_payload<R: RngCore + ?Sized>(
    config: &HandshakeConfig,
    key: &[u8; 32],
    nonce: &[u8; 8],
    mut plain: Vec<u8>,
    rng: &mut R,
) -> Result<Vec<u8>, HandshakeError> {
    if config.encless {
        let mut r = [0u8; 16];
        rng.fill_bytes(&mut r);
        encless::encode_with_r(key, nonce, &r, &plain).map_err(|_| HandshakeError::Crypto)
    } else {
        salsa::salsa20_xor(key, nonce, &mut plain);
        Ok(plain)
    }
}

fn decode_payload(
    config: &HandshakeConfig,
    key: &[u8; 32],
    nonce: &[u8; 8],
    data: &[u8],
    plain_len: usize,
) -> Result<Vec<u8>, HandshakeError> {
    if config.encless {
        let decoded = encless::decode(key, nonce, data).map_err(|_| HandshakeError::Crypto)?;
        if decoded.len() < plain_len {
            return Err(HandshakeError::TooShort);
        }
        Ok(decoded[..plain_len].to_vec())
    } else {
        if data.len() < plain_len {
            return Err(HandshakeError::TooShort);
        }
        let mut out = data[..plain_len].to_vec();
        salsa::salsa20_xor(key, nonce, &mut out);
        Ok(out)
    }
}

pub struct ClientHandshake {
    config: HandshakeConfig,
    signing_key: SigningKey,
    dsa_pub_h: [u8; 32],
    dh_private: [u8; 32],
    r_nonce: [u8; R_SIZE],
    key: Option<[u8; 32]>,
    r_server: [u8; R_SIZE],
    s_server: [u8; S_SIZE],
    r_client: [u8; R_SIZE],
    s_client: [u8; S_SIZE],
    stage: u8,
}

impl ClientHandshake {
    pub fn start<R: RngCore + ?Sized>(
        config: HandshakeConfig,
        mut rng: &mut R,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let signing_key = config
            .signing_key
            .clone()
            .ok_or(HandshakeError::MissingSigningKey)?;
        let dsa_pub_h = config.dsa_pub_h();
        let (dh_private, repr) = dh_keypair_gen(&mut rng);
        let mut r_nonce = [0u8; R_SIZE];
        rng.fill_bytes(&mut r_nonce);

        let enc_len = if config.noise {
            config
                .mtu
                .checked_sub(XTEA_BLOCK + R_SIZE)
                .ok_or(HandshakeError::BadSize)?
        } else {
            32
        };
        let mut plain = vec![0u8; enc_len];
        plain[..32].copy_from_slice(&repr);
        let enc = encode_payload(&config, &dsa_pub_h, &r_nonce, plain, &mut rng)?;

        let mut message = Vec::with_capacity(R_SIZE + enc.len() + XTEA_BLOCK);
        message.extend_from_slice(&r_nonce);
        message.extend_from_slice(&enc);
        message.extend_from_slice(&id_tag(&config.id, config.time_sync, &r_nonce));

        Ok((
            Self {
                config,
                signing_key,
                dsa_pub_h,
                dh_private,
                r_nonce,
                key: None,
                r_server: [0; R_SIZE],
                s_server: [0; S_SIZE],
                r_client: [0; R_SIZE],
                s_client: [0; S_SIZE],
                stage: 0,
            },
            message,
        ))
    }

    pub fn client<R: RngCore + ?Sized>(
        &mut self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<ClientOutput, HandshakeError> {
        match self.stage {
            0 => self.stage_reply(message, rng),
            1 => self.stage_final(message),
            _ => Err(HandshakeError::Stage),
        }
    }

    fn stage_reply<R: RngCore + ?Sized>(
        &mut self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<ClientOutput, HandshakeError> {
        if self.config.encless {
            if message.len() != 2 * (ENCLESS_ENLARGE_SIZE + self.config.mtu) {
                return Err(HandshakeError::BadSize);
            }
        } else if message.len() < 80 {
            return Err(HandshakeError::TooShort);
        }
        let nonce1 = r_nonce_next(&self.r_nonce, 1);

        // Server's El(SDHPub)
        let sdh_repr = if self.config.encless {
            let decoded = encless::decode(&self.dsa_pub_h, &nonce1, &message[..message.len() / 2])
                .map_err(|_| HandshakeError::Crypto)?;
            if decoded.len() < 32 {
                return Err(HandshakeError::TooShort);
            }
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&decoded[..32]);
            repr
        } else {
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&message[..32]);
            salsa::salsa20_xor(&self.dsa_pub_h, &nonce1, &mut repr);
            repr
        };
        let key = dh_key_gen(&self.dh_private, &sdh_repr)?;
        self.key = Some(key);

        // RS + SS
        let rs_ss = if self.config.encless {
            let decoded = encless::decode(
                &key,
                &self.r_nonce,
                &message[message.len() / 2..message.len() - XTEA_BLOCK],
            )
            .map_err(|_| HandshakeError::Crypto)?;
            if decoded.len() < 40 {
                return Err(HandshakeError::TooShort);
            }
            decoded[..40].to_vec()
        } else {
            if message.len() < 72 {
                return Err(HandshakeError::TooShort);
            }
            let mut data = message[32..72].to_vec();
            salsa::salsa20_xor(&key, &self.r_nonce, &mut data);
            data
        };
        self.r_server.copy_from_slice(&rs_ss[..8]);
        self.s_server.copy_from_slice(&rs_ss[8..40]);

        rng.fill_bytes(&mut self.r_client);
        rng.fill_bytes(&mut self.s_client);
        let signature = self.signing_key.sign(&key).to_bytes();

        let enc_len = if self.config.noise {
            self.config
                .mtu
                .checked_sub(XTEA_BLOCK)
                .ok_or(HandshakeError::BadSize)?
        } else {
            112
        };
        let mut plain = vec![0u8; enc_len];
        plain[..8].copy_from_slice(&self.r_server);
        plain[8..16].copy_from_slice(&self.r_client);
        plain[16..48].copy_from_slice(&self.s_client);
        plain[48..48 + SIGNATURE_SIZE].copy_from_slice(&signature);
        let enc = encode_payload(&self.config, &key, &nonce1, plain, rng)?;

        let mut out = Vec::with_capacity(enc.len() + XTEA_BLOCK);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&id_tag(&self.config.id, self.config.time_sync, &enc));
        self.stage = 1;
        Ok(ClientOutput::Reply(out))
    }

    fn stage_final(&mut self, message: &[u8]) -> Result<ClientOutput, HandshakeError> {
        let key = self.key.ok_or(HandshakeError::Stage)?;
        if self.config.encless {
            if message.len() != ENCLESS_ENLARGE_SIZE + self.config.mtu {
                return Err(HandshakeError::BadSize);
            }
        } else if message.len() < 16 {
            return Err(HandshakeError::TooShort);
        }
        let nonce2 = r_nonce_next(&self.r_nonce, 2);
        let decoded = decode_payload(
            &self.config,
            &key,
            &nonce2,
            &message[..message.len() - XTEA_BLOCK],
            8,
        )?;
        if decoded.ct_eq(&self.r_client).unwrap_u8() != 1 {
            return Err(HandshakeError::Mismatch);
        }
        let session_key = std::array::from_fn(|i| self.s_server[i] ^ self.s_client[i]);
        self.stage = 2;
        Ok(ClientOutput::Complete(session_key))
    }
}

pub struct ServerHandshake {
    config: HandshakeConfig,
    dsa_pub_h: [u8; 32],
    dh_private: [u8; 32],
    r_nonce: [u8; R_SIZE],
    key: [u8; 32],
    r_server: [u8; R_SIZE],
    s_server: [u8; S_SIZE],
    stage: u8,
}

impl ServerHandshake {
    pub fn new(config: HandshakeConfig) -> Self {
        let dsa_pub_h = config.dsa_pub_h();
        Self {
            config,
            dsa_pub_h,
            dh_private: [0; 32],
            r_nonce: [0; R_SIZE],
            key: [0; 32],
            r_server: [0; R_SIZE],
            s_server: [0; S_SIZE],
            stage: 0,
        }
    }

    pub fn server<R: RngCore + ?Sized>(
        &mut self,
        message: &[u8],
        mut rng: &mut R,
    ) -> Result<ServerOutput, HandshakeError> {
        match self.stage {
            0 => self.stage_first(message, &mut rng),
            1 => self.stage_third(message, rng),
            _ => Err(HandshakeError::Stage),
        }
    }

    fn stage_first<R: RngCore + ?Sized>(
        &mut self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<ServerOutput, HandshakeError> {
        if self.config.encless {
            if message.len() != ENCLESS_ENLARGE_SIZE + self.config.mtu {
                return Err(HandshakeError::BadSize);
            }
        } else if message.len() < 48 {
            return Err(HandshakeError::TooShort);
        }
        self.r_nonce.copy_from_slice(&message[..R_SIZE]);
        let c_repr = if self.config.encless {
            let decoded = encless::decode(
                &self.dsa_pub_h,
                &self.r_nonce,
                &message[R_SIZE..message.len() - XTEA_BLOCK],
            )
            .map_err(|_| HandshakeError::Crypto)?;
            if decoded.len() < 32 {
                return Err(HandshakeError::TooShort);
            }
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&decoded[..32]);
            repr
        } else {
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&message[R_SIZE..R_SIZE + 32]);
            salsa::salsa20_xor(&self.dsa_pub_h, &self.r_nonce, &mut repr);
            repr
        };

        let (dh_private, repr) = dh_keypair_gen(rng);
        self.dh_private = dh_private;
        self.key = dh_key_gen(&dh_private, &c_repr)?;
        let nonce1 = r_nonce_next(&self.r_nonce, 1);
        // Go encodes encPub (which consumes AONT randomness in encless
        // mode) before generating R* and S*.
        let enc_pub = if self.config.encless {
            let mut plain = vec![0u8; self.config.mtu];
            plain[..32].copy_from_slice(&repr);
            encode_payload(&self.config, &self.dsa_pub_h, &nonce1, plain, rng)?
        } else {
            let mut buf = repr;
            salsa::salsa20_xor(&self.dsa_pub_h, &nonce1, &mut buf);
            buf.to_vec()
        };

        rng.fill_bytes(&mut self.r_server);
        rng.fill_bytes(&mut self.s_server);

        let enc_rs_len = if self.config.encless {
            self.config
                .mtu
                .checked_sub(XTEA_BLOCK)
                .ok_or(HandshakeError::BadSize)?
        } else if self.config.noise {
            self.config
                .mtu
                .checked_sub(enc_pub.len() + XTEA_BLOCK)
                .ok_or(HandshakeError::BadSize)?
        } else {
            40
        };
        let mut rs = vec![0u8; enc_rs_len];
        rs[..8].copy_from_slice(&self.r_server);
        rs[8..40].copy_from_slice(&self.s_server);
        let enc_rs = encode_payload(&self.config, &self.key, &self.r_nonce, rs, rng)?;

        let mut out = Vec::with_capacity(enc_pub.len() + enc_rs.len() + XTEA_BLOCK);
        out.extend_from_slice(&enc_pub);
        out.extend_from_slice(&enc_rs);
        out.extend_from_slice(&id_tag(
            &self.config.id,
            self.config.time_sync,
            &enc_pub[..8],
        ));
        self.stage = 1;
        Ok(ServerOutput::Reply(out))
    }

    fn stage_third<R: RngCore + ?Sized>(
        &mut self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<ServerOutput, HandshakeError> {
        if self.config.encless {
            if message.len() != ENCLESS_ENLARGE_SIZE + self.config.mtu {
                return Err(HandshakeError::BadSize);
            }
        } else if message.len() < 120 {
            return Err(HandshakeError::TooShort);
        }
        let nonce1 = r_nonce_next(&self.r_nonce, 1);
        let decoded = decode_payload(
            &self.config,
            &self.key,
            &nonce1,
            &message[..message.len() - XTEA_BLOCK],
            8 + 8 + 32 + SIGNATURE_SIZE,
        )?;
        if decoded[..8].ct_eq(&self.r_server).unwrap_u8() != 1 {
            return Err(HandshakeError::Mismatch);
        }
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&decoded[48..48 + SIGNATURE_SIZE]);
        let verifying_key = VerifyingKey::from_bytes(&self.config.verifier_public)
            .map_err(|_| HandshakeError::Signature)?;
        verifying_key
            .verify(&self.key, &Signature::from_bytes(&signature))
            .map_err(|_| HandshakeError::Signature)?;

        let session_key = std::array::from_fn(|i| self.s_server[i] ^ decoded[16 + i]);

        let nonce2 = r_nonce_next(&self.r_nonce, 2);
        let enc_len = if self.config.noise {
            self.config
                .mtu
                .checked_sub(XTEA_BLOCK)
                .ok_or(HandshakeError::BadSize)?
        } else {
            8
        };
        let mut plain = vec![0u8; enc_len];
        plain[..8].copy_from_slice(&decoded[8..16]); // RC
        let enc = encode_payload(&self.config, &self.key, &nonce2, plain, rng)?;
        let mut out = Vec::with_capacity(enc.len() + XTEA_BLOCK);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&id_tag(&self.config.id, self.config.time_sync, &enc));
        self.stage = 2;
        Ok(ServerOutput::Complete {
            reply: out,
            session_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const U1_REPR: [u8; 32] = [
        0x1f, 0xc6, 0x93, 0xab, 0xdb, 0x36, 0xb8, 0x2d, 0xfb, 0x20, 0xd7, 0x82, 0xd3, 0xa3, 0xe4,
        0x0b, 0xe2, 0x44, 0xa8, 0xe7, 0xc5, 0x2a, 0x45, 0xeb, 0xd3, 0xdc, 0x2c, 0xac, 0xae, 0x51,
        0x5f, 0x62,
    ];

    fn signing_key(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        SigningKey::from_bytes(&s)
    }

    fn configs() -> (HandshakeConfig, HandshakeConfig) {
        let sk = signing_key(1);
        let vk = sk.verifying_key().to_bytes();
        (
            HandshakeConfig::client([9u8; ID_SIZE], 1515, false, false, 0, sk),
            HandshakeConfig::server([9u8; ID_SIZE], 1515, false, false, 0, vk),
        )
    }

    #[test]
    fn dh_key_gen_rejects_low_order_representatives() {
        let mut private = [0u8; 32];
        for (i, b) in private.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        for repr in [[0u8; 32], U1_REPR] {
            assert_eq!(
                dh_key_gen(&private, &repr),
                Err(HandshakeError::InvalidDh),
                "low-order repr accepted: {repr:02x?}"
            );
        }
        let (private, repr) = dh_keypair_gen(&mut OsRng);
        assert!(dh_key_gen(&private, &repr).is_ok());
    }

    #[test]
    fn client_rejects_low_order_server_repr() {
        let (client_cfg, _) = configs();
        let dsa_pub_h = client_cfg.dsa_pub_h();
        let mut rng = OsRng;
        let (mut hs, _msg1) = ClientHandshake::start(client_cfg, &mut rng).unwrap();
        let nonce1 = r_nonce_next(&hs.r_nonce, 1);
        for repr0 in [[0u8; 32], U1_REPR] {
            let mut repr = repr0;
            salsa::salsa20_xor(&dsa_pub_h, &nonce1, &mut repr);
            let mut msg = Vec::with_capacity(80);
            msg.extend_from_slice(&repr);
            msg.extend_from_slice(&[0u8; 48]);
            assert!(matches!(
                hs.client(&msg, &mut rng),
                Err(HandshakeError::InvalidDh)
            ));
        }
    }

    #[test]
    fn server_rejects_low_order_client_repr() {
        let (_, server_cfg) = configs();
        let dsa_pub_h = server_cfg.dsa_pub_h();
        let id = server_cfg.id;
        let mut rng = OsRng;
        let r_nonce = [7u8; R_SIZE];
        for repr0 in [[0u8; 32], U1_REPR] {
            let mut repr = repr0;
            salsa::salsa20_xor(&dsa_pub_h, &r_nonce, &mut repr);
            let mut msg = Vec::with_capacity(48);
            msg.extend_from_slice(&r_nonce);
            msg.extend_from_slice(&repr);
            msg.extend_from_slice(&id_tag(&id, 0, &r_nonce));
            let mut hs = ServerHandshake::new(server_cfg.clone());
            assert!(matches!(
                hs.server(&msg, &mut rng),
                Err(HandshakeError::InvalidDh)
            ));
        }
    }
}
