//! Augmented passphrase verifier: Argon2d v1.3 + Ed25519.
//!
//! Go version:
//! `argon2.Key(password, id, t, p, m, 32)` then
//! `ed25519.GenerateKey(bytes.NewBuffer(seed))`.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use crate::CryptoError;

pub const ID_SIZE: usize = 16;
/// Upper bounds accepted for Argon2 parameters (KiB / iterations / lanes).
pub const MAX_M: u32 = 262_144;
pub const MAX_T: u32 = 4096;
pub const MAX_P: u32 = 64;
pub const DEFAULT_M: u32 = 1 << 12;
pub const DEFAULT_T: u32 = 1 << 7;
pub const DEFAULT_P: u32 = 1;

#[derive(Clone, Debug)]
pub struct Verifier {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub id: [u8; ID_SIZE],
    pub public: Option<[u8; 32]>,
}

impl Verifier {
    pub fn new(m: u32, t: u32, p: u32, id: [u8; ID_SIZE]) -> Self {
        Self {
            m,
            t,
            p,
            id,
            public: None,
        }
    }

    /// Derive the Ed25519 key pair from the passphrase.  The 32-byte
    /// Argon2d output is the Ed25519 seed.
    pub fn password_apply(&mut self, password: &str) -> Result<SigningKey, CryptoError> {
        if !(1..=MAX_M).contains(&self.m)
            || !(1..=MAX_T).contains(&self.t)
            || !(1..=MAX_P).contains(&self.p)
        {
            return Err(CryptoError::Argon2("parameters out of range".into()));
        }
        let params = Params::new(self.m, self.t, self.p, Some(32))
            .map_err(|e| CryptoError::Argon2(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
        let mut seed = [0u8; 32];
        argon
            .hash_password_into(password.as_bytes(), &self.id, &mut seed)
            .map_err(|e| CryptoError::Argon2(e.to_string()))?;
        let key = SigningKey::from_bytes(&seed);
        self.public = Some(key.verifying_key().to_bytes());
        use zeroize::Zeroize;
        seed.zeroize();
        Ok(key)
    }

    pub fn from_string(input: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = input.split('$').collect();
        if parts.len() < 4 || parts[1] != "argon2d" {
            return Err(CryptoError::InvalidVerifier);
        }
        let mut m = 0u32;
        let mut t = 0u32;
        let mut p = 0u32;
        for item in parts[2].split(',') {
            let (k, v) = item.split_once('=').ok_or(CryptoError::InvalidVerifier)?;
            let value = v.parse::<u32>().map_err(|_| CryptoError::InvalidVerifier)?;
            match k {
                "m" => m = value,
                "t" => t = value,
                "p" => p = value,
                _ => return Err(CryptoError::InvalidVerifier),
            }
        }
        if !(1..=MAX_M).contains(&m) || !(1..=MAX_T).contains(&t) || !(1..=MAX_P).contains(&p) {
            return Err(CryptoError::InvalidVerifier);
        }
        let salt = STANDARD_NO_PAD
            .decode(parts[3])
            .map_err(|_| CryptoError::Base64)?;
        if salt.len() < ID_SIZE {
            return Err(CryptoError::InvalidVerifier);
        }
        let mut id = [0u8; ID_SIZE];
        id.copy_from_slice(&salt[..ID_SIZE]);
        let mut verifier = Self::new(m, t, p, id);
        if parts.len() == 5 {
            let pubkey = STANDARD_NO_PAD
                .decode(parts[4])
                .map_err(|_| CryptoError::Base64)?;
            if pubkey.len() != 32 {
                return Err(CryptoError::InvalidVerifier);
            }
            let mut public = [0u8; 32];
            public.copy_from_slice(&pubkey);
            verifier.public = Some(public);
        }
        Ok(verifier)
    }

    pub fn short_form(&self) -> String {
        format!(
            "$argon2d$m={},t={},p={}${}",
            self.m,
            self.t,
            self.p,
            STANDARD_NO_PAD.encode(self.id)
        )
    }

    pub fn long_form(&self) -> Result<String, CryptoError> {
        let public = self.public.ok_or(CryptoError::InvalidVerifier)?;
        Ok(format!(
            "{}${}",
            self.short_form(),
            STANDARD_NO_PAD.encode(public)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_range_params() {
        // m = 2^32-1 would request terabytes of Argon2 memory.
        let bad = "$argon2d$m=4294967295,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA";
        assert!(Verifier::from_string(bad).is_err());
        let mut v = Verifier::new(1_000_000, 1, 1, [1u8; 16]);
        assert!(v.password_apply("x").is_err());
    }

    #[test]
    fn verifier_form_roundtrip() {
        let mut v = Verifier::new(1024, 4, 1, [7u8; 16]);
        v.password_apply("passphrase").unwrap();
        let long = v.long_form().unwrap();
        let parsed = Verifier::from_string(&long).unwrap();
        assert_eq!(parsed.m, 1024);
        assert_eq!(parsed.id, [7u8; 16]);
        assert_eq!(parsed.public, v.public);
        assert_eq!(Verifier::from_string(&v.short_form()).unwrap().public, None);
    }
}
