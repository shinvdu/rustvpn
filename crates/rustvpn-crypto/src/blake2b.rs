//! BLAKE2b-256, matching `github.com/dchest/blake2b.New256`.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub type Blake2b256 = Blake2b<U32>;

#[derive(Clone)]
pub struct Hasher(Blake2b256);

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self(Blake2b256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let out = self.0.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

pub fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}
