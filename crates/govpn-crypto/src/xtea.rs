//! XTEA as used by GoVPN 5.7 (`golang.org/x/crypto/xtea`).
//!
//! 64 rounds, 128-bit key, big-endian block encoding.  Used only as a
//! pseudo-random permutation for transport serial numbers.

const DELTA: u32 = 0x9E37_79B9;
const ROUNDS: usize = 64;

#[derive(Clone, Debug)]
pub struct Xtea {
    table: [u32; ROUNDS],
}

impl Xtea {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut k = [0u32; 4];
        for (i, word) in k.iter_mut().enumerate() {
            *word =
                u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        let mut table = [0u32; ROUNDS];
        let mut sum: u32 = 0;
        let mut i = 0;
        while i < ROUNDS {
            table[i] = sum.wrapping_add(k[(sum & 3) as usize]);
            i += 1;
            sum = sum.wrapping_add(DELTA);
            table[i] = sum.wrapping_add(k[((sum >> 11) & 3) as usize]);
            i += 1;
        }
        Self { table }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let mut v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut i = 0;
        while i < ROUNDS {
            v0 = v0.wrapping_add(((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1) ^ self.table[i]);
            i += 1;
            v1 = v1.wrapping_add(((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0) ^ self.table[i]);
            i += 1;
        }
        block[..4].copy_from_slice(&v0.to_be_bytes());
        block[4..].copy_from_slice(&v1.to_be_bytes());
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let mut v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut i = ROUNDS;
        while i > 0 {
            i -= 1;
            v1 = v1.wrapping_sub(((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0) ^ self.table[i]);
            i -= 1;
            v0 = v0.wrapping_sub(((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1) ^ self.table[i]);
        }
        block[..4].copy_from_slice(&v0.to_be_bytes());
        block[4..].copy_from_slice(&v1.to_be_bytes());
    }

    /// Encrypt a big-endian 64-bit value as a block.
    pub fn encrypt_u64(&self, value: u64) -> [u8; 8] {
        let mut block = value.to_be_bytes();
        self.encrypt_block(&mut block);
        block
    }

    /// Decrypt a block into a big-endian 64-bit value.
    pub fn decrypt_u64(&self, block: &[u8; 8]) -> u64 {
        let mut b = *block;
        self.decrypt_block(&mut b);
        u64::from_be_bytes(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 16];
        let cipher = Xtea::new(&key);
        let mut block = [1, 2, 3, 4, 5, 6, 7, 8];
        let orig = block;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, orig);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, orig);
    }
}
