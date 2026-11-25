//! AVX2 Salsa20 backend: eight independent Salsa20 states per core call.
//!
//! One AVX2 register holds eight 32-bit lanes.  The sixteen Salsa20 state
//! words become sixteen `__m256i` values, so eight independent blocks or
//! eight independent streams are evaluated in parallel.  Runtime feature
//! detection keeps a scalar fallback.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(crate) const C0: u32 = 0x6170_7865;
pub(crate) const C1: u32 = 0x3320_646e;
pub(crate) const C2: u32 = 0x7962_2d32;
pub(crate) const C3: u32 = 0x6b20_6574;

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl7(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(v, 7), _mm256_srli_epi32(v, 25))
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl9(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(v, 9), _mm256_srli_epi32(v, 23))
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl13(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(v, 13), _mm256_srli_epi32(v, 19))
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl18(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(v, 18), _mm256_srli_epi32(v, 14))
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn qr(x: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] = _mm256_xor_si256(x[b], rotl7(_mm256_add_epi32(x[a], x[d])));
    x[c] = _mm256_xor_si256(x[c], rotl9(_mm256_add_epi32(x[b], x[a])));
    x[d] = _mm256_xor_si256(x[d], rotl13(_mm256_add_epi32(x[c], x[b])));
    x[a] = _mm256_xor_si256(x[a], rotl18(_mm256_add_epi32(x[d], x[c])));
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn core(mut x: [__m256i; 16]) -> [__m256i; 16] {
    let init = x;
    for _ in 0..10 {
        // column rounds
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 5, 9, 13, 1);
        qr(&mut x, 10, 14, 2, 6);
        qr(&mut x, 15, 3, 7, 11);
        // row rounds
        qr(&mut x, 0, 1, 2, 3);
        qr(&mut x, 5, 6, 7, 4);
        qr(&mut x, 10, 11, 8, 9);
        qr(&mut x, 15, 12, 13, 14);
    }
    for i in 0..16 {
        x[i] = _mm256_add_epi32(x[i], init[i]);
    }
    x
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn broadcast(v: u32) -> __m256i {
    _mm256_set1_epi32(v as i32)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn init_single(key: &[u8; 32], nonce: &[u8; 8], block: u64) -> [__m256i; 16] {
    let mut k = [0u32; 8];
    for (i, w) in k.iter_mut().enumerate() {
        *w = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    let n0 = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    let n1 = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    let lo = block as u32;
    let hi = (block >> 32) as u32;
    [
        broadcast(C0),
        broadcast(k[0]),
        broadcast(k[1]),
        broadcast(k[2]),
        broadcast(k[3]),
        broadcast(C1),
        broadcast(n0),
        broadcast(n1),
        _mm256_setr_epi32(
            lo as i32,
            lo.wrapping_add(1) as i32,
            lo.wrapping_add(2) as i32,
            lo.wrapping_add(3) as i32,
            lo.wrapping_add(4) as i32,
            lo.wrapping_add(5) as i32,
            lo.wrapping_add(6) as i32,
            lo.wrapping_add(7) as i32,
        ),
        _mm256_setr_epi32(
            hi as i32, hi as i32, hi as i32, hi as i32, hi as i32, hi as i32, hi as i32, hi as i32,
        ),
        broadcast(C2),
        broadcast(k[4]),
        broadcast(k[5]),
        broadcast(k[6]),
        broadcast(k[7]),
        broadcast(C3),
    ]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn transpose_store(x: &[__m256i; 16], words: &mut [u32; 128]) {
    for i in 0..16 {
        _mm256_storeu_si256(words[i * 8..].as_mut_ptr() as *mut __m256i, x[i]);
    }
}

/// XOR `data` with Salsa20 keystream (8-byte nonce), starting at block 0.
/// Requires AVX2.  Every full 64-byte block is handled here (eight blocks
/// per core call); the caller's scalar fallback only sees the final
/// `len % 64` bytes.  Returns the number of bytes consumed.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn xor_blocks(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8]) -> usize {
    let mut off = 0usize;
    let mut block = 0u64;
    let mut words = [0u32; 128];
    while data.len() - off >= 64 {
        // One core call computes eight consecutive blocks; use only the
        // blocks that are still needed in this pass.
        let blocks = ((data.len() - off) / 64).min(8);
        let x = core(init_single(key, nonce, block));
        transpose_store(&x, &mut words);
        for j in 0..blocks {
            let base = off + j * 64;
            for i in 0..16 {
                let dst = data.as_mut_ptr().add(base + i * 4) as *mut u32;
                let cur = core::ptr::read_unaligned(dst);
                core::ptr::write_unaligned(dst, cur ^ words[i * 8 + j]);
            }
        }
        off += blocks * 64;
        block += blocks as u64;
    }
    // Final partial block: one more AVX2 core call XORs only the bytes
    // still needed, so no scalar Salsa20 tail remains.
    if off < data.len() {
        let x = core(init_single(key, nonce, block));
        transpose_store(&x, &mut words);
        let remaining = data.len() - off;
        let words_n = remaining / 4;
        for i in 0..words_n {
            let dst = data.as_mut_ptr().add(off + i * 4) as *mut u32;
            let cur = core::ptr::read_unaligned(dst);
            core::ptr::write_unaligned(dst, cur ^ words[i * 8]);
        }
        let tail = remaining - words_n * 4;
        if tail > 0 {
            let ks = words[words_n * 8].to_le_bytes();
            let pos = off + words_n * 4;
            for b in 0..tail {
                data[pos + b] ^= ks[b];
            }
        }
        off = data.len();
    }
    off
}

/// Generate eight independent 512-byte Salsa20 keystreams for eight
/// 8-byte nonces under one key.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn keystream8_512(key: &[u8; 32], nonces: &[[u8; 8]; 8]) -> [[u8; 512]; 8] {
    let mut out = [[0u8; 512]; 8];
    let mut k = [0u32; 8];
    for (i, w) in k.iter_mut().enumerate() {
        *w = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    let mut n0 = [0u32; 8];
    let mut n1 = [0u32; 8];
    for (j, nonce) in nonces.iter().enumerate() {
        n0[j] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        n1[j] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    }
    let mut words = [0u32; 128];
    for block in 0..8u64 {
        let mut x = [
            broadcast(C0),
            broadcast(k[0]),
            broadcast(k[1]),
            broadcast(k[2]),
            broadcast(k[3]),
            broadcast(C1),
            _mm256_setr_epi32(
                n0[0] as i32,
                n0[1] as i32,
                n0[2] as i32,
                n0[3] as i32,
                n0[4] as i32,
                n0[5] as i32,
                n0[6] as i32,
                n0[7] as i32,
            ),
            _mm256_setr_epi32(
                n1[0] as i32,
                n1[1] as i32,
                n1[2] as i32,
                n1[3] as i32,
                n1[4] as i32,
                n1[5] as i32,
                n1[6] as i32,
                n1[7] as i32,
            ),
            broadcast(block as u32),
            broadcast((block >> 32) as u32),
            broadcast(C2),
            broadcast(k[4]),
            broadcast(k[5]),
            broadcast(k[6]),
            broadcast(k[7]),
            broadcast(C3),
        ];
        x = core(x);
        transpose_store(&x, &mut words);
        for lane in 0..8 {
            for i in 0..16 {
                let at = block as usize * 64 + i * 4;
                out[lane][at..at + 4].copy_from_slice(&words[i * 8 + lane].to_le_bytes());
            }
        }
    }
    out
}
