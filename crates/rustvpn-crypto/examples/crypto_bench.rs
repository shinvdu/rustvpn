//! Crypto primitive micro-benchmarks, matched to the Go VPN suite.
//!
//! Input sizes mirror `cypherpunks.ru/govpn`'s benchmarks:
//! CnW 16 B, encless 128 B and 1506 B (MTUDefault-9), AONT 128 B.
//! A counting allocator reports allocs/op and bytes/op alongside the
//! timing so the Go `-benchmem` numbers can be compared directly.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rustvpn_crypto::{aont, cnw, encless, poly1305, salsa, xtea::Xtea};

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(
            new_size.saturating_sub(layout.size()) as u64,
            Ordering::Relaxed,
        );
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn bench(name: &str, iters: usize, mut f: impl FnMut()) {
    f(); // warm up
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let b0 = BYTES.load(Ordering::Relaxed);
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = t.elapsed();
    let allocs = (ALLOCS.load(Ordering::Relaxed) - a0) as f64 / iters as f64;
    let bytes = (BYTES.load(Ordering::Relaxed) - b0) as f64 / iters as f64;
    println!(
        "{name:<30} {:9.1} ns/op  {:5.2} allocs/op  {:7.1} B/op",
        elapsed.as_nanos() as f64 / iters as f64,
        allocs,
        bytes
    );
}

fn main() {
    let key = [3u8; 32];
    let nonce = [9u8; 8];
    let r = [5u8; 16];

    let input16 = [7u8; 16];
    bench("cnw chaff 16B", 50_000, || {
        cnw::chaff(&key, &nonce, &input16);
    });
    let chaffed = cnw::chaff(&key, &nonce, &input16);
    bench("cnw winnow 16B", 50_000, || {
        cnw::winnow(&key, &nonce, &chaffed).unwrap();
    });

    for &(label, len) in &[("128B", 128usize), ("MTU (1506B)", 1506)] {
        let data = vec![0x42u8; len];
        let enc_name = format!("encless encode {label}");
        let dec_name = format!("encless decode {label}");
        bench(&enc_name, 5_000, || {
            encless::encode_with_r(&key, &nonce, &r, &data).unwrap();
        });
        let encoded = encless::encode_with_r(&key, &nonce, &r, &data).unwrap();
        bench(&dec_name, 5_000, || {
            encless::decode(&key, &nonce, &encoded).unwrap();
        });
    }

    let aont_data = vec![0x42u8; 128];
    bench("aont encode 128B", 100_000, || {
        aont::encode(&r, &aont_data).unwrap();
    });
    let aont_enc = aont::encode(&r, &aont_data).unwrap();
    bench("aont decode 128B", 100_000, || {
        aont::decode(&aont_enc).unwrap();
    });

    // Components of the classic 789B transport path.
    let xkey = [7u8; 16];
    let xtea = Xtea::new(&xkey);
    let ct = xtea.encrypt_u64(0x0123_4567_89ab_cdef);
    bench("xtea encrypt 8B", 1_000_000, || {
        let _ = xtea.encrypt_u64(0x0123_4567_89ab_cdef);
    });
    bench("xtea decrypt 8B", 1_000_000, || {
        let _ = xtea.decrypt_u64(&ct);
    });

    let skey = [11u8; 32];
    let snonce = [3u8; 8];
    let mut salsa854 = vec![0u8; 854];
    bench("salsa20 xor 854B", 300_000, || {
        salsa::salsa20_xor(&skey, &snonce, &mut salsa854);
    });
    let mut salsa1500 = vec![0u8; 1500];
    bench("salsa20 xor 1500B", 200_000, || {
        salsa::salsa20_xor(&skey, &snonce, &mut salsa1500);
    });

    let pkey = [13u8; 32];
    let msg = vec![0x5au8; 1500];
    for &len in &[16usize, 64, 256, 798, 1500] {
        let tag = poly1305::tag(&pkey, &msg[..len]);
        bench(&format!("poly1305 tag {len}B"), 300_000, || {
            let _ = poly1305::tag(&pkey, &msg[..len]);
        });
        bench(&format!("poly1305 verify {len}B"), 300_000, || {
            let _ = poly1305::verify(&pkey, &msg[..len], &tag);
        });
    }
}
