//! Transport codec micro-benchmarks, matched to the Go VPN suite.
//!
//! * classic 789 B encode/decode (`BenchmarkEnc`/`BenchmarkDec`)
//! * noise at MTU 1515 (payload 1490, `BenchmarkEncNoiseMTU`)
//!
//! Decode benchmarks feed a batch of packets with strictly increasing
//! serials to one decoder, so the replay window is exercised exactly as
//! in the data path; decoder construction is amortised over the batch.
//! A counting allocator reports allocs/op and bytes/op.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Instant;

use rustvpn_proto::{Decoder, Encoder, Mode, Ordering};

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, AtomicOrdering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, AtomicOrdering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, AtomicOrdering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, AtomicOrdering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, AtomicOrdering::Relaxed);
        BYTES.fetch_add(
            new_size.saturating_sub(layout.size()) as u64,
            AtomicOrdering::Relaxed,
        );
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const BATCH: usize = 1024;

fn bench(name: &str, iters: usize, ops_per_iter: usize, mut f: impl FnMut()) {
    f(); // warm up
    let a0 = ALLOCS.load(AtomicOrdering::Relaxed);
    let b0 = BYTES.load(AtomicOrdering::Relaxed);
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = t.elapsed();
    let ops = (iters * ops_per_iter) as f64;
    let allocs = (ALLOCS.load(AtomicOrdering::Relaxed) - a0) as f64 / ops;
    let bytes = (BYTES.load(AtomicOrdering::Relaxed) - b0) as f64 / ops;
    println!(
        "{name:<32} {:9.1} ns/op  {:5.2} allocs/op  {:8.1} B/op",
        elapsed.as_nanos() as f64 / ops,
        allocs,
        bytes
    );
}

fn wires_for(key: [u8; 32], payload: &[u8], mode: Mode) -> Vec<Vec<u8>> {
    let mut enc = Encoder::new(key, true);
    (0..BATCH)
        .map(|_| enc.encode(payload, mode, 1515).unwrap())
        .collect()
}

fn main() {
    let key = [11u8; 32];

    let payload = vec![0x5a; 789];
    let mut enc = Encoder::new(key, true);
    bench("transport encode 789 plain", 200_000, 1, || {
        let _ = enc.encode(&payload, Mode::Plain, 1515).unwrap();
    });
    let wires = wires_for(key, &payload, Mode::Plain);
    bench("transport decode 789 plain", 200, BATCH, || {
        let mut dec = Decoder::new(key, false);
        for w in &wires {
            dec.decode(w, Mode::Plain, 1515, Ordering::Reorderable)
                .unwrap();
        }
    });

    // In-place variants: reused buffers, zero allocation per packet.
    let mut enc_ip = Encoder::new(key, true);
    let mut wire: Vec<u8> = Vec::new();
    let mut scratch: Vec<u8> = Vec::new();
    bench("transport enc 789 plain in-place", 200_000, 1, || {
        enc_ip
            .encode_into(&payload, Mode::Plain, 1515, &mut wire, &mut scratch)
            .unwrap();
    });
    bench("transport dec 789 plain in-place", 200, BATCH, || {
        let mut dec = Decoder::new(key, false);
        let mut out = Vec::new();
        let mut scr = Vec::new();
        for w in &wires {
            dec.decode_into(
                w,
                Mode::Plain,
                1515,
                Ordering::Reorderable,
                &mut out,
                &mut scr,
            )
            .unwrap();
        }
    });

    let payload2 = vec![0x5a; Mode::Noise.max_payload(1515)];
    let mut enc2 = Encoder::new(key, true);
    bench("transport encode MTU noise", 100_000, 1, || {
        let _ = enc2.encode(&payload2, Mode::Noise, 1515).unwrap();
    });
    let wires2 = wires_for(key, &payload2, Mode::Noise);
    bench("transport decode MTU noise", 100, BATCH, || {
        let mut dec = Decoder::new(key, false);
        for w in &wires2 {
            dec.decode(w, Mode::Noise, 1515, Ordering::Reorderable)
                .unwrap();
        }
    });

    let mut enc2_ip = Encoder::new(key, true);
    let mut wire2: Vec<u8> = Vec::new();
    let mut scratch2: Vec<u8> = Vec::new();
    bench("transport enc MTU noise in-place", 100_000, 1, || {
        enc2_ip
            .encode_into(&payload2, Mode::Noise, 1515, &mut wire2, &mut scratch2)
            .unwrap();
    });
    bench("transport dec MTU noise in-place", 100, BATCH, || {
        let mut dec = Decoder::new(key, false);
        let mut out = Vec::new();
        let mut scr = Vec::new();
        for w in &wires2 {
            dec.decode_into(
                w,
                Mode::Noise,
                1515,
                Ordering::Reorderable,
                &mut out,
                &mut scr,
            )
            .unwrap();
        }
    });
}
