# Performance

**English** | [中文](../zh/performance.md) | [Русский](../ru/performance.md)

This page combines the Go-side optimization record with the same-machine
Rust-vs-Go comparison. All numbers are microbenchmarks of the packet
codec (no TAP, no NIC) unless stated otherwise, and they vary with a
shared/virtualized host; compare only numbers from the same batch.

## Environment and method

- CPU: AMD Ryzen 5 PRO 5675U (Zen3, AVX2), 12 threads.
- Go 1.22.2 linux/amd64, `GO111MODULE=off GOPATH=$(pwd)`.
- Rust edition 2021, `cargo build --release`, runtime AVX2 dispatch.
- Go: `-count 5 -benchmem`; Rust: `crypto_bench` / `proto_bench` with an
  internal counting allocator. Results are medians of five runs.
- Inputs aligned with the Go benchmarks (`MTUDefault = 1515`): classic
  789 B, noise MTU 1490 B, encless 128 B, encless MTU 1506 B, CnW 16 B,
  AONT 128 B.

```bash
# Go (requires the upstream GoVPN 5.7 source tree, not included here)
cd /path/to/upstream-govpn
GO111MODULE=off GOPATH=$(pwd) go test -run XXX -bench . -benchmem -count 5 \
  cypherpunk.ru/govpn cypherpunk.ru/govpn/cnw cypherpunk.ru/govpn/aont

# Rust (from this repository root)
cargo build --release --examples
for i in 1 2 3 4 5; do ./target/release/examples/crypto_bench; done
for i in 1 2 3 4 5; do ./target/release/examples/proto_bench; done
```

## Go-side optimizations

The Go implementation was optimized first, both to remove real
bottlenecks and to establish a fair baseline. Wire bytes are unchanged.

| Change | Result |
|---|---|
| CnW: 1-byte Poly1305 formula + one HSalsa20 per packet | Chaff **4.45×**, Winnow **6.72×** |
| Encless: remove intermediate slices/copies | 128 B decode **5.49×**, MTU decode **5.44×**; decode allocs 5 → 1 |
| Peer send path: no per-packet `append`, targeted zeroing | classic encrypt **1.54×**, decrypt **1.13×**; allocs 1 → 0 |
| Noise/encless MTU validation | oversized frames are rejected instead of silently truncated |
| UDP server data path | no per-packet goroutine, no per-peer 2-buffer limit, no per-packet strings/global lock |
| Identity cache, config/TAP concurrency | sequential scan, RWMutex snapshots, TAP read errors no longer panic |

Before/after (median of 3):

| Scenario | Before | After | Gain |
|---|---:|---:|---:|
| classic 789 B encrypt | 2,805 ns | 1,827 ns | 1.54× |
| classic 789 B decrypt | 2,068 ns | 1,827 ns | 1.13× |
| classic noise MTU encrypt | 4,217 ns / 359 MB/s | 3,040 ns / 490 MB/s | 1.39× |
| encless 128 B encode | 32,817 ns | 11,232 ns | 2.92× |
| encless 128 B decode | 54,688 ns | 9,964 ns | 5.49× |
| encless MTU encode | 42,288 ns / 35.8 MB/s | 15,326 ns / 98.3 MB/s | 2.76× |
| encless MTU decode | 75,593 ns / 20.0 MB/s | 13,889 ns / 108.8 MB/s | 5.44× |
| CnW Chaff (16 B) | 41,097 ns | 9,235 ns | 4.45× |
| CnW Winnow (16 B) | 58,928 ns | 8,769 ns | 6.72× |

Why CnW matters: Winnow performs 512 one-byte Poly1305 computations per
packet (256 one-time keys × 2 candidate tags). A general Poly1305 call
is dominated by key parsing and finalization, so the optimized form
computes both candidate tags for a key with **one** 130-bit multiply:

```text
block("0") = 0x30 + 0x01 * 2^8 = 0x130
block("1") = 0x131

h0   = 0x130 * r  mod (2^130 - 5)
h1   = (h0 + r)   mod (2^130 - 5)
tag0 = low128(h0 + s)
tag1 = low128(h1 + s)
```

with `r` clamped per RFC 8439 and constant-time selection/comparison.
The Rust implementation uses the same formula and additionally batches
eight independent keystreams through AVX2.

## Rust implementation choices

- `encode_into` / `decode_into` with reused buffers: classic/noise reach
  **0 allocations per packet** in the peer path.
- AVX2 Salsa20 covers all complete 64-byte blocks *and* the final partial
  block; the scalar tail was removed. CnW calls the 8-stream AVX2 core in
  batches of 8 bytes.
- Poly1305 is pinned to the software backend. On this Zen3 machine the
  crate's AVX2 backend has a ~845 ns fixed cost and is 2.5–4.5× slower
  than the scalar backend across 16 B–1500 B.
- UDP uses 64-datagram `recvmmsg`/`sendmmsg`; TAP uses io_uring with an
  eventfd wakeup and an epoll fallback.

## Rust vs Go (same batch, medians)

`Go/Rust > 1` means Rust is faster.

| Scenario | Go ns/op | Go allocs | Rust ns/op | Rust allocs | Go/Rust |
|---|---:|---:|---:|---:|---:|
| classic 789 B encode | 1,967 | 0 | 1,308 | 0 | **1.50×** |
| classic 789 B decode | 1,979 | 0 | 1,338 | 0 | **1.48×** |
| noise MTU encode (1490 B) | 3,320 | 0 | 2,070 | 0 | **1.60×** |
| noise MTU decode (1490 B) | — | — | 2,122 | 0 | — |
| encless 128 B encode | 13,128 | 5 | 7,023 | 2 | **1.87×** |
| encless 128 B decode | 10,970 | 1 | 7,040 | 1 | **1.56×** |
| encless MTU encode (1506 B) | 17,240 | 5 | 9,820 | 2 | **1.76×** |
| encless MTU decode (1506 B) | 15,257 | 1 | 10,209 | 1 | **1.49×** |
| CnW chaff 16 B | 10,410 | 1 | 6,025 | 1 | **1.73×** |
| CnW winnow 16 B | 9,845 | 1 | 6,122 | 1 | **1.61×** |
| AONT 128 B encode | 1,355 | 3 | 910 | 1 | **1.49×** |
| AONT 128 B decode | 1,312 | 3 | 982 | 1 | **1.34×** |

Single-core payload throughput:

| Scenario | Go | Rust |
|---|---:|---:|
| classic 789 B encode | 401 MB/s | 603 MB/s |
| classic 789 B decode | 399 MB/s | 590 MB/s |
| noise MTU encode | 449 MB/s | 720 MB/s |
| noise MTU decode | — | 702 MB/s |
| encless MTU encode | 87.4 MB/s | 153.4 MB/s |
| encless MTU decode | 98.7 MB/s | 147.5 MB/s |

The Rust convenience API (`encode`/`decode`) allocates a result buffer and
is 1–6% slower than the in-place path; production uses the in-place path
except for the UDP batcher handoff (currently 1 allocation per packet).

## Component timings (classic 789 B, Rust)

| Component | Time | Note |
|---|---:|---|
| XTEA encrypt/decrypt 8 B | 76.0 / 73.9 ns | 64 rounds, precomputed tables |
| Salsa20 XOR 854 B | 574.7 ns | AVX2, all blocks + tail |
| Salsa20 XOR 1500 B | 793.5 ns | AVX2 |
| Poly1305 tag 798 B (soft) | 590.7 ns | pinned backend |
| Poly1305 tag 798 B (AVX2 path) | 1,523 ns | not used |
| Poly1305 tag 16 B (soft / AVX2) | 24.8 / 845.1 ns | AVX2 fixed cost visible |

76 + 575 + 591 ≈ 1,242 ns, plus ~60 ns of copying/framing, matches the
measured 1,308 ns.

## Caveats

- Results are from a shared/virtualized host; a single run can vary by
  ±20%. Different Go batches (earlier vs later) differ by 10–15%, so do
  not mix numbers across documents.
- Batch I/O throughput is not in this table: end-to-end pps depends on
  the NIC, kernel and TAP backend, and the test host cannot create TAP
  without privileges. Correctness of the batching/io_uring paths is
  covered by loopback/socketpair tests.
- There is no Go noise-MTU decode benchmark, so that row reports Rust
  only.
- Remaining opportunities: multi-packet SIMD Poly1305, buffer-pooled
  encless encoding, XTEA bitslicing across packets, and a timer wheel for
  very large peer counts. The server's UDP send handoff costs 1 alloc per
  packet; a pool could remove it (<100 ns/packet expected).

Next: [Overview](index.md).