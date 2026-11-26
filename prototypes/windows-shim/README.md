# RustVPN Windows Ethernet shim — Phase 0 spike

A **standalone Phase 0 reference implementation** of the L2 Ethernet shim that
a Windows Wintun (L3) client needs in front of the unchanged GoVPN 5.7 tunnel.
It is intentionally not part of the RustVPN Cargo workspace and it does not
modify any existing crate.

> Status: prototype / spike. Not production-ready. The wire MTU is a fixed
> two-sided numeric contract; automatic/path-MTU negotiation is not
> implemented, matching the v1 client design.

## What is here

| File | Purpose |
|---|---|
| `src/ethernet.rs` | Build `[dst][src][0x0800][IPv4]`; validate inbound frames; strip Ethernet padding using IPv4 `total_length`; drop VLAN/IPv6/unknown EtherTypes/oversized/malformed frames. |
| `src/ipv4.rs` | Minimal IPv4 header validation, subnet/multicast/broadcast helpers, checksums for the smoke probe. |
| `src/arp.rs` | 28-byte ARP request/reply parse+build, bounded cache (TTL), bounded per-target pending IP queue, ARP request dedupe/retry, gratuitous ARP, reply learning. |
| `src/mac.rs` | Stable locally administered unicast MAC derived from the verifier id (`02:52:56:xx:xx:xx`). |
| `src/mtu.rs` | `inner_ip_mtu = Mode::max_payload(wire_mtu) - 14`, MSS v4/v6, encless ~4128-byte expansion warning. |
| `src/shim.rs` | Platform-independent orchestration: OS IP -> frames toward the tunnel; tunnel frame -> IP toward Wintun; internal bounded outbound queue for ARP replies/requests and flushed packets. Also `ShimPump`, the concurrency-safe wrapper (dedicated blocking reader thread, bounded channel, no lock across blocking I/O). |
| `src/safety.rs` | Isolated-test-subnet / prefix / peer / adapter-name / ring / netsh-path policy helpers (pure, shared by CLI, adapter and self-test). |
| `src/wintun_verify.rs` | Absolute-path + SHA-256 pinning of `wintun.dll` before load. |
| `src/selftest.rs` | `--self-test` checks shared by unit tests and the CLI. |
| `src/wintun_adapter.rs` | Windows-only minimal Wintun wrapper (`wintun-bindings` 0.7.40 / Wintun 0.14.1 DLL), adapter setup, one-packet UDP probe, close/persistence check. |
| `src/main.rs` | CLI, MTU plan printing, self-test and smoke test. |
| `tests/wire_contract.rs` | Dev-only golden test against `../../crates/rustvpn-proto` (payload budgets and MTU constants). |

### Data flow and queue direction

`rustvpn-net`'s `Tap::recv()` is the **OS → tunnel** direction. Therefore the
Windows `Tap` implementation must:

1. drain the shim's internal outbound queue first (ARP replies and requests,
   plus IP frames released from the ARP pending queue);
2. only then read an IP packet from Wintun, wrap it in Ethernet, and return
   it.

`Tap::send()` is **tunnel → OS**. An inbound IPv4 frame is written to Wintun;
an inbound ARP frame is consumed locally and any reply is put on the internal
queue for the next `recv()` — it is never written back into Wintun.

```
Wintun (L3)  --IP-->  EthernetShim::ingest_os_ip  --frames--> tunnel
Wintun (L3)  <--IP--  EthernetShim::ingest_tunnel_frame <--frames-- tunnel
                         |
                         +-- ARP reply/flush -> internal outbound queue
```

### Concurrency-safe wrapper (`ShimPump`)

Do **not** wrap `EthernetShim` in a plain `Mutex` and hold it across a
blocking Wintun read: `send()` would stall behind `recv()`, and a Tokio worker
would be blocked. `ShimPump` is the safe shape:

* a dedicated blocking thread calls the `L3Device` reader (Wintun
  `recv_timeout`, ~100 ms) and feeds a **bounded** channel (backpressure);
* `recv()` briefly locks the shim to drain `take_outbound()`, then blocks on
  the channel; an OS packet is ingested under a short lock;
* `send()` briefly locks the shim for `ingest_tunnel_frame()`, drops the lock,
  and only then writes the L3 packet;
* idle `recv()` blocks on the channel and returns `Ok(None)` only after
  `shutdown()` (never a busy `Ok(0)` loop);
* a reader error is surfaced as `BrokenPipe` and then the pump reports
  closure.

`WintunAdapter` implements `shim::L3Device`, so the production `Tap` facade
only needs to forward `recv()`/`send()`.

## Pure checks (Linux or Windows)

```sh
cd prototypes/windows-shim
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run -- --self-test
```

`cargo test --all-targets` also runs the dev-only golden test
(`tests/wire_contract.rs`), which checks `inner_ip_mtu + 14 ==
rustvpn_proto::Mode::max_payload(wire)` and the shared MTU constants. The
prototype remains standalone: `rustvpn-proto` is a dev-dependency only.

The same four commands run in CI (`.github/workflows/windows-shim.yml`) on
Linux and `windows-latest`. The Wintun adapter smoke test is **not** run in
CI: it needs administrator rights, the signed Wintun driver and an isolated
host network, so it stays manual (below).

The self-test exits non-zero on any failure. It covers: frame layout, padding
stripping, MAC filtering, VLAN/IPv6/unknown EtherType drops, oversized and
malformed frames, ARP request/reply, cache expiry, pending queue bounds,
gratuitous/reply flush, MAC derivation, MTU/MSS math, the encless expansion
warning, the test-subnet/prefix/peer/MTU/ring/netsh-path policy, the shim's
wire-budget validation, 64-bit checksum folding for large buffers and the
`wintun.dll` hash parser.

## Windows smoke test

Prerequisites (already present on the Phase 0 host): Rust MSVC toolchain,
Visual Studio Build Tools environment, Wintun 0.14.1 x64 DLL, administrator
(rights to create the adapter).

The prototype must live at `<repo>/prototypes/windows-shim` because the
dev-only golden test references `../../crates/rustvpn-proto`; Cargo resolves
that manifest even when the dev-dependency is not built. A synced copy outside
the repository needs the same sibling layout (`crates/` two levels up) or the
Windows adapter check uses a repo checkout instead.

From a Visual Studio Developer Command Prompt (or after
`call D:\BuildTools\VC\Auxiliary\Build\vcvars64.bat`):

```powershell
$env:CARGO_TARGET_DIR = "D:\rustvpn-dev\target-spike"
# optional, only when crates.io is slow:
$env:CARGO_HTTP_MULTIPLEXING = "false"

$repo = "D:\rustvpn-dev\rustvpn"   # checkout containing crates\ and prototypes\
cargo build --manifest-path "$repo\prototypes\windows-shim\Cargo.toml"

& "$env:CARGO_TARGET_DIR\debug\windows-shim-spike.exe" --self-test
& "$env:CARGO_TARGET_DIR\debug\windows-shim-spike.exe" --smoke-test `
    --wintun-file C:\rustvpn-dev\vendor\wintun\wintun.dll `
    --adapter RustVPN-Spike --address 10.88.0.2 --prefix 24 `
    --peer 10.88.0.3 --wire-mtu 1515 --mode plain
    # optional, only after verifying a different binary yourself:
    #   --wintun-sha256 <64-hex>
```

Use `--release` / `\release\` for an optimized build. Note that a plain
`cmd /c "set VAR=value && ..."` keeps the space before `&&` in the value; use
`set "VAR=value"` or a small `.cmd` file (as the Phase 0 build did).

Safety envelope, enforced **before any adapter work**:

* the DLL path must be absolute and its SHA-256 must match the pinned Wintun
  0.14.1 amd64 value
  (`E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`); a
  mismatch, relative path or unreadable file refuses the load. `--wintun-sha256`
  overrides the pin but the file is still hashed and verified;
* the adapter address must be inside `10.88.0.0/24`, the prefix must be
  `/24../32` (so `--prefix 8`, `--prefix 1` and any off-subnet address are
  rejected), and the address cannot be the subnet network/broadcast;
* `--peer` must be another address inside `10.88.0.0/24` and `--peer-port`
  must be non-zero;
* the derived inner IP MTU must be `>= 576`; wire MTUs that would produce a
  53-byte IP MTU or TCP MSS 0 (for example plain 68) are refused;
* the ring capacity must be a power of two in `128 KiB..64 MiB`;
* adapter names are restricted to ASCII letters/digits/`-_.`.

The smoke test then:

* loads `wintun.dll` from the absolute, verified path;
* probes the adapter name and only falls back to creation on a genuine
  "not found" OS error (access-denied, driver and transient errors are
  propagated, never masked by creating a second device);
* opens or creates only the named adapter with a deterministic per-name GUID
  and configures only the validated test address/prefix plus interface MTU
  `inner_ip_mtu` (1500 for plain wire 1515);
* **never sets a default gateway, default route, DNS or firewall rule**;
* enables the interface with `%SystemRoot%\System32\netsh.exe` by absolute path
  (no `PATH`/cwd lookup); a non-zero `admin=enable` result stays non-fatal and
  is reported as a note;
* binds a UDP socket to the adapter address, sends one datagram to
  `--peer` (default `10.88.0.3`, inside the test subnet), reads the packet
  from Wintun, injects a matching reply, and reports whether the socket
  received it;
* prints adapter name/index/MTU/addresses and the Wintun driver version;
* closes the session and adapter, then reports whether the adapter survived
  the close.

Wintun removes an adapter created with `WintunCreateAdapter` when the last
handle closes. If the adapter pre-existed (opened rather than created), or
survives for any other reason, close it manually:

```powershell
Remove-NetAdapter -Name "RustVPN-Spike" -Confirm:$false
```

The connected `10.88.0.0/24` on-link route is created implicitly by assigning
the address. It is confined to the isolated test subnet by the /24.. /32
prefix rule above; no default route is installed. If the ACK for the injected
UDP reply is blocked by the Windows firewall, the read direction is still
valid and the report says so.

Hash pinning is a prototype control only. A production service must own the
DLL with restrictive ACLs, pin code-signing/catalog identity and re-verify at
load time (or load from a signed, immutable package).

### Observed on the Phase 0 host (2026-11-26)

The adapter GUID is now derived from the adapter name (previously a single
fixed GUID); the rest of this historical observation still applies.

* Windows 10 Pro 19045 x64, Rust 1.100.0 MSVC, Wintun DLL 0.14.1.
* Adapter created as `RustVPN-Spike`, `created=true`, interface index 44 (the
  index is not stable across runs), MTU 1500, addresses included
  `10.88.0.2` and an OS-generated IPv6 link-local address.
* UDP probe: OS->Wintun read of the 44-byte UDP packet and Wintun->OS
  injection of the 43-byte reply both succeeded; the socket received the
  round-trip payload.
* Without a settle delay, the injected reply was intermittently dropped by
  Windows (socket receive timed out, WSAETIMEDOUT 10060). A 250 ms wait after
  observing the outbound datagram made it reliable (3/3 final runs).
* The adapter was removed when the last handle closed and the implicit
  `10.88.0.0/24` route disappeared with it. The pre-existing default route
  (illustrated here as `192.0.2.1` in host-local testing) was unchanged.
* The first adapter creation auto-installed the signed `wintun.sys` driver
  (no reboot was required). After the last adapter closed, the `wintun`
  service was `Stopped`/`Manual`; the driver file remains installed. Removing
  it is optional and was not done to avoid unrelated system changes.
* `netsh interface set interface admin=enable` exited 1 although the adapter
  was already up after the static address assignment; the probe confirms it
  is non-fatal.
* Windows generated IPv6 link-local/MLD traffic on the new interface. The
  shim drops non-IPv4 packets; the smoke test reports the aggregate count
  rather than one line per packet.

## Integration notes for `rustvpn-net`

This is what can be lifted once the P0 API/MTU work lands:

* `ethernet.rs`, `ipv4.rs`, `arp.rs`, `mac.rs`, `mtu.rs` are pure and have no
  Windows dependency; they can move under `rustvpn-net/src/windows_shim/`
  essentially unchanged (replace the local `Mode`/`MTU_MAX` constants with
  `rustvpn_proto::Mode`).
* `EthernetShim` + `ShimPump` are the suitable core for a Windows `Tap`
  facade. The safe shape (already implemented here) is:
  * a dedicated blocking reader thread feeding a bounded OS->tunnel channel
    (or a genuinely non-blocking/async receive) behind the same `recv`/`send`
    shape;
  * lock the shim only for `take_outbound()` / `ingest_os_ip()` /
    `ingest_tunnel_frame()`; **never** across a blocking Wintun read/write and
    never across an await;
  * `Tap::recv()` drains `take_outbound()` first, then waits for the next OS
    packet; `Tap::send()` dispatches IPv4 vs ARP and writes Wintun after
    dropping the shim lock;
  * `ARP` stats/log rate limiting and MTU-aware drop accounting;
  * the MAC derived from the verifier id at session start, and an optional
    gratuitous ARP after connect.
* `ShimConfig` now carries `wire_mtu` + `mode` and validates
  `inner_ip_mtu + 14 <= Mode::max_payload(wire_mtu)` and `inner_ip_mtu >= 42`;
  the adapter/smoke path additionally refuses `inner_ip_mtu < 576`. The inner
  MTU must come from the fixed wire-MTU helper
  (`wire = Mode::max_payload(configured_mtu) - 14`), not from a locally probed
  value.
* `AdapterConfig` deliberately uses `wintun-bindings` directly (absolute,
  hash-pinned DLL path; absolute `%SystemRoot%\System32\netsh.exe`; explicit
  open-vs-create classification), so it can be swapped for `tun` or a
  service-owned adapter without touching the shim.

## Must wait for the P0 fixes / later phases

* Final `TapConfig`/`Tap::open` API and the placement of address/gateway/DNS
  arguments.
* The finalized numeric wire-MTU contract and MTU helper ownership (this spike
  duplicates the reference arithmetic on purpose).
* `rustvpn-client-ipc` transport abstraction (named pipes), Windows service
  lifecycle, tunnel lock, route/DNS/NRPT installation, crash cleanup and
  IPv6 blocking — all out of scope here.
* Windows firewall behavior for injected test traffic, and adapter
  persistence across service restarts.
* Wintun DLL distribution/licensing and signature verification (the prototype
  only pins a SHA-256; production needs code-signing/catalog pinning, ACLs and
  re-verification).

## Limitations

* IPv6, VLAN, non-IP EtherTypes and unknown unicast are dropped by design.
* No DHCP, no proxy ARP, no IPv6 neighbor discovery.
* No fragmentation handling: oversized outbound IP packets are dropped.
* ARP cache/pending/outbound queues are bounded and drop with counters, but
  the prototype does not yet rate-limit log lines.
* The self-test and the on-link UDP probe are reference checks, not a
  production acceptance suite. CI cannot run the adapter smoke test (admin +
  isolated network + signed driver); it remains a manual host check.