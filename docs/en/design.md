# Design

**English** | [中文](../zh/design.md) | [Русский](../ru/design.md)

This page describes the implemented architecture. The original design
proposal is kept in this repository as [`docs/design.md`](../design.md)
(written before the rename, so it still uses the old `govpn-*` names);
this version records what was actually built and why.

## Goals

1. **Wire compatibility first.** The Rust binaries must be drop-in
   replacements for GoVPN 5.7. Protocol bytes, CLI flags, defaults,
   `peers.yaml`, scripts, stats JSON and proxy behaviour are all part of
   the compatibility surface.
2. **A second implementation as an oracle.** Differential testing against
   the Go code catches protocol drift that unit tests alone would miss.
3. **A predictable data path.** No per-packet heap allocation in steady
   state, bounded queues, explicit buffer ownership, and batched I/O.
4. **Operational parity.** Same deployment model, permissions and
   diagnostics as the Go daemons.

Non-goals for this version: a protocol v2, Windows/macOS clients, a
cross-platform client GUI (a Linux MVP exists, see
[`client-ui.md`](../client-ui.md); the cross-platform plan is
[`client-ui-plan.md`](../client-ui-plan.md)), routing/NAT management,
load-balancing control planes, or changing any cryptographic algorithm (that
would break interoperability). The server admin Web UI is implemented as a
separate process; see "Management plane" below.

## Workspace layout

```text
.
├── crates/rustvpn-crypto/   # primitives, AONT/CnW/encless, verifier, EGD
├── crates/rustvpn-proto/    # packet layout, codec, handshake state machines
├── crates/rustvpn-net/      # TAP, config, scripts, stats, peer lifecycle,
│                            # UDP batching, io_uring TAP
├── crates/rustvpn-control/  # admin↔server control protocol (Unix socket, JSON)
├── crates/rustvpn-admin/    # rustvpn-admind + rustvpn-admin-passwd (HTTP UI, SQLite)
├── crates/rustvpn-client/   # client binary
├── crates/rustvpn-server/   # server binary
├── crates/rustvpn-verifier/ # verifier binary
├── testdata/                # Go-generated differential vectors
└── docs/                    # this manual (en/zh/ru) + upstream design notes
```

`rustvpn-crypto` and `rustvpn-proto` are pure logic with no async or I/O, so
they can be unit-tested and fuzzed independently. `rustvpn-net` owns the
OS-facing pieces. The binaries are thin composition layers. `rustvpn-control`
holds only the shared DTOs and frame codec; the data-plane crates do not
depend on admin dependencies (axum, SQLite, static assets).

## Control plane

The daemons run on Tokio:

- TCP sessions and the HTTP CONNECT proxy are Tokio tasks.
- Handshakes, TAP opening, scripts and stats are control-plane work.
- Handshake admission uses token buckets: 5/s per source IP (burst 10)
  and 200/s globally (burst 400); TCP also uses a concurrency semaphore.
- Configuration is held in an `RwLock<ConfigSet>` and refreshed every
  60 seconds; a failed parse keeps the previous set.

Each UDP peer has a decode task fed by an mpsc channel; TCP has a reader
task per connection. This is deliberately simpler than the original
"one worker per core" proposal: it preserves correctness and bounded
queues, while the expensive parts (batching, SIMD, buffer reuse) are
handled inside the tasks.

## Management plane (admin Web UI)

The server admin UI is a **separate program** that shares only libraries with
the data plane. `rustvpn-server` does not link axum, SQLite or static assets,
and is not taken down by an admin failure.

```text
Browser ──TLS──▶ Caddy/Nginx ──▶ rustvpn-admind
                                  ├─ HTTP API + embedded static UI (vanilla JS + Canvas)
                                  ├─ Argon2id login / session cookie / CSRF / admin|viewer
                                  ├─ SQLite history, audit, config backups
                                  └─ config validation and atomic write
                                           │
                                           │ /run/rustvpn/control.sock
                                           │ 4B BE length + JSON, protocol v1
                                  rustvpn-server
                                  ├─ UDP/TCP/TAP data plane
                                  └─ status/sessions/kick/reload/
                                     recent_sessions/validate_config/subscribe
```

### Control protocol

- Unix domain socket only; no TCP listener. Enabled with `-control PATH`
  (off by default).
- Frames are a 4-byte big-endian length plus JSON, capped at 4 MiB. `hello`
  checks the protocol version and rejects incompatible peers rather than
  silently degrading.
- Requests: `hello`, `status`, `sessions`, `kick`, `reload`,
  `recent_sessions`, `validate_config`, `subscribe`.
- Events: `session_started`, `session_ended` (with final counters and end
  reason), `config_reloaded`, `lagged`, `server_shutdown`. The server keeps
  the last 1024 end events for admin reconnection reconciliation.
- Authentication: `SO_PEERCRED` allows root or the socket's group
  (`-control-group`; without it, only the server user). Socket mode is
  `0660`/`0600`; at most 8 concurrent control connections.
- No `write_config`/`shutdown` command: the admin validates and writes the
  file, while service lifecycle stays with systemd.

### Privilege boundary

| Process | User/group | Capabilities |
|---|---|---|
| `rustvpn-server` | `rustvpn`, group `rustvpn-adm` | `CAP_NET_ADMIN`/`CAP_NET_RAW`; may run scripts |
| `rustvpn-admind` | `rustvpn-admin`, primary group `rustvpn-adm` | **no capabilities**; may write the config dir and SQLite |
| Control socket | `rustvpn:rustvpn-adm` `0660` | admin group only |
| Config dir | `root:rustvpn-adm` `2770` | server reads; admind renames atomically |
| Script dir | `root:root` `0755` | not writable by the admin group |

With `-control`, the server **requires** at least one `-script-dir` and
refuses to start otherwise. Every up/down path must be inside the allow-list,
must exist, and every directory from the allow-list root to the script's
parent must be owned by root/the server user and not group- or
world-writable. The server revalidates before loading config and before every
script execution. The admin may only fill in script paths; it cannot edit or
upload script contents.

### Config writes

1. Render YAML and validate with the same `ConfigSet`.
2. Call the server's `validate_config` for the script/path preflight.
3. Back up → temporary file in the same directory → fsync → `rename`.
4. Call `reload`; the server applies it immediately.

Writes use an ETag optimistic lock. When the server is offline the preflight
fails and the admin refuses to write, keeping config, backups, history and
audit read-only. This avoids leaving a half-valid config that the server
would reject at its next start.

### Session accounting

- The admin polls active sessions every 10 seconds for rates; the
  `session_started`/`session_ended` events define session boundaries.
- Counters carried by `session_started` seed the first sampling baseline; the
  immediately fired first tick is skipped, and unknown sessions use a zero
  baseline so pre-session traffic is not attributed to the first interval.
- The server captures final counters in `end_session()` and emits
  `session_ended`, so the last sampling interval is not lost.
- Each server start generates a random 52-bit `server_instance` used as the
  session-id base. This avoids SQLite primary-key collisions after a restart
  and stays within JavaScript's safe-integer range.
- On restart the admin pulls `sessions` + `recent_sessions` first and only
  marks open rows the server no longer knows as `server_restart`.

### Admin and client UI

- Auth: Argon2id passwords, HttpOnly + SameSite=Strict session cookie, CSRF on
  writes, login rate limiting; roles `admin`/`viewer`.
- Pages: overview, client list/detail, 1h/24h/7d/30d traffic charts, session
  history, config preview/apply/backup/restore, audit, SSE live refresh,
  Prometheus `/metrics`, and health checks.
- Listens on `127.0.0.1:8080` by default, reached over an SSH tunnel or a TLS
  reverse proxy; the control socket never leaves the host.
- Storage: `/var/lib/rustvpn/admin.db` (SQLite WAL) holds accounts, history and
  audit; `peers.yaml` remains the single source of truth for config.
- **The client GUI has a Linux MVP** ([`client-ui.md`](../client-ui.md)): a
  Tauri 2 static UI, an unprivileged GUI, the least-privilege
  `rustvpn-clientd` daemon and the shared `rustvpn-client-core`. CLI and GUI
  remain separate programs sharing libraries only. Windows/macOS and mobile
  are not implemented; the hard part there is the user-space Ethernet shim on
  L3-only systems, not the UI toolkit
  ([`client-ui-plan.md`](../client-ui-plan.md)).

## Data path

### Send

1. Read a frame from TAP.
2. Validate the mode-specific payload limit (`MTU-1`, `MTU-25` or
   `MTU-9`). Oversized frames are rejected and counted, never truncated.
3. Write the `0x80` pad, optionally pad to MTU (noise/CPR).
4. Encode with `Encoder::encode_into` into reused buffers: serial →
   XTEA PRP → Salsa20 keystream split → Poly1305 tag.
5. Hand the wire buffer to the shared UDP batcher (`sendmmsg`, up to 64
   datagrams per syscall) or write it to the TCP stream.
6. Update atomic counters and return the buffer to the pool.

### Receive

1. `recvmmsg` returns up to 64 datagrams per syscall (or one TCP frame).
2. Decode with `Decoder::decode_into` into reused `payload`/`scratch`
   buffers; verify the MAC before accepting the serial.
3. Update the replay window, strip padding, verify trailing zeros.
4. Write the Ethernet frame to TAP (io_uring or epoll-backed async write).
5. Update stats; duplicates/old serials are counted and dropped.

`encode_into`/`decode_into` keep the classic and noise paths at zero
allocations per packet; encless still allocates for the AONT/CnW
transform.

### I/O backends

- UDP: `recvmmsg`/`sendmmsg` batching, one shared batcher per socket.
- TAP: io_uring with an eventfd wakeup (no idle wakeups), with an epoll
  fallback. `GOVPN_IO_URING=0` forces the fallback.
- Replay window: `[u64; 5]`-style 257-bit bitmap, O(1), no hashing, no
  allocation.
- Rekey: the client triggers a fresh handshake after 4 GiB
  (`MAX_BYTES_PER_KEY = 1 << 32`) of wire traffic.

### SIMD

Salsa20 has an AVX2 backend with runtime dispatch in
`rustvpn-crypto/src/salsa_simd.rs`, covering eight blocks (or eight
independent CnW keystreams) per core call. The scalar RustCrypto path is
the reference and is differentially tested against the AVX2 path. The
`unsafe` surface is confined to that module; all other code uses safe Rust.

## Cryptography choices

| Primitive | Implementation |
|---|---|
| Salsa20/XSalsa20 | RustCrypto `salsa20` + AVX2 fast path |
| Poly1305 | RustCrypto `poly1305`, software backend pinned via `.cargo/config.toml` |
| XTEA | in-tree, byte-compatible with Go |
| BLAKE2b-256 | RustCrypto `blake2` |
| Argon2d v1.3 | RustCrypto `argon2` (`m/t/p`, 32-byte output as Ed25519 seed) |
| Ed25519 | `ed25519-dalek` |
| X25519 + Elligator | `curve25519-dalek` + a port of Go's `extra25519` representative encoding |
| Constant time | `subtle` for MAC/pad comparisons |

The Poly1305 software-backend pin is a measured choice: on Zen3 the
crate's AVX2 backend has a large fixed per-message cost and is several
times slower than its scalar backend for small packets. Go vectors confirm
byte equality. See [Performance](performance.md).

## Protocol invariants covered by tests

- Handshake: four message lengths (48/80/120/16), field order, padding
  position, `IDtag`, and the resulting master key.
- Transport: tag/ciphertext/nonce layout, Salsa20 offsets, Poly1305
  coverage, serial parity/step and XTEA byte order.
- Replay: UDP window semantics and TCP exact-ordering rules.
- Encless: AONT/CnW byte sequence, 4128-byte expansion, XSalsa20 nonce
  layout, minimum-length rejection.
- Noise: fill length and zero padding.
- Timesync: second-granularity timestamp XOR in `IDtag`.
- Verifier: string format, Argon2d parameters, Ed25519 seed derivation.
- Config: field names/defaults, MTU clamping, encless→noise, long-form
  verifier requirement.
- Scripts: `GOVPN_IFACE`/`GOVPN_REMOTE`; server uses stdout of `up` when
  `iface` is empty.
- Stats: JSON field names/types.
- Proxy: CONNECT response and raw-TCP handoff.

## Testing strategy

- **Differential vectors.** `testdata/go_vectors.json` contains
  byte-exact outputs from the Go implementation for every primitive,
  transport mode, handshake message and verifier form. Tests compare both
  directions.
- **Unit/equivalence tests.** AVX2 vs scalar keystreams, CnW/AONT
  roundtrips, replay-window properties, `encode_into` equivalence with the
  convenience API, loopback `sendmmsg`/`recvmmsg`, and a socketpair
  roundtrip through the io_uring loop.
- **Management plane.** Control-protocol codec and version negotiation,
  socket permissions and `SO_PEERCRED`, script allow-list and
  execution-time revalidation, config preflight, sampling baselines and
  orphan reconciliation. The admin is unit-tested against a fake control
  socket; end-to-end tests use netns + TAP to verify kick, final counters
  and reconnect reconciliation.
- **Interoperability matrix.** `{Go,Rust} × {client,server} × {UDP,TCP,
  proxy} × {plain,noise,encless}` with TAP and network namespaces,
  including ICMP through the tunnel. The matrix is recorded in the root
  README.
- **Fuzzing** (not yet wired into CI) is the natural next step for packet
  parsing, handshake state, TCP framing, YAML/verifier parsing and
  AONT/CnW decoding; the pure-logic crates make this straightforward.

## Deviations and open items

- No thread-per-core `SO_REUSEPORT` sharding; one socket per protocol with
  a shared batcher. Simpler, and the measured wins came from batching and
  SIMD rather than sharding.
- No automatic effective-MTU configuration.
- FreeBSD/macOS builds are untested.
- The encless path still allocates; a buffer-pooled AONT/CnW encoder is
  possible.
- Only one admin instance is supported (no process lock; two would sample
  twice); the control plane is a local Unix socket, not cross-host
  management.
- The admin has no TOTP and does not auto-disable or rate-limit on quotas;
  config cannot be written while the server is offline.
- The client GUI is Linux-only for now; auto-update, i18n, deb/rpm packaging,
  IPv6 and cross-platform support are not implemented yet (tray, single
  instance, login autostart and keychain are available)
  ([`client-ui-plan.md`](../client-ui-plan.md)).

Next: [Performance](performance.md).