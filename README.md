# RustVPN — a wire-compatible GoVPN 5.7 rewrite in Rust

**English** | [中文](README.zh.md) | [Русский](README.ru.md)

RustVPN is a from-scratch Rust implementation of the GoVPN 5.7 protocol.
It is not a new VPN design: it speaks the exact same wire format, so its
`rustvpn-server`, `rustvpn-client` and `rustvpn-verifier` binaries can replace
the Go ones on either side of an existing deployment.

This repository contains the standalone RustVPN implementation. The
upstream GoVPN tree is not included or modified; it is used only as a
differential-testing oracle.

## Highlights

- **PAKE handshake** — passphrase-authenticated, augmented Diffie-Hellman
  key agreement (DH A-EKE) with zero-knowledge mutual authentication.
- **Strong verifiers** — Argon2d + Ed25519 tokens that resist offline
  dictionary attacks; a compromised server verifier cannot impersonate a
  client.
- **Authenticated transport** — Salsa20 + Poly1305, XTEA-based serial
  obfuscation, a 257-bit replay window, and perfect forward secrecy.
- **Censorship resistance** — handshake and transport bytes are
  indistinguishable from random data; optional `noise` padding hides
  packet lengths.
- **Encryptionless mode** — AONT + Chaffing-and-Winnowing provide
  confidentiality without encryption functions (TCP only on the client).
- **Operational parity** — same CLI flags and defaults, same `peers.yaml`
  format and 60-second hot reload, same `up`/`down` script environment,
  same JSON stats fields, same UDP/TCP/HTTP-CONNECT proxy behavior.
- **Performance work** — zero-allocation steady-state codec, `recvmmsg`/
  `sendmmsg` batching, an io_uring TAP backend with epoll fallback, and an
  AVX2 Salsa20 backend with runtime dispatch.

## Status

Implemented and differentially tested against the Go 5.7 code:

| Crate | Contents |
|---|---|
| `rustvpn-crypto` | XTEA, Salsa20/XSalsa20, Poly1305, BLAKE2b-256, Chaffing-and-Winnowing, AONT, encless, Argon2d/Ed25519 verifiers, EGD reader, `extra25519` representative encoding |
| `rustvpn-proto` | Classic/noise/encless transport codec, replay window, TCP framing, complete PAKE handshake for both roles |
| `rustvpn-net` | TAP devices, YAML config + hot reload, scripts, stats, heartbeat/CPR/rekey lifecycle, UDP batching, io_uring TAP |
| `rustvpn-client` / `rustvpn-server` | UDP and TCP transports, HTTP CONNECT proxy, noise and encless modes, stats endpoint, graceful shutdown |
| `rustvpn-verifier` | CLI-compatible verifier generator/validator |

Interoperability verified end-to-end (loopback + TAP + network namespaces,
ICMP through the tunnel):

| Direction | UDP | TCP | Proxy | Noise | Encless |
|---|---|---|---|---|---|
| Rust client → Go server | yes | yes | yes | (protocol bytes verified)* | (protocol bytes verified)* |
| Go client → Rust server | yes | yes | yes | yes | yes |
| Rust client → Rust server | yes | yes | yes | yes | yes |

\* In this environment Go's water TAP reader intermittently reports
`not pollable`; the same Go server works when its TAP is pre-created.
The wire format is covered by byte-exact handshake/transport vectors
regardless.

Not implemented yet: portability packaging for FreeBSD/macOS (only Linux
has been exercised) and automatic effective-MTU handling for TAP interfaces.

## Quick start

Requirements: Rust >= 1.85, Linux `/dev/net/tun`, and root or
`CAP_NET_ADMIN` for TAP creation.

```bash
cargo build --release
# binaries: target/release/rustvpn-{server,client,verifier}

# 1. Generate a verifier (prints the long form then the short form)
echo 'correct horse battery staple' > /tmp/rustvpn.pass
target/release/rustvpn-verifier -key /tmp/rustvpn.pass

# 2. Start the server (peers.yaml uses the Go format)
target/release/rustvpn-server -proto udp -bind 0.0.0.0:1194 \
    -conf /tmp/peers.yaml -stats 127.0.0.1:1294

# 3. Start the client (short verifier form)
target/release/rustvpn-client -remote server:1194 -proto udp -iface tap0 \
    -verifier '$argon2d$m=4096,t=128,p=1$...' -key /tmp/rustvpn.pass \
    -up /path/to/up.sh -down /path/to/down.sh
```

```yaml
# /tmp/peers.yaml
alice:
  iface: tap0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: $argon2d$m=4096,t=128,p=1$...$...
  up: /path/to/up.sh
  down: /path/to/down.sh
```

The server runs `up` **before** opening the TAP device, so the script must
create a persistent TAP itself (`ip tuntap add ... mode tap`); the client
opens its TAP first and runs `up` after the session is established. See
[Getting started](docs/en/getting-started.md) for a complete walkthrough.

## Documentation

The manual is available in three languages, each in its own directory:

| Language | Entry point |
|---|---|
| English | [`docs/en/index.md`](docs/en/index.md) |
| 中文 | [`docs/zh/index.md`](docs/zh/index.md) |
| Русский | [`docs/ru/index.md`](docs/ru/index.md) |

English pages:

- [Overview and concepts](docs/en/index.md)
- [Getting started](docs/en/getting-started.md)
- [Configuration reference](docs/en/configuration.md)
- [Protocol](docs/en/protocol.md)
- [Operations and deployment](docs/en/operations.md)
- [Security](docs/en/security.md)
- [FAQ](docs/en/faq.md)
- [Design](docs/en/design.md)
- [Performance](docs/en/performance.md)
- [Desktop client UI (Linux MVP, Chinese)](docs/client-ui.md)

## Tests and benchmarks

```bash
cargo test
cargo run --release -p rustvpn-crypto --example crypto_bench
cargo run --release -p rustvpn-proto  --example proto_bench
cargo run --release -p rustvpn-net    --example mmsg_bench
```

The tests consume `testdata/go_vectors.json`, generated from the upstream
GoVPN 5.7 tree and checked in so the suite is self-contained. Regenerating
it requires the upstream Go source and the vector generator shipped with
that project; this repository does not include the Go tree.

## Verifier interoperability

```bash
# RustVPN validates a GoVPN-generated verifier:
target/debug/rustvpn-verifier -verifier "$LONG_FORM" -key pass.txt

# GoVPN validates a RustVPN-generated verifier:
./govpn-verifier -verifier "$(target/debug/rustvpn-verifier \
    -key pass.txt -m 1024 -t 4 -p 1 | head -1)" -key pass.txt
```

Both directions print `true`.

## Relationship to GoVPN

RustVPN is an independent implementation of the same protocol and is
released under **GPL-3.0-or-later**, matching the Go project. It does not
modify the Go tree; both implementations can run side by side on
different ports/networks.

## License

GPL-3.0-or-later.