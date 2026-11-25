# RustVPN manual — overview

**English** | [中文](../zh/index.md) | [Русский](../ru/index.md)

RustVPN is a wire-compatible reimplementation of GoVPN 5.7 in Rust. This
manual describes how to build, configure, deploy and understand it. It is
adapted from the original GoVPN manual, with every command, flag and
default checked against the Rust code.

## What it is

RustVPN is a small virtual private network daemon that connects TAP
interfaces through an encrypted, authenticated tunnel. It is not a new
protocol: a Rust client can talk to a Go server, a Go client can talk to a
Rust server, and either binary can be replaced on one side without
touching the other.

Design goals, inherited from GoVPN:

- **Reviewable** — a compact code base and standard, well-understood
  cryptographic primitives.
- **Secure** — passphrase-authenticated key agreement, authenticated
  transport, perfect forward secrecy, replay protection.
- **Censorship-resistant** — handshake and transport messages look like
  random noise; optional padding hides their length and timing.
- **Operationally boring** — the daemon only moves packets. Addresses,
  routes, MTU and NAT are configured by the administrator, exactly as for
  an Ethernet cable.

## Feature summary

- PAKE DH A-EKE handshake with zero-knowledge mutual authentication.
- Argon2d + Ed25519 verifiers resistant to offline dictionary attacks.
- Salsa20 + Poly1305 transport with 128-bit security margin.
- Optional encryptionless mode (AONT + Chaffing-and-Winnowing).
- Noise padding and optional constant packet rate (CPR).
- Optional timestamp windows for handshake replay resistance.
- Built-in rehandshake, heartbeat, timeout and JSON statistics.
- Built-in handshake rate limiting (5/s per source, 200/s global).
- UDP and TCP transports, plus HTTP CONNECT proxy on both sides.
- IPv4 and IPv6.
- EGD entropy-daemon support for systems with weak `/dev/urandom`.

## Terminology

| Term | Meaning |
|---|---|
| **Peer** | A named client entry in the server's `peers.yaml`; one TAP device per peer. |
| **Identity** | A 128-bit, non-secret client identifier. Used as an XTEA key for `IDtag` and as the Argon2 salt. |
| **Passphrase** | The human-memorable secret entered on the client. |
| **Verifier** | An Argon2d-derived token. The server stores the long form (with an Ed25519 public key); the client uses the short form. |
| **Handshake** | The four-message PAKE exchange that establishes a session key. |
| **Transport** | The authenticated, encrypted (or encoded) packet format used after the handshake. |
| **Noise** | Padding every outgoing packet to the configured MTU. |
| **Encless** | Encryptionless mode: AONT + Chaffing-and-Winnowing instead of stream encryption. |
| **CPR** | Constant packet rate: emit filler traffic at a configured KiB/s. |
| **MTU** | The configured maximum TAP frame size. The usable payload is smaller in noise/encless modes. |

## Documentation map

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Build, verifier, a minimal server/client, tests and benchmarks. |
| [Configuration](configuration.md) | All CLI flags, `peers.yaml`, scripts, MTU/timeout/CPR/stats/proxy. |
| [Protocol](protocol.md) | Verifier/PAKE, handshake messages, transport format, noise, encless. |
| [Operations](operations.md) | systemd deployment, capabilities, rotation, troubleshooting. |
| [Security](security.md) | Threat model, precautions, key handling, hardening checklist. |
| [FAQ](faq.md) | Design questions and "when should I use X" answers. |
| [Design](design.md) | Architecture, data path, compatibility invariants, tests. |
| [Performance](performance.md) | Go-side optimizations and same-machine Rust-vs-Go results. |

## Status and limitations

Implemented and differentially tested: all cryptographic primitives, the
complete handshake, the classic/noise/encless codec, TAP, YAML config and
hot reload, scripts, stats, proxy, UDP batching, io_uring TAP and AVX2
Salsa20. Interoperability with the Go binaries has been verified for UDP,
TCP, proxy, noise and encless in both directions.

Known limitations:

- Only Linux has been exercised. FreeBSD and macOS may work through the
  `tun` crate but are untested; set `GOVPN_IO_URING=0` to force the epoll
  TAP backend.
- Effective MTU is not adjusted automatically. In noise/encless modes the
  up script should raise the interface MTU (or accept a smaller payload).
- The client only supports encryptionless mode over TCP, matching Go.

Next: [Getting started](getting-started.md).