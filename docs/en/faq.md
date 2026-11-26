# FAQ

**English** | [中文](../zh/faq.md) | [Русский](../ru/faq.md)

## Is RustVPN a new VPN protocol?

No. It is a wire-compatible implementation of GoVPN 5.7. A Rust client
works with a Go server and vice versa. The packet formats, flags,
configuration and stats fields are the same.

## Why Rust instead of Go?

The goal was a second, independent implementation that could be
differentially tested against the Go code, with tighter control over the
data path. Rust gives predictable memory use and no garbage-collector
pauses, and lets the hot path be allocation-free. The project explicitly
does **not** assume that Rust is automatically faster; performance claims
are measured against the Go build on the same machine (see
[Performance](performance.md)).

## Why not TLS?

- TLS is a large, complicated protocol with many optional extensions.
- Classic TLS cipher suites use authenticate-then-encrypt ordering.
- Mainstream TLS stacks are huge and hard to review relative to the small
  surface needed here.

RustVPN needs a fixed, minimal tunnel format, not general-purpose
transport security.

## Why not SSH?

- SSH's early protocol versions also used authenticate-then-encrypt.
- OpenSSH does not provide strong zero-knowledge passphrase
  authentication.

## Why not IPsec?

It lacks strong zero-knowledge passphrase authentication and its
configuration/code surface is much larger.

## Why authenticate with passphrases?

Humans can memorize 100–200 character passphrases, which provides high
overall entropy while requiring no hardware token or secure key storage.
Unlike a password, a passphrase can be long and still memorable. This is
why RustVPN uses a PAKE and augmented verifiers instead of pre-shared
keys.

## Why is all network configuration manual?

There are too many setups and protocols for one tool to configure
correctly. Like an Ethernet cable, the VPN is a layer: the administrator
assigns addresses, routes, MTU, NAT and so on. This keeps the daemon
small and auditable.

## Is there a GUI?

Linux has an optional desktop client (Tauri UI plus `rustvpn-clientd`). It is a
separate program from the CLI and shares only libraries; the GUI itself is
unprivileged. It manages static addresses, routes and DNS: a profile needs an
IPv4 `address`, and a full tunnel also needs a `gateway` and IPv4 `dns`.
Routes are installed only after the first successful handshake, and a full
tunnel blocks the IPv6 default route to avoid leaks. The daemon and CLI share
a tunnel lock so only one tunnel owns the host routes. See the
[desktop client guide](../client-ui.md) (currently in Chinese). Windows and
macOS do not have a GUI yet.

## Why no Windows or macOS support?

Closed, proprietary systems do not let you control the computing device
well enough for cryptography-focused security. Only Linux is tested;
FreeBSD/macOS support may work through the `tun` crate (`GOVPN_IO_URING=0`
forces the epoll TAP backend), but is not exercised.

## What is perfect forward secrecy here?

Compromising long-lived secrets (the passphrase or the verifier) does not
decrypt previously captured traffic: each session uses fresh DH values.
PFS is per session; it does not save a session key that leaks from live
memory.

## What does "clients are anonymous" mean?

A third party observing the network cannot tell one client's traffic or
handshake from another's. Identities are not sent in the clear in a way
that allows linkage.

## What does "censorship resistant" mean?

It should be impossible to tell RustVPN traffic apart from
`cat /dev/urandom | nc host`. If an observer cannot distinguish it, the
only remaining policy is to block all random-looking traffic.

## When should I use encryptionless mode?

When a jurisdiction can compel disclosure of encryption keys or forbid
encryption functions, but does not forbid authentication/signing. It still
provides confidentiality via encoding, at the cost of 4128 extra bytes
per packet, and on the client it requires TCP. Do not use it just because
the name sounds safer — it is a legal/regulatory tool, not a performance
feature. See [Protocol → Encless](protocol.md#encless).

## When should I use noise?

When you care about hiding packet sizes, or together with CPR. Without
noise (and CPR), an observer can infer traffic patterns from packet
lengths and timing, as with TLS, SSH or IPsec. Noise alone hides lengths
but not timing; CPR hides timing. Both cost bandwidth.

## When should I use timesync?

If you want to prevent an active DPI from replaying a captured first
handshake packet to confirm that a given identity exists and that the
server is RustVPN. It requires reasonably synchronized clocks. Without it,
the server answers replayed first messages, which reveals its presence.

## Can I DoS the daemon?

Each transport packet is authenticated before expensive work, and the
implementation bounds queues and handshake states. First handshake
messages are rate-limited to **5/s per source IP** (burst 10) and
**200/s globally** (burst 400); excess messages are dropped, and TCP
handshakes also pass a concurrency semaphore. TCP/UDP stack costs usually
dominate in practice. Still firewall the port where possible.

## Why YAML?

YAML supports comments, is human-editable, and its anchors/aliases are
convenient for many peers sharing options. XML is not human-friendly;
JSON lacks comments.

## Can RustVPN and GoVPN run side by side?

Yes. Use different ports and TAP devices/subnets on the same host, or
replace one side of an existing deployment. See
[Operations → Coexistence](operations.md#coexistence-with-an-existing-govpn).

## Where are the other language versions?

English lives in [`docs/en/`](index.md), Chinese in
[`docs/zh/`](../zh/index.md), Russian in [`docs/ru/`](../ru/index.md). Each
language has its own complete copy of the manual.

Next: [Design](design.md).