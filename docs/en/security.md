# Security

**English** | [中文](../zh/security.md) | [Русский](../ru/security.md)

This page summarizes what RustVPN protects against, what it does not, and
the operational precautions that matter in practice.

## Security properties

- **Mutual authentication with a shared passphrase.** The PAKE handshake
  proves knowledge of the passphrase without sending it, and the server
  proves it holds the matching verifier. An active attacker cannot
  impersonate either side without a passphrase guess or a break of the
  primitives.
- **Augmented, dictionary-resistant verifiers.** The server stores an
  Argon2d-derived verifier plus an Ed25519 public key. Stealing it does
  not let the attacker authenticate as the client, and Argon2d makes
  offline guessing expensive.
- **Perfect forward secrecy.** Session keys are derived from fresh
  Diffie-Hellman values. Compromising long-lived passphrases or verifiers
  later does not reveal previously recorded sessions. PFS is per session:
  it does not protect a session key leaked from live memory.
- **Authenticated transport.** Every packet is MACed with a one-time
  Poly1305 key before use; tampering and forgery are rejected. The
  encrypt-then-MAC-style construction avoids authenticate-then-encrypt
  pitfalls.
- **Replay protection.** A 257-bit sliding window rejects duplicate and
  too-old serials; the handshake also carries fresh nonces. Optional
  `timesync` narrows the validity window of handshake packets further.
- **Client anonymity.** Third parties cannot distinguish one client's
  handshake/transport bytes from another's or from random data.
- **Censorship resistance.** Handshake and transport packets are designed
  to be indistinguishable from noise; `noise` hides packet lengths, and
  CPR hides timing.
- **No compression.** There is no compression layer, so compression
  side channels do not apply.

## Precautions

1. **Use long, high-entropy passphrases.** Overall security depends on
   passphrase strength. Prefer a 100+ character phrase or a random
   high-entropy string. The passphrase is the only human secret.
2. **Never reuse a passphrase/verifier across clients.** Each client must
   have its own identity and verifier. A shared verifier breaks the
   one-peer-per-identity model and weakens anonymity.
3. **Keep the passphrase on the client only**, in a file readable only by
   the service user (for example `0640 root:rustvpn`). The server only
   needs the long-form verifier. Do not put the passphrase in
   `peers.yaml`, shell history, or service unit files.
4. **Protect the identity/verifier files** like any credential: restrictive
   permissions, no world-readable backups.
5. **Use a trustworthy RNG.** By default the OS CSPRNG is used. If your
   platform's entropy source is suspect, supply `-egd` to every binary
   that consumes randomness (server, client, verifier).
6. **Do not invent custom modes.** Stay with the documented combinations;
   mismatched modes show up as `FramesUnauth` growth, not as a secure
   fallback.

## Verifier compromise

If an attacker obtains the server's `peers.yaml`:

- They cannot impersonate the client (the verifier has no private key).
- They can attempt an offline dictionary attack against the Argon2d
  verifier; use a strong passphrase and the default (or higher) Argon2d
  cost.
- They learn identities and public keys; identities are not secret by
  design.

If an attacker obtains the client's passphrase:

- They can impersonate that one client until the verifier is rotated.
- Rotate immediately: generate a new verifier and replace both sides (see
  [Operations → Passphrase rotation](operations.md#passphrase-rotation)).

## Encless considerations

Encryptionless mode preserves confidentiality and authenticity using
AONT + Chaffing-and-Winnowing, i.e. only authentication primitives. It
protects against jurisdictions that can compel encryption keys or forbid
encryption. It does **not** protect against an attacker who can break the
underlying authentication primitives, and it is expensive. The packet
serial is still XTEA-obfuscated by default; that obfuscation is for
traffic randomization, not confidentiality, and does not affect forward
secrecy.

## Known gaps and operational risks

- **Handshake flooding is rate-limited.** First handshake messages are
  capped at 5/s per source IP (burst 10) and 200/s globally (burst 400);
  excess messages are dropped. TCP handshakes also pass through a
  concurrency semaphore. Keep the port firewalled and monitor
  `FramesUnauth`.
- **Denial of service is always possible at the network layer.** The
  daemon authenticates transport packets before doing expensive work and
  bounds internal queues, but it cannot prevent link saturation.
- **Stats endpoint has no authentication.** Bind it to `127.0.0.1` (or a
  tunnel address) and never expose it publicly.
- **No automatic MTU adjustment.** Misconfigured MTU causes large frames
  to be rejected; it is not a confidentiality issue, but it can look like
  an outage.
- **Desktop client leak boundary (optional).** The GUI's `rustvpn-clientd`
  blocks the IPv6 default route and requires IPv4 DNS only for a full tunnel
  (`routes` containing `default`). Split-tunnel profiles do not block IPv6 or
  system DNS and may leak. Routes/DNS are installed only after the first
  successful handshake; the daemon and CLI share a tunnel lock. See the
  [desktop client guide](../client-ui.md) (currently in Chinese).
- **Only Linux is tested.** Run on platforms you can audit and test.

## Hardening checklist

- [ ] Dedicated unprivileged user; `NoNewPrivileges=yes`.
- [ ] Only `CAP_NET_ADMIN` and `CAP_NET_RAW` in the bounding set.
- [ ] `peers.yaml`, passphrase and environment files are `0640`, owned by
      `root:rustvpn`.
- [ ] Up/down scripts are `0750` and not writable by the service user
      beyond what is required.
- [ ] Stats binds to loopback only.
- [ ] Firewall allows only the VPN port, ideally limited to known client
      addresses.
- [ ] Passphrases are unique per client and rotated on suspicion.
- [ ] Use a build you compiled yourself or verified (`cargo build
      --release --locked`), and track dependency audits (`cargo audit`,
      `cargo deny`).
- [ ] Backups of `peers.yaml` are protected as credentials.

## Reporting issues

Security reports should go to the maintainers privately rather than a
public issue tracker. Include the affected component (crypto, protocol,
net, client/server), the version/commit, and a minimal reproduction if
possible.

Next: [FAQ](faq.md).