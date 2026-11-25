# Getting started

**English** | [中文](../zh/getting-started.md) | [Русский](../ru/getting-started.md)

This page takes you from a checkout to a working client/server pair. For
every option see the [configuration reference](configuration.md).

## Requirements

- Rust **1.85** or newer (the workspace MSRV).
- Linux with `/dev/net/tun`, and root or `CAP_NET_ADMIN` + `CAP_NET_RAW`
  to create TAP devices and run `ip` commands.
- No C toolchain is required for a normal build. For a fully static
  binary (recommended for deployment) use the musl target below.

## Build

Run from the repository root:

```bash
cargo build --release
```

Binaries are written to `target/release/`:

- `rustvpn-server` — the daemon that terminates clients.
- `rustvpn-client` — the daemon that connects to a server.
- `rustvpn-verifier` — generates and validates passphrase verifiers.

For a static binary that runs on older glibc systems:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/rustvpn-{server,client,verifier}
```

`.cargo/config.toml` pins Poly1305 to the RustCrypto software backend; this
is intentional and measurably faster on Zen3-class CPUs. See
[Performance](performance.md).

By default the TAP backend tries io_uring and falls back to epoll. To force
the epoll backend, set `GOVPN_IO_URING=0` in the environment.

## Generate a verifier

The verifier is derived from a passphrase and a random 128-bit identity.
The tool prints **two lines**: the first is the long form (with the Ed25519
public key) for the server, the second is the short form for the client.

```bash
printf 'correct horse battery staple\n' > /tmp/rustvpn.pass
./target/release/rustvpn-verifier -key /tmp/rustvpn.pass
# $argon2d$m=4096,t=128,p=1$BASE64_ID$BASE64_PUBLIC_KEY   <- server
# $argon2d$m=4096,t=128,p=1$BASE64_ID                     <- client
```

Both lines must come from the **same run** (they share the same random
identity/salt). Useful flags:

| Flag | Meaning | Default |
|---|---|---|
| `-key PATH` | Read the passphrase from a file (otherwise prompt). | prompt |
| `-verifier STR` | Validate a passphrase against a long-form verifier; prints `true`/`false`. | — |
| `-m N` | Argon2d memory cost in KiB. | 4096 |
| `-t N` | Argon2d iteration count. | 128 |
| `-p N` | Argon2d parallelism. | 1 |
| `-egd PATH` | Read randomness from an EGD socket. | `/dev/urandom` |

```bash
# Check a passphrase against the long form
./target/release/rustvpn-verifier -verifier "$LONG_FORM" -key /tmp/rustvpn.pass
```

Keep the passphrase on the client only, in a file with restrictive
permissions (for example `0640 root:rustvpn`). The server needs only the
long-form verifier.

## Minimal server

`peers.yaml` maps peer names to configuration. The verifier must be the
**long form**; the server process will refuse entries without a public key.

```yaml
alice:
  iface: tap0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: $argon2d$m=4096,t=128,p=1$...$...
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
```

The framework runs the `up` script **before** opening the TAP device.
Therefore the script must create a persistent TAP itself; the daemon then
attaches to it. A minimal up script:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1515 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

`GOVPN_IFACE` and `GOVPN_REMOTE` are exported to both scripts. If the YAML
`iface` is empty, the first line of the up script's stdout becomes the
interface name.

Start the server:

```bash
sudo ./target/release/rustvpn-server \
    -proto udp -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml \
    -stats 127.0.0.1:1294
```

The configuration file is re-read every 60 seconds; new peers appear and
removed peers disappear without a restart. A parse error keeps the last
good configuration and logs a message.

## Minimal client

The client uses the **short form** of the verifier and the same
passphrase. It opens its TAP device first, then performs the handshake,
then runs `up`.

```bash
sudo ./target/release/rustvpn-client \
    -remote 203.0.113.10:1194 -proto udp -iface tap0 -mtu 1515 -timeout 60 \
    -verifier '$argon2d$m=4096,t=128,p=1$...' \
    -key /etc/rustvpn/pass \
    -up /etc/rustvpn/up.sh -down /etc/rustvpn/down.sh
```

Client up script (runs after the tunnel is established):

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1515 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

The client reconnects automatically after a timeout, a rehandshake, or a
closed TCP session, and runs `down` on shutdown.

## Complete IPv4 example

Assume an insecure WiFi link between a client (`192.168.0.2`) and a server
(`192.168.0.1`), and that you want an encrypted `172.16.0.0/24` network
over it.

On the server:

```bash
# TAP and addressing (also do this in up.sh for production)
ip tuntap add dev tap10 mode tap
ip addr replace 172.16.0.1/24 dev tap10
ip link set dev tap10 mtu 1540 up   # 1515 + noise overhead if noise is on

sudo rustvpn-server -bind 192.168.0.1:1194 -conf peers.yaml
```

On the client:

```bash
ip tuntap add dev tap10 mode tap
ip addr replace 172.16.0.2/24 dev tap10
ip link set dev tap10 mtu 1540 up
ip route add 0/1 via 172.16.0.1
ip route add 128/1 via 172.16.0.1

sudo rustvpn-client \
    -verifier '$argon2d$m=4096,t=128,p=1$...' \
    -iface tap10 -remote 192.168.0.1:1194
```

The two `/1` routes override the default route without deleting it, so
the tunnel carries all traffic while the underlying link still carries the
encrypted UDP packets. Adjust MTU according to the mode:

| Mode | Usable payload with `mtu: 1515` |
|---|---|
| classic | 1514 bytes |
| noise | 1490 bytes |
| encless | 1506 bytes |

Either raise the configured/interface MTU or lower the interior network's
MTU. See [Configuration → MTU](configuration.md#mtu).

## Tests and benchmarks

```bash
cargo test
cargo run --release -p rustvpn-crypto --example crypto_bench
cargo run --release -p rustvpn-proto  --example proto_bench
cargo run --release -p rustvpn-net    --example mmsg_bench
```

The differential tests read `testdata/go_vectors.json`, produced from the
upstream GoVPN 5.7 tree and checked in so the suite is self-contained.
Regenerating it requires that upstream Go source and the vector generator
shipped with it; the Go tree is not part of this repository.

## Common first-run problems

| Symptom | Cause / fix |
|---|---|
| `Cannot find device "tap0"` | The server's `up` script did not create the persistent TAP. Add `ip tuntap add ... mode tap`. |
| Handshake succeeds, no traffic | TAP has no IP, wrong MTU, or the route is missing. Check `ip addr` / `ip route`. |
| Large packets disappear with noise/encless | Payload exceeds `MTU-25` / `MTU-9`. Raise MTU or lower the interior MTU. |
| `Currently encryptionless mode works only with TCP` | Use `-proto tcp` (also implied by `-proxy`) for encless on the client. |
| `server verifier has no public key` | `peers.yaml` contains the short form; use the long form generated in the same run. |
| `random number mismatch` during handshake | Usually two overlapping sessions from a simultaneous restart; a clean restart or client auto-reconnect resolves it. |

Next: [Configuration reference](configuration.md).