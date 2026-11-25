# Configuration reference

**English** | [中文](../zh/configuration.md) | [Русский](../ru/configuration.md)

All three binaries intentionally accept the same flags, defaults and
configuration format as GoVPN 5.7. This page is the authoritative list for
the Rust build.

## `rustvpn-server` flags

| Flag | Meaning | Default |
|---|---|---|
| `-bind ADDR` | `host:port` to listen on. UDP and TCP use this address. | `[::]:1194` |
| `-conf PATH` | YAML peer configuration file. | `peers.yaml` |
| `-proto udp\|tcp\|all` | Transport(s) to serve. | `udp` |
| `-stats ADDR` | Start the JSON statistics HTTP endpoint on `host:port`. | disabled |
| `-proxy ADDR` | Start the trivial HTTP CONNECT proxy on `host:port`. | disabled |
| `-egd PATH` | Read randomness from an EGD unix socket instead of the OS RNG. | OS RNG |
| `-warranty` | Print the license warranty notice and exit. | — |

```bash
sudo rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294
```

## `rustvpn-client` flags

| Flag | Meaning | Default |
|---|---|---|
| `-remote ADDR` | Server `host:port` to connect to. **Required.** | — |
| `-proto udp\|tcp` | Transport to use. `-proxy` forces `tcp`. | `udp` |
| `-iface NAME` | TAP interface name. | `tap0` |
| `-verifier STR` | Client's short-form verifier. **Required.** | — |
| `-key PATH` | Passphrase file; if omitted, prompt on the terminal. | prompt |
| `-up PATH` | Script run after a session is established. | — |
| `-down PATH` | Script run on disconnect/shutdown. | — |
| `-stats ADDR` | JSON statistics HTTP endpoint. | disabled |
| `-proxy ADDR` | HTTP CONNECT proxy `host:port`. | direct |
| `-proxy-auth USER:PASS` | HTTP Basic credentials for the proxy. | — |
| `-mtu N` | Maximum TAP frame size. | `1515` |
| `-timeout N` | Peer liveness timeout in seconds. | `60` |
| `-timesync N` | Handshake timestamp window in seconds (0 = off). | `0` |
| `-noise` | Pad outgoing packets to the MTU. | off |
| `-encless` | Encryptionless mode (implies noise, TCP only). | off |
| `-cpr KIB` | Constant packet rate in KiB/s. | `0` |
| `-egd PATH` | EGD socket for randomness. | OS RNG |
| `-warranty` | Print the warranty notice and exit. | — |

Validation performed at startup:

- `mtu` must be in `68..=9015`; noise/encless modes require `mtu >= 120`.
- `-encless` requires `-proto tcp` (or `-proxy`, which forces TCP).
- An unknown `-proto` value is rejected.

## `rustvpn-verifier` flags

| Flag | Meaning | Default |
|---|---|---|
| `-key PATH` | Passphrase file; if omitted, prompt. | prompt |
| `-verifier STR` | Validate the passphrase against a long-form verifier. | — |
| `-m N` | Argon2d memory cost (KiB). | `4096` |
| `-t N` | Argon2d iterations. | `128` |
| `-p N` | Argon2d parallelism. | `1` |
| `-egd PATH` | EGD socket. | OS RNG |
| `-warranty` | Print the warranty notice and exit. | — |

Without `-verifier`, the tool prints the long form and the short form (in
that order) from one shared identity. With `-verifier`, it prints
`true` or `false`.

## `peers.yaml`

One top-level key per peer. Unknown fields are ignored, matching the Go
YAML behaviour.

```yaml
alice:
  iface: tap0           # TAP device name; may be empty if up prints it
  mtu: 1515             # max TAP frame size (default 1515, clamped 68..9015)
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
  timeout: 60           # seconds; <= 0 means 60
  timesync: 0           # handshake timestamp window; 0 = off
  noise: false          # pad every outgoing frame to mtu
  cpr: 0                # constant packet rate, KiB/s; 0 = off
  encless: false        # encryptionless mode (forces noise)
  verifier: $argon2d$m=4096,t=128,p=1$...$...   # LONG form required
```

Rules applied when the file is loaded:

- At least one of `iface` or `up` must be usable. If `iface` is empty, the
  first line of the up script's stdout becomes the interface name.
- `verifier` must decode and contain a public key. The short form is
  rejected with `server verifier has no public key`.
- `mtu: 0` means 1515. Values are clamped to `[68, 9015]`; noise/encless
  entries are raised to at least 120.
- `encless: true` forces `noise: true` (the padding is part of the
  encoding).
- `timeout <= 0` means 60 seconds.
- The file is re-read every **60 seconds**. A failed parse keeps the last
  good configuration and prints an error.

Each peer gets its own TAP device on the server. Two peers must not share
the same `iface` if they are active at the same time.

## Scripts (`up` / `down`)

Both scripts receive:

| Variable | Value |
|---|---|
| `GOVPN_IFACE` | The configured interface name (may be empty on the server). |
| `GOVPN_REMOTE` | The peer's remote address. |

Server order: **up script → TAP open → handshake**. Because the daemon
opens the TAP itself, `up` must create a persistent device:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1540 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

Client order: **TAP open → handshake → up script**. The client's `-iface`
is a real value (`tap0` by default), so its up script normally configures
an existing device:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip link set dev "$IFACE" mtu 1540 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

The `down` script runs on disconnect or shutdown. Keep both scripts
idempotent (`|| true`, `replace` instead of `add`); the client reconnects
after failures.

## MTU

`mtu` is the maximum frame size the daemon expects from the TAP device.
Frames larger than the mode's effective payload limit are rejected and
logged; they are never silently truncated.

| Mode | Effective payload limit |
|---|---|
| classic | `MTU - 1` |
| noise | `MTU - 25` (16 tag + 8 nonce + 1 pad) |
| encless | `MTU - 9` (8 nonce + 1 pad) |

With the default `mtu: 1515` that is 1514 / 1490 / 1506 bytes. If you need
to carry a full 1500-byte IP packet (1514-byte Ethernet frame) through a
noise or encless tunnel, raise the configured MTU to at least 1540 (noise)
or 1524 (encless), and set the TAP interface MTU accordingly in the up
script. The peer's interior MTU should not exceed the effective payload.

## Timeout and heartbeat

Because UDP is stateless, a peer is considered dead after `timeout`
seconds without packets. Both sides should use the same value (default
60). If nothing is sent for a quarter of the timeout, a heartbeat packet
is emitted so the session stays alive even when the TAP is idle — this
consumes a little traffic.

The server periodically cleans up stale peers and abandoned handshake
states (roughly every 10 seconds; incomplete handshakes older than 60
seconds are dropped). TCP sessions use the same timeout: a silently dead
TCP peer is detected after the timeout rather than waiting forever.

## CPR (constant packet rate)

`cpr: KIB` (or `-cpr`) emits filler traffic at approximately `KIB` KiB/s.
The packet cycle is computed from the wire size (including the encless
expansion) and drives both filler transmission and the heartbeat
interval. CPR hides timestamps of real payload traffic but is traffic-
and CPU-hungry. Use it together with noise.

## Timesync

`timesync: N` (or `-timesync`) requires handshake packets to be tagged
with the current timestamp rounded to `N` seconds. It defends against an
active DPI replaying a captured first handshake packet to confirm that a
given identity exists and that the server is GoVPN. Clocks must be
reasonably synchronized on both sides. `0` disables it.

## Noise

`noise: true` (or `-noise`) pads every outgoing frame to the MTU. It hides
packet lengths but can significantly increase traffic. Enable it on both
sides for the intended effect. See [MTU](#mtu) for the payload cost.

## Encless

`encless: true` (or `-encless`) replaces stream encryption with
AONT + Chaffing-and-Winnowing, which preserves confidentiality using only
authentication primitives (no encryption function). It forces noise and
adds **4128 bytes** to every packet, so it is expensive. The client only
supports it over TCP, matching Go: `-encless` with the default UDP proto
is rejected. See [Protocol → Encless](protocol.md#encless).

## Statistics endpoint

`-stats host:port` starts a minimal TCP listener. It accepts a connection,
ignores the request, and returns an `HTTP/1.0 200 OK` response with a JSON
array of peer objects:

```bash
curl http://127.0.0.1:1294/ | jq .
```

```json
[
  {
    "Addr": "203.0.113.10:52341",
    "Id": "q83v...==",
    "BytesIn": 1392774,
    "BytesOut": 17228877,
    "BytesPayloadIn": 1389000,
    "BytesPayloadOut": 17220000,
    "FramesIn": 12412,
    "FramesOut": 16588,
    "FramesUnauth": 0,
    "FramesDup": 0,
    "HeartbeatRecv": 2,
    "HeartbeatSent": 1,
    "NoiseEnable": false,
    "CPR": 0,
    "Encless": false,
    "MTU": 1515,
    "Established": "2026-11-25T20:00:00Z",
    "LastPing": "2026-11-25T20:05:49Z",
    "LastSent": "2026-11-25T20:05:49Z"
  }
]
```

`Id` is the base64 (no padding) encoding of the peer identity. All field
names match the Go implementation.

## Proxy

Both roles can use HTTP CONNECT.

- **Server `-proxy host:port`**: accepts any HTTP request, replies
  `HTTP/1.0 200 OK`, and switches to the raw TCP session state machine.
  It does not authenticate the proxy client.
- **Client `-proxy host:port`**: connects to the proxy and sends
  `CONNECT remote:port`. `-proxy-auth user:password` adds HTTP Basic
  authorization. The transport becomes TCP.

Any external HTTP proxy can be used as long as it supports CONNECT.

## EGD

`-egd PATH` (all binaries) reads randomness from an EGD
(entropy gathering daemon) unix socket. Use it on systems whose
`/dev/urandom` is not trustworthy. If the option is absent, the OS CSPRNG
is used.

Next: [Protocol](protocol.md).