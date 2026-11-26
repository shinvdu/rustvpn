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
| `-mtu N` | Numeric wire MTU shared with the server (two-sided contract; `auto`/`0` are invalid). | `1515` |
| `-timeout N` | Peer liveness timeout in seconds. | `60` |
| `-timesync N` | Handshake timestamp window in seconds (0 = off). | `0` |
| `-noise` | Pad outgoing packets to the MTU. | off |
| `-encless` | Encryptionless mode (implies noise, TCP only). | off |
| `-cpr KIB` | Constant packet rate in KiB/s. | `0` |
| `-keepalive N` | Idle keepalive interval seconds (0 = legacy `timeout/4` heartbeat). | `0` |
| `-rekey-time N` | Time-driven rekey interval seconds (0 = 4 GiB threshold only). | `0` |
| `-rekey-jitter N` | Random jitter added to `-rekey-time`. | `0` |
| `-egd PATH` | EGD socket for randomness. | OS RNG |
| `-warranty` | Print the warranty notice and exit. | — |

Validation performed at startup:

- `mtu` must be a positive number in `68..=9015` (0 and `auto` are
  rejected); noise/encless modes require `mtu >= 120`.
- `-encless` requires `-proto tcp` (or `-proxy`, which forces TCP).
- An unknown `-proto` value is rejected.
- `keepalive` is 0 (off) or 10..=3600 s in plain mode, 25..=3600 s in
  noise/encless mode, and must be shorter than `timeout`.
- `rekey-time` is 0 (off) or 60..=86400 s; `rekey-jitter` is
  0..=min(rekey-time, 3600).  The CLI/daemon default is 0; newly generated
  GUI/onboarding profiles default to 1800 s.

## Desktop client profile (optional)

The Tauri client does not read CLI flags; it uses
`~/.config/rustvpn/profiles/*.yaml`. Differences from the CLI:

- An IPv4 `address` is required. A full tunnel (`routes` containing
  `default`/`0.0.0.0/0`) also needs `gateway` and at least one IPv4 `dns`.
- The default `iface` is `rsvpn-gui`, avoiding a collision with a local
  `rustvpn-client` using `tap0`/`rsvpn0`.
- `up`/`down` scripts are not supported; `rustvpn-clientd` manages addresses,
  routes, DNS and IPv6 leak protection itself.
- `mtu` is a positive numeric **wire** MTU shared by both peers (see
  [MTU](#mtu)).  `auto` and `0` are rejected in v1; only the TAP interface IP
  MTU and MSS are derived from it.
- `mss_clamp: true` (or `auto`) clamps TCP MSS with nftables on the daemon
  path; it is opt-in, best-effort if `nft` is missing, and removed on
  disconnect.  IPv4 and IPv6 get separate derived values.
- `kill_switch: true` installs a full-tunnel nftables kill switch; it is
  opt-in, requires `routes` to contain `default`, and is rejected for
  split-tunnel profiles.  It filters host `output` only; forwarded/LAN/NAT
  traffic is not protected.
- `keepalive: 25` (alias: `persistent_keepalive`) enables an idle NAT
  keepalive; `0` keeps the historical heartbeat.  In noise/encless mode every
  keepalive is padded to the MTU, so the minimum accepted interval is 25 s
  (plain mode: 10 s).
- `rekey_time` / `rekey_jitter` add a time-driven rekey on top of the 4 GiB
  threshold (whichever comes first); `0` disables it.  The daemon default is
  0; newly created GUI/onboarding profiles default to `rekey_time: 1800` with
  a visible status line, and rekey is a scheduled reconnect (short packet gap).
- `-no-host-dns` on `rustvpn-clientd` leaves DNS to the caller (netns or
  container); see [`docs/netns-client.md`](../netns-client.md).
- The UI/tray language and login autostart are GUI settings, not profile fields;
  the language lives in WebView local storage and autostart writes
  `~/.config/autostart/rustvpn-client.desktop`.
- The update source (Tauri updater) is build-time configuration in
  `tauri.conf.json`, not part of a profile.
- Full fields, build, systemd, migration and troubleshooting are in the
  [desktop client guide](../client-ui.md) (currently in Chinese).

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
| `-profile NAME` | Write a client profile YAML (mode `0600`). | — |
| `-profile-out PATH` | Explicit profile path instead of `~/.config/rustvpn/profiles`. | — |
| `-qr PATH` | Write a QR PNG containing the `rustvpn://profile` URI. | — |
| `-remote HOST:PORT` | Remote address for the generated profile/QR. | — |
| `-proto udp\|tcp` | Profile transport. | `udp` |
| `-mtu N` | Profile numeric wire MTU shared with the server. `auto` and `0` are rejected. | `1515` |
| `-iface NAME` | Profile TAP name. | `rsvpn-gui` |
| `-address CIDR` | Profile TAP address. | `10.88.0.2/24` |
| `-gateway IP` | Profile gateway. | `10.88.0.1` |
| `-dns IP` | DNS server (repeatable). | `10.88.0.1` |
| `-routes CIDR` | Route (repeatable). | `default` |
| `-noise` / `-encless` | Enable padding / encryptionless mode in the profile. | off |
| `-kill-switch` | Enable the full-tunnel kill switch. | off |
| `-mss-clamp` | Enable MSS clamping on the tunnel interface. | off |
| `-keepalive N` | Profile idle keepalive seconds (0 = off; 10 plain / 25 padded minimum). | `0` |
| `-rekey-time N` | Profile time-driven rekey seconds (0 = off). | `1800` |
| `-rekey-jitter N` | Profile rekey jitter seconds. | `0` |

Without `-verifier`, the tool prints the long form and the short form (in
that order) from one shared identity. With `-verifier`, it prints
`true` or `false`.

### One-step onboarding

```bash
rustvpn-verifier -key pass.txt -remote vpn.example.com:1194 \
  -profile office -qr office.png
# stdout (unchanged):
#   long : $argon2d$m=4096,t=128,p=1$ID$PUBLIC_KEY   <- server
#   short: $argon2d$m=4096,t=128,p=1$ID             <- client
# stderr:
#   profile -> ~/.config/rustvpn/profiles/office.yaml (0600)
#   QR      -> office.png (0600; verifier id only, no password)
```

- **Server side:** add the **long** form (first stdout line) to the peer's
  `verifier` in `peers.yaml`.  The long form contains the public key and is
  required by the server.
- **Client side:** import the generated YAML profile (or the QR image), then
  enter the passphrase.  The profile and QR contain only the short verifier
  id, remote, protocol, numeric MTU and non-secret network fields; **no
  password is written to either file**.
- The `rustvpn://profile?...` URI carries the same non-secret fields for
  reference.  **v1 has no automatic URI importer**, so treat it as
  informational: the YAML profile is canonical.  Documentation does not claim
  "scan to connect" until an importer exists.
- Generated directories are `0700` and files are `0600`.  QR generation uses
  the external `qrencode` binary when available (override with
  `RUSTVPN_QRENCODE_BIN`); without it the URI is printed instead.  Temporary
  files are reserved with `O_EXCL`/owner-only permissions and atomically
  renamed, so a predictable output path cannot be redirected through a
  symlink.  If `HOME` is unset, onboarding refuses to fall back to `/tmp`;
  pass `-profile-out` explicitly.

## `peers.yaml`

One top-level key per peer. Unknown fields are ignored, matching the Go
YAML behaviour.

```yaml
alice:
  iface: tap0           # TAP device name; may be empty if up prints it
  mtu: 1515             # numeric wire MTU (default 1515, clamped 68..9015; 0 invalid)
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
  timeout: 60           # seconds; <= 0 means 60
  timesync: 0           # handshake timestamp window; 0 = off
  noise: false          # pad every outgoing frame to mtu
  cpr: 0                # constant packet rate, KiB/s; 0 = off
  encless: false        # encryptionless mode (forces noise)
  verifier: $argon2d$m=4096,t=128,p=1$...$...   # LONG form required
  # Optional RustVPN-only declarative TAP setup (replaces the up script):
  # network:
  #   address: 10.88.0.1/24
  #   gateway: 10.88.0.1
  #   dns: [10.88.0.1]
  #   routes: [10.88.0.0/24]      # explicit CIDRs; default route is rejected
```

Rules applied when the file is loaded:

- At least one of `iface` or `up` must be usable. If `iface` is empty, the
  first line of the up script's stdout becomes the interface name.
- `verifier` must decode and contain a public key. The short form is
  rejected with `server verifier has no public key`.
- `mtu: 0` is invalid and rejected.  Omitting `mtu` keeps the historical
  default 1515.  Values are clamped to `[68, 9015]`; noise/encless entries are
  raised to at least 120.
- `encless: true` forces `noise: true` (the padding is part of the
  encoding).
- `timeout <= 0` means 60 seconds.
- `network` is optional. If present, `iface` (or an up script that prints an
  interface) is required; IPv4 address/gateway/DNS/routes are validated and a
  default route (including non-canonical prefix-0 spellings) is rejected. See
  “Declarative server network” below.
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
# TAP IP MTU, not the wire MTU (plain wire 1515 -> 1500).
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

Client order: **TAP open → handshake → up script**. The client's `-iface`
is a real value (`tap0` by default), so its up script normally configures
an existing device:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
# TAP IP MTU, not the wire MTU (plain wire 1515 -> 1500).
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

The `down` script runs on disconnect or shutdown. Keep both scripts
idempotent (`|| true`, `replace` instead of `add`); the client reconnects
after failures.

## MTU

In v1, `mtu` is a **two-sided wire contract**: the client and server must use
the same numeric value.  Deriving it from one side's local path changes the
handshake and transport wire lengths and makes the other side reject packets
as `TooLarge`.  Therefore:

- `mtu` must be a positive number; **`mtu: auto` and `mtu: 0` are rejected**.
- Only the TAP **interface IP MTU** and TCP MSS are derived locally:

```text
inner_ip_mtu = Mode::max_payload(wire_mtu) - 14
ipv4_mss     = inner_ip_mtu - 40
ipv6_mss     = inner_ip_mtu - 60
```

| Mode | Effective payload limit | Inner IP MTU for wire 1515 | MSS v4 / v6 |
|---|---|---:|---:|
| plain | `MTU - 1` | 1500 | 1460 / 1440 |
| noise | `MTU - 25` (16 tag + 8 nonce + 1 pad) | 1476 | 1436 / 1416 |
| encless | `MTU - 9` (8 nonce + 1 pad) | 1492 | 1452 / 1432 |

- The daemon (`rustvpn-clientd`) and the declarative server path
  (`network:`) set the TAP interface to `inner_ip_mtu`, never to the frame
  budget.  Both log the wire MTU, mode, inner MTU and MSS values.
- The Go-compatible CLI/up scripts must set the same inner value themselves
  if they configure the interface: e.g. plain `-mtu 1515` → `ip link set
  ... mtu 1500`, noise → `1476`, encless → `1492`.
- Frames larger than the mode's effective payload are rejected and logged;
  they are never silently truncated.
- **Automatic path-MTU derivation is deferred to a v2 MTU negotiation.**
  v1 does not claim path-MTU adaptation.  If a path is smaller than the
  configured MTU, lower the numeric value on **both** sides.
- encless with a normal 1500-byte outer path still logs a capacity warning:
  every packet grows by `4128` bytes.  Do not rely on IP fragmentation; use
  jumbo frames or another mode.

`mss_clamp: true` (or `auto`) applies nftables `maxseg size set` rules to TCP
SYNs leaving the tunnel, with separate IPv4/IPv6 values.  It is opt-in and
best-effort: if `nft` is missing or the rule fails, the tunnel still connects
and the failure is logged; `status --json` reports `mss_applied: false`.  A
strict `mss_clamp: required` mode is not implemented in this batch (the
default remains best-effort).  Tables are named per daemon instance
(`rustvpn_mss_<hash>`) and removed on disconnect.

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

## NAT keepalive

`keepalive: N` (or `-keepalive N`) sends an empty authenticated packet after
`N` seconds without outbound traffic.  `0` (default) preserves the existing
heartbeat: an empty packet every `timeout / 4` seconds of idleness.

- Default: **off**.  Recommended value: **25 s** for clients behind
  CGNAT/stateful NAT.
- It must be shorter than `timeout`; values below **10 s** in plain mode and
  **25 s** in noise/encless mode are rejected, and the maximum is 3600 s.
- **noise/encless cost:** the v1 wire format requires padded packets, so a
  keepalive is sent at the configured MTU, not as a tiny 32–60-byte packet.
  The daemon logs a warning at connect time; do not enable it casually in
  padded modes.
- Traffic is counted as `HeartbeatSent`/`HeartbeatRecv` in stats and
  `heartbeat_sent`/`heartbeat_recv` in `status --json`.
- `keepalive` is a client profile/CLI feature; `peers.yaml` intentionally has
  no such field so a Rust-written file stays GoVPN-compatible.

## Time-driven rekey

`rekey_time: 1800` (or `-rekey-time 1800`) triggers a fresh PAKE handshake
every 30 minutes, in addition to the existing 4 GiB per-key threshold
(whichever comes first).  `rekey_jitter: 30` randomizes the deadline by 0–30
seconds so many clients do not rekey together.  `0` disables the timer.

- **Defaults:** the daemon/CLI default is `0` (off), preserving old behavior.
  Newly created GUI profiles and `rustvpn-verifier` onboarding profiles
  default to `1800`; the GUI shows the configured interval in its status
  line.
- Existing profiles are never rewritten by an upgrade; `0` means explicitly
  "rekey disabled".

- Only the client (the original initiator) runs the timer; the server never
  initiates a rekey.
- RustVPN v1 has no in-band rekey or session-overlap message.  The client
  therefore performs a **scheduled reconnect**: it closes the old session and
  immediately starts a new handshake while keeping the TAP and routes.
  TCP/application flows normally survive through retransmission, but this is
  **not zero-loss**; expect a short packet gap.
- Long-running sessions should use `rekey_time` to bound key lifetime; the
  handshake is rate-limited globally/per-source, and jitter avoids storms.

## Declarative server network (`network:`)

The client daemon already configures address, routes, DNS, the derived TAP
IP MTU, MSS clamp and the kill switch from profile fields.  The server can
do the equivalent for a peer TAP when the `peers.yaml` entry contains an
optional `network:` section:

```yaml
alice:
  iface: tap10
  mtu: 1515
  network:
    address: 10.88.0.1/24
    dns: [10.88.0.1]
    routes: [10.88.0.0/24]      # same subnet as address: device route
    # gateway: 10.88.0.2        # optional next hop for non-connected routes
  verifier: $argon2d$...
```

- `rustvpn-server` creates the TAP if missing, sets the **interface IP MTU**
  derived from the numeric wire MTU (`inner_ip_mtu = max_payload - 14`; plain
  1515 → 1500, noise 1515 → 1476), adds the address/routes and (when `dns` is
  present) calls `resolvectl`.  It validates the interface kind.
- **Strict ownership:** a newly created TAP is marked with
  `ip link set dev <iface> alias rustvpn-managed`.  A pre-existing TAP
  **without** that alias is refused and left untouched, so an administrator's
  address/routes/DNS are never destroyed.  A marked TAP is treated as an
  orphan from a previous RustVPN run (crash/restart) and adopted; it is deleted
  on shutdown.  When upgrading from a build that created an unmarked TAP,
  delete it (or set the alias manually) before starting this version.
- `up`/`down` remain fully supported escape hatches.  If both are present,
  `up` runs first and the declarative setup is applied idempotently after it.
  No script is required for the declarative path.
- On any setup failure the address/routes/DNS/MTU changes and the RustVPN TAP
  are rolled back.  Successfully configured declarative state is removed on
  server shutdown.
- **Non-destructive installation:** addresses and routes are added with
  `ip addr add` / `ip route add`, never `replace`.  On `EEXIST`, an exactly
  matching pre-existing address/route is treated as idempotent (useful when
  adopting a marked orphan after a crash); any other conflict aborts the
  setup and rolls back.  RustVPN records and later deletes only the
  address/routes it actually added, so a pre-existing route (including a host
  default route) is never overwritten or removed.
- Server `network.routes` must be explicit IPv4 CIDRs; a default route is
  rejected to avoid hijacking the server's own routing.  This includes
  non-canonical prefix-0 spellings (`00.0.0.0/0`, `0.0.0.00/0`,
  `0.0.0.0/00`, ...) that `ipnet` normalises to prefix length 0.  If
  `gateway` is set
  it is used as the next hop (`via`) for those routes; connected routes created
  by `address` are detected and left alone.
- `network.dns` configures the server's own resolver for that interface via
  `resolvectl`; omit it unless that is intended.
- Server `mtu` stays the top-level numeric wire value; the TAP IP MTU and MSS
  are derived from it.  MSS clamp and kill-switch remain client-profile
  features, and `mtu: auto` is deferred to v2.
- Switching an existing peer from `network:` back to a pure script path is not
  auto-migrated while the server runs; restart the server (or clean the TAP
  manually) so the declarative state is removed on shutdown.
- Validate new TAP/route settings in a disposable network namespace (see
  [`docs/netns-client.md`](../netns-client.md)) before pointing a real server
  at them.
- **Compatibility / migration:** `network:` is a RustVPN-only extension.
  Entries without it are parsed and rendered exactly as GoVPN 5.7 YAML.
  Rendering an entry that *has* `network:` produces a file the Go server will
  reject (`deny_unknown_fields`).  Do not share such a `peers.yaml` with Go
  binaries; keep a Go-compatible file or remove the section for Go servers.

## Config reload semantics (`syncconf`-style)

The 60-second reloader (and the admin/control reload) compares parsed
configurations by peer id and a semantic fingerprint:

- **added peers** → available for the next handshake;
- **removed peers** → their active session is closed;
- **changed peers** → only that peer's active session is revoked;
- **unchanged peers** → sessions and counters are preserved.

Comments, quoting, key order and whitespace do not change the fingerprint, so
they do not bump the config generation and never revoke a session.  The log
summary lists counts and names, e.g.:

```text
reload: added=1 [dave] removed=0 [-] changed=1 [carol{mtu,keepalive}] unchanged=2 [alice,bob]; revoked 1 active session(s)
reload: peer carol changed fields: mtu,keepalive, session revoked (203.0.113.10:52341)
```

Each revocation names the semantic fields that changed (or says the peer was
removed), so operators can see why a session dropped.  A handshake snapshot is
re-checked against the live generation before a peer is created, so a reload
cannot resurrect a revoked peer.

Security invariant: a changed peer is still revoked; "no disruption" applies
only to peers whose parsed configuration is unchanged.

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

## `status --json`

`rustvpn-client` and `rustvpn-server` both expose a versioned, secret-free
status document. Existing CLI flags are unchanged; the subcommand is
additive.

```bash
# Client: query the running rustvpn-clientd over its socket
rustvpn-client status --json | jq '{state, endpoint, rekey_in_sec}'
rustvpn-client status --json | jq -e '.frames_unauth == 0' || alert

# Server: query the optional control socket
rustvpn-server status --json -control /run/rustvpn/server.sock
```

The document starts with `"schema": "rustvpn.status.v1"` and includes
`role`, `state`, `since`, `server`/`bind`, `proto`, `mode`, `iface`,
`endpoint`, `last_handshake`, `rekey_in_sec` (4 GiB budget),
`rekey_time_sec` (configured time-driven interval), `keepalive_sec`, traffic
totals/rates, heartbeat counters, `frames_unauth`, `frames_dup` and the
effective MTU/MSS where available.  The client additionally reports:

- `mtu` (numeric wire value), `inner_mtu` (derived TAP IP MTU) and
  `mtu_source` (`configured`; `auto` is deferred to v2);
- `mss`/`mss_v6` (derived values) and `mss_applied` (whether the nftables
  table was really installed);
- `kill_switch` (profile value) and `kill_switch_applied`;
- `rates_available` and `rate_window_sec` (the daemon samples over ~1 s).

Server output includes a `sessions` array, but no rate sampler: server
`tx_rate_bps`/`rx_rate_bps` remain `null` with `rates_available: false` and
`rate_window_sec: null`.  Compute rates from two counter samples if needed.
No passwords, keys, proxy credentials or full verifier material are included.

If the daemon/socket is unreachable with `--json`, command still prints a
**schema-complete** document with `"state": "unavailable"`, the same field
set (neutral values) and `last_error`, and exits non-zero.

## Kill switch (full tunnel only)

`kill_switch: true` creates an nftables table
`inet rustvpn_killswitch_<hash>` with an `output` chain whose policy is
`drop`.  It accepts loopback, the tunnel interface, the resolved outer VPN
endpoint (TCP and UDP), DHCPv4 renewal, and — scoped to the underlay
interface — the IPv6 control packets required for neighbour discovery/MLD
(types 130–136, 143) and DHCPv6 (UDP 546/547).  All other host IPv4/IPv6/DNS
traffic is blocked while connected.

- Opt-in only; never enabled by default.
- **Scope is the host `output` chain only.**  Forwarded traffic (router/NAT
  gateway, containers/VMs, Internet Connection Sharing) and LAN access are
  **not** protected.  Do not treat this as a gateway-wide kill switch.
- Requires `routes` to contain `default`/`0.0.0.0/0`.  Split-tunnel
  profiles are rejected rather than silently downgraded.
- **Fail-closed:** if `nft` is missing or a rule cannot be applied, the
  connection is refused instead of silently running without protection.
- The table is removed on disconnect and on the next start of the same
  daemon instance (the suffix is derived from the IPC socket path, so another
  RustVPN daemon in the same netns is unaffected).  If the daemon is killed
  uncleanly, the rules stay installed (fail-closed) until it starts again;
  the systemd unit deliberately does not run a global `nft delete`, which
  would race with other instances and require `nft` on the host PATH.
- Install the `nftables` package on hosts using `kill_switch`/`mss_clamp`.
- Only RustVPN-owned tables are touched; existing NAT/filter rules and
  interfaces are not modified.
- Tests and CI must apply kill-switch rules inside a disposable network
  namespace; see [`docs/netns-client.md`](../netns-client.md).

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