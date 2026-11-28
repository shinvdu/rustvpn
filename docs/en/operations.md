# Operations and deployment

**English** | [中文](../zh/operations.md) | [Русский](../ru/operations.md)

This page shows a production-style Linux deployment with systemd, a
dedicated unprivileged user and Linux capabilities. The same layout works
for a RustVPN↔GoVPN mixed deployment; only the binary changes.

For a one-command server plus generated Windows-client profile, see
[Docker / Compose deployment](docker.md).

## Deployment model

Run both daemons as a non-root service user with only the capabilities
they need:

- `CAP_NET_ADMIN` — create/configure TAP interfaces and run `ip`.
- `CAP_NET_RAW` — required by the TAP/io_uring path.

`NoNewPrivileges=yes` and a minimal capability bounding set keep the
process from gaining more. If your distribution cannot grant ambient
capabilities, a small wrapper using `setcap` on the binary is an
alternative, but a dedicated user plus `AmbientCapabilities` is simpler
and auditable.

## Files

```text
/usr/local/bin/rustvpn-server                 0755 root:root
/usr/local/bin/rustvpn-client                 0755 root:root
/etc/rustvpn/                               0750 root:rustvpn
/etc/rustvpn/peers.yaml                     0640 root:rustvpn
/etc/rustvpn/pass                           0640 root:rustvpn   # client only
/etc/rustvpn/client.env                     0640 root:rustvpn   # client only
/etc/rustvpn/up.sh                          0750 root:rustvpn
/etc/rustvpn/down.sh                        0750 root:rustvpn
/etc/systemd/system/rustvpn-server.service    0644 root:root
/etc/systemd/system/rustvpn-client.service    0644 root:root
```

Create the user once:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustvpn
sudo install -d -m 0750 -o root -g rustvpn /etc/rustvpn
```

## Server configuration

`peers.yaml` (the verifier is the **long form**):

```yaml
alice:
  iface: rsvpn0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: '$argon2d$m=4096,t=128,p=1$BASE64_ID$BASE64_PUBLIC_KEY'
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
```

`up.sh` — note that it runs **before** the daemon opens the TAP, so it
must create the persistent device:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# TAP IP MTU, not the wire MTU (plain wire 1515 -> 1500).
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

`down.sh`:

```sh
#!/bin/sh
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip addr del 10.88.0.1/24 dev "$IFACE" 2>/dev/null || true
ip link set dev "$IFACE" down 2>/dev/null || true
```

## Client configuration

Keep the passphrase and the short-form verifier on the client only.

`/etc/rustvpn/pass` contains the passphrase and must not have a trailing
newline issue; the daemon strips a single trailing `\n`.

`/etc/rustvpn/client.env`:

```sh
RUSTVPN_VERIFIER='$argon2d$m=4096,t=128,p=1$BASE64_ID'
```

`EnvironmentFile` avoids systemd expanding the `$...` in the verifier.

`up.sh` (runs after the session is established):

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# TAP IP MTU, not the wire MTU (plain wire 1515 -> 1500).
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

`down.sh` removes the route and address and brings the link down.

## systemd units

`/etc/systemd/system/rustvpn-server.service`:

```ini
[Unit]
Description=RustVPN server (GoVPN 5.7 compatible)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustvpn
Group=rustvpn
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-server -proto udp -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/rustvpn-client.service`:

```ini
[Unit]
Description=RustVPN client (GoVPN 5.7 compatible)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustvpn
Group=rustvpn
EnvironmentFile=/etc/rustvpn/client.env
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-client -remote 203.0.113.10:1194 \
    -proto udp -iface rsvpn0 -mtu 1515 -timeout 60 \
    -verifier "${RUSTVPN_VERIFIER}" -key /etc/rustvpn/pass \
    -up /etc/rustvpn/up.sh -down /etc/rustvpn/down.sh
Restart=always
RestartSec=5
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rustvpn-server
sudo systemctl enable --now rustvpn-client
```

## Monitoring

The stats endpoint is a minimal HTTP server; query it locally:

```bash
curl -s http://127.0.0.1:1294/ | jq .
```

Useful checks:

- `FramesIn` / `FramesOut` increase under traffic.
- `FramesUnauth` stays 0; a growing value means packets that fail MAC or
  handshake validation (wrong key, wrong mode, or an attack).
- `FramesDup` stays near 0; growth means replay or duplicate delivery.
- `Established` matches the last successful handshake.
- `HeartbeatSent` / `HeartbeatRecv` show liveness on idle links.

Common commands:

```bash
# client
systemctl status rustvpn-client
journalctl -u rustvpn-client -f
sudo systemctl restart rustvpn-client
ping 10.88.0.1

# server
ssh root@server systemctl status rustvpn-server
ssh root@server journalctl -u rustvpn-server -f
ssh root@server 'curl -s 127.0.0.1:1294/ | jq .'
```

## Desktop client UI (Linux, optional)

The Tauri client (`rustvpn-clientd` plus `rustvpn-client-ui`) is independent of
the `rustvpn-client` CLI and uses its own local Unix socket. Install it with
`packaging/linux/build-packages.sh` and the distribution package manager
(`apt install ./dist/rustvpn-client_*.deb` or
`dnf install ./dist/rustvpn-client-*.rpm`), then enable the daemon and add
the desktop user to the `rustvpn` group.

- The GUI runs unprivileged; `rustvpn-clientd` keeps only
  `CAP_NET_ADMIN`/`CAP_NET_RAW`.
- Every profile needs an IPv4 `address`. A full-tunnel profile (`routes`
  containing `default`/`0.0.0.0/0`) also needs `gateway` and IPv4 `dns`.
- Routes and DNS are installed only after the first successful handshake.
  Full-tunnel connections install an IPv6 blackhole default route; split
  tunnels do not block IPv6/DNS.
- The daemon and CLI share `/run/rustvpn-client/tunnel.lock`, so only one
  tunnel can be active.
- The GUI provides a tray, close-to-tray, single-instance, login autostart,
  optional Secret Service keychain storage and zh/en/ru UI and tray
  translations. Tray/autostart need a desktop session; the daemon is still
  started by systemd.
- `packaging/linux/build-packages.sh` builds deb/rpm packages containing the
  CLI, daemon, GUI, unit and desktop entry. Both were built and inspected on
  Ubuntu with `rpmbuild`; installation still deserves a target-distro check.
- The daemon's `-hello-timeout` (5 s) and `-idle-timeout` (300 s) bound IPC
  handshakes and idle requests; event subscriptions stay open. The signed Tauri
  updater is an opt-in build feature and needs your own key and endpoint.
- Users running the GUI must be members of the `rustvpn` group. See the
  [client guide](../client-ui.md) (currently in Chinese) for the systemd unit,
  migration and troubleshooting details.

## Passphrase rotation

Rotate by generating a new verifier and **using both lines from the same
run** (they share the identity/salt):

```bash
openssl rand -hex 24 | tr -d '\n' | sudo tee /etc/rustvpn/pass.raw >/dev/null
sudo /usr/local/bin/rustvpn-verifier -key /etc/rustvpn/pass.raw > /tmp/rvver
# line 1: long form  -> server peers.yaml
# line 2: short form -> client client.env
sudo mv /etc/rustvpn/pass.raw /etc/rustvpn/pass
sudo systemctl restart rustvpn-client
ssh root@server systemctl restart rustvpn-server
```

Restart both sides close together; the client retries automatically.

## Upgrade and rollback

1. Build a static binary (see [Getting started](getting-started.md)).
2. Copy it to `/usr/local/bin/`, replacing the old one.
3. `systemctl restart` both sides. Config format and wire protocol are
   unchanged across Rust builds and versus GoVPN 5.7.

Rollback is the same procedure with the previous binary. Keep a copy of
the last known-good binary and `peers.yaml`.

## Uninstall

```bash
# client
sudo systemctl disable --now rustvpn-client
sudo rm -f /etc/systemd/system/rustvpn-client.service /usr/local/bin/rustvpn-client
sudo rm -rf /etc/rustvpn
sudo systemctl daemon-reload
# optional: sudo userdel rustvpn

# server
sudo systemctl disable --now rustvpn-server
sudo rm -f /etc/systemd/system/rustvpn-server.service /usr/local/bin/rustvpn-server
sudo rm -rf /etc/rustvpn
sudo systemctl daemon-reload
sudo ip link del rsvpn0 2>/dev/null || true
```

## Coexistence with an existing GoVPN

RustVPN uses its own ports and networks, so both can run on one host:

- give RustVPN a different UDP/TCP port (for example 1194) and a
  different TAP name/prefix (`rsvpn0`) and subnet (`10.88.0.0/24`);
- do not touch the existing GoVPN service, its TAP device or its NAT
  rules;
- if the host firewalls inbound traffic, open only the new port and
  consider limiting it to the client's current address.

## Troubleshooting

| Symptom | Diagnosis |
|---|---|
| `Cannot find device` on the server | The `up` script did not run `ip tuntap add ... mode tap`. |
| Handshake works, ping fails | Missing address/route on TAP, or MTU too large for the mode. |
| `FramesUnauth` grows | Mode mismatch (noise/encless), wrong verifier/passphrase, or injected traffic. |
| `session failed: random number mismatch` | Usually overlapping old/new sessions after a simultaneous restart; let the client reconnect. |
| Client reconnects only every `timeout` seconds | The first handshake packet is not retransmitted; the client waits for the timeout. Lower `-timeout` for faster recovery. |
| Stats endpoint unreachable | It is bound to the `-stats` address; use `127.0.0.1` and query from the same host or a tunnel. |

Next: [Security](security.md).