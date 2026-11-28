# Docker / Compose deployment

[中文](../zh/docker.md) | **English**

This page describes the container deployment: one bootstrap command starts
`rustvpn-server` + `rustvpn-admind` and generates a Windows-client profile.
TAP creation, forwarding and NAT stay inside the server container's network
namespace; the host only publishes the VPN port.

For the systemd deployment see [Operations](operations.md); for the Windows
installer see [`docs/windows-install.md`](../windows-install.md).

---

## 1. Requirements

- Linux with Docker 24+ and Docker Compose v2 (rootful Docker).
- `/dev/net/tun` on the host (`sudo modprobe tun` if missing).
- An IPv4 default route. The server container needs `NET_ADMIN`, `NET_RAW`,
  `CHOWN` and `DAC_READ_SEARCH`, plus the TUN device.
- A reachable TCP+UDP port (default 1194), opened in the host firewall and the
  cloud security group; behind a router/NAT, forward that port to this host.
- 1 vCPU / 512 MB is enough to start; the admin SQLite database needs a little
  disk.

The host does not need Rust, WiX or `nft`; they are inside the images.

---

## 2. One command

From the repository root:

```bash
sudo ./deploy/docker/quickstart.sh --endpoint vpn.example.com
```

`--endpoint` is the address clients connect to. When omitted the script probes
the outbound IPv4 address and refuses to continue if it is private/CGNAT; a
server behind NAT must pass an explicit public name or address.

Without a checkout:

```bash
curl -fsSL https://raw.githubusercontent.com/shinvdu/rustvpn/main/deploy/docker/quickstart.sh \
  -o rustvpn-quickstart.sh
sudo bash rustvpn-quickstart.sh --endpoint vpn.example.com
```

The script downloads `compose.yaml` from the same `RUSTVPN_RAW_BASE`. Pin that
URL to a tag or commit in production instead of following `main`.

What it does:

1. creates the data directory (`/opt/rustvpn` by default) with the required
   permissions;
2. generates a client passphrase and runs `rustvpn-verifier` to obtain the
   LONG/SHORT verifier;
3. writes `conf/peers.yaml` with the LONG verifier and a declarative
   `network:` section;
4. initializes the admin account (the password is only written to a 0600 file);
5. runs `docker compose up -d` and waits for the control socket and admin;
6. prints the client profile, passphrase file, admin password file and the SSH
   tunnel command.

### Options

| Option | Meaning | Default |
|---|---|---|
| `--endpoint HOST[:PORT]` | Client-visible address | auto-detect |
| `--client NAME` | First client name | `windows` |
| `--pool CIDR` | Tunnel pool, IPv4 `/16` | `10.88.0.0/16` |
| `--dns IP` | Client DNS, repeatable | `1.1.1.1` |
| `--split CIDR` | Split-tunnel route, repeatable | full tunnel |
| `--mtu N` | Wire MTU shared by both sides | `1420` |
| `--data-dir PATH` | State directory | `/opt/rustvpn` |
| `--port PORT` | Published VPN port | `1194` |
| `--admin-port PORT` | Admin loopback port | `8080` |
| `--no-admin` | Do not run the admin UI | run it |
| `--no-nat` | Do not install NAT/forwarding in the container | install |
| `--build` | Build images from this checkout | pull from GHCR |
| `--open-firewall` | Add a ufw/firewalld allow rule | do not modify |

> **Pool collisions:** the default `10.88.0.0/16` matches many GoVPN/WireGuard
> examples. If the host or a peer already uses `10.88.0.0/24`, pick an unused
> `/16` such as `10.99.0.0/16`. Each client gets one `/24` (server
> `10.88.N.1`, client `10.88.N.2`).

---

## 3. Client profile

The first client is `windows`:

```text
/opt/rustvpn/clients/windows.yaml     # profile, no password
/opt/rustvpn/secrets/windows.pass     # passphrase, root-only
```

On Windows:

1. install `RustVPN-<version>-x64.msi` from GitHub Releases;
2. copy `windows.yaml` to `%LOCALAPPDATA%\RustVPN\profiles\`;
3. open the GUI, select the profile and enter the passphrase from
   `windows.pass` (optionally stored in Windows Credential Manager).

The profile contains the remote endpoint, SHORT verifier, MTU, address,
gateway, DNS and default route. It never contains the passphrase. Transfer the
profile and the passphrase separately, and delete the passphrase file after the
user has stored it.

Add clients:

```bash
sudo ./deploy/docker/quickstart.sh add-client laptop
```

A new `/24` is allocated and `clients/laptop.yaml` + `secrets/laptop.pass` are
written. The server hot-reloads peers within 60 seconds; pass `--restart` to
restart it immediately (this drops active sessions). Rotate a passphrase with:

```bash
sudo ./deploy/docker/quickstart.sh rotate-client laptop
```

---

## 4. Admin UI

The admin daemon listens on the host loopback only:

```bash
ssh -N -L 8080:127.0.0.1:8080 root@vpn.example.com
# open http://127.0.0.1:8080/
```

The login is `admin`; the initial password is in
`/opt/rustvpn/secrets/admin.pass` (root-only and not printed). Rotate it with
`quickstart.sh rotate-admin-password`.

**Known limitation:** in 0.2.x the admin UI's “create client” does not add the
declarative `network:` section, so peers created there will not create a TAP in
this container deployment. Use `quickstart.sh add-client`. The UI is still
useful for sessions, kick/disable/enable, rotation, config apply/backups and
history.

Do not publish 8080. If remote access is required, put a TLS reverse proxy in
front and restrict the source network.

---

## 5. Data directory

```text
/opt/rustvpn/
  conf/peers.yaml               # source of truth; server reads, admin writes
  conf/peers.disabled.yaml      # optional, written by admin
  run/control.sock              # shared control socket
  state/admin.db                # accounts, history, audit (SQLite)
  state/backups/                # config backups
  secrets/                      # client/admin passphrases (0700 root)
  clients/                      # client profiles (owned by the operator)
  .env                          # Compose variables (0600)
```

Permissions:

| Path | Mode |
|---|---|
| `conf/`, `run/` | `0770 root:10001` |
| `peers*.yaml` | `0660 root:10001` (`0640 10001:10001` after an admin write) |
| `state/`, `state/backups/` | `0700 10001:10001` |
| `secrets/` | `0700 root:root`, files `0600` |
| `clients/` | `0750`, owned by the invoking `sudo` user |

The server runs as root in its container with a reduced capability set and no
`DAC_OVERRIDE`; `DAC_READ_SEARCH` lets it read config files rewritten by the
admin (uid 10001), while the config directory is writable by the admin group.

Back up and upgrade:

```bash
sudo tar -C /opt -czf rustvpn-backup.tgz rustvpn
sudo ./deploy/docker/quickstart.sh setup --data-dir /opt/rustvpn --tag 0.3.0
```

Setup is idempotent: existing peers, passphrases and the admin database are
kept. Pin image tags or digests in production instead of tracking `edge`.

Stop or remove:

```bash
sudo ./deploy/docker/quickstart.sh down
sudo ./deploy/docker/quickstart.sh destroy --yes    # also deletes the data
```

---

## 6. Images and GHCR

```text
ghcr.io/shinvdu/rustvpn/rustvpn-server:<version>
ghcr.io/shinvdu/rustvpn/rustvpn-admind:<version>
```

- pushes to `main` publish `edge` and `sha-<commit>`;
- `v*` tags publish the version, `<major>.<minor>`, `latest` and `sha-<commit>`;
- a manual `workflow_dispatch` can publish a version matching `Cargo.toml`.

GHCR packages may be private by default. Make them public before advertising
anonymous pulls, or run `docker login ghcr.io`. For local development:

```bash
sudo ./deploy/docker/quickstart.sh setup --endpoint ... --build   # local :dev images
```

`rustvpn-clientd` is a Windows service (Wintun + named pipes) and is not
containerized; Windows users install the MSI. The server image also contains
`rustvpn-client` and `rustvpn-verifier` for debugging and automation.

---

## 7. Network and security model

- The server uses a Docker bridge network. The TAP, `ip_forward` and the
  `inet rustvpn_nat` nftables table live only in the container network
  namespace and disappear with the container.
- Only `${RUSTVPN_PORT}/udp` and `${RUSTVPN_PORT}/tcp` are published; the admin
  binds the host loopback via `network_mode: host`.
- Server container: root with `cap_drop: ALL` and only `NET_ADMIN`, `NET_RAW`,
  `CHOWN`, `DAC_READ_SEARCH`; `no-new-privileges`, read-only root filesystem.
- Admin container: uid/gid `10001`, no capabilities, read-only root filesystem,
  loopback only.
- The control socket is `0660 root:10001`; the server authorizes the admin by
  its primary gid via `SO_PEERCRED`.
- `--no-nat` is for hosts that already provide forwarding/NAT; otherwise a
  full-tunnel client can only reach the server itself.
- No IPv6 tunneling. The Windows full-tunnel guard blocks IPv6.
- The default DNS `1.1.1.1` is routed through the tunnel; override with `--dns`.

---

## 8. Troubleshooting

| Symptom | Action |
|---|---|
| `/dev/net/tun is missing` | `modprobe tun` on the host |
| server exits immediately | `docker compose logs server`; check `peers.yaml` and `-script-dir` permissions |
| TAP never appears | confirm the client completed the handshake and `network:` is still in the peer block |
| client connects but has no Internet | check 1194/udp in the cloud firewall; do not use `--no-nat`; inspect `nft list table inet rustvpn_nat` |
| admin says “server offline” | server not running or `-control` missing; check the shared `run/` volume and socket permissions |
| `docker compose pull` returns 403 | GHCR package is private; log in or make it public |
| `add-client` not active after 60 s | use `--restart`, or check `config_last_error` |

Container self-test (temporary Compose project, does not touch host routing or
NAT):

```bash
sudo RUSTVPN_SELFTEST_PORT=21941 ./deploy/docker/selftest.sh
```

It builds/uses local `:dev` images, starts the server, runs a client container
on an isolated Docker network, and verifies ping, full-tunnel egress, session
counters, a second client and host isolation. With existing images set
`RUSTVPN_SELFTEST_SKIP_BUILD=1`.

---

## 9. Verification status (2026-11-28)

- Linux host, Docker 29.7 + Compose v5.5: isolated server+client container E2E
  passed (ping, full-tunnel egress, session counters, a second client, and no
  host TAP/NAT leakage).
- Windows 11 VM with the 0.2.0 MSI, driven through the daemon IPC with a
  profile generated by this flow (MTU 1420, `10.99.0.0/16` pool, full tunnel):
  ping to the gateway 4/4, ping to `1.1.1.1` 4/4, DNS A records, TCP 443, and
  `curl` egress matching the server. After disconnect the Wintun adapter, DNS
  and default route were restored.
- The generated YAML was placed in `%LOCALAPPDATA%\RustVPN\profiles\`; the
  connection was verified through the daemon IPC, not through a visual GUI
  check. The passphrase is still entered in the GUI.

## 10. Out of scope

- A standalone Linux client image (the server image's `rustvpn-client` is for
  debugging only).
- A Linux equivalent of `rustvpn-clientd`.
- ARM64 images, IPv6 transport, a built-in DNS service, and admin-managed
  `network:` allocation.
- Automatic cloud-security-group changes; opening the port is an operator task.