# Packaging notes

These files are templates for a split deployment:

- `systemd/rustvpn-server.service` — data plane; owns TAP and `CAP_NET_ADMIN`.
- `systemd/rustvpn-admind.service` — HTTP admin UI, SQLite and config writes;
  no capabilities.

The server works without the admin daemon. Only add the second unit (and the
`-control` flag) when you want live sessions/kick/reload from the UI. Enabling
`-control` requires at least one `-script-dir`; the admin daemon refuses to
write configuration while the server is offline because it cannot preflight it.

## Users, groups and directories

```bash
sudo groupadd --system rustvpn
sudo groupadd --system rustvpn-adm
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
    --gid rustvpn --groups rustvpn-adm rustvpn
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
    --gid rustvpn-adm rustvpn-admin

# Existing deployments: add the group instead of recreating the user.
# sudo usermod -aG rustvpn-adm rustvpn

sudo chgrp rustvpn-adm /etc/rustvpn
sudo chmod 2770 /etc/rustvpn
sudo chmod 0640 /etc/rustvpn/peers.yaml /etc/rustvpn/peers.disabled.yaml
sudo install -d -m 0755 -o root -g root /etc/rustvpn/scripts
sudo install -d -m 0750 -o rustvpn-admin -g rustvpn-adm \
    /var/lib/rustvpn /var/lib/rustvpn/backups
```

Scripts under `/etc/rustvpn/scripts` must be root-owned or owned by the server
user, not writable by group/others, and exist before they are referenced.
`rustvpn-admind` cannot write this directory.

## Install binaries and units

```bash
cargo build --release -p rustvpn-server
cargo build --release -p rustvpn-admin --bins
sudo install -m 0755 target/release/rustvpn-server /usr/local/bin/
sudo install -m 0755 target/release/rustvpn-admind \
    target/release/rustvpn-admin-passwd /usr/local/bin/

sudo install -m 0644 packaging/systemd/rustvpn-server.service \
    packaging/systemd/rustvpn-admind.service /etc/systemd/system/
sudo systemctl daemon-reload
```

For a static musl deployment, add
`--target x86_64-unknown-linux-musl` and install from
`target/x86_64-unknown-linux-musl/release/`.

## Initialize admin and start

```bash
sudo rustvpn-admin-passwd -db /var/lib/rustvpn/admin.db -user admin
sudo systemctl enable --now rustvpn-server.service
sudo systemctl enable --now rustvpn-admind.service
```

The admin UI listens on `127.0.0.1:8080`. Put a TLS reverse proxy in front of
it; do not expose the port directly. See [`docs/admin-web-ui.md`](../docs/admin-web-ui.md)
for Caddy, API, security and rollback details.

## Upgrading an existing deployment

Changing the server user's group and adding `-control` requires a restart, so
do it in a maintenance window. Keep a copy of the previous binary and unit.
If the admin daemon fails to start, the data plane is unaffected; stop
`rustvpn-admind` and continue with the server alone.

The control socket lives in `/run/rustvpn` and is local-only. Do not expose it
over TCP or mount it from an untrusted namespace.

## Desktop client (Linux)

- `systemd/rustvpn-clientd.service` — privileged client daemon (TAP, routes,
  DNS, reconnect); keeps `CAP_NET_ADMIN`/`CAP_NET_RAW`.
- `desktop/rustvpn-client.desktop` — desktop entry for the Tauri UI.

The GUI (`rustvpn-client-ui`) runs as the logged-in user and talks to the
daemon over `/run/rustvpn-client/client.sock` (`0660`, group `rustvpn`). Users must be
members of that group (primary or supplementary; the daemon checks
`/proc/<pid>/status`). The CLI `rustvpn-client` remains independent and does
not need the daemon, but both share `/run/rustvpn-client/tunnel.lock` so only one
tunnel can own the host routes. If the CLI runs as a systemd service, give it
`RuntimeDirectory=rustvpn-client` and `RuntimeDirectoryMode=0750` as well, otherwise
it cannot see the shared lock created by the daemon.

A GUI profile must have an IPv4 `address`. A full-tunnel profile (`routes`
containing `default`/`0.0.0.0/0`) also needs a `gateway` and an IPv4 `dns`
server; the daemon refuses to connect otherwise to avoid accidentally
installing an unreachable default route or leaking DNS. On full-tunnel
connections it installs an IPv6 blackhole default route for the duration of
the tunnel; IPv6 is not tunnelled yet.

```bash
sudo groupadd --system rustvpn
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g rustvpn rustvpn
sudo usermod -aG rustvpn "$USER"

cargo build --release -p rustvpn-clientd -p rustvpn-client-gui
sudo install -m 0755 target/release/rustvpn-clientd /usr/local/bin/
sudo install -m 0755 target/release/rustvpn-client-ui /usr/local/bin/
sudo install -m 0644 packaging/systemd/rustvpn-clientd.service /etc/systemd/system/
sudo install -Dm0644 packaging/desktop/rustvpn-client.desktop \
    /usr/share/applications/rustvpn-client.desktop
sudo install -Dm0644 packaging/desktop/rustvpn.png \
    /usr/share/icons/hicolor/128x128/apps/rustvpn.png
sudo systemctl daemon-reload
sudo systemctl enable --now rustvpn-clientd.service
```

Build the GUI on Ubuntu 24.04 needs the Tauri dependencies:
`libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
libxdo-dev libssl-dev libdbus-1-dev`. The tray uses
`libayatana-appindicator3`; the optional keychain integration uses the desktop
Secret Service (GNOME Keyring or KWallet). See
[`docs/client-ui.md`](../docs/client-ui.md).