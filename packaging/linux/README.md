# Linux packages (deb / rpm)

`build-packages.sh` produces installable packages for the RustVPN desktop
client stack. Both packages ship the same payload:

| Path | Purpose |
| --- | --- |
| `/usr/bin/rustvpn-client` | command-line client (no daemon required) |
| `/usr/bin/rustvpn-clientd` | privileged daemon; systemd unit, system user `rustvpn` |
| `/usr/bin/rustvpn-client-ui` | Tauri desktop GUI |
| `/lib/systemd/system/rustvpn-clientd.service` | daemon unit (attached in the deb; rpm uses `%{_unitdir}`, normally `/usr/lib/systemd/system`) |
| `/usr/share/applications/rustvpn-client.desktop` | desktop entry |
| `/usr/share/icons/hicolor/256x256/apps/rustvpn.png` | application icon |
| `/usr/share/doc/rustvpn-client/README.md` | these packaging notes |
| `/usr/share/doc/rustvpn-client/COPYING` | license text |

No configuration files are shipped, so the packages declare no `conffiles`.
Profiles, keys and the keychain remain per-user (see below).

## Prerequisites

Build prerequisites on a Debian/Ubuntu host:

```bash
sudo apt install build-essential pkg-config dpkg-dev rpm \
    libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
    librsvg2-dev libxdo-dev libssl-dev libdbus-1-dev
```

- `dpkg-deb` comes from `dpkg-dev` and is needed for the `.deb` target.
- `rpmbuild` comes from the `rpm` package and is needed for the `.rpm` target.
- The Tauri/WebKitGTK development headers are needed to compile the GUI.
- Rust 1.85 or newer (`rustup` or the distribution toolchain).

On Fedora / openSUSE build hosts, install the equivalent `webkit2gtk4.1-devel`,
`gtk3-devel`, `libayatana-appindicator-gtk3-devel`, `librsvg2-devel`,
`openssl-devel` and `dbus-devel` packages plus `rpm-build`. Building the RPM on
the target distribution (or in a container for it) is recommended so automatic
library dependencies and `%{_unitdir}`/`%{_docdir}` resolve to that distro's
paths.

## Building

```bash
# Build the release binaries and both packages.
packaging/linux/build-packages.sh

# One format only.
packaging/linux/build-packages.sh deb
packaging/linux/build-packages.sh rpm

# Reuse binaries already in target/release (no cargo build).
packaging/linux/build-packages.sh --skip-build

# Reuse binaries from another directory (useful for CI or testing).
RUSTVPN_BIN_DIR=/path/to/bin packaging/linux/build-packages.sh all --skip-build
```

Outputs land in `dist/` at the repository root:

- `rustvpn-client_<version>_<deb-arch>.deb`
- `rustvpn-client-<version>-1.<rpm-arch>.rpm`

The version is read from `[workspace.package] version` in `Cargo.toml`. The deb
architecture comes from `dpkg --print-architecture`; the rpm architecture is
mapped from `uname -m`. If `rpmbuild` is missing, only the rpm target fails
with a clear message and the deb target still runs.

## Installing

```bash
sudo apt install ./dist/rustvpn-client_*.deb          # Debian/Ubuntu
sudo dnf install ./dist/rustvpn-client-*.rpm          # Fedora
sudo zypper install ./dist/rustvpn-client-*.rpm       # openSUSE
```

The package creates the system group and user `rustvpn` and reloads systemd.
The daemon is not enabled automatically; it needs an administrator's decision
about which profiles to trust.

## Enabling and starting the daemon

```bash
sudo systemctl enable --now rustvpn-clientd.service
systemctl status rustvpn-clientd.service
```

The unit keeps `CAP_NET_ADMIN`/`CAP_NET_RAW`, creates
`/run/rustvpn-client` and serves `/run/rustvpn-client/client.sock` (`0660`,
group `rustvpn`). Enabling the unit at boot is optional; the GUI and CLI work
without it, but only the daemon can install routes, DNS and reconnect.

Check the journal if the unit does not come up:

```bash
journalctl -u rustvpn-clientd.service -b
```

## Allowing desktop users to use the daemon

Membership is checked against `/proc/<pid>/status`, so supplementary groups are
fine:

```bash
sudo usermod -aG rustvpn "$USER"
# Log out and back in (or run `newgrp rustvpn`) so the new group is applied.
id -nG
```

The CLI `rustvpn-client` does not need the daemon or the group, but it shares
`/run/rustvpn-client/tunnel.lock` with the daemon so only one tunnel owns the
host routes.

## GUI autostart and keychain

Autostart is deliberately left to end users: the package does not drop a file
into `/etc/xdg/autostart`. To start the GUI at login, create a per-user entry:

```bash
mkdir -p ~/.config/autostart
cp /usr/share/applications/rustvpn-client.desktop ~/.config/autostart/
```

Disable it again by deleting that copy (or setting `Hidden=true` in it).

Secret storage uses the desktop Secret Service (GNOME Keyring, KWallet, or any
compatible provider) and is unlocked per login session. The package does not
provision a keyring; if none is available the GUI falls back to a
password prompt per connection. Profiles and preferences live under the user's
home directory and are never installed system-wide.

## Removing

```bash
sudo apt remove rustvpn-client       # keeps the rustvpn user
sudo apt purge rustvpn-client        # removes the user/group as well
sudo dnf remove rustvpn-client       # final erase removes the user/group
```

The db purges the `rustvpn` user and group only on `purge`; the rpm spec does
the same on final erase. Removal also stops and disables the service.

## Distro-specific notes

- **AppIndicator package name.** The rpm spec requires
  `libayatana-appindicator-gtk3`, the Fedora name. openSUSE calls the same
  library `libayatana-appindicator3-1`; if you build for openSUSE, edit the
  `Requires` line in `rustvpn-client.spec.in` (or add a
  `%if 0%{?suse_version}` branch).
- **OpenSSL package name.** The spec requires `openssl-libs` (Fedora/openSUSE
  both provide it on current releases). On older openSUSE use `libopenssl3`.
- **Unit and doc directories.** RPM installs the unit to `%{_unitdir}` (normally
  `/usr/lib/systemd/system`) and the README to `%{_docdir}`; the deb uses
  `/lib/systemd/system` and `/usr/share/doc`. On merged-`/usr` systems
  `/lib/systemd/system` and `/usr/lib/systemd/system` are the same directory.
- **Automatic dependencies.** Building the RPM on a non-target host may produce
  soname `Requires` for libraries that the host has but the target names
  differently. Build in a Fedora/openSUSE container to avoid surprises.

## Testing without a full build

`RUSTVPN_BIN_DIR` overrides the binary source directory, so packaging can be
exercised with placeholder executables:

```bash
tmp=$(mktemp -d)
for b in rustvpn-client rustvpn-clientd rustvpn-client-ui; do
    printf '#!/bin/sh\nexit 0\n' > "$tmp/$b"
    chmod 0755 "$tmp/$b"
done
RUSTVPN_BIN_DIR="$tmp" packaging/linux/build-packages.sh --skip-build all
```

Inspect the results with `dpkg-deb -c dist/*.deb`, `dpkg-deb -I dist/*.deb`
and `rpm -qpl dist/*.rpm`.
