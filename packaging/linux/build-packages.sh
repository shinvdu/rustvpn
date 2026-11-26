#!/usr/bin/env bash
#
# Build Linux distribution packages for the RustVPN desktop client stack.
#
# The resulting packages install:
#   rustvpn-client       command-line client
#   rustvpn-clientd      privileged daemon (systemd unit, system user/group)
#   rustvpn-client-ui    Tauri desktop GUI
#
# Usage: build-packages.sh [deb|rpm|all] [--skip-build]
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

PKG_NAME="rustvpn-client"
RPM_RELEASE="1"
CARGO="${CARGO:-cargo}"
MAINTAINER="RustVPN contributors <rustvpn-maintainers@users.noreply.github.com>"
HOMEPAGE="https://github.com/shinvdu/rustvpn"

usage() {
    cat <<'EOF'
Usage: build-packages.sh [deb|rpm|all] [--skip-build]

  deb           build dist/rustvpn-client_<version>_<deb-arch>.deb
  rpm           build dist/rustvpn-client-<version>-<release>.<rpm-arch>.rpm
  all           build both (default)

  --skip-build  reuse existing binaries instead of running cargo build
  -h, --help    show this help

Environment:
  RUSTVPN_BIN_DIR  directory holding the release binaries
                   (default: <repo>/target/release)
  CARGO            cargo executable to use (default: cargo)
EOF
}

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

target="all"
skip_build=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        deb|rpm|all) target="$1" ;;
        --skip-build) skip_build=1 ;;
        -h|--help) usage; exit 0 ;;
        *)
            printf 'error: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

[ -f "$REPO_ROOT/Cargo.toml" ] || die "workspace Cargo.toml not found at $REPO_ROOT"

# Version comes from the [workspace.package] table, not from a crate.
VERSION="$(awk '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/                     { in_section = 0 }
    in_section && /^[[:space:]]*version[[:space:]]*=/ {
        line = $0
        sub(/^[^=]*=[[:space:]]*"/, "", line)
        sub(/".*$/, "", line)
        print line
        exit
    }
' "$REPO_ROOT/Cargo.toml")"
[ -n "$VERSION" ] || die "could not read version from [workspace.package] in Cargo.toml"

if [ "$skip_build" -eq 0 ]; then
    log "building release binaries"
    ( cd "$REPO_ROOT" && "$CARGO" build --release \
        -p rustvpn-client -p rustvpn-clientd -p rustvpn-client-gui )
else
    log "skipping cargo build (--skip-build)"
fi

BIN_DIR="${RUSTVPN_BIN_DIR:-$REPO_ROOT/target/release}"
[ -d "$BIN_DIR" ] || die "binary directory does not exist: $BIN_DIR"

missing=0
for bin in rustvpn-client rustvpn-clientd rustvpn-client-ui; do
    if [ ! -x "$BIN_DIR/$bin" ]; then
        printf 'error: missing executable: %s\n' "$BIN_DIR/$bin" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    die "build the binaries first (omit --skip-build) or set RUSTVPN_BIN_DIR"
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/rustvpn-pkg.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

PAYLOAD="$STAGE/root"

stage_payload() {
    log "staging payload"
    install -Dm755 "$BIN_DIR/rustvpn-client"    "$PAYLOAD/usr/bin/rustvpn-client"
    install -Dm755 "$BIN_DIR/rustvpn-clientd"   "$PAYLOAD/usr/bin/rustvpn-clientd"
    install -Dm755 "$BIN_DIR/rustvpn-client-ui" "$PAYLOAD/usr/bin/rustvpn-client-ui"

    # The upstream unit points at /usr/local/bin; packages install to /usr/bin.
    install -d "$PAYLOAD/lib/systemd/system"
    sed -e 's#^ExecStart=/usr/local/bin/#ExecStart=/usr/bin/#' \
        "$REPO_ROOT/packaging/systemd/rustvpn-clientd.service" \
        > "$PAYLOAD/lib/systemd/system/rustvpn-clientd.service"
    chmod 0644 "$PAYLOAD/lib/systemd/system/rustvpn-clientd.service"

    install -Dm644 "$REPO_ROOT/packaging/desktop/rustvpn-client.desktop" \
        "$PAYLOAD/usr/share/applications/rustvpn-client.desktop"

    # Prefer the real 256x256 artwork; fall back to the bundled desktop icon.
    local icon_src="$REPO_ROOT/crates/rustvpn-client-gui/icons/128x128@2x.png"
    [ -f "$icon_src" ] || icon_src="$REPO_ROOT/packaging/desktop/rustvpn.png"
    install -Dm644 "$icon_src" \
        "$PAYLOAD/usr/share/icons/hicolor/256x256/apps/rustvpn.png"

    install -Dm644 "$REPO_ROOT/packaging/README.md" \
        "$PAYLOAD/usr/share/doc/$PKG_NAME/README.md"
    install -Dm644 "$REPO_ROOT/COPYING" \
        "$PAYLOAD/usr/share/doc/$PKG_NAME/COPYING"
}

deb_arch() {
    command -v dpkg >/dev/null 2>&1 || die "dpkg not found; cannot determine the Debian architecture"
    dpkg --print-architecture
}

rpm_arch() {
    case "$(uname -m)" in
        x86_64|amd64)         echo "x86_64" ;;
        aarch64|arm64)        echo "aarch64" ;;
        armv7l|armv7hl)       echo "armv7hl" ;;
        armv6l)               echo "armv6hl" ;;
        i386|i486|i586|i686)  echo "i686" ;;
        ppc64le)              echo "ppc64le" ;;
        s390x)                echo "s390x" ;;
        riscv64)              echo "riscv64" ;;
        *)                    uname -m ;;
    esac
}

build_deb() {
    command -v dpkg-deb >/dev/null 2>&1 \
        || die "dpkg-deb not found; install dpkg-dev to build the .deb (the rpm target is unaffected)"

    local arch root size out
    arch="$(deb_arch)"
    root="$STAGE/deb"
    log "building deb ($arch)"
    mkdir -p "$root"
    cp -a "$PAYLOAD/." "$root/"
    mkdir -p "$root/DEBIAN"
    size="$(du -sk "$PAYLOAD" | awk '{print $1}')"

    cat > "$root/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $arch
Maintainer: $MAINTAINER
Installed-Size: $size
Depends: libwebkit2gtk-4.1-0, libgtk-3-0, libayatana-appindicator3-1,
 librsvg2-2, libssl3, libdbus-1-3
Homepage: $HOMEPAGE
Description: RustVPN desktop client
 RustVPN client stack: the rustvpn-client command-line client, the
 privileged rustvpn-clientd system daemon and the rustvpn-client-ui
 Tauri desktop GUI.
EOF
    chmod 0644 "$root/DEBIAN/control"

    # Create the unprivileged system user/group that the daemon runs as.
    cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group rustvpn >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system rustvpn
    else
        addgroup --system rustvpn
    fi
fi

if ! getent passwd rustvpn >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid rustvpn rustvpn
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

    cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop rustvpn-clientd.service >/dev/null 2>&1 || true
        systemctl disable rustvpn-clientd.service >/dev/null 2>&1 || true
    fi
fi
exit 0
EOF

    # Remove the system user/group only on purge, never on upgrade or remove.
    cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "purge" ]; then
    if getent passwd rustvpn >/dev/null 2>&1; then
        userdel rustvpn >/dev/null 2>&1 || true
    fi
    if getent group rustvpn >/dev/null 2>&1; then
        groupdel rustvpn >/dev/null 2>&1 || true
    fi
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

    chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

    # No conffiles: the package ships no configuration files.
    ( cd "$root" && find . -type f ! -path './DEBIAN/*' -print0 \
        | sort -z | xargs -0 -r md5sum | sed 's#  \./#  #' ) \
        > "$root/DEBIAN/md5sums"
    chmod 0644 "$root/DEBIAN/md5sums"

    mkdir -p "$DIST_DIR"
    out="$DIST_DIR/${PKG_NAME}_${VERSION}_${arch}.deb"
    if dpkg-deb --help 2>&1 | grep -q -- '--root-owner-group'; then
        dpkg-deb --root-owner-group --build "$root" "$out"
    else
        dpkg-deb --build "$root" "$out"
    fi
    log "built $out"
}

build_rpm() {
    command -v rpmbuild >/dev/null 2>&1 \
        || die "rpmbuild not found; install the 'rpm' package (e.g. 'sudo apt install rpm') to build RPMs. The deb target is unaffected."

    local arch topdir spec rendered rpmfile
    arch="$(rpm_arch)"
    topdir="$STAGE/rpmbuild"
    mkdir -p "$topdir"/BUILD "$topdir"/BUILDROOT "$topdir"/RPMS \
        "$topdir"/SOURCES "$topdir"/SPECS "$topdir"/SRPMS

    rendered="$topdir/SPECS/${PKG_NAME}.spec"
    sed -e "s|@VERSION@|${VERSION}|g" \
        -e "s|@RELEASE@|${RPM_RELEASE}|g" \
        -e "s|@RPM_ARCH@|${arch}|g" \
        "$SCRIPT_DIR/${PKG_NAME}.spec.in" > "$rendered"

    log "building rpm ($arch)"
    rpmbuild -bb \
        --define "_topdir $topdir" \
        --define "staging $PAYLOAD" \
        "$rendered"

    rpmfile="$(find "$topdir/RPMS" -type f -name '*.rpm' -print -quit)"
    [ -n "$rpmfile" ] || die "rpmbuild did not produce an RPM"
    mkdir -p "$DIST_DIR"
    cp -f "$rpmfile" "$DIST_DIR/"
    log "built $DIST_DIR/$(basename "$rpmfile")"
}

stage_payload

status=0
if [ "$target" = "deb" ] || [ "$target" = "all" ]; then
    set +e
    ( set -e; build_deb )
    target_status=$?
    set -e
    [ "$target_status" -eq 0 ] || status=1
fi
if [ "$target" = "rpm" ] || [ "$target" = "all" ]; then
    set +e
    ( set -e; build_rpm )
    target_status=$?
    set -e
    [ "$target_status" -eq 0 ] || status=1
fi

if [ "$status" -eq 0 ]; then
    log "packages written to $DIST_DIR"
else
    printf 'error: one or more package targets failed\n' >&2
fi
exit "$status"
