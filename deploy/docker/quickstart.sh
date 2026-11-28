#!/usr/bin/env bash
#
# One-command RustVPN server bootstrap.
#
#   sudo ./deploy/docker/quickstart.sh --endpoint vpn.example.com
#   sudo ./deploy/docker/quickstart.sh add-client laptop
#   sudo ./deploy/docker/quickstart.sh status
#   sudo ./deploy/docker/quickstart.sh down
#
# It creates the data directory, generates a Windows-client profile and
# passphrase, initializes the admin account, and starts the Compose stack.
# Passphrases are only written to 0600 files; nothing secret is printed.
set -euo pipefail
umask 022

PROGRAM="$(basename "${BASH_SOURCE[0]:-$0}")"

# ------------------------------------------------------------------ defaults
DATA_DIR="/opt/rustvpn"
PROJECT="rustvpn"
PORT="1194"
ADMIN_PORT="8080"
LISTEN_IP="0.0.0.0"
MTU="1420"
POOL="10.88.0.0/16"
CLIENT="windows"
TAG=""
TAG_SET=0
SERVER_IMAGE=""
ADMIN_IMAGE=""
SERVER_IMAGE_OVERRIDE=""
ADMIN_IMAGE_OVERRIDE=""
ENDPOINT=""
DNS=(1.1.1.1)
DNS_SET=0
SPLIT=()
NO_ADMIN=0
NAT="1"
BUILD=0
SOURCE_DIR=""
OPEN_FW=0
ALLOW_PRIVATE=0
ASSUME_YES=0
RESTART=0
SUBCOMMAND=""
RAW_BASE="${RUSTVPN_RAW_BASE:-https://raw.githubusercontent.com/shinvdu/rustvpn/main/deploy/docker}"

# ------------------------------------------------------------- small helpers
log() { printf 'rustvpn: %s\n' "$*" >&2; }
warn() { printf 'rustvpn: warning: %s\n' "$*" >&2; }
die() { printf 'rustvpn: error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $PROGRAM [command] [options]

Commands (default: setup):
  setup                 initialize data, create the first client, start the stack
  add-client NAME       add another client (profile + passphrase)
  rotate-client NAME    replace a client's passphrase and verifier
  rotate-admin-password generate a new admin password
  status                show containers, server status and admin readiness
  logs                  follow container logs
  down                  stop and remove the containers (data is kept)
  destroy --yes         remove containers and delete the data directory

Options:
  --endpoint HOST[:PORT]  public server address (detected when omitted)
  --client NAME           first client name (default: windows)
  --dns IP                DNS server for the client profile (repeatable)
  --split CIDR            split-tunnel route (repeatable; replaces default)
  --mtu N                 wire MTU shared by server and client (default: 1420)
  --pool CIDR             tunnel address pool, /16 (default: 10.88.0.0/16)
  --data-dir PATH         state directory (default: /opt/rustvpn)
  --project NAME          Compose project name (default: rustvpn)
  --port PORT             published VPN port (default: 1194)
  --listen-ip IP          published address (default: 0.0.0.0)
  --admin-port PORT       admin loopback port (default: 8080)
  --tag TAG               image tag (default: Cargo.toml version)
  --server-image IMAGE    override the server image
  --admin-image IMAGE     override the admin image
  --build                 build both images from this checkout
  --source-dir PATH       repository root for --build when running standalone
  --no-admin              do not run the admin web UI
  --admin                 run the admin web UI (overrides a stored --no-admin)
  --no-nat                do not install NAT/forwarding in the server container
  --nat                   install NAT/forwarding (overrides a stored --no-nat)
  --open-firewall         add a ufw/firewalld allow rule for the VPN port
  --allow-private-endpoint accept a private detected address (testing only)
  --restart               restart the server after add-client/rotate-client
  --yes                   skip the destroy confirmation
  -h, --help              show this help

Windows client:
  Copy \$DATA/clients/<name>.yaml to %LOCALAPPDATA%\\RustVPN\\profiles\\
  and enter the passphrase from \$DATA/secrets/<name>.pass in the GUI.
EOF
}

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "run this command as root (for example with sudo)"
    fi
}

need_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed"
    docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
}

need_tun() {
    if [ ! -c /dev/net/tun ]; then
        modprobe tun 2>/dev/null || true
    fi
    [ -c /dev/net/tun ] || die "/dev/net/tun is missing; load the tun module on the host"
}

is_private_ip() {
    local ip=$1
    [[ $ip =~ ^10\. ]] && return 0
    [[ $ip =~ ^192\.168\. ]] && return 0
    [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
    [[ $ip =~ ^127\. ]] && return 0
    [[ $ip =~ ^169\.254\. ]] && return 0
    [[ $ip =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]] && return 0
    return 1
}

normalize_endpoint() {
    local value=$1
    case "$value" in
        *:*) printf '%s' "$value" ;;
        *) printf '%s:%s' "$value" "$PORT" ;;
    esac
}

detect_endpoint() {
    local ip
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
    [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$ip" ] || die "cannot detect the public address; pass --endpoint HOST[:PORT]"
    if is_private_ip "$ip" && [ "$ALLOW_PRIVATE" -ne 1 ]; then
        die "detected private address $ip; the client cannot reach it. Pass --endpoint <public-host> (or --allow-private-endpoint for a lab test)"
    fi
    printf '%s:%s' "$ip" "$PORT"
}

gen_secret() {
    od -An -N20 -tx1 /dev/urandom | tr -d ' \n'
}

write_secret() {
    local path=$1 value=$2
    printf '%s\n' "$value" >"$path"
    chmod 0600 "$path"
    chown root:root "$path"
}

valid_name() {
    [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]
}

# --------------------------------------------------------------- environment
SELF_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

pre_data_dir=""
pre_args=("$@")
for ((i = 0; i < ${#pre_args[@]}; i++)); do
    case "${pre_args[i]}" in
        --data-dir=*) pre_data_dir=${pre_args[i]#*=} ;;
        --data-dir)
            next=$((i + 1))
            if [ "$next" -lt "${#pre_args[@]}" ]; then pre_data_dir=${pre_args[next]}; fi
            ;;
    esac
done
DATA_DIR="${pre_data_dir:-$DATA_DIR}"

if [ -f "$DATA_DIR/.env" ]; then
    # shellcheck disable=SC1090
    . "$DATA_DIR/.env"
fi
if [ -n "$pre_data_dir" ]; then DATA_DIR=$pre_data_dir; fi
DATA_DIR="${RUSTVPN_DATA_DIR:-$DATA_DIR}"
PROJECT="${RUSTVPN_PROJECT:-$PROJECT}"
PORT="${RUSTVPN_PORT:-$PORT}"
ADMIN_PORT="${RUSTVPN_ADMIN_PORT:-$ADMIN_PORT}"
LISTEN_IP="${RUSTVPN_LISTEN_IP:-$LISTEN_IP}"
TAG="${RUSTVPN_IMAGE_TAG:-$TAG}"
ENV_SERVER_IMAGE="${RUSTVPN_SERVER_IMAGE:-}"
ENV_ADMIN_IMAGE="${RUSTVPN_ADMIN_IMAGE:-}"
ENDPOINT="${RUSTVPN_ENDPOINT:-$ENDPOINT}"
NAT="${RUSTVPN_NAT:-$NAT}"
POOL="${RUSTVPN_TUNNEL_POOL:-$POOL}"
if [ "${RUSTVPN_ADMIN_ENABLED:-1}" = "0" ]; then NO_ADMIN=1; fi

OPERATOR_UID="${SUDO_UID:-$(id -u)}"
OPERATOR_GID="${SUDO_GID:-$(id -g)}"

REPO_ROOT=""
if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/../../Cargo.toml" ]; then
    REPO_ROOT="$(cd "$SELF_DIR/../.." && pwd)"
fi

# ------------------------------------------------------------------ arguments
if [ $# -gt 0 ]; then
    case "$1" in
        setup|add-client|rotate-client|rotate-admin-password|status|logs|down|destroy)
            SUBCOMMAND=$1
            shift
            ;;
    esac
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT=${2:?--endpoint needs a value}; shift 2 ;;
        --endpoint=*) ENDPOINT=${1#*=}; shift ;;
        --client) CLIENT=${2:?--client needs a value}; shift 2 ;;
        --client=*) CLIENT=${1#*=}; shift ;;
        --dns)
            if [ "$DNS_SET" -eq 0 ]; then DNS=(); DNS_SET=1; fi
            DNS+=("${2:?--dns needs a value}")
            shift 2
            ;;
        --dns=*)
            if [ "$DNS_SET" -eq 0 ]; then DNS=(); DNS_SET=1; fi
            DNS+=("${1#*=}")
            shift
            ;;
        --split) SPLIT+=("${2:?--split needs a CIDR}"); shift 2 ;;
        --split=*) SPLIT+=("${1#*=}"); shift ;;
        --mtu) MTU=${2:?--mtu needs a value}; shift 2 ;;
        --mtu=*) MTU=${1#*=}; shift ;;
        --pool) POOL=${2:?--pool needs a CIDR}; shift 2 ;;
        --pool=*) POOL=${1#*=}; shift ;;
        --data-dir) DATA_DIR=${2:?--data-dir needs a value}; shift 2 ;;
        --data-dir=*) DATA_DIR=${1#*=}; shift ;;
        --project) PROJECT=${2:?--project needs a value}; shift 2 ;;
        --project=*) PROJECT=${1#*=}; shift ;;
        --port) PORT=${2:?--port needs a value}; shift 2 ;;
        --port=*) PORT=${1#*=}; shift ;;
        --listen-ip) LISTEN_IP=${2:?--listen-ip needs a value}; shift 2 ;;
        --listen-ip=*) LISTEN_IP=${1#*=}; shift ;;
        --admin-port) ADMIN_PORT=${2:?--admin-port needs a value}; shift 2 ;;
        --admin-port=*) ADMIN_PORT=${1#*=}; shift ;;
        --tag) TAG=${2:?--tag needs a value}; TAG_SET=1; shift 2 ;;
        --tag=*) TAG=${1#*=}; TAG_SET=1; shift ;;
        --server-image) SERVER_IMAGE_OVERRIDE=${2:?--server-image needs a value}; shift 2 ;;
        --server-image=*) SERVER_IMAGE_OVERRIDE=${1#*=}; shift ;;
        --admin-image) ADMIN_IMAGE_OVERRIDE=${2:?--admin-image needs a value}; shift 2 ;;
        --admin-image=*) ADMIN_IMAGE_OVERRIDE=${1#*=}; shift ;;
        --build) BUILD=1; shift ;;
        --source-dir) SOURCE_DIR=${2:?--source-dir needs a value}; shift 2 ;;
        --source-dir=*) SOURCE_DIR=${1#*=}; shift ;;
        --no-admin) NO_ADMIN=1; shift ;;
        --admin) NO_ADMIN=0; shift ;;
        --no-nat) NAT=0; shift ;;
        --nat) NAT=1; shift ;;
        --open-firewall) OPEN_FW=1; shift ;;
        --allow-private-endpoint) ALLOW_PRIVATE=1; shift ;;
        --restart) RESTART=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; continue ;;
        -*) die "unknown option: $1 (see --help)" ;;
        *)
            if [ -z "$SUBCOMMAND" ] || [ "$SUBCOMMAND" = "setup" ]; then
                die "unexpected argument: $1"
            fi
            CLIENT=$1
            shift
            ;;
    esac
done

valid_name "$CLIENT" || die "invalid client name: $CLIENT (use letters, digits, . _ -)"
if ! [[ $POOL =~ ^([0-9]{1,3})\.([0-9]{1,3})\.0\.0/16$ ]]; then
    die "invalid tunnel pool: $POOL (expected an IPv4 /16 such as 10.88.0.0/16)"
fi
if [ "${BASH_REMATCH[1]}" -gt 255 ] || [ "${BASH_REMATCH[2]}" -gt 255 ]; then
    die "invalid tunnel pool: $POOL (octets must be 0-255)"
fi
POOL_PREFIX="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"

# -------------------------------------------------------------------- images
if [ -z "$TAG" ]; then
    if [ -n "$REPO_ROOT" ]; then
        TAG="$(awk -F'"' '/^version = /{print $2; exit}' "$REPO_ROOT/Cargo.toml")"
    fi
    TAG="${TAG:-0.2.0}"
fi

if [ "$BUILD" -eq 1 ]; then
    if [ "$TAG_SET" -eq 0 ]; then TAG=dev; fi
    SERVER_IMAGE="${SERVER_IMAGE_OVERRIDE:-rustvpn-server:dev}"
    ADMIN_IMAGE="${ADMIN_IMAGE_OVERRIDE:-rustvpn-admind:dev}"
    if [ -z "$SOURCE_DIR" ]; then
        [ -n "$REPO_ROOT" ] || die "--build needs a checkout or --source-dir PATH"
        SOURCE_DIR="$REPO_ROOT"
    fi
    SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
else
    if [ -n "$SERVER_IMAGE_OVERRIDE" ]; then
        SERVER_IMAGE="$SERVER_IMAGE_OVERRIDE"
    elif [ "$TAG_SET" -eq 0 ] && [ -n "$ENV_SERVER_IMAGE" ]; then
        SERVER_IMAGE="$ENV_SERVER_IMAGE"
    else
        SERVER_IMAGE="ghcr.io/shinvdu/rustvpn/rustvpn-server:$TAG"
    fi
    if [ -n "$ADMIN_IMAGE_OVERRIDE" ]; then
        ADMIN_IMAGE="$ADMIN_IMAGE_OVERRIDE"
    elif [ "$TAG_SET" -eq 0 ] && [ -n "$ENV_ADMIN_IMAGE" ]; then
        ADMIN_IMAGE="$ENV_ADMIN_IMAGE"
    else
        ADMIN_IMAGE="ghcr.io/shinvdu/rustvpn/rustvpn-admind:$TAG"
    fi
fi

# -------------------------------------------------------------------- compose
if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/compose.yaml" ]; then
    COMPOSE_FILE="$SELF_DIR/compose.yaml"
    BUILD_FILE="$SELF_DIR/compose.build.yaml"
else
    COMPOSE_FILE="$DATA_DIR/compose.yaml"
    BUILD_FILE="$DATA_DIR/compose.build.yaml"
    if [ ! -f "$COMPOSE_FILE" ]; then
        command -v curl >/dev/null 2>&1 || die "curl is required to download compose.yaml"
        mkdir -p "$DATA_DIR"
        curl -fsSL "$RAW_BASE/compose.yaml" -o "$COMPOSE_FILE" ||
            die "cannot download $RAW_BASE/compose.yaml"
    fi
fi
if [ "$BUILD" -eq 1 ]; then
    if [ ! -f "$BUILD_FILE" ]; then
        curl -fsSL "$RAW_BASE/compose.build.yaml" -o "$BUILD_FILE" ||
            die "cannot download $RAW_BASE/compose.build.yaml"
    fi
fi

compose() {
    local -a args=(--project-name "$PROJECT" --env-file "$DATA_DIR/.env" -f "$COMPOSE_FILE")
    if [ "$BUILD" -eq 1 ]; then
        args+=(-f "$BUILD_FILE")
    fi
    docker compose "${args[@]}" "$@"
}

write_env() {
    local tmp="$DATA_DIR/.env.tmp"
    cat >"$tmp" <<EOF
RUSTVPN_PROJECT='$PROJECT'
RUSTVPN_IMAGE_TAG='$TAG'
RUSTVPN_SERVER_IMAGE='$SERVER_IMAGE'
RUSTVPN_ADMIN_IMAGE='$ADMIN_IMAGE'
RUSTVPN_DATA_DIR='$DATA_DIR'
RUSTVPN_LISTEN_IP='$LISTEN_IP'
RUSTVPN_PORT='$PORT'
RUSTVPN_ADMIN_PORT='$ADMIN_PORT'
RUSTVPN_NAT='$NAT'
RUSTVPN_TUNNEL_POOL='$POOL'
RUSTVPN_ADMIN_ENABLED='$((1 - NO_ADMIN))'
RUSTVPN_ENDPOINT='$ENDPOINT'
EOF
    if [ "$BUILD" -eq 1 ]; then
        printf "RUSTVPN_SOURCE_DIR='%s'\n" "$SOURCE_DIR" >>"$tmp"
    fi
    chmod 0600 "$tmp"
    mv "$tmp" "$DATA_DIR/.env"
}

setup_dirs() {
    # The server runs as root inside its container but without DAC_OVERRIDE;
    # root must own these directories to create the socket, while the admin
    # (uid/gid 10001) needs group access for the socket and config writes.
    install -d -m 0770 -o root -g 10001 "$DATA_DIR/conf" "$DATA_DIR/run"
    install -d -m 0700 -o 10001 -g 10001 "$DATA_DIR/state" "$DATA_DIR/state/backups"
    install -d -m 0700 -o root -g root "$DATA_DIR/secrets"
    install -d -m 0750 "$DATA_DIR/clients"
    chown "$OPERATOR_UID:$OPERATOR_GID" "$DATA_DIR/clients"
    if [ ! -f "$DATA_DIR/conf/peers.yaml" ]; then
        install -m 0660 -o root -g 10001 /dev/null "$DATA_DIR/conf/peers.yaml"
    fi
    chown root:10001 "$DATA_DIR/conf/peers.yaml"
    chmod 0660 "$DATA_DIR/conf/peers.yaml"
}

ensure_images() {
    if [ "$BUILD" -eq 1 ]; then
        log "building images from $SOURCE_DIR"
        if [ "$NO_ADMIN" -eq 1 ]; then
            compose build server
        else
            compose --profile admin build
        fi
        return
    fi
    if ! docker image inspect "$SERVER_IMAGE" >/dev/null 2>&1; then
        log "pulling $SERVER_IMAGE"
        docker pull "$SERVER_IMAGE" ||
            die "cannot pull $SERVER_IMAGE; log in to ghcr.io or build with --build"
    fi
    if [ "$NO_ADMIN" -eq 0 ] && ! docker image inspect "$ADMIN_IMAGE" >/dev/null 2>&1; then
        log "pulling $ADMIN_IMAGE"
        docker pull "$ADMIN_IMAGE" || die "cannot pull $ADMIN_IMAGE"
    fi
}

peer_count() {
    if [ -f "$DATA_DIR/conf/peers.yaml" ]; then
        grep -cE '^[A-Za-z0-9][A-Za-z0-9._-]*:' "$DATA_DIR/conf/peers.yaml" || true
    else
        printf '0\n'
    fi
}

alloc_index() {
    local used n esc_prefix
    esc_prefix="${POOL_PREFIX//./\\.}"
    used="$(grep -oE "${esc_prefix}\.[0-9]+\.1/24" "$DATA_DIR/conf/peers.yaml" 2>/dev/null |
        sed -E "s/${esc_prefix}\\.([0-9]+)\\.1\\/24/\\1/" | sort -n | tr '\n' ' ' || true)"
    for ((n = 0; n < 255; n++)); do
        case " $used " in
            *" $n "*) continue ;;
        esac
        if grep -qE "^  iface: rsvpn$n\$" "$DATA_DIR/conf/peers.yaml" 2>/dev/null; then
            continue
        fi
        printf '%s\n' "$n"
        return 0
    done
    die "no free client subnet left in $POOL"
}

peer_exists() {
    grep -qxF "$1:" "$DATA_DIR/conf/peers.yaml" 2>/dev/null
}

generate_profile() {
    local name=$1 index=$2
    local pass="$DATA_DIR/secrets/$name.pass"
    local profile="$DATA_DIR/clients/$name.yaml"
    local out="$DATA_DIR/state/verifier.out"
    local err="$DATA_DIR/state/verifier.err"
    local -a args
    local d r

    [ -f "$pass" ] || write_secret "$pass" "$(gen_secret)"

    args=(-key "/secrets/$name.pass"
        -profile "$name"
        -profile-out "/out/$name.yaml"
        -remote "$ENDPOINT"
        -proto udp
        -mtu "$MTU"
        -iface rsvpn-gui
        -address "$POOL_PREFIX.$index.2/24"
        -gateway "$POOL_PREFIX.$index.1"
        -keepalive 25
        -rekey-time 1800)
    for d in "${DNS[@]}"; do args+=(-dns "$d"); done
    if [ "${#SPLIT[@]}" -gt 0 ]; then
        for r in "${SPLIT[@]}"; do args+=(-routes "$r"); done
    else
        args+=(-routes default)
    fi

    if ! docker run --rm --network none --entrypoint rustvpn-verifier \
        -v "$DATA_DIR/secrets:/secrets:ro" \
        -v "$DATA_DIR/clients:/out" \
        "$SERVER_IMAGE" "${args[@]}" >"$out" 2>"$err"; then
        cat "$err" >&2
        die "verifier failed; no profile was written"
    fi

    mapfile -t lines < <(grep '^\$argon2d' "$out")
    if [ "${#lines[@]}" -lt 2 ]; then
        cat "$out" >&2
        die "verifier output did not contain the long and short verifiers"
    fi
    LONG_VERIFIER=${lines[0]}
    SHORT_VERIFIER=${lines[1]}

    chown "$OPERATOR_UID:$OPERATOR_GID" "$profile"
    chmod 0600 "$profile"

    if grep -q 'password\|passphrase' "$profile"; then
        die "generated profile unexpectedly contains a password field"
    fi
}

commit_peer() {
    local name=$1 index=$2
    local file="$DATA_DIR/conf/peers.yaml"
    local tmp="$DATA_DIR/conf/.peers.$$"

    cp "$file" "$tmp"
    if [ -s "$tmp" ]; then printf '\n' >>"$tmp"; fi
    cat >>"$tmp" <<EOF
$name:
  iface: rsvpn$index
  mtu: $MTU
  timeout: 60
  noise: false
  encless: false
  verifier: '$LONG_VERIFIER'
  network:
    address: $POOL_PREFIX.$index.1/24
EOF
    chown root:10001 "$tmp"
    chmod 0660 "$tmp"
    mv "$tmp" "$file"
}

validate_config() {
    local log_file="$DATA_DIR/state/config-check.log"
    local rc=0
    timeout 4 docker run --rm --network none --entrypoint rustvpn-server \
        -v "$DATA_DIR/conf:/etc/rustvpn:ro" \
        "$SERVER_IMAGE" -bind 127.0.0.1:0 -proto udp -conf /etc/rustvpn/peers.yaml \
        >"$log_file" 2>&1 || rc=$?
    if grep -q 'Server started' "$log_file"; then
        return 0
    fi
    cat "$log_file" >&2
    die "generated peers.yaml did not load (exit $rc)"
}

remove_peer_block() {
    local name=$1 file="$DATA_DIR/conf/peers.yaml"
    awk -v name="$name" '
        index($0, name ":") == 1 { skip = 1; next }
        skip && /^[^[:space:]#]/ { skip = 0 }
        !skip { print }
    ' "$file" >"$file.tmp"
    chown root:10001 "$file.tmp"
    chmod 0660 "$file.tmp"
    mv "$file.tmp" "$file"
}

peer_index() {
    local name=$1 address third
    address="$(awk -v name="$name" '
        index($0, name ":") == 1 { inblock = 1; next }
        inblock && /^[^[:space:]]/ { inblock = 0 }
        inblock && /address: / {
            sub(/^[[:space:]]*address:[[:space:]]*/, ""); print; exit
        }
    ' "$DATA_DIR/conf/peers.yaml")"
    [ -n "$address" ] || return 0
    IFS=. read -r _ _ third _ <<<"$address"
    [ -n "$third" ] || return 0
    printf '%s\n' "$third"
}

init_admin() {
    local db="$DATA_DIR/state/admin.db"
    local pass="$DATA_DIR/secrets/admin.pass"
    if [ -f "$db" ]; then
        if [ ! -f "$pass" ]; then
            warn "admin DB exists but $pass is missing; use 'rotate-admin-password'"
        fi
        return 0
    fi
    [ -f "$pass" ] || write_secret "$pass" "$(gen_secret)"
    if ! docker run --rm --user 0:0 --entrypoint rustvpn-admin-passwd \
        -v "$DATA_DIR/state:/var/lib/rustvpn" \
        -v "$DATA_DIR/secrets:/secrets:ro" \
        "$ADMIN_IMAGE" -db /var/lib/rustvpn/admin.db -user admin \
        -password-file /secrets/admin.pass; then
        die "failed to initialize the admin account"
    fi
    chown 10001:10001 "$db" "$db-wal" "$db-shm" 2>/dev/null || true
}

start_stack() {
    if [ "$NO_ADMIN" -eq 1 ]; then
        compose up -d --remove-orphans
    else
        compose --profile admin up -d --remove-orphans
    fi
}

wait_ready() {
    local i status_ok
    for ((i = 0; i < 90; i++)); do
        status_ok=0
        if compose exec -T server rustvpn-server status --json \
            -control /run/rustvpn/control.sock >/dev/null 2>&1; then
            status_ok=1
        fi
        if [ "$status_ok" -eq 1 ]; then
            if [ "$NO_ADMIN" -eq 1 ] || curl -fsS "http://127.0.0.1:$ADMIN_PORT/readyz" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 1
    done
    compose ps >&2 || true
    die "the stack did not become ready; check '$PROGRAM logs'"
}

open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
        ufw allow "$PORT/udp"
        ufw allow "$PORT/tcp"
        log "ufw rules added for $PORT (Docker may still bypass ufw; check DOCKER-USER)"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null
        firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
        log "firewalld rules added for $PORT"
    else
        warn "no active ufw/firewalld found; open TCP+UDP $PORT in the host/cloud firewall"
    fi
}

summary() {
    local first_client=${1:-}
    cat >&2 <<EOF

RustVPN is ready.

  Endpoint:          $ENDPOINT
  Data directory:    $DATA_DIR
  Containers:        $(if [ "$NO_ADMIN" -eq 1 ]; then
                            compose ps --status running --format '{{.Name}}'
                        else
                            compose --profile admin ps --status running --format '{{.Name}}'
                        fi 2>/dev/null | paste -sd, - || true)
EOF
    if [ -n "$first_client" ]; then
        cat >&2 <<EOF
  Client profile:    $DATA_DIR/clients/$first_client.yaml
  Client passphrase: $DATA_DIR/secrets/$first_client.pass  (root-only)
EOF
    fi
    if [ "$NO_ADMIN" -eq 0 ]; then
        cat >&2 <<EOF
  Admin password:    $DATA_DIR/secrets/admin.pass  (root-only)
  Admin UI:          ssh -N -L $ADMIN_PORT:127.0.0.1:$ADMIN_PORT root@<server>
                     then open http://127.0.0.1:$ADMIN_PORT/
EOF
    fi
    cat >&2 <<EOF

Windows client:
  1. Install the RustVPN MSI from GitHub Releases.
  2. Copy clients/<name>.yaml to %LOCALAPPDATA%\\RustVPN\\profiles\\
  3. Open the GUI, select the profile and enter the passphrase.

Firewall: allow TCP and UDP port $PORT on the host and in the cloud
security group (and forward it here if the server is behind NAT).
Add more clients with: $PROGRAM add-client <name>
EOF
}

# --------------------------------------------------------------------- setup
do_setup() {
    need_root
    need_docker
    need_tun
    setup_dirs
    if [ -z "$ENDPOINT" ]; then
        ENDPOINT="$(detect_endpoint)"
    else
        ENDPOINT="$(normalize_endpoint "$ENDPOINT")"
    fi
    write_env
    ensure_images

    local first="" index=""
    if [ "$(peer_count)" -eq 0 ]; then
        log "creating the first client: $CLIENT"
        index="$(alloc_index)"
        generate_profile "$CLIENT" "$index"
        commit_peer "$CLIENT" "$index"
        validate_config
        first=$CLIENT
    else
        log "peers.yaml already has $(peer_count) peer(s); leaving clients unchanged"
        if [ -z "$(peer_index "$CLIENT")" ]; then
            warn "client $CLIENT does not exist; use '$PROGRAM add-client $CLIENT'"
        fi
    fi

    if [ "$NO_ADMIN" -eq 0 ]; then init_admin; fi
    if [ "$OPEN_FW" -eq 1 ]; then open_firewall; fi
    start_stack
    wait_ready
    summary "$first"
}

do_add_client() {
    need_root
    need_docker
    setup_dirs
    if [ -z "$ENDPOINT" ]; then
        ENDPOINT="$(detect_endpoint)"
    else
        ENDPOINT="$(normalize_endpoint "$ENDPOINT")"
    fi
    write_env
    ensure_images

    peer_exists "$CLIENT" && die "client $CLIENT already exists; use rotate-client"
    log "creating client: $CLIENT"
    local index
    index="$(alloc_index)"
    generate_profile "$CLIENT" "$index"
    commit_peer "$CLIENT" "$index"
    validate_config

    if compose ps --status running --format '{{.Name}}' 2>/dev/null | grep -q .; then
        if [ "$RESTART" -eq 1 ]; then
            compose restart server
            log "server restarted; the new peer is active"
        else
            log "the server reloads peers within 60 seconds (or pass --restart)"
        fi
    else
        log "the stack is not running; start it with '$PROGRAM setup'"
    fi
    summary "$CLIENT"
}

do_rotate_client() {
    need_root
    need_docker
    setup_dirs
    if [ -z "$ENDPOINT" ]; then
        ENDPOINT="$(detect_endpoint)"
    else
        ENDPOINT="$(normalize_endpoint "$ENDPOINT")"
    fi
    write_env
    ensure_images

    peer_exists "$CLIENT" || die "client $CLIENT does not exist"
    local index
    index="$(peer_index "$CLIENT")"
    [ -n "$index" ] || die "cannot determine the subnet for $CLIENT"
    log "rotating client $CLIENT (new passphrase and verifier)"
    remove_peer_block "$CLIENT"
    write_secret "$DATA_DIR/secrets/$CLIENT.pass" "$(gen_secret)"
    generate_profile "$CLIENT" "$index"
    commit_peer "$CLIENT" "$index"
    validate_config
    warn "old sessions for $CLIENT will be rejected; previous traffic history stays in the admin DB"
    if [ "$RESTART" -eq 1 ]; then compose restart server; fi
    summary "$CLIENT"
}

do_rotate_admin_password() {
    need_root
    need_docker
    [ -f "$DATA_DIR/state/admin.db" ] || die "no admin database; run setup first"
    write_secret "$DATA_DIR/secrets/admin.pass" "$(gen_secret)"
    NO_ADMIN=0
    ensure_images
    docker run --rm --user 0:0 --entrypoint rustvpn-admin-passwd \
        -v "$DATA_DIR/state:/var/lib/rustvpn" \
        -v "$DATA_DIR/secrets:/secrets:ro" \
        "$ADMIN_IMAGE" -db /var/lib/rustvpn/admin.db -user admin \
        -password-file /secrets/admin.pass ||
        die "failed to update the admin password"
    chown 10001:10001 "$DATA_DIR"/state/admin.db* 2>/dev/null || true
    log "admin password updated: $DATA_DIR/secrets/admin.pass"
}

do_status() {
    need_docker
    if [ "$NO_ADMIN" -eq 1 ]; then compose ps; else compose --profile admin ps; fi
    if compose exec -T server rustvpn-server status --json \
        -control /run/rustvpn/control.sock 2>/dev/null; then
        :
    else
        warn "server status is unavailable"
    fi
    if [ "$NO_ADMIN" -eq 0 ] &&
        curl -fsS "http://127.0.0.1:$ADMIN_PORT/readyz" >/dev/null 2>&1; then
        log "admin UI: http://127.0.0.1:$ADMIN_PORT/ (via SSH tunnel)"
    fi
}

do_down() {
    need_docker
    if [ "$NO_ADMIN" -eq 1 ]; then compose down; else compose --profile admin down; fi
}

do_destroy() {
    need_root
    need_docker
    [[ $DATA_DIR == /* ]] || die "refusing to delete a relative path: $DATA_DIR"
    if [ "$ASSUME_YES" -ne 1 ]; then
        printf 'Delete ALL RustVPN containers and data in %s? [y/N] ' "$DATA_DIR" >&2
        read -r answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) die "aborted" ;;
        esac
    fi
    case "$DATA_DIR" in
        /|/opt|/var|/home|/root|/etc|/usr|"") die "refusing to delete $DATA_DIR" ;;
    esac
    if [ "$NO_ADMIN" -eq 1 ]; then compose down; else compose --profile admin down; fi
    rm -rf "$DATA_DIR"
    log "removed $DATA_DIR"
}

# ----------------------------------------------------------------- dispatcher
case "${SUBCOMMAND:-setup}" in
    setup) do_setup ;;
    add-client) do_add_client ;;
    rotate-client) do_rotate_client ;;
    rotate-admin-password) do_rotate_admin_password ;;
    status) do_status ;;
    logs)
        need_docker
        if [ "$NO_ADMIN" -eq 1 ]; then compose logs -f --tail=200; else compose --profile admin logs -f --tail=200; fi
        ;;
    down) do_down ;;
    destroy) do_destroy ;;
    *) usage; exit 2 ;;
esac