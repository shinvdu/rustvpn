#!/usr/bin/env bash
#
# Disposable end-to-end test for the container deployment.
#
# It builds the images, starts the server on an isolated Compose network,
# connects a client container through the generated profile, and checks
# tunnel/Internet egress.  It also asserts that the host network namespace is
# untouched (no TAP and no NAT table escape the container).
#
# Requires root (quickstart uses privileged container capabilities), Docker and
# /dev/net/tun.  Nothing outside /tmp and Docker is modified.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICKSTART="$SELF_DIR/quickstart.sh"
PROJECT="${RUSTVPN_SELFTEST_PROJECT:-rustvpn-selftest-$$}"
DATA_DIR="$(mktemp -d "/tmp/rustvpn-selftest.${PROJECT##*-}.XXXXXX")"
PORT="${RUSTVPN_SELFTEST_PORT:-21940}"
POOL="${RUSTVPN_SELFTEST_POOL:-10.99.0.0/16}"
SERVER_IMAGE="rustvpn-server:dev"
CLIENT_NAME="${PROJECT}-client"

log() { printf 'selftest: %s\n' "$*" >&2; }
fail() { printf 'selftest: FAIL: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    fail "run as root (sudo $0)"
fi
[ -f "$QUICKSTART" ] || fail "quickstart.sh not found next to $0"
[ -c /dev/net/tun ] || fail "/dev/net/tun is missing"

before_route="$(ip route show default)"
before_taps="$(ip -o link show | awk -F': ' '{print $2}' | grep '^rsvpn' | sort | tr '\n' ' ' || true)"

cleanup() {
    docker rm -f "$CLIENT_NAME" >/dev/null 2>&1 || true
    "$QUICKSTART" down --data-dir "$DATA_DIR" --project "$PROJECT" --no-admin \
        >/dev/null 2>&1 || true
    rm -rf "$DATA_DIR"
}
if [ "${RUSTVPN_SELFTEST_KEEP:-0}" = "1" ]; then
    log "keeping containers and $DATA_DIR for debugging"
else
    trap cleanup EXIT
fi

log "project=$PROJECT data=$DATA_DIR"
build_args=()
if [ "${RUSTVPN_SELFTEST_SKIP_BUILD:-0}" = "1" ]; then
    docker image inspect "$SERVER_IMAGE" >/dev/null 2>&1 ||
        fail "RUSTVPN_SELFTEST_SKIP_BUILD=1 but $SERVER_IMAGE is missing"
    build_args+=(--tag dev --server-image "$SERVER_IMAGE")
else
    build_args+=(--build)
fi
"$QUICKSTART" setup \
    --data-dir "$DATA_DIR" \
    --project "$PROJECT" \
    --endpoint server:1194 \
    --allow-private-endpoint \
    --no-admin \
    --port "$PORT" \
    --listen-ip 127.0.0.1 \
    --pool "$POOL" \
    "${build_args[@]}"

SERVER_CID="$(docker ps -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=server")"
[ -n "$SERVER_CID" ] || fail "server container not found"
NETWORK="$(docker network ls --filter "label=com.docker.compose.project=$PROJECT" \
    --format '{{.Name}}' | head -n1)"
[ -n "$NETWORK" ] || fail "compose network not found"

PROFILE="$DATA_DIR/clients/windows.yaml"
CLIENT_ADDR="$(sed -n 's/^address: *"\(.*\)"$/\1/p' "$PROFILE")"
GATEWAY="$(sed -n 's/^gateway: *"\(.*\)"$/\1/p' "$PROFILE")"
SHORT_VERIFIER="$(sed -n 's/^verifier: *"\(.*\)"$/\1/p' "$PROFILE")"
[ -n "$CLIENT_ADDR" ] && [ -n "$GATEWAY" ] && [ -n "$SHORT_VERIFIER" ] ||
    fail "generated profile is missing address/gateway/verifier"
SERVER_ADDR="$(printf '%s' "$CLIENT_ADDR" | sed -E 's/\.2\/24$/.1\/24/')"
CLIENT_SUBNET="$(printf '%s' "$CLIENT_ADDR" | sed -E 's/\.2\/24$/.0\/24/')"

log "checking the server namespace"
[ "$(docker exec "$SERVER_CID" cat /proc/sys/net/ipv4/ip_forward)" = "1" ] ||
    fail "ip_forward is not enabled in the container"
docker exec "$SERVER_CID" nft list table inet rustvpn_nat >/dev/null ||
    fail "container NAT table missing"
docker exec "$SERVER_CID" rustvpn-server status --json \
    -control /run/rustvpn/control.sock | grep -q 'rustvpn.status.v1' ||
    fail "server status is not available"

log "checking host isolation"
after_taps="$(ip -o link show | awk -F': ' '{print $2}' | grep '^rsvpn' | sort | tr '\n' ' ' || true)"
for tap in $after_taps; do
    case " $before_taps " in
        *" $tap "*) ;;
        *) fail "TAP $tap leaked into the host" ;;
    esac
done
if [ "$(ip route show default)" != "$before_route" ]; then
    fail "host default route changed"
fi
if nft list tables 2>/dev/null | grep -q rustvpn_nat; then
    fail "container NAT table leaked into the host"
fi

log "starting the client container"
mkdir -m 0755 "$DATA_DIR/test-client"
cat >"$DATA_DIR/test-client/up.sh" <<EOF
#!/bin/sh
set -eu
IFACE=rsvpn-test
ip tuntap add dev "\$IFACE" mode tap 2>/dev/null || true
ip link set dev "\$IFACE" mtu 1405 up
ip addr replace $CLIENT_ADDR dev "\$IFACE"
ip route replace $CLIENT_SUBNET dev "\$IFACE"
ip route replace default via $GATEWAY dev "\$IFACE"
EOF
cat >"$DATA_DIR/test-client/down.sh" <<'EOF'
#!/bin/sh
IFACE=rsvpn-test
ip link set dev "$IFACE" down 2>/dev/null || true
ip link del dev "$IFACE" 2>/dev/null || true
EOF
chmod 0755 "$DATA_DIR/test-client/up.sh" "$DATA_DIR/test-client/down.sh"

docker run -d --name "$CLIENT_NAME" \
    --network "$NETWORK" \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
    --device /dev/net/tun:/dev/net/tun \
    --entrypoint rustvpn-client \
    -v "$DATA_DIR/secrets:/secrets:ro" \
    -v "$DATA_DIR/test-client:/scripts:ro" \
    "$SERVER_IMAGE" \
    -remote server:1194 -proto udp -iface rsvpn-test -mtu 1420 -timeout 60 \
    -verifier "$SHORT_VERIFIER" \
    -key /secrets/windows.pass \
    -up /scripts/up.sh -down /scripts/down.sh >/dev/null

for _ in $(seq 1 60); do
    if docker exec "$CLIENT_NAME" ip -4 addr show rsvpn-test 2>/dev/null |
        grep -q "$CLIENT_ADDR"; then
        break
    fi
    sleep 1
done
docker exec "$CLIENT_NAME" ip -4 addr show rsvpn-test | grep -q "$CLIENT_ADDR" ||
    { docker logs --tail=80 "$CLIENT_NAME" >&2; fail "client TAP was not configured"; }
docker exec "$CLIENT_NAME" ip route | grep -q "default via $GATEWAY dev rsvpn-test" ||
    fail "client default route does not use the tunnel"
docker exec "$SERVER_CID" ip -4 addr show rsvpn0 | grep -q "$SERVER_ADDR" ||
    fail "server TAP address missing"
docker exec "$SERVER_CID" sh -c 'ip -d link show rsvpn0 | grep -q rustvpn-managed' ||
    fail "server TAP ownership alias missing"

log "pinging the server through the tunnel"
docker exec "$CLIENT_NAME" ping -c 3 -W 2 "$GATEWAY" >/dev/null ||
    fail "tunnel ping failed"

log "checking full-tunnel Internet egress"
server_ip="$(docker exec "$SERVER_CID" curl -4 -fsS --max-time 20 https://ifconfig.me)" ||
    fail "server egress curl failed"
client_ip="$(docker exec "$CLIENT_NAME" curl -4 -fsS --max-time 20 https://ifconfig.me)" ||
    fail "client egress curl failed"
[ -n "$server_ip" ] || fail "server egress check failed"
[ "$client_ip" = "$server_ip" ] ||
    fail "client egress IP ($client_ip) differs from server ($server_ip)"

# The client's only default route is the TAP, so non-zero payload counters
# prove the traffic actually crossed the server TAP.
docker exec "$SERVER_CID" rustvpn-server status --json \
    -control /run/rustvpn/control.sock |
    python3 -c '
import json, sys
doc = json.load(sys.stdin)
sessions = doc.get("sessions") or []
assert len(sessions) == 1, f"expected one session, got {len(sessions)}"
c = sessions[0]["counters"]
assert c["payload_in"] > 0 and c["payload_out"] > 0, c
' || fail "server did not see tunnel payload counters"

log "adding a second client"
"$QUICKSTART" add-client laptop \
    --data-dir "$DATA_DIR" --project "$PROJECT" --no-admin --restart >/dev/null
grep -qxF 'laptop:' "$DATA_DIR/conf/peers.yaml" || fail "second client missing"
grep -q '10\.99\.1\.1/24' "$DATA_DIR/conf/peers.yaml" || fail "second subnet missing"
for _ in $(seq 1 30); do
    if docker exec "$SERVER_CID" rustvpn-server status --json \
        -control /run/rustvpn/control.sock 2>/dev/null |
        grep -q '"configured_peers": 2'; then
        break
    fi
    sleep 1
done
docker exec "$SERVER_CID" rustvpn-server status --json \
    -control /run/rustvpn/control.sock | grep -q '"configured_peers": 2' ||
    fail "server did not load the second client"

log "PASS: container E2E and host isolation"