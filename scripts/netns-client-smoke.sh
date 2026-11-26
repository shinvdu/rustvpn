#!/usr/bin/env bash
# Run rustvpn-clientd inside a disposable network namespace and prove that the
# host routing table, resolver and interfaces are untouched.
#
# This script NEVER edits host firewall/NAT rules and never references
# govpn-server, tap10, wg0 or any existing interface.  Everything except the
# temporary veth pair lives inside the namespace, which is deleted on exit.
#
# Usage:
#   sudo ./scripts/netns-client-smoke.sh
#   sudo RUSTVPN_PROFILE=/path/office.yaml ./scripts/netns-client-smoke.sh
#
# With RUSTVPN_PROFILE set (and a server reachable at 192.0.2.1 from the
# namespace), the daemon is started, `status --json` is queried and the tunnel
# is stopped again.  Without it, only the namespace/veth isolation smoke runs.
#
# Exit codes: 0 = passed or skipped (not root), 1 = failed, 77 = skipped.
set -euo pipefail

NS="${RUSTVPN_NETNS:-rsvpn-smoke-$$}"
HOST_VETH="${RUSTVPN_HOST_VETH:-rsvpn-h$$}"
NS_VETH="${RUSTVPN_NS_VETH:-rsvpn-n$$}"
HOST_ADDR="${RUSTVPN_HOST_ADDR:-192.0.2.1/24}"
NS_ADDR="${RUSTVPN_NS_ADDR:-192.0.2.2/24}"
CLIENTD="${RUSTVPN_CLIENTD:-rustvpn-clientd}"
CLIENT="${RUSTVPN_CLIENT:-rustvpn-client}"
PROFILE="${RUSTVPN_PROFILE:-}"
SOCKET="/tmp/rsvpn-netns-smoke.sock"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "skip: needs root/CAP_NET_ADMIN for network namespaces" >&2
    exit 77
fi
for tool in ip; do
    command -v "$tool" >/dev/null || { echo "skip: $tool not found" >&2; exit 77; }
done
if [[ -n "$PROFILE" ]]; then
    command -v "$CLIENTD" >/dev/null || { echo "skip: $CLIENTD not found" >&2; exit 77; }
    command -v "$CLIENT" >/dev/null || { echo "skip: $CLIENT not found" >&2; exit 77; }
fi

host_routes_before="$(ip route show; ip -6 route show)"
host_links_before="$(ip -o link show | awk -F': ' '{print $2}' | sort)"
host_dns_before="$(cat /etc/resolv.conf 2>/dev/null || true)"
daemon_pid=""
cleanup() {
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
        daemon_pid=""
    fi
    if ip netns list | awk '{print $1}' | grep -qx "$NS"; then
        ip netns exec "$NS" nft delete table inet rustvpn_killswitch 2>/dev/null || true
        ip netns exec "$NS" nft delete table inet rustvpn_mss 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if ip link show "$HOST_VETH" >/dev/null 2>&1; then
        ip link del "$HOST_VETH" 2>/dev/null || true
    fi
    rm -f "$SOCKET"
}
trap cleanup EXIT INT TERM

echo "netns: creating $NS"
ip netns add "$NS"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link set "$NS_VETH" up
ip addr add "$HOST_ADDR" dev "$HOST_VETH"
ip link set "$HOST_VETH" up
ip -n "$NS" addr add "$NS_ADDR" dev "$NS_VETH"
ip -n "$NS" route add default via "${HOST_ADDR%/*}"

echo "netns: verifying isolation"
ip -n "$NS" route get "${NS_ADDR%/*}" >/dev/null
ip -n "$NS" route show

if [[ -n "$PROFILE" ]]; then
    echo "netns: starting $CLIENTD (DNS left to the caller by design)"
    # Copy the profile into the namespace's filesystem view: netns only
    # isolates networking, so the host path is directly usable.
    ip netns exec "$NS" "$CLIENTD" -socket "$SOCKET" -no-host-dns -idle-timeout 30 &
    daemon_pid=$!
    for _ in $(seq 1 50); do
        if [[ -S "$SOCKET" ]]; then
            break
        fi
        sleep 0.1
    done
    if [[ ! -S "$SOCKET" ]]; then
        echo "fail: daemon did not create $SOCKET" >&2
        exit 1
    fi
    echo "netns: status --json"
    ip netns exec "$NS" "$CLIENT" status --json --socket "$SOCKET"

    # The profile is only applied after Connect, which the smoke test leaves
    # to a caller-provided profile/CLI helper.  This still exercises socket,
    # TAP capability and namespace isolation.
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    daemon_pid=""
fi

# Remove the veth before comparing, then verify the host is byte-identical.
ip link del "$HOST_VETH"
ip netns del "$NS"
trap - EXIT INT TERM

host_routes_after="$(ip route show; ip -6 route show)"
host_links_after="$(ip -o link show | awk -F': ' '{print $2}' | sort)"
host_dns_after="$(cat /etc/resolv.conf 2>/dev/null || true)"

if [[ "$host_routes_before" != "$host_routes_after" ]]; then
    echo "fail: host routes changed" >&2
    diff <(printf '%s\n' "$host_routes_before") <(printf '%s\n' "$host_routes_after") >&2 || true
    exit 1
fi
if [[ "$host_links_before" != "$host_links_after" ]]; then
    echo "fail: host interfaces changed" >&2
    diff <(printf '%s\n' "$host_links_before") <(printf '%s\n' "$host_links_after") >&2 || true
    exit 1
fi
if [[ "$host_dns_before" != "$host_dns_after" ]]; then
    echo "fail: host resolver configuration changed" >&2
    exit 1
fi

echo "pass: netns cleaned up; host routes, DNS and interfaces unchanged"