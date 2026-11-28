#!/bin/sh
# Container entrypoint for rustvpn-server.
#
# The server does not manage forwarding/NAT itself, so the entrypoint prepares
# them inside this container's network namespace.  Nothing on the host is
# touched: deleting the container also removes the table and the sysctl.
set -eu

TUNNEL_POOL="${RUSTVPN_TUNNEL_POOL:-10.88.0.0/16}"

if [ "${RUSTVPN_NAT:-1}" = "1" ]; then
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
    fi

    UPLINK="$(ip -4 route show default | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
    if [ -z "$UPLINK" ]; then
        echo "rustvpn: no IPv4 default route in the container network; set RUSTVPN_NAT=0 or attach a network" >&2
        exit 1
    fi

    # Dedicated table, recreated on every start.  Keeping it in the container
    # netns avoids clobbering host firewall state.
    nft delete table inet rustvpn_nat 2>/dev/null || true
    nft -f - <<EOF
table inet rustvpn_nat {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "rsvpn*" oifname "$UPLINK" ip saddr $TUNNEL_POOL accept
  }
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "$UPLINK" ip saddr $TUNNEL_POOL masquerade
  }
}
EOF
fi

exec /usr/local/bin/rustvpn-server "$@"