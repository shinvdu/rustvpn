# Running the client daemon in a network namespace

RustVPN's client daemon manages a TAP device, routes, DNS and (optionally)
nftables.  All of that is namespace-local on Linux, so `rustvpn-clientd` can
run inside a disposable network namespace without touching the host.  This is
useful for CI, sidecar/container deployments and for testing kill-switch rules
without risking the host's connectivity.

Two existing flags make this safe:

| Flag | Purpose |
|---|---|
| `-socket PATH` | Use an explicit Unix socket instead of `/run/rustvpn-client/client.sock`. |
| `-no-host-dns` | Do not call `resolvectl`; the caller owns DNS in the namespace/container. |

`-socket` was already supported; `-no-host-dns` is additive and off by
default, so normal host behaviour is unchanged.

## Reusable smoke script

[`scripts/netns-client-smoke.sh`](../scripts/netns-client-smoke.sh) creates a
temporary namespace, a veth pair, starts the daemon with `-no-host-dns`, and
compares the host's `ip route`, `/etc/resolv.conf` and interface list before and
after.  It never touches `govpn-server`, `tap10`, `wg0` or any existing
NAT/firewall rule.  Everything is removed on exit (including on failure).

```bash
# Isolation-only smoke (no profile/server required)
sudo ./scripts/netns-client-smoke.sh

# With a client profile whose server is reachable at 192.0.2.1 from the ns
sudo -E RUSTVPN_PROFILE=/path/office.yaml \
     RUSTVPN_CLIENTD=target/debug/rustvpn-clientd \
     RUSTVPN_CLIENT=target/debug/rustvpn-client \
     ./scripts/netns-client-smoke.sh
```

The script skips with exit code `77` when not run as root or when `ip` is
unavailable.  It does not silently fall back to host networking.

## Manual recipe

```bash
ip netns add vpncli
ip link add veth0 type veth peer name veth1
ip link set veth1 netns vpncli
ip -n vpncli link set lo up
ip -n vpncli link set veth1 up
ip addr add 192.0.2.1/24 dev veth0 && ip link set veth0 up
ip -n vpncli addr add 192.0.2.2/24 dev veth1
ip -n vpncli route add default via 192.0.2.1

# explicit socket + leave DNS to the caller
ip netns exec vpncli rustvpn-clientd \
  -socket /tmp/rsvpn.sock -no-host-dns -idle-timeout 30 &
ip netns exec vpncli rustvpn-client status --json --socket /tmp/rsvpn.sock

# Verify the TAP and tunnel from inside the namespace
ip netns exec vpncli ip addr show rsvpn-gui
ip netns exec vpncli ping -c3 10.88.0.1

# Stop and clean up
kill %1
ip netns del vpncli
ip link del veth0
```

## DNS in a namespace

`-no-host-dns` deliberately leaves the resolver alone.  Provide DNS by one of:

- running a resolver inside the namespace (for example `dnsmasq` bound to the
  veth address) and writing its address into the namespace's
  `/etc/resolv.conf`;
- passing the tunnel's DNS server to the workload directly; or
- injecting `/etc/resolv.conf` with a bind mount in the container.

Full-tunnel profiles in the namespace still require a DNS entry in the profile
(validation is unchanged); `-no-host-dns` only skips the host-side
`resolvectl` call.

## Kill switch and MSS clamp inside a namespace

Both features use namespace-local nftables tables whose names are scoped to
the daemon instance (a short hash of the IPC socket path):

- `inet rustvpn_killswitch_<hash>` — full-tunnel kill switch, opt-in via
  `kill_switch: true`;
- `inet rustvpn_mss_<hash>` — optional TCP MSS clamp.

Because a network namespace has its own nftables state, tests and CI can enable
`kill_switch: true` and exercise leakage checks without affecting the host.
Do **not** run kill-switch tests on the host outside a disposable namespace.
The scope prevents two RustVPN daemons in the same namespace from deleting
each other's tables; list them with:

```bash
ip netns exec vpncli nft list tables | grep rustvpn_
```

A full-tunnel namespace profile can be verified with:

```bash
ip netns exec vpncli curl -s --max-time 5 https://example.invalid
# Expect the request to use the tunnel, not the host's real address.
ip netns exec vpncli nft list tables | grep rustvpn_killswitch_
```

## Container example

```bash
docker run --rm \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v /run/rustvpn-client:/run/rustvpn-client \
  rustvpn-clientd -socket /run/rustvpn-client/client.sock -no-host-dns
```

Give the container its own network namespace and make the tunnel interface the
only egress if you want container-only routing.  The same `-socket` and
`-no-host-dns` flags apply; default host behaviour is unchanged when neither
flag is used.