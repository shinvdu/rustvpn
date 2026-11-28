# Container deployment

One-command bootstrap for a Linux server:

```bash
sudo ./quickstart.sh --endpoint vpn.example.com
```

Full documentation: [`docs/zh/docker.md`](../../docs/zh/docker.md) and
[`docs/en/docker.md`](../../docs/en/docker.md).

Files:

- `Dockerfile.server` — `rustvpn-server` + `rustvpn-client` + `rustvpn-verifier`,
  runtime with `iproute2`/`nftables`.
- `Dockerfile.admind` — `rustvpn-admind` + `rustvpn-admin-passwd`, uid/gid 10001.
- `server-entrypoint.sh` — optional container-local forwarding/NAT, then the
  server.
- `compose.yaml` — published-image stack; admin is the `admin` profile and binds
  host loopback.
- `compose.build.yaml` — source-build override (`--build`).
- `.env.example` — interpolation defaults.
- `quickstart.sh` — setup/add-client/rotate/status/logs/down/destroy.
- `selftest.sh` — isolated server+client container E2E; requires root/Docker/tun.

Contracts:

- Server runs as root in its container with `NET_ADMIN`, `NET_RAW`, `CHOWN`,
  `DAC_READ_SEARCH`; admin runs as 10001 without capabilities.
- `conf/` and `run/` are `0770 root:10001`; `peers*.yaml` are `0660 root:10001`;
  `state/` is `0700 10001:10001`; secrets are root-only.
- Tunnel pool defaults to `10.88.0.0/16`; each client uses one `/24`.
- Default wire MTU is 1420; the server and profile must match.
- Images: `ghcr.io/shinvdu/rustvpn/rustvpn-server` and
  `ghcr.io/shinvdu/rustvpn/rustvpn-admind`.

CI: `.github/workflows/container.yml` publishes images; `.github/workflows/ci.yml`
checks shell syntax and Compose interpolation. `rustvpn-clientd` is not
containerized (Windows service).