# Windows Client Development Status

> **Last updated:** 2026-11-27
> **Branch:** `feature/client-ui`
> **HEAD:** `d6466c5 docs(windows): record M6 hardening acceptance`
> **Sync:** 3 commits ahead of `origin/feature/client-ui`; not pushed
> **Working tree:** documentation changes only, no code changes
> **Issue index:** `docs/windows-client-dev/windows-client-issues.xlsx` (local-only)
> **Issue details:** `docs/windows-client-dev/issues/WIN-<NNN>-<slug>.md` (local-only)

**State:** M1-M5 are complete and M6 code is complete with most acceptance done. The
remaining items are condition-blocked or bounded investigations, not missing M6
implementation.

Related docs: [Windows install/signing](windows-install.md) ·
[Windows research](windows-client-research.md) ·
[Development environment](windows-dev-environment.md) ·
[P0 decisions](p0-decision-review.md) · [Desktop UI](client-ui.md)

---

## 1. Snapshot

| Item | State |
|---|---|
| Milestones | M1-M5 complete and committed; M6 code complete, acceptance mostly done |
| Windows targets | Windows 10/11 x64; ARM64 deferred |
| Installer | Per-machine MSI/WiX, unsigned development build; signing hooks ready |
| Service | LocalSystem `rustvpn-clientd`, delayed auto-start, failure recovery |
| Transport | Wintun L3 + in-process Ethernet shim; IPv4 only |
| Validation hosts | Windows 10 physical host (split tunnel), Windows 11 VM (full tunnel and hardening) |

## 2. Milestones

| Phase | Code | Status | Acceptance summary |
|---|---|---|---|
| M1 Core integration | `9bc1466` | Done | Platform-neutral `TapConfig`, Wintun backend, Ethernet shim, bounded async pump, engine wiring. Windows target builds; real E2E deferred to M6. |
| M2 Service + IPC | `8cef993`, `8132f24` | Done | Named pipe, explicit DACL, peer identity, SCM/console daemon, tunnel lock. Windows IPC/lock tests and standard-user access pass. |
| M3 Network configuration | `cac143a`, `06a092b` | Done | Address/routes/DNS/NRPT/IPv6 guard, anti-loop route, ACL-restricted netstate, crash cleanup. Real Windows contract bugs fixed and split-tunnel routing verified in M6. |
| M4 GUI adaptation | `7b73a82` | Done | Profile ACLs, Credential Manager, HKCU autostart, locale, named-pipe info, pre-password daemon identity. RDP validation passed. |
| M5 Packaging | `cb39124` | Done | MSI, LocalSystem service, RustVPN group, process-query DACL, Wintun pinning, signing hooks. Install, same-version upgrade, uninstall and standard-user access validated. |
| M6 Hardening + E2E | `06a092b` … `7f05a3e` | Mostly done | Split/full tunnel plain+noise, DNS/NRPT, IPv6 block, disconnect fix, rekey/reconnect, link flap, forced-kill recovery, fuzz, iperf3. Condition-blocked items remain below. |

## 3. Validated on Windows

- **Split tunnel (Windows 10 physical):** handshake, ping 4/4 to both test addresses, TCP SSH banner through the tunnel, no default-route takeover.
- **Full tunnel (Windows 11 VM, plain and noise):** default route moves to Wintun, anti-loop `/32` keeps the underlay path, NRPT `.` resolves through tunnel DNS, IPv6 `2000::/3` and `fc00::/7` blocked.
- **Disconnect:** after the direct-cmdlet fix, the physical host survived >130 s; the next daemon start cleaned the anti-loop route/netstate and survived >145 s; the original default route stayed unchanged.
- **Service restart:** direct startup cleanup with no Wintun adapter succeeded; firewall/NRPT cleanup is idempotent when rules are already absent.
- **Rekey:** 60 s rekey test produced two rehandshakes in 140 s with 68/69 pings successful and no state flapping.
- **Reconnect and link flap:** server outage recovered after reconnect; NIC down 12 s kept the session, down 30 s timed out and reconnected with routes restored.
- **Crash recovery:** two forced daemon kills were followed by SCM restart and startup route/netstate cleanup; default route correct both times.
- **Performance:** split-tunnel iperf3 about 174 Mbit/s VM→server and 150 Mbit/s reverse, average latency 4.9 ms; reverse direction shows retransmits (WIN-013).
- **Fuzz:** 7 deterministic shim fuzz tests; `rustvpn-net` reports 118 passing tests.
- **Packaging:** MSI static checks, real install, service/group state, standard-user pipe access, non-member denial, same-version upgrade, uninstall with profile preservation.

## 4. Open investigations

| Issue | Symptom | Next step |
|---|---|---|
| WIN-012 | `last_handshake_unix` stays null in connected status | Trace daemon Status path vs traffic-sampler publication; add a live timestamp test |
| WIN-013 | Reverse iperf3 ~150 Mbit/s with 193 retransmits | Capture packets, compare with MSS clamp, inspect Wintun RX/queue counters |
| WIN-014 | Crash cleanup takes ~10-15 s before reconnect is allowed | Replace PowerShell-heavy startup cleanup or batch it; publish cleanup progress |

## 5. Condition-blocked

| Issue | Item | Blocker |
|---|---|---|
| WIN-016 | Sleep/hibernate recovery | VM exposes no usable suspend; use disposable physical hardware later |
| WIN-017 | Internet egress through full tunnel | No NAT environment scoped to the tunnel test subnet |
| WIN-018 | Windows CI first real run | Branch not pushed; no self-hosted elevated Windows runner registered |
| WIN-019 | Authenticode signing | No EV/OV certificate or private key available; unsigned builds clearly marked |

## 6. Known unsupported or deferred

| Issue | Capability | Decision |
|---|---|---|
| WIN-020 | Windows kill-switch | Not implemented; profile/guard reject it, UI shows unsupported. Windows is fail-open by design. |
| WIN-021 | Windows MSS clamp | Deferred; connection warns and reports `mss_applied=false`. |
| WIN-024 | IPv6 transport | IPv4-only shim. Full tunnel blocks global unicast/ULA; loopback/link-local/multicast stay local. |
| WIN-015 | Encless/TCP mode | Deferred; AONT expansion (~4128 B) needs more outer capacity and has no Windows E2E. |
| WIN-023 | DHCP-only server networks | Static-address MVP only; DHCP client not implemented. |
| WIN-022 | Windows ARM64 | x64-only packaging and Wintun pinning; ARM64 needs a separate matrix. |
| WIN-001 | True L2 features | Wintun L3 loses VLAN, broadcast discovery and non-IP EtherTypes; `tap-windows6` is documented as a future alternative only. |

## 7. Pointers

- **Issue index (authoritative):** `docs/windows-client-dev/windows-client-issues.xlsx` — sheets `Issues`, `Summary`, `Legend`.
- **Issue details:** `docs/windows-client-dev/issues/WIN-<NNN>-<slug>.md` — one issue per file, concise evidence and follow-up.
- Both paths are **development-only and local-only**, excluded through `.git/info/exclude`, and must never be uploaded or committed.
- Install/signing procedure: [windows-install.md](windows-install.md).
- Architecture and rationale: [windows-client-research.md](windows-client-research.md).
- Toolchain and VM setup: [windows-dev-environment.md](windows-dev-environment.md).

## 8. Security and operability constraints

- Never store passwords, private keys, verifier secrets, real host credentials, or tunnel secrets in the status doc, Excel index or issue files. Use generic test-host descriptions.
- The daemon runs as LocalSystem. Its named pipe uses an explicit protected DACL and peer token checks; process access is limited to query rights.
- Production distribution must use a signed MSI. Unsigned development builds are marked in `UNSIGNED.txt`, Product comments and `docs\SIGNING.txt`.
- Windows has no kill switch; do not claim Linux-equivalent fail-closed behavior.
- Run connect/disconnect, route, DNS, NRPT, IPv6 and crash tests only on disposable VMs/hosts with a dedicated test subnet.
- Do not modify existing VPNs, the production default route, DNS, NAT or firewall during acceptance.
- Wintun must be loaded from the installed absolute path with the pinned SHA-256; it is not user-configurable.
- Logs may include rejected client PID/SID lists but no passwords, profiles or key material.

## 9. Next actions

1. Trace the live status path and fix WIN-012 (`last_handshake_unix`), with a regression test.
2. Capture the reverse iperf3 flow and evaluate MSS/path effects for WIN-013.
3. Batch or replace the PowerShell-heavy startup cleanup to shorten the WIN-014 window.
4. Build a disposable NAT environment and validate off-subnet egress (WIN-017).
5. Validate sleep/resume on disposable physical hardware (WIN-016).
6. Push the branch and run the client CI; register the protected self-hosted runner for E2E (WIN-018).
7. Acquire an EV/OV certificate, sign GUI/daemon/MSI, and pin the publisher identity (WIN-019).
8. Re-check encless/TCP only after an outer path with sufficient capacity is available (WIN-015).

## 10. Update cadence

- The Excel index is the issue register; every discovered, fixed, deferred or blocked item gets one `WIN-NNN` row and one matching Markdown file.
- Update the Excel row and the issue Markdown together. Keep the status doc high-level: milestones, validated capabilities, blockers, decisions.
- Record commits, changed files, tests and remaining risk in the issue files, not in long narratives here.
- After every Windows code commit, update the HEAD/sync line, the milestone table and any changed validation bullets.