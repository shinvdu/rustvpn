# Windows installation, upgrade and signing

This manual covers the M5 per-machine MSI for the RustVPN Windows client. It
does not describe the tunnel/routing test matrix (M6); see
[windows-client-status.md](windows-client-status.md) and
[windows-client-research.md](windows-client-research.md).

> Scope: Windows 10/11 x64, GUI + LocalSystem daemon + Wintun. The daemon never
> listens on TCP and the MSI never opens a tunnel.

---

## 1. What the installer does

The MSI installs to `Program Files\RustVPN` for all users:

| Path | Purpose |
| --- | --- |
| `rustvpn-client-ui.exe` | Tauri GUI, runs as the logged-in user |
| `rustvpn-clientd.exe` | daemon, registered as service `rustvpn-clientd` |
| `wintun.dll` | Wintun 0.14.1 amd64, loaded by absolute path |
| `installer\setup-group.ps1` | creates the local `RustVPN` group and adds the installer |
| `docs\` | GPL text, this manual, signing/version metadata |
| `licenses\` | Wintun license, version and SHA-256 |

It also creates:

- service `rustvpn-clientd`: LocalSystem, **automatic** start (not delayed),
  own process, image path `"...\rustvpn-clientd.exe" --service`; automatic
  start ensures the service owns the production pipe before interactive logon;
- failure recovery: restart after 5 s, 10 s and 30 s, counter reset after one day;
- Start Menu shortcut under `RustVPN`;
- local group `RustVPN` and membership for the account that ran the installer;
- `HKLM\Software\RustVPN\Client` with the semantic version and MSI version.

No user profile, profile directory, passphrase or keychain entry is installed.
Profiles stay in `%LOCALAPPDATA%\RustVPN\profiles`; passphrases stay in Windows
Credential Manager, per user.

The desktop shortcut is **off by default**:

```powershell
msiexec /i RustVPN-<version>-x64.msi INSTALLDESKTOPSHORTCUT=1
```

### WebView2

The GUI needs the Microsoft Edge WebView2 Evergreen Runtime (Windows 11
normally has it; older Windows 10 may not). The MSI checks the per-machine or
per-user EdgeUpdate registration and stops with a clear message if it is
missing. Install the Evergreen runtime first:

<https://go.microsoft.com/fwlink/p/?LinkId=2124703>

This is the equivalent of the Tauri `downloadBootstrapper` setting; the
standalone MSI does not silently download anything during installation.

---

## 2. Install

Interactive (recommended first install):

```powershell
msiexec /i .\RustVPN-0.2.0-beta.1-x64.msi
```

Silent, adding the deploying account explicitly (otherwise `LogonUser` is
used):

```powershell
msiexec /i .\RustVPN-0.2.0-beta.1-x64.msi /qn /l*v install.log `
    RUSTVPN_USER="$env:USERDOMAIN\$env:USERNAME"
```

The install requires an elevated (per-machine) context and shows a UAC
prompt. `RUSTVPN_USER` is a public property; a deployment system that installs
as SYSTEM should always set it, because SYSTEM itself cannot be a useful local
group member.

After installation:

```powershell
Get-Service rustvpn-clientd | Format-List Name,Status,StartType
Get-LocalGroupMember RustVPN
Get-FileHash 'C:\Program Files\RustVPN\wintun.dll' -Algorithm SHA256
```

Expected service query (`sc.exe qc rustvpn-clientd`) includes:

```text
BINARY_PATH_NAME   : "C:\Program Files\RustVPN\rustvpn-clientd.exe" --service
SERVICE_START_NAME : LocalSystem
START_TYPE         : 2   AUTO_START
```

`sc.exe qfailure rustvpn-clientd` shows three restart actions. The service
starts idle; it creates `wintun.dll` adapters only after a profile connects.

---

## 3. Service account, RustVPN group and re-login

The daemon runs as LocalSystem because creating the Wintun adapter, installing
routes/DNS/NRPT and the IPv6 firewall rule need administrator rights. The GUI
never elevates.

Access to the local named pipe `\\.\pipe\rustvpn-clientd` is limited to:

- SYSTEM and Administrators;
- the local `RustVPN` group (required by service mode; a missing group makes
  the service fail closed instead of falling back to INTERACTIVE);
- the daemon's own account for a console-mode development daemon.

The installer creates `RustVPN` and adds the installing account. Group
membership is captured in the account's logon token, so **log out and back in**
(or start a new process with a fresh logon) before a standard account can use
the pipe. Until then the GUI/CLI reports access denied.

Add another standard user (administrator action):

```powershell
net localgroup RustVPN <user> /add
# that user must log off/on afterwards
```

If the installer cannot add the user (for example a domain policy), the helper
keeps the `RustVPN` group (empty if necessary) so the fail-closed service can
start; add the account manually and log on again. If the group itself cannot
be created, the service start fails and the install rolls back. The reason is
logged to `%TEMP%\RustVPN-setup-group.log`.

On uninstall the group is **kept**, together with its membership, because an
administrator may manage it independently of the package. Remove it manually
if it is no longer wanted.

### Standard-user verification and the process DACL

Before sending a passphrase, the GUI resolves the pipe server PID and verifies
its image path/Authenticode publisher. A LocalSystem process is not openable
by a standard user by default, so at startup the daemon applies a process DACL
that grants `PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL` (0x21000) to the same
pipe audience. SYSTEM/Administrators retain full access; no memory, handle or
terminate rights are exposed. This does not weaken the M4 identity policy: an
image outside `Program Files\RustVPN` still needs a valid RustVPN signature,
and a debug build still needs the debug-only sibling rule.

Use `packaging\windows\verify-client-access.ps1` as a standard user:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
    -File .\verify-client-access.ps1
```

Success prints the server image and:

```text
RESULT: OK (pipe, process query, installed image, admin/SYSTEM owner and Hello v2 all verified)
```

Run it as a non-member (or after removing the account from `RustVPN`) to
confirm access is denied. The daemon never sends a passphrase over this probe;
it only verifies reachability and identity.

---

## 4. Wintun

The package ships exactly Wintun 0.14.1 amd64:

- SHA-256 `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`;
- `licenses\wintun-LICENSE.txt` (WireGuard LLC Prebuilt Binaries License);
- `licenses\wintun-VERSION.txt` and `wintun-SHA256SUMS.txt`.

`rustvpn-net` defaults to the absolute path
`C:\Program Files\RustVPN\wintun.dll` and verifies the hash before loading, so
the SCM working directory (`System32`) cannot redirect the load. A build or
package with a different DLL is refused by both the build script and the
daemon. The Wintun driver itself is installed by the Wintun API on first
adapter creation; no reboot is required.

---

## 5. Versions, upgrade and downgrade

### Mapping

Cargo/Tauri use `0.2.0-beta.1`; MSI `ProductVersion` is numeric:

| Semantic version | MSI ProductVersion |
| --- | --- |
| `0.2.0-beta.1` | `0.1.99.0` |
| `0.2.0` | `0.2.0.0` |
| later beta with `-MsiVersion 0.1.99.1` | `0.1.99.1` |

Pre-releases map below the corresponding stable release, so `0.2.0` upgrades
`0.2.0-beta.1`. Windows Installer ignores the fourth field for ordering; if
two pre-release builds must upgrade in a specific order, pass an increasing
`-MsiVersion`. The semantic version is displayed in the Product name,
`HKLM\Software\RustVPN\Client\Version`, the GUI, `docs\VERSION.txt` and the
artifact name.

### Upgrade

Install the newer MSI normally (interactive or `/qn`). The package uses
`MajorUpgrade` with `AllowSameVersionUpgrades="yes"`:

1. the old service is stopped before files are replaced;
2. old components are removed and the new binaries/Wintun DLL installed;
3. the group helper re-runs (idempotent);
4. the new service is started and failure recovery reapplied.

The GUI is closed by the MSI (`CloseApplication`, 10 s timeout) so its exe can
be replaced. Profiles, Credential Manager entries and the `RustVPN` group are
preserved. The daemon's clean stop removes any active network state before the
upgrade; **do not upgrade during an active tunnel** if you need a maintenance
window guarantee.

### Downgrade

A lower `ProductVersion` is blocked with:

> A newer version of RustVPN is already installed. Uninstall it before
> installing this older build.

To roll back, uninstall the newer build and install the older MSI. Profiles
remain compatible (the profile YAML format is unchanged), but a profile using
a field the older GUI does not understand may be reported in `profile_errors`.

### Check installed versions

```powershell
(Get-ItemProperty 'HKLM:\Software\RustVPN\Client').Version
(Get-ItemProperty 'HKLM:\Software\RustVPN\Client').MsiVersion
Get-Content 'C:\Program Files\RustVPN\docs\VERSION.txt'
```

---

## 6. Signing and SmartScreen

Release builds should sign the GUI, daemon and MSI with Authenticode SHA-256
and an RFC 3161 timestamp. Certificates and private keys are never stored in
the repository. The build reads:

| Variable | Meaning |
| --- | --- |
| `RUSTVPN_SIGN_CERT_THUMBPRINT` | SHA-1 thumbprint in `CurrentUser\My` |
| `RUSTVPN_SIGN_CERT_FILE` | `.pfx`/`.p12` path |
| `RUSTVPN_SIGN_CERT_PASSWORD` | PFX password |
| `RUSTVPN_SIGN_CERT_PASSWORD_FILE` | protected file containing the PFX password |
| `RUSTVPN_TIMESTAMP_URL` | timestamp server, default `http://timestamp.digicert.com` |
| `RUSTVPN_NO_TIMESTAMP` | `1` disables timestamping for local dev builds |
| `RUSTVPN_SIGNTOOL` | explicit `signtool.exe` |

The script signs the executables before packaging and the MSI after linking,
then verifies each artifact with `signtool verify /pa`. If no certificate is
configured it does **not** pretend to sign:

- `Get-AuthenticodeSignature` must confirm the file is `NotSigned`;
- `dist\windows\UNSIGNED.txt` is written;
- Product comments, `docs\SIGNING.txt` and `BUILD-INFO.txt` say
  "Unsigned development build".

### Self-signed development signing

Until an EV/OV certificate is available, a dedicated Windows build host can
use a self-signed certificate for local development and VM testing. This
proves the signing path end to end; it is **not** suitable for public
distribution.

On the elevated build host:

```powershell
# from packaging\windows
.\create-dev-cert.ps1
.\trust-dev-cert.ps1 -CertFile C:\rustvpn-signing\rustvpn-dev.cer

# from the repository root (the cargo build needs Cargo.toml in the CWD)
$env:RUSTVPN_SIGN_CERT_FILE = 'C:\rustvpn-signing\rustvpn-dev.pfx'
$env:RUSTVPN_SIGN_CERT_PASSWORD_FILE = 'C:\rustvpn-signing\dev-cert.password'
$env:RUSTVPN_NO_TIMESTAMP = '1'
.\packaging\windows\build-msi.ps1 -WintunDir C:\rustvpn-dev\vendor\wintun
```

`create-dev-cert.ps1` creates a three-year self-signed code-signing
certificate (`CN=RustVPN Development`, SHA-256, Code Signing EKU,
DigitalSignature key usage) and stores the PFX, password and public `.cer`
under `C:\rustvpn-signing` with ACLs limited to Administrators/SYSTEM. It
never writes inside the repository and never prints the password. A timestamp
is optional for local builds; `-NoTimestamp` is equivalent to
`RUSTVPN_NO_TIMESTAMP=1`.

Before installing on a test VM, import the public `.cer` into the machine
`Root` and `TrustedPublisher` stores (elevated):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-dev-cert.ps1 `
    -CertFile .\rustvpn-dev.cer
Get-AuthenticodeSignature 'C:\Program Files\RustVPN\rustvpn-clientd.exe'
```

`Status` must be `Valid`; the signer subject contains `RustVPN Development`,
so the GUI's pre-passphrase publisher check accepts the daemon. After testing,
uninstall the MSI and remove the certificate from both stores:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-dev-cert.ps1 `
    -CertFile .\rustvpn-dev.cer -Remove
```

> **Warning:** self-signed builds are for development/testing only. Other
> machines reject them unless the certificate is imported manually. Public
> releases still require an EV or OV certificate, a timestamp server, and
> publisher/certificate pinning. Uninstall the test MSI and remove the
> development certificate from test hosts when finished.

Unsigned and newly issued OV certificates trigger SmartScreen "Unknown
publisher" warnings until reputation accumulates. Formal distribution should
use an EV certificate (hardware token or cloud HSM) and a timestamp server.
Enterprise deployment should also validate the signer thumbprint in the
deployment policy. A certificate whose subject contains "RustVPN" is accepted
by the GUI's portable-binary rule; pinning the exact certificate is an M6
hardening item.

---

## 7. Uninstall and what is preserved

```powershell
msiexec /x .\RustVPN-0.2.0-beta.1-x64.msi /qn /l*v uninstall.log
```

The MSI:

1. sends a stop to `rustvpn-clientd` and waits; the normal stop removes
   non-route state (NRPT/DNS/metric/IPv6), while routes/address are deferred;
2. deletes the service registration (`DeleteServices`);
3. runs the uninstall-only `--cleanup` helper before files are removed; it
   waits for the service's StopPending window, then clears the deferred
   anti-loop route and `netstate.json`;
4. removes `Program Files\RustVPN`;
5. removes the Start Menu/desktop shortcuts and the MSI registry values.

Preserved by design:

- per-user profiles in `%LOCALAPPDATA%\RustVPN\profiles`;
- per-user Credential Manager entries;
- the local `RustVPN` group and membership;
- `%ProgramData%\RustVPN` (daemon log). The uninstall `--cleanup` action
  removes the crash-recovery state file and deferred host route when it can;
  the hardened log directory itself is preserved. Administrators can remove
  the directory manually.

Uninstall does **not** remove Wintun adapters that are still open by another
process; RustVPN closes its own adapter on stop. If a crash left an adapter or
routes, start the service once before uninstalling, or use the M6 recovery
checks.

---

## 8. Acceptance commands

Minimal post-install checks that do not connect a tunnel:

```powershell
# service + recovery + automatic start
sc.exe qc rustvpn-clientd
sc.exe qfailure rustvpn-clientd

# group and membership (log off/on before the standard-user probe)
Get-LocalGroup RustVPN
Get-LocalGroupMember RustVPN

# payload and Wintun pin
Get-ChildItem 'C:\Program Files\RustVPN'
(Get-FileHash 'C:\Program Files\RustVPN\wintun.dll' -Algorithm SHA256).Hash

# pipe/process identity/Hello (run as Administrator and as a group member)
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-client-access.ps1

# signing status
& '<Windows SDK>\signtool.exe' verify /pa 'C:\Program Files\RustVPN\rustvpn-clientd.exe'
& '<Windows SDK>\signtool.exe' verify /pa .\RustVPN-0.2.0-beta.1-x64.msi
```

MSI static inspection (no service install):

```powershell
.\packaging\windows\verify-msi.ps1 `
    -MsiPath .\dist\windows\RustVPN-0.2.0-beta.1-x64.msi `
    -ExpectedMsiVersion 0.1.99.0
```

This performs `msiexec /a` extraction, checks the payload, and queries the
`ProductVersion`, `ALLUSERS`, `ServiceInstall` and `ServiceControl` tables;
`dark.exe` output is checked for the `--cleanup` uninstall action, the
`sc.exe` failure-recovery commands, and the shortcut/group/upgrade elements.

---

## 9. Troubleshooting

| Symptom | Cause / action |
| --- | --- |
| Install stops with WebView2 message | Install the Evergreen runtime, then retry. |
| GUI: "service is not installed or not running" | `Get-Service rustvpn-clientd`; check `%ProgramData%\RustVPN\clientd.log`; `Start-Service rustvpn-clientd`. |
| GUI/CLI: access denied on the pipe | Add the account to `RustVPN` and log off/on. If the installer could not create the group, the service fails closed and the install rolls back; inspect `%TEMP%\RustVPN-setup-group.log`. |
| Daemon log: cannot load Wintun / hash mismatch | Reinstall; verify the DLL hash and that the file is `C:\Program Files\RustVPN\wintun.dll`. |
| Service fails to start after upgrade | Read `%ProgramData%\RustVPN\clientd.log` and Event Viewer; the failure policy retries three times. Check that the previous service stopped. |
| MSI upgrade blocked | A newer ProductVersion is installed; uninstall it or build with an explicit higher `-MsiVersion`. |
| Unsigned build warning | Expected without a certificate; see section 6. |
| GUI connects to a development daemon | Console mode must use a non-production `-socket`; point the GUI at the same pipe with `RUSTVPN_CLIENTD_SOCKET`. The daemon grants its own user query access; the debug sibling rule permits an unsigned sibling only in debug builds. |

Logs: `%ProgramData%\RustVPN\clientd.log` (service), stderr (console). The
installer group helper logs to `%TEMP%\RustVPN-setup-group.log`.

---

## 10. Building and CI

Build prerequisites and the packaging design are in
[`packaging/windows/README.md`](../packaging/windows/README.md). Summary:

```powershell
$env:CARGO_TARGET_DIR = 'D:\rustvpn-dev\target-m5'
.\packaging\windows\build-msi.ps1
```

`.github/workflows/windows-client.yml` builds and inspects the unsigned MSI on
`windows-latest` with the pinned Wintun DLL, but never installs it. The
existing `windows-shim.yml` prototype workflow is separate.

---

## 11. Known gaps (M6)

- A real split-tunnel E2E (plain/UDP, installed MSI/service, handshake, ping,
  bidirectional TCP, route/DNS/IPv6 observation) passed twice.
- **Critical:** sending `Disconnect` made the Windows 10 acceptance host lose
  all network connectivity on 2 out of 2 attempts (ARP/SSH/RDP unreachable).
  The first outage had no Kernel-Power 41 and no sleep state was available;
  the host was later cleanly shut down and rebooted. The daemon log reached
  `tunnel stopped`/`disconnected` before the loss, so the cleanup commands
  (removing routes/address while the Wintun adapter is still open), the
  Wintun/NDIS adapter teardown, and an immediate post-disconnect OS network
  query (WMI/netsh) are all suspects.
- **Teardown fix in the working tree (review P1/P2 fixes, not committed, NOT
  yet verified on Windows):**
  1. `Session::close` is now async and cancels **and joins** every peer task;
     tasks no longer keep the last `Arc<Tap>`, so the adapter close is
     deterministic. Also `PeerHandle` cancels its tasks on Drop even if
     `shutdown` is never called (the server disarms this guard explicitly
     because it keeps the cancellation token in its own entry).
  2. The Windows shim's dedicated blocking Wintun reader is explicitly joined
     (`Tap::stop_reader`) before any route/DNS command runs. A cancelled
     `ShimPump::recv` restores its receiver, so a reconnect/reused adapter can
     still receive.
  3. The disconnect path no longer issues `Remove-NetIPAddress` **before** the
     close: it removes NRPT, DNS, split/default routes (anti-loop `/32` last),
     the interface metric and the IPv6 firewall rule, but keeps the profile
     address and does **not** clear `netstate.json` yet.
  4. The Wintun session/adapter is closed next. Only then does
     `ConnectionCleanup::finish` delete the state file. For a **created**
     adapter (`created=true`) the address and connected route go with the
     device; for a **pre-existing** adapter (`created=false`, opened rather than
     created) the address is removed only after the session/handle close, and
     the state file is kept if that removal fails.
  5. No `Get-Net*`/PowerShell/netsh query runs after the adapter close; the
     `idle` status is published last. The IPC `Disconnect` acknowledgement only
     means the command was queued — the engine publishes `disconnecting` first
     and `idle` after teardown.
  Install failure rollback is deferred to the engine: it stops the peer
  tasks/reader, rolls back the returned partial state, closes the adapter, then
  clears state. Previous-state cleanup runs **before** the adapter is opened;
  install refuses if state is still present, so no `Remove-Net*` ever runs
  against a live Wintun session. Unit tests cover these orderings and the
  `created` policy on Linux; Linux teardown behaviour is unchanged.
- **Still unverified:** this is a code-level hypothesis. Do not use
  connect/disconnect on a host you cannot physically recover. A disposable VM
  must run the matrix in the status document before the physical host is used:
  (1) disconnect with no OS query, wait 120 s, check ARP/ping/SSH; (2) query
  after a 60 s delay; (3) bisect the old build (close adapter only vs remove
  address only); (4) injected cleanup failure + daemon restart; (5) install
  failure rollback; (6) pre-existing (`created=false`) adapter disconnect and
  the post-close address removal; (7) reconnect/reuse adapter after a cancelled
  read; (8) IPC `disconnecting`/`idle`; (9) full-tunnel DNS/NRPT/IPv6
  disconnect. If the VM still hangs, the cause is Wintun/NDIS close itself, not
  the explicit address removal. Disconnect cleanup, crash recovery, full-tunnel
  DNS/NRPT/IPv6, resume/network-switch and performance remain unverified; see
  the status document.
- If a test host was left with this build installed, uninstall the test MSI and
  delete any temporary credential/profile directories after verifying the
  network state file has been cleaned.
- kill-switch and MSS clamp remain unsupported/disabled on Windows.
- ARM64 is not packaged.
- Event Log integration for the service is absent; the file log is primary.
- Certificate pinning for portable signed daemons is not implemented; the
  installer path check is the primary rule.
- Authenticode signing has been validated end to end with a development
  self-signed certificate (section 6), but a formal EV/OV certificate,
  timestamping for releases, and publisher/certificate pinning remain future
  work. Development-signed builds are not for public distribution.
- Pre-release MSI versions need an explicit increasing `-MsiVersion` if two
  betas must upgrade in order.
- The MSI does not remove the `RustVPN` group or `%ProgramData%\RustVPN` on
  uninstall by design.