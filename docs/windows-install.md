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

- service `rustvpn-clientd`: LocalSystem, automatic **delayed** start, own
  process, image path `"...\rustvpn-clientd.exe" --service`;
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
START_TYPE         : 2   AUTO_START (DELAYED)
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
- the local `RustVPN` group when it exists, otherwise INTERACTIVE users;
- the daemon's own account (so a development `--console` daemon is reachable).

The installer creates `RustVPN` and adds the installing account. Group
membership is captured in the account's logon token, so **log out and back in**
(or start a new process with a fresh logon) before a standard account can use
the pipe. Until then the GUI/CLI reports access denied.

Add another standard user (administrator action):

```powershell
net localgroup RustVPN <user> /add
# that user must log off/on afterwards
```

If the installer cannot create the group or add the user (for example a
domain policy), `installer\setup-group.ps1` rolls back a group it created and
leaves the daemon on the INTERACTIVE fallback, so non-admin interactive users
are not locked out. The reason is logged to
`%TEMP%\RustVPN-setup-group.log`. If a pre-existing group cannot accept the
user, add the user manually and re-login.

On uninstall the group is **kept**, together with its membership, because an
administrator may manage it independently of the package. Remove it manually
if it is no longer wanted.

### Standard-user verification and the process DACL

Before sending a passphrase, the GUI resolves the pipe server PID and verifies
its image path/Authenticode publisher. A LocalSystem process is not openable
by a standard user by default, so at startup the daemon applies a process DACL
that grants **only** `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) to the same
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
RESULT: OK (pipe, process query, installed image and Hello v2 all verified)
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
4. the new service is started and failure recovery/delayed start reapplied.

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
| `RUSTVPN_SIGN_CERT_THUMBPRINT` | SHA-1 thumbprint in `CurrentUser\My` (preferred) |
| `RUSTVPN_SIGN_CERT_FILE` | `.pfx`/`.p12` path |
| `RUSTVPN_SIGN_CERT_PASSWORD` | PFX password |
| `RUSTVPN_TIMESTAMP_URL` | timestamp server, default `http://timestamp.digicert.com` |
| `RUSTVPN_SIGNTOOL` | explicit `signtool.exe` |

Example:

```powershell
$env:RUSTVPN_SIGN_CERT_THUMBPRINT = '<thumbprint>'
$env:RUSTVPN_TIMESTAMP_URL = 'http://timestamp.digicert.com'
.\packaging\windows\build-msi.ps1 -WintunDir C:\rustvpn-dev\vendor\wintun
```

The script signs the executables before packaging and the MSI after linking,
then verifies each artifact with `signtool verify /pa`. If no certificate is
configured it does **not** pretend to sign:

- `signtool verify /pa` must confirm the file is unsigned;
- `dist\windows\UNSIGNED.txt` is written;
- Product comments, `docs\SIGNING.txt` and `BUILD-INFO.txt` say
  "Unsigned development build".

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

1. sends a stop to `rustvpn-clientd` and waits (the daemon removes its
   transient routes/DNS/NRPT/IPv6 rules as on a normal stop);
2. removes the service registration and `Program Files\RustVPN`;
3. removes the Start Menu/desktop shortcuts and the MSI registry values.

Preserved by design:

- per-user profiles in `%LOCALAPPDATA%\RustVPN\profiles`;
- per-user Credential Manager entries;
- the local `RustVPN` group and membership;
- `%ProgramData%\RustVPN` (daemon log and crash-recovery state). The state file
  is normally absent after a clean stop; if present it is only used to clean
  an owner that is dead on the next start. Administrators can remove the
  directory manually.

Uninstall does **not** remove Wintun adapters that are still open by another
process; RustVPN closes its own adapter on stop. If a crash left an adapter or
routes, start the service once before uninstalling, or use the M6 recovery
checks.

---

## 8. Acceptance commands

Minimal post-install checks that do not connect a tunnel:

```powershell
# service + recovery + delayed start
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
`dark.exe` output is checked for the `sc.exe` delayed-start/failure-recovery
commands plus the shortcut/group/upgrade elements.

---

## 9. Troubleshooting

| Symptom | Cause / action |
| --- | --- |
| Install stops with WebView2 message | Install the Evergreen runtime, then retry. |
| GUI: "service is not installed or not running" | `Get-Service rustvpn-clientd`; check `%ProgramData%\RustVPN\clientd.log`; `Start-Service rustvpn-clientd`. |
| GUI/CLI: access denied on the pipe | Add the account to `RustVPN` and log off/on. If the installer rolled the group back, the group may not exist. |
| Daemon log: cannot load Wintun / hash mismatch | Reinstall; verify the DLL hash and that the file is `C:\Program Files\RustVPN\wintun.dll`. |
| Service fails to start after upgrade | Read `%ProgramData%\RustVPN\clientd.log` and Event Viewer; the failure policy retries three times. Check that the previous service stopped. |
| MSI upgrade blocked | A newer ProductVersion is installed; uninstall it or build with an explicit higher `-MsiVersion`. |
| Unsigned build warning | Expected without a certificate; see section 6. |
| GUI connects to a `--console` daemon during development | The daemon grants its own user query access; the M4 debug sibling rule permits an unsigned sibling only in debug builds. |

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
  bidirectional TCP, route/DNS/IPv6 observation) passed. Disconnect cleanup,
  crash recovery, full-tunnel DNS/NRPT/IPv6, resume/network-switch and
  performance are still unverified. The acceptance host went offline during
  the disconnect phase; see the status document.
- If a test host was left with this build installed, uninstall the test MSI and
  delete any temporary credential/profile directories after verifying the
  network state file has been cleaned.
- kill-switch and MSS clamp remain unsupported/disabled on Windows.
- ARM64 is not packaged.
- Event Log integration for the service is absent; the file log is primary.
- Certificate pinning for portable signed daemons is not implemented; the
  installer path check is the primary rule.
- Pre-release MSI versions need an explicit increasing `-MsiVersion` if two
  betas must upgrade in order.
- The MSI does not remove the `RustVPN` group or `%ProgramData%\RustVPN` on
  uninstall by design.