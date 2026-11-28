# Windows packaging (MSI / WiX)

This directory builds the per-machine RustVPN Windows installer:

| File | Purpose |
| --- | --- |
| `rustvpn-client.wxs` | WiX Toolset 3.14 source: files, shortcuts, service, group helper |
| `build-msi.ps1` | Release build, Wintun verification, candle/light, signing hooks |
| `sign-artifacts.ps1` | `signtool` wrapper; cert store or PFX via environment |
| `create-dev-cert.ps1` | Development-only self-signed code-signing certificate + protected PFX/CER |
| `trust-dev-cert.ps1` | Import/remove the `.cer` in machine `Root` and `TrustedPublisher` |
| `verify-msi.ps1` | Administrative-install extraction + MSI table inspection |
| `verify-client-access.ps1` | Standard-user pipe / process-query / owner-SID / Hello acceptance probe |
| `setup-group.ps1` | Creates `RustVPN`, adds the installing user, best-effort membership |
| `license.rtf` | License page shown by `WixUI_Minimal` |
| `licenses/` | Wintun 0.14.1 license, version and SHA-256 metadata |

The Tauri GUI is unchanged: `bundle.active` stays `false`. The MSI is built
directly with `cargo build --release` plus `candle.exe`/`light.exe`.

## Why a standalone WiX project instead of a Tauri WiX fragment

The Tauri bundler's WiX main template owns the Product/Feature/UpgradeCode
layout and is designed around a single GUI executable. M5 additionally needs a
LocalSystem service with automatic start, failure recovery, stop-before-
replace/start-after-install ordering, a local-group helper that runs before
the service starts, and an explicit upgrade policy for pre-release versions.
Extending Tauri's generated template with those tables is possible but couples
the service lifecycle to bundler internals and makes MSI inspection harder.
A standalone `.wxs` keeps every table explicit and is built with the WiX 3.14
toolset already present on the Windows host and in CI. The GUI binary is the
same one produced by the existing `cargo build` path (the frontend is static
and embedded by `tauri-build`), so GUI behaviour is untouched.

## Prerequisites

- Windows 10/11 x64 build host.
- Rust 1.90+ with `x86_64-pc-windows-msvc`; VS 2022 Build Tools.
- WiX Toolset 3.14 (`candle.exe`, `light.exe`, `dark.exe`) on `PATH` or in
  `C:\Program Files (x86)\WiX Toolset v3.14\bin`.  The CI fallback pins the
  official `wix314-binaries.zip` SHA-256 to
  `6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31`.
- Windows SDK `signtool.exe` (only needed for signing/verification; the build
  script locates it under `Windows Kits\10\bin` when it is not on `PATH`).
- A genuine Wintun 0.14.1 amd64 DLL. The default source is
  `C:\rustvpn-dev\vendor\wintun\wintun.dll`; the build refuses any other
  SHA-256. The pinned digest is
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.

## Build

```powershell
# from the repository root, with D: used for the Cargo target dir when C: is tight
$env:CARGO_TARGET_DIR = 'D:\rustvpn-dev\target-m5'
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\build-msi.ps1
```

Outputs in `dist\windows\`:

- `RustVPN-<semver>-x64.msi`
- `BUILD-INFO.txt`, `SHA256SUMS.txt`
- `UNSIGNED.txt` when no certificate is configured

Useful switches:

```powershell
# reuse an existing release build
... build-msi.ps1 -SkipBuild

# override the Wintun source directory
... build-msi.ps1 -WintunDir D:\vendor\wintun

# explicit numeric MSI ProductVersion (e.g. to order two beta builds)
... build-msi.ps1 -MsiVersion 0.1.99.1
```

The script checks that `Cargo.toml` and `tauri.conf.json` versions match,
verifies that the DLL and both executables are amd64 PE images, and refuses a
Wintun hash mismatch. Both executables are staged and signed (or verified as
unsigned) before they are embedded, so the MSI never contains a binary whose
signing status was changed after packaging.

## Payload and install layout

`Program Files\RustVPN\` (per-machine, fixed):

```text
rustvpn-client-ui.exe        Tauri GUI
rustvpn-clientd.exe          LocalSystem daemon, started with --service
wintun.dll                   Wintun 0.14.1 amd64 (absolute-path load)
installer\setup-group.ps1    local group creation/membership helper
docs\COPYING                 GPL-3.0-or-later
docs\windows-install.md      install/upgrade/uninstall/signing manual
docs\README-windows-packaging.md
docs\SIGNING.txt             signed/unsigned status of this build
docs\VERSION.txt             semver, MSI version, Wintun hash, commit
licenses\wintun-LICENSE.txt  WireGuard LLC prebuilt binaries license
licenses\wintun-VERSION.txt
licenses\wintun-SHA256SUMS.txt
```

The daemon loads `C:\Program Files\RustVPN\wintun.dll` via the existing
absolute default in `rustvpn-net` (`DEFAULT_WINTUN_DLL_PATH`), so the install
and runtime paths cannot drift. `RUSTVPN_WINTUN_DLL` remains an explicit
development override.

Start Menu: `RustVPN` shortcut. Desktop: off by default; pass
`INSTALLDESKTOPSHORTCUT=1` to `msiexec`.

No user profile, profile directory or keychain entry is shipped. Profiles stay
in `%LOCALAPPDATA%\RustVPN\profiles` and passphrases in Credential Manager.

## Service, group and access control

`ServiceInstall` registers `rustvpn-clientd`:

- account `LocalSystem`, own process, `--service`;
- automatic start (not delayed, so the production pipe is owned before
  interactive logon); the Windows Installer `ServiceConfig*` tables are
  unreliable and produced Error 1939 on Windows 10;
- failure recovery via `sc.exe failure`: restart after 5 s, 10 s and 30 s;
  reset after one day;
- `ServiceControl Stop="both" Start="install" Remove="uninstall" Wait="yes"`:
  stop before files are replaced (including upgrades), start after install,
  stop and delete the SCM entry on uninstall.

The `setup-group.ps1` deferred custom action runs after `InstallFiles` and
before `StartServices`. It creates the local `RustVPN` group if needed and adds
`[LogonUser]` (override with the public `RUSTVPN_USER` property). The daemon
then auto-detects the group (M2) and restricts the pipe to SYSTEM,
Administrators and that group. If membership cannot be applied, the helper
keeps the created group (empty if necessary) so the fail-closed service can
start; add the account manually and re-login. There is no INTERACTIVE fallback.

At startup the daemon also applies a process DACL that grants
`PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL` (0x21000) to the same pipe
audience. The M4
GUI resolves the pipe server's image path with `QueryFullProcessImageNameW` and
checks its Authenticode publisher before sending a passphrase. Without this
grant a standard user cannot open a LocalSystem service process and the GUI
would fail closed. The grant adds no memory, handle or terminate rights.

## Version mapping

Cargo/Tauri use `0.2.0`; MSI `ProductVersion` must be numeric:

| SemVer | MSI ProductVersion |
| --- | --- |
| `0.2.0` | `0.2.0.0` (this release) |
| `0.2.0-beta.2` | `0.1.99.1` (previous beta) |
| later beta | explicit increasing `-MsiVersion` |

`0.2.0` upgrades the previous `0.2.0-beta.2` beta. Windows Installer ignores the fourth field for ordering, so two betas
that must upgrade in order need an explicit, increasing `-MsiVersion` (or a
different build field). The semantic version is shown in the Product name,
`HKLM\Software\RustVPN\Client\Version`, the GUI, `docs\VERSION.txt` and the
release artifact name.

`MajorUpgrade AllowSameVersionUpgrades="yes"` is used so a rebuilt beta with
the same numeric version but a new ProductCode upgrades in place. Downgrades
are blocked with a clear message; uninstall the newer build first.

## Signing

Never commit certificates, private keys or passwords. The build reads:

| Variable | Meaning |
| --- | --- |
| `RUSTVPN_SIGN_CERT_THUMBPRINT` | SHA-1 thumbprint in `CurrentUser\My` |
| `RUSTVPN_SIGN_CERT_FILE` | `.pfx`/`.p12` path |
| `RUSTVPN_SIGN_CERT_PASSWORD` | PFX password |
| `RUSTVPN_SIGN_CERT_PASSWORD_FILE` | protected file containing the PFX password |
| `RUSTVPN_TIMESTAMP_URL` | RFC 3161 timestamp server |
| `RUSTVPN_NO_TIMESTAMP` | `1` disables timestamping for local dev builds |
| `RUSTVPN_SIGNTOOL` | explicit `signtool.exe` |

The build signs the GUI and daemon before packaging and the MSI after linking,
then verifies each signed file with `signtool verify /pa`. If no certificate is
configured it verifies that the artifacts really are unsigned, writes
`UNSIGNED.txt` and records `Unsigned development build` in the Product
comments, `docs\SIGNING.txt` and `BUILD-INFO.txt`. It never labels an unsigned
build as signed.

### Self-signed development certificate (development only)

`create-dev-cert.ps1` creates a SHA-256/RSA-3072 code-signing certificate with
subject `CN=RustVPN Development`, valid for three years by default, and
exports:

```text
C:\rustvpn-signing\rustvpn-dev.pfx        private key (never copy to the repo/VM)
C:\rustvpn-signing\rustvpn-dev.cer        public certificate for trust import
C:\rustvpn-signing\dev-cert.password      generated PFX password
```

The directory and files are ACL-restricted to Administrators and SYSTEM, and
the password is never printed. The script refuses to write inside the
repository. Run the certificate helpers from `packaging\windows` on the
dedicated Windows build host (elevated):

```powershell
# from packaging\windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\create-dev-cert.ps1
# trust the public .cer locally so signtool verify /pa succeeds
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-dev-cert.ps1 `
    -CertFile C:\rustvpn-signing\rustvpn-dev.cer

# from the repository root (cargo needs Cargo.toml in the current directory)
$env:RUSTVPN_SIGN_CERT_FILE = 'C:\rustvpn-signing\rustvpn-dev.pfx'
$env:RUSTVPN_SIGN_CERT_PASSWORD_FILE = 'C:\rustvpn-signing\dev-cert.password'
$env:RUSTVPN_NO_TIMESTAMP = '1'
.\packaging\windows\build-msi.ps1 -WintunDir C:\rustvpn-dev\vendor\wintun
```

A timestamp is not required for a local self-signed build; OV/EV releases
should use a timestamp server. `-NoTimestamp` is equivalent to
`RUSTVPN_NO_TIMESTAMP=1`. The build host keeps the development certificate in
its machine trust stores so `signtool verify /pa` validates future builds; run
`trust-dev-cert.ps1 -Remove` to revoke that local trust.

Import the same `.cer` on the test VM before installing (elevated):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-dev-cert.ps1 `
    -CertFile .\rustvpn-dev.cer
Get-AuthenticodeSignature 'C:\Program Files\RustVPN\rustvpn-clientd.exe'
```

Remove it after testing (and uninstall the MSI first):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-dev-cert.ps1 `
    -CertFile .\rustvpn-dev.cer -Remove
```

> **Development only.** A self-signed certificate is trusted only on hosts
> that import it manually. Do not distribute these builds. Public releases
> need an EV or OV code-signing certificate, a timestamp, and explicit
> publisher/certificate pinning (the current GUI accepts any trusted subject
> containing "RustVPN"). EV/OV onboarding remains future work.

Unsigned or newly issued OV builds trigger SmartScreen "Unknown publisher"
warnings until reputation accrues. See `docs/windows-install.md`.

## Inspection and acceptance

No service is installed by `verify-msi.ps1`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\verify-msi.ps1 `
    -MsiPath dist\windows\RustVPN-0.2.0-x64.msi `
    -ExpectedMsiVersion 0.2.0.0
```

It performs an administrative install (`msiexec /a`) into a temporary folder,
checks the payload and queries the MSI database directly for
`ProductVersion`, `ALLUSERS`, the `ServiceInstall` row (name, auto start type,
LocalSystem, `--service`) and the `ServiceControl` event bits. It also
decompiles with WiX `dark.exe` and checks the `--cleanup` uninstall action and
the 5/10/30-second failure-recovery custom actions.

Manual end-to-end acceptance (service install, standard-user probe, uninstall)
is documented in [`docs/windows-install.md`](../../docs/windows-install.md).
The standard-user probe is `verify-client-access.ps1` from this directory. Run
it as the test account (it is not installed by the MSI) and expect:

```text
RESULT: OK (pipe, process query, installed image, admin/SYSTEM owner and Hello v2 all verified)
```

## Manual tunnel E2E

`e2e-tunnel.ps1` is a manual acceptance harness for a real tunnel. It is not
installed or run by the MSI and not part of the default CI. Run it elevated
against an external `rustvpn-server` (the server's `peers.yaml` holds the long
verifier, the client uses the short verifier):

```powershell
$pass = Join-Path $env:TEMP 'rustvpn-e2e-pass.txt'
# Create this file outside the repository with restricted ACLs; delete it after.
powershell -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows\e2e-tunnel.ps1 `
  -Phase connect -Remote <server>:1194 -ShortVerifier '<short-verifier>' `
  -PasswordFile $pass -Address 10.88.0.2/24 -Gateway 10.88.0.1 `
  -Routes 10.88.0.0/24 -PingTargets 10.88.0.1 -OuterEndpoint <server-ip>

powershell -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows\e2e-tunnel.ps1 `
  -Phase disconnect -WaitSeconds 60
```

Split routes are required by default and a default route is refused unless
`-AllowFullTunnel` is passed (full tunnel can cut RDP/SSH). Use `-Phase
snapshot`, `pingtcp` and `crash` to inspect the OS state, run ping/TCP checks,
or kill the service and verify crash recovery. The harness never writes the
passphrase itself and reports the default route, Wintun routes/addresses, DNS,
NRPT, RustVPN firewall rules and `netstate.json` before/after.

`.github/workflows/windows-client-e2e.yml` wraps this harness as a manual
`workflow_dispatch` job. It requires a self-hosted, elevated Windows runner
with the `rustvpn-e2e` label, the protected environment
`windows-client-e2e`, and the `RUSTVPN_E2E_VERIFIER` /
`RUSTVPN_E2E_PASSWORD` secrets. It is never triggered by push or pull_request,
installs the MSI only for the run, and uninstalls it in an `always()` step.

## CI

`.github/workflows/windows-client.yml` is an isolated `windows-latest` job. It
installs Rust and WiX 3.14, downloads the pinned Wintun release, runs the
client test/clippy set, builds the MSI and inspects it. It never installs the
MSI or registers the service, and it never uses signing secrets. The existing
`windows-shim.yml` prototype workflow is unchanged.