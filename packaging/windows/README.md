# Windows packaging (MSI / WiX)

This directory builds the per-machine RustVPN Windows installer:

| File | Purpose |
| --- | --- |
| `rustvpn-client.wxs` | WiX Toolset 3.14 source: files, shortcuts, service, group helper |
| `build-msi.ps1` | Release build, Wintun verification, candle/light, signing hooks |
| `sign-artifacts.ps1` | `signtool` wrapper; cert store or PFX via environment |
| `verify-msi.ps1` | Administrative-install extraction + MSI table inspection |
| `verify-client-access.ps1` | Standard-user pipe / process-query / Hello acceptance probe |
| `setup-group.ps1` | Creates `RustVPN`, adds the installing user, safe rollback |
| `license.rtf` | License page shown by `WixUI_Minimal` |
| `licenses/` | Wintun 0.14.1 license, version and SHA-256 metadata |

The Tauri GUI is unchanged: `bundle.active` stays `false`. The MSI is built
directly with `cargo build --release` plus `candle.exe`/`light.exe`.

## Why a standalone WiX project instead of a Tauri WiX fragment

The Tauri bundler's WiX main template owns the Product/Feature/UpgradeCode
layout and is designed around a single GUI executable. M5 additionally needs a
LocalSystem service with delayed auto-start, failure recovery, stop-before-
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
  `C:\Program Files (x86)\WiX Toolset v3.14\bin`.
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
- automatic start, changed to delayed auto-start by `sc.exe config` during
  installation (the Windows Installer `ServiceConfig*` tables are unreliable
  and produced Error 1939 on Windows 10);
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
rolls back a group it created so the daemon keeps the INTERACTIVE fallback;
otherwise the account needs a re-login before its token carries the group.

At startup the daemon also applies a process DACL that grants
`PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) to the same pipe audience. The M4
GUI resolves the pipe server's image path with `QueryFullProcessImageNameW` and
checks its Authenticode publisher before sending a passphrase. Without this
grant a standard user cannot open a LocalSystem service process and the GUI
would fail closed. The grant adds no memory, handle or terminate rights.

## Version mapping

Cargo/Tauri use `0.2.0-beta.1`; MSI `ProductVersion` must be numeric:

| SemVer | MSI ProductVersion |
| --- | --- |
| `0.2.0-beta.1` | `0.1.99.0` (this release) |
| `0.2.0` | `0.2.0.0` |
| `0.2.0-beta.2` with `-MsiVersion 0.1.99.1` | `0.1.99.1` |

Pre-releases are deliberately below the stable release so `0.2.0` upgrades a
beta. Windows Installer ignores the fourth field for ordering, so two betas
that must upgrade in order need an explicit, increasing `-MsiVersion` (or a
different build field). The semantic version is shown in the Product name,
`HKLM\Software\RustVPN\Client\Version`, the GUI, `docs\VERSION.txt` and the
release artifact name.

`MajorUpgrade AllowSameVersionUpgrades="yes"` is used so a rebuilt beta with
the same numeric version but a new ProductCode upgrades in place. Downgrades
are blocked with a clear message; uninstall the newer build first.

## Signing

Never commit certificates or private keys. Configure:

```powershell
$env:RUSTVPN_SIGN_CERT_THUMBPRINT = '<SHA-1 thumbprint in CurrentUser\My>'
# or
$env:RUSTVPN_SIGN_CERT_FILE = 'D:\secure\rustvpn.pfx'
$env:RUSTVPN_SIGN_CERT_PASSWORD = '<password>'
$env:RUSTVPN_TIMESTAMP_URL = 'http://timestamp.digicert.com'  # optional
```

The build signs the GUI and daemon before packaging and the MSI after linking,
then verifies each file with `signtool verify /pa`. If no certificate is
configured it verifies that the artifacts really are unsigned, writes
`UNSIGNED.txt` and records `Unsigned development build` in the Product
comments, `docs\SIGNING.txt` and `BUILD-INFO.txt`. It never labels an unsigned
build as signed.

Formal distribution should use an EV code-signing certificate (hardware token
or cloud HSM) and a timestamp server. Unsigned or newly issued OV builds will
trigger SmartScreen "Unknown publisher" warnings until reputation accrues.
See `docs/windows-install.md`.

## Inspection and acceptance

No service is installed by `verify-msi.ps1`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\verify-msi.ps1 `
    -MsiPath dist\windows\RustVPN-0.2.0-beta.1-x64.msi `
    -ExpectedMsiVersion 0.1.99.0
```

It performs an administrative install (`msiexec /a`) into a temporary folder,
checks the payload and queries the MSI database directly for
`ProductVersion`, `ALLUSERS`, the `ServiceInstall` row (name, auto start type,
LocalSystem, `--service`) and the `ServiceControl` event bits. It also
decompiles with WiX `dark.exe` and checks the `sc.exe` delayed-start and
5/10/30-second failure-recovery custom actions.

Manual end-to-end acceptance (service install, standard-user probe, uninstall)
is documented in [`docs/windows-install.md`](../../docs/windows-install.md).
The standard-user probe is `verify-client-access.ps1` from this directory. Run
it as the test account (it is not installed by the MSI) and expect:

```text
RESULT: OK (pipe, process query, installed image and Hello v2 all verified)
```

## CI

`.github/workflows/windows-client.yml` is an isolated `windows-latest` job. It
installs Rust and WiX 3.14, downloads the pinned Wintun release, runs the
client test/clippy set, builds the MSI and inspects it. It never installs the
MSI or registers the service, and it never uses signing secrets. The existing
`windows-shim.yml` prototype workflow is unchanged.