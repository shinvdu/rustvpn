# Build the RustVPN Windows client MSI with WiX Toolset 3.14.
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build-msi.ps1
#
# Required at build time:
#   * Rust MSVC toolchain and the x86_64-pc-windows-msvc target
#   * WiX Toolset 3.14 (candle.exe/light.exe on PATH or in the default folder)
#   * a genuine Wintun 0.14.1 amd64 wintun.dll (default vendored path below)
#
# Outputs in dist\windows\:
#   RustVPN-<semver>-x64.msi, BUILD-INFO.txt, SHA256SUMS.txt
#   UNSIGNED.txt when no Authenticode certificate is configured.
#
# The layout and upgrade rules are explained in packaging/windows/README.md.
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [string]$WintunDir = 'C:\rustvpn-dev\vendor\wintun',
    [string]$OutputDir = '',
    [string]$MsiVersion = '',
    [string]$Cargo = 'cargo',
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$WixBin = '',
    [switch]$SkipBuild,
    [switch]$SkipSign,
    [string]$SignCertThumbprint = $env:RUSTVPN_SIGN_CERT_THUMBPRINT,
    [string]$SignCertFile = $env:RUSTVPN_SIGN_CERT_FILE,
    [string]$SignCertPassword = $env:RUSTVPN_SIGN_CERT_PASSWORD,
    [string]$SignCertPasswordFile = $env:RUSTVPN_SIGN_CERT_PASSWORD_FILE,
    [string]$TimestampUrl = $env:RUSTVPN_TIMESTAMP_URL,
    [string]$SignTool = $env:RUSTVPN_SIGNTOOL,
    [switch]$NoTimestamp
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$envNoTimestamp = if ($env:RUSTVPN_NO_TIMESTAMP) {
    $env:RUSTVPN_NO_TIMESTAMP.Trim().ToLowerInvariant()
} else {
    ''
}
$timestampDisabled = [bool]$NoTimestamp -or ($envNoTimestamp -in @('1', 'true', 'yes', 'on'))
$timestampText = if ($timestampDisabled) {
    'disabled (development self-signed build)'
} elseif ($TimestampUrl) {
    $TimestampUrl
} else {
    'http://timestamp.digicert.com'
}

$PinnedWintunSha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
$PinnedWintunVersion = '0.14.1'

function Write-Step([string]$Message) {
    Write-Host "==> $Message"
}

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    # Cargo and WiX routinely write warnings to stderr.  PowerShell 5.1 wraps
    # native stderr in an ErrorRecord, and the script's Stop preference would
    # otherwise turn a warning into a build failure.  Keep the exit code as the
    # only failure signal for native tools.
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Exe @Arguments
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) {
        throw "command failed with exit code $code`: $Exe $($Arguments -join ' ')"
    }
}

function Get-WorkspaceSemver([string]$Root) {
    $path = Join-Path $Root 'Cargo.toml'
    if (-not (Test-Path -LiteralPath $path)) { throw "missing $path" }
    $inSection = $false
    foreach ($line in Get-Content -LiteralPath $path) {
        if ($line -match '^\s*\[workspace\.package\]\s*$') { $inSection = $true; continue }
        if ($line -match '^\s*\[') { $inSection = $false }
        if ($inSection -and $line -match '^\s*version\s*=\s*"([^"]+)"') { return $matches[1] }
    }
    throw 'could not read version from [workspace.package] in Cargo.toml'
}

# MSI ProductVersion is numeric and ignores the fourth revision field for
# ordering.  A pre-release is mapped below the stable release (0.2.0-beta.1 ->
# 0.1.99.0).  Later pre-release builds can pass -MsiVersion explicitly.
function ConvertTo-MsiVersion([string]$Semver) {
    $match = [regex]::Match($Semver,
        '^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<pre>[0-9A-Za-z.-]+))?(?:\+.*)?$')
    if (-not $match.Success) { throw "unsupported semver: $Semver" }
    $major = [int]$match.Groups['major'].Value
    $minor = [int]$match.Groups['minor'].Value
    $patch = [int]$match.Groups['patch'].Value
    $pre = $match.Groups['pre'].Value
    $revision = 0
    if ($pre) {
        if ($patch -gt 0) {
            $patch -= 1
        } else {
            $minor -= 1
            $patch = 99
        }
        if ($pre -match '(\d+)$') { $revision = [int]$matches[1] - 1 }
        if ($revision -lt 0) { $revision = 0 }
    }
    if ($minor -lt 0) {
        throw "cannot map pre-release $Semver below a stable release; pass -MsiVersion"
    }
    if ($major -gt 255 -or $minor -gt 255 -or $patch -gt 65535 -or $revision -gt 65535) {
        throw "MSI version fields out of range for $Semver"
    }
    return "$major.$minor.$patch.$revision"
}

function Find-WixBin([string]$Explicit) {
    if ($Explicit) {
        $candle = Join-Path $Explicit 'candle.exe'
        if (-not (Test-Path -LiteralPath $candle)) { throw "candle.exe not found in $Explicit" }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    $command = Get-Command candle.exe -ErrorAction SilentlyContinue
    if ($command) { return (Split-Path -Parent $command.Source) }
    foreach ($candidate in @(
            'C:\Program Files (x86)\WiX Toolset v3.14\bin',
            'C:\Program Files\WiX Toolset v3.14\bin',
            'C:\Program Files (x86)\WiX Toolset v3.11\bin')) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'candle.exe')) {
            return $candidate
        }
    }
    throw 'WiX Toolset 3.x not found. Install it or pass -WixBin.'
}

function Get-PeMachine([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) {
            throw "invalid PE header offset in $Path"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "not a PE file: $Path" }
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

function Assert-X64Pe([string]$Path) {
    if ((Get-PeMachine $Path) -ne 0x8664) { throw "$Path is not an amd64 PE image" }
}

# $PSScriptRoot is not populated in a CmdletBinding param default when the
# script is launched through `powershell -File` from another PowerShell
# session, so resolve the repository root in the body.
$repo = if ($RepoRoot) {
    (Resolve-Path -LiteralPath $RepoRoot).Path
} else {
    (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
}
$semver = Get-WorkspaceSemver $repo
$tauriConfPath = Join-Path $repo 'crates\rustvpn-client-gui\tauri.conf.json'
$tauriVersion = (Get-Content -LiteralPath $tauriConfPath -Raw | ConvertFrom-Json).version
if ($tauriVersion -ne $semver) {
    throw "tauri.conf.json version $tauriVersion does not match Cargo.toml $semver"
}
if (-not $MsiVersion) { $MsiVersion = ConvertTo-MsiVersion $semver }

$wix = Find-WixBin $WixBin
$output = if ($OutputDir) {
    [IO.Path]::GetFullPath($OutputDir)
} else {
    Join-Path $repo 'dist\windows'
}
New-Item -ItemType Directory -Force -Path $output | Out-Null
# The release directory is a build output, not an archive.  Remove this
# package's generated files so a stale MSI/wixpdb cannot be uploaded without a
# checksum or inspected instead of the current build.
Get-ChildItem -LiteralPath $output -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(RustVPN-.*\.msi|.*\.wixpdb|SHA256SUMS\.txt|BUILD-INFO\.txt|UNSIGNED\.txt)$' } |
    Remove-Item -Force -ErrorAction SilentlyContinue
$work = Join-Path $repo 'target\windows-msi'
$stage = Join-Path $work 'stage'
$wixobj = Join-Path $work 'wixobj'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stage, $wixobj
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'bin'),
    (Join-Path $stage 'docs'), (Join-Path $stage 'licenses'),
    (Join-Path $stage 'installer'), $wixobj | Out-Null

Write-Step "RustVPN $semver -> MSI ProductVersion $MsiVersion"

if (-not $SkipBuild) {
    Write-Step "building release binaries for $Target"
    Invoke-Checked $Cargo @('build', '--release', '--target', $Target,
        '-p', 'rustvpn-clientd', '-p', 'rustvpn-client-gui')
} else {
    Write-Step 'skipping cargo build (-SkipBuild)'
}

$targetRoot = if ($env:CARGO_TARGET_DIR) {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
} else {
    Join-Path $repo 'target'
}
$release = Join-Path (Join-Path $targetRoot $Target) 'release'
$gui = Join-Path $release 'rustvpn-client-ui.exe'
$daemon = Join-Path $release 'rustvpn-clientd.exe'
foreach ($binary in @($gui, $daemon)) {
    if (-not (Test-Path -LiteralPath $binary)) { throw "missing release binary: $binary" }
    Assert-X64Pe $binary
}
Copy-Item -LiteralPath $gui -Destination (Join-Path $stage 'bin\rustvpn-client-ui.exe')
Copy-Item -LiteralPath $daemon -Destination (Join-Path $stage 'bin\rustvpn-clientd.exe')

Write-Step 'verifying the Wintun DLL'
$wintunSource = Join-Path $WintunDir 'wintun.dll'
if (-not (Test-Path -LiteralPath $wintunSource)) {
    throw "wintun.dll not found at $wintunSource; pass -WintunDir or copy Wintun $PinnedWintunVersion there"
}
Assert-X64Pe $wintunSource
$wintunHash = (Get-FileHash -LiteralPath $wintunSource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($wintunHash -ne $PinnedWintunSha256) {
    throw "wintun.dll SHA-256 $wintunHash does not match the pinned $PinnedWintunSha256"
}
Copy-Item -LiteralPath $wintunSource -Destination (Join-Path $stage 'bin\wintun.dll')

$licenseRoot = Join-Path $PSScriptRoot 'licenses'
foreach ($name in @('wintun-LICENSE.txt', 'wintun-VERSION.txt', 'wintun-SHA256SUMS.txt')) {
    $source = Join-Path $licenseRoot $name
    if (-not (Test-Path -LiteralPath $source)) { throw "missing packaged license metadata: $source" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage "licenses\$name")
}
if (-not (Select-String -LiteralPath (Join-Path $licenseRoot 'wintun-VERSION.txt') `
        -Pattern "Wintun $([regex]::Escape($PinnedWintunVersion))" -Quiet)) {
    throw "packaging/windows/licenses/wintun-VERSION.txt does not name Wintun $PinnedWintunVersion"
}

Copy-Item -LiteralPath (Join-Path $repo 'COPYING') -Destination (Join-Path $stage 'docs\COPYING')
Copy-Item -LiteralPath (Join-Path $repo 'docs\windows-install.md') `
    -Destination (Join-Path $stage 'docs\windows-install.md')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') `
    -Destination (Join-Path $stage 'docs\README-windows-packaging.md')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'setup-group.ps1') `
    -Destination (Join-Path $stage 'installer\setup-group.ps1')

$gitCommit = 'unknown'
$gitDirty = 'unknown'
if ((Get-Command git.exe -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $repo '.git'))) {
    Push-Location $repo
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $gitCommit = (& git.exe rev-parse --short HEAD 2>$null)
        $gitDirty = if (@(& git.exe status --porcelain 2>$null).Count -gt 0) { 'dirty' } else { 'clean' }
    } finally {
        $ErrorActionPreference = $previous
        Pop-Location
    }
}
$versionText = @(
    "SemVer: $semver",
    "MSI ProductVersion: $MsiVersion",
    "Target: $Target",
    "Wintun: $PinnedWintunVersion amd64",
    "Wintun SHA-256: $wintunHash",
    "Source commit: $gitCommit ($gitDirty)",
    "Built (UTC): $([DateTime]::UtcNow.ToString('o'))"
) -join [Environment]::NewLine
Set-Content -LiteralPath (Join-Path $stage 'docs\VERSION.txt') -Value $versionText -Encoding ASCII

$exes = @(
    (Join-Path $stage 'bin\rustvpn-client-ui.exe'),
    (Join-Path $stage 'bin\rustvpn-clientd.exe')
)
$marker = Join-Path $output 'UNSIGNED.txt'
$signed = $false
if ($SkipSign) {
    foreach ($exe in $exes) {
        $signature = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
        if ($signature.Status -ne 'NotSigned') {
            throw "refusing -SkipSign: $exe already has signature status $($signature.Status); build a clean binary or configure signing"
        }
    }
    Write-Step 'signing skipped (-SkipSign); artifacts will be marked unsigned'
    $signingStatus = 'Unsigned development build (signing skipped)'
    @(
        'UNSIGNED BUILD', '',
        'Signing was skipped with -SkipSign. No Authenticode signature is present.',
        'See docs/windows-install.md.'
    ) -join [Environment]::NewLine |
        Set-Content -LiteralPath $marker -Encoding ASCII
} else {
    Write-Step 'signing / verifying the GUI and daemon binaries'
    $signResult = & (Join-Path $PSScriptRoot 'sign-artifacts.ps1') `
        -Files $exes `
        -Thumbprint $SignCertThumbprint `
        -PfxFile $SignCertFile `
        -PfxPassword $SignCertPassword `
        -PfxPasswordFile $SignCertPasswordFile `
        -TimestampUrl $TimestampUrl `
        -SignTool $SignTool `
        -UnsignedMarker $marker `
        -NoTimestamp:$timestampDisabled
    $signed = [bool]$signResult.Signed
    $signingStatus = if ($signed) {
        'Signed build (signtool /pa verified)'
    } else {
        'Unsigned development build (no certificate configured)'
    }
}

$signingText = @(
    "Signing status: $signingStatus",
    "Timestamp: $timestampText",
    'Certificate material is never stored in the repository.',
    'Self-signed development builds must not be distributed publicly; see',
    'docs/windows-install.md for trust-store steps and EV/OV expectations.'
) -join [Environment]::NewLine
Set-Content -LiteralPath (Join-Path $stage 'docs\SIGNING.txt') -Value $signingText -Encoding ASCII

$msi = Join-Path $output "RustVPN-$semver-x64.msi"
$icon = Join-Path $repo 'crates\rustvpn-client-gui\icons\icon.ico'
if (-not (Test-Path -LiteralPath $icon)) { throw "missing application icon: $icon" }

Write-Step 'compiling WiX source (candle)'
Invoke-Checked (Join-Path $wix 'candle.exe') @(
    '-nologo', '-arch', 'x64', '-ext', 'WixUtilExtension',
    "-dSemver=$semver",
    "-dMsiVersion=$MsiVersion",
    "-dSigningStatus=$signingStatus",
    "-dGuiExe=$(Join-Path $stage 'bin\rustvpn-client-ui.exe')",
    "-dDaemonExe=$(Join-Path $stage 'bin\rustvpn-clientd.exe')",
    "-dWintunDll=$(Join-Path $stage 'bin\wintun.dll')",
    "-dWintunLicense=$(Join-Path $stage 'licenses\wintun-LICENSE.txt')",
    "-dWintunVersion=$(Join-Path $stage 'licenses\wintun-VERSION.txt')",
    "-dWintunSha=$(Join-Path $stage 'licenses\wintun-SHA256SUMS.txt')",
    "-dCopying=$(Join-Path $stage 'docs\COPYING')",
    "-dWindowsInstallDoc=$(Join-Path $stage 'docs\windows-install.md')",
    "-dPackagingReadme=$(Join-Path $stage 'docs\README-windows-packaging.md')",
    "-dSigningTxt=$(Join-Path $stage 'docs\SIGNING.txt')",
    "-dVersionTxt=$(Join-Path $stage 'docs\VERSION.txt')",
    "-dSetupGroupScript=$(Join-Path $stage 'installer\setup-group.ps1')",
    "-dIconFile=$icon",
    '-out', (Join-Path $wixobj 'rustvpn-client.wixobj'),
    (Join-Path $PSScriptRoot 'rustvpn-client.wxs')
)

Write-Step 'linking the MSI (light)'
Invoke-Checked (Join-Path $wix 'light.exe') @(
    '-nologo',
    '-ext', 'WixUtilExtension',
    '-ext', 'WixUIExtension',
    '-cultures:en-us',
    "-dWixUILicenseRtf=$(Join-Path $PSScriptRoot 'license.rtf')",
    '-out', $msi,
    (Join-Path $wixobj 'rustvpn-client.wixobj')
)

if (-not $SkipSign) {
    Write-Step 'signing / verifying the MSI'
    $msiSign = & (Join-Path $PSScriptRoot 'sign-artifacts.ps1') `
        -Files @($msi) `
        -Thumbprint $SignCertThumbprint `
        -PfxFile $SignCertFile `
        -PfxPassword $SignCertPassword `
        -PfxPasswordFile $SignCertPasswordFile `
        -TimestampUrl $TimestampUrl `
        -SignTool $SignTool `
        -UnsignedMarker $marker `
        -NoTimestamp:$timestampDisabled
    if ($msiSign.Signed -ne $signed) {
        throw 'the MSI signing result differs from the binaries; refusing a partially signed release'
    }
}

Write-Step 'writing checksums and build information'
$info = @(
    "SemVer: $semver",
    "MSI ProductVersion: $MsiVersion",
    "Target: $Target",
    "Wintun: $PinnedWintunVersion amd64 ($wintunHash)",
    "Source commit: $gitCommit ($gitDirty)",
    "Signing: $signingStatus",
    "Timestamp: $timestampText",
    "Built (UTC): $([DateTime]::UtcNow.ToString('o'))"
) -join [Environment]::NewLine
Set-Content -LiteralPath (Join-Path $output 'BUILD-INFO.txt') -Value $info -Encoding ASCII

# Checksum only this build's release assets.  The output directory may contain
# earlier builds and a .wixpdb; neither is uploaded with this release.
$checksumFiles = @($msi, (Join-Path $output 'BUILD-INFO.txt'))
if (Test-Path -LiteralPath (Join-Path $output 'UNSIGNED.txt')) {
    $checksumFiles += (Join-Path $output 'UNSIGNED.txt')
}
$checksums = foreach ($file in $checksumFiles | Sort-Object) {
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($file))"
}
Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Value $checksums -Encoding ASCII

Write-Step "done: $msi"
Write-Host "Signing: $signingStatus"
Get-ChildItem -LiteralPath $output | Select-Object Name, Length | Format-Table -AutoSize