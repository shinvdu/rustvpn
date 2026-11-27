# Authenticode signing hook for the RustVPN Windows artifacts.
#
# Certificate material is never part of the repository.  Configure one of:
#   $env:RUSTVPN_SIGN_CERT_THUMBPRINT     certificate in the CurrentUser/My store
#   $env:RUSTVPN_SIGN_CERT_FILE           .pfx/.p12 path
#   $env:RUSTVPN_SIGN_CERT_PASSWORD       password for the .pfx
#   $env:RUSTVPN_SIGN_CERT_PASSWORD_FILE  protected file with the .pfx password
#   $env:RUSTVPN_TIMESTAMP_URL            RFC 3161 timestamp server (optional)
#   $env:RUSTVPN_NO_TIMESTAMP             1/true/yes disables timestamping
#   $env:RUSTVPN_SIGNTOOL                 explicit signtool.exe (optional)
#
# Development self-signed builds can disable timestamping (-NoTimestamp or
# RUSTVPN_NO_TIMESTAMP=1).  A timestamp is recommended for OV/EV releases.
#
# Without a certificate the script verifies that every artifact really is
# unsigned (rather than claiming success) and optionally writes an UNSIGNED
# marker for the release directory.  It never invents a signature.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Files,

    [string]$Thumbprint = $env:RUSTVPN_SIGN_CERT_THUMBPRINT,
    [string]$PfxFile = $env:RUSTVPN_SIGN_CERT_FILE,
    [string]$PfxPassword = $env:RUSTVPN_SIGN_CERT_PASSWORD,
    [string]$PfxPasswordFile = $env:RUSTVPN_SIGN_CERT_PASSWORD_FILE,
    [string]$TimestampUrl = $env:RUSTVPN_TIMESTAMP_URL,
    [string]$SignTool = $env:RUSTVPN_SIGNTOOL,
    [string]$UnsignedMarker = '',
    [switch]$RequireSigned,
    [switch]$NoTimestamp
)

$ErrorActionPreference = 'Stop'

$envNoTimestamp = if ($env:RUSTVPN_NO_TIMESTAMP) {
    $env:RUSTVPN_NO_TIMESTAMP.Trim().ToLowerInvariant()
} else {
    ''
}
$skipTimestamp = [bool]$NoTimestamp -or ($envNoTimestamp -in @('1', 'true', 'yes', 'on'))
if (-not $skipTimestamp -and [string]::IsNullOrWhiteSpace($TimestampUrl)) {
    $TimestampUrl = 'http://timestamp.digicert.com'
}

function Find-SignTool {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "configured signtool.exe does not exist: $Explicit"
        }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $kits = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kits) {
        $candidate = Get-ChildItem -LiteralPath $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw 'signtool.exe was not found. Set RUSTVPN_SIGNTOOL or install the Windows SDK signing tools.'
}

$signToolPath = Find-SignTool -Explicit $SignTool
$missing = @($Files | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing.Count -gt 0) {
    throw "cannot sign missing file(s): $($missing -join ', ')"
}

function Invoke-SignTool([string[]]$Arguments) {
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        # Out-Host keeps signtool output visible without mixing it into the
        # function's return value; callers must receive only the exit code.
        & $signToolPath @Arguments | Out-Host
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Test-Signature([string]$Path) {
    return ((Invoke-SignTool @('verify', '/pa', '/q', $Path)) -eq 0)
}

$thumb = if ($Thumbprint) { $Thumbprint.Trim() } else { '' }
$configured = ($thumb -ne '') -or ($PfxFile -ne '')

if ([string]::IsNullOrEmpty($PfxPassword) -and -not [string]::IsNullOrEmpty($PfxPasswordFile)) {
    if (-not (Test-Path -LiteralPath $PfxPasswordFile)) {
        throw "PFX password file does not exist: $PfxPasswordFile"
    }
    $PfxPassword = (Get-Content -LiteralPath $PfxPasswordFile -Raw).Trim()
}
if ($configured -and $thumb -eq '' -and [string]::IsNullOrEmpty($PfxPassword)) {
    throw 'PFX signing requires RUSTVPN_SIGN_CERT_PASSWORD or RUSTVPN_SIGN_CERT_PASSWORD_FILE (or use -Thumbprint)'
}

if (-not $configured) {
    foreach ($file in $Files) {
        if (Test-Signature $file) {
            throw "no certificate is configured, but $file already carries a valid signature; refusing to label an untracked artifact as unsigned"
        }
    }
    if ($RequireSigned) {
        throw 'signing was required but no RUSTVPN_SIGN_CERT_THUMBPRINT or RUSTVPN_SIGN_CERT_FILE is set'
    }
    $message = @(
        'UNSIGNED BUILD',
        '',
        'No Authenticode certificate was configured. The binaries and MSI in this',
        'directory are unsigned development artifacts. Windows SmartScreen will',
        'warn and enterprise deployment policies may reject them.',
        '',
        'Signing inputs: RUSTVPN_SIGN_CERT_THUMBPRINT, or RUSTVPN_SIGN_CERT_FILE +',
        'RUSTVPN_SIGN_CERT_PASSWORD / RUSTVPN_SIGN_CERT_PASSWORD_FILE.',
        'See docs/windows-install.md and packaging/windows/README.md.',
        'Verified with: ' + $signToolPath,
        'Time: ' + (Get-Date -Format o)
    ) -join [Environment]::NewLine
    if ($UnsignedMarker) {
        Set-Content -LiteralPath $UnsignedMarker -Value $message -Encoding ASCII
    }
    Write-Host 'SIGNING STATUS: UNSIGNED (signtool verify confirmed no embedded signature)'
    [pscustomobject]@{ Signed = $false; Timestamped = $false; Files = $Files; SignTool = $signToolPath }
    exit 0
}

foreach ($file in $Files) {
    if ($thumb -ne '') {
        $signArguments = @('sign', '/sha1', $thumb, '/fd', 'SHA256')
    } else {
        if (-not (Test-Path -LiteralPath $PfxFile)) {
            throw "certificate file does not exist: $PfxFile"
        }
        $signArguments = @('sign', '/f', $PfxFile, '/p', $PfxPassword, '/fd', 'SHA256')
    }
    if (-not $skipTimestamp) {
        $signArguments += @('/tr', $TimestampUrl, '/td', 'SHA256')
    }
    $signArguments += $file

    $exit = Invoke-SignTool $signArguments
    if ($exit -ne 0) {
        throw "signtool sign failed for $file (exit $exit)"
    }
    if (-not (Test-Signature $file)) {
        throw "signtool verify failed for $file"
    }
    Write-Host "signed and verified: $file"
}

if ($UnsignedMarker -and (Test-Path -LiteralPath $UnsignedMarker)) {
    Remove-Item -LiteralPath $UnsignedMarker -Force
}
$timestampStatus = if ($skipTimestamp) { 'unsigned timestamp (disabled)' } else { $TimestampUrl }
Write-Host "SIGNING STATUS: SIGNED (all artifacts verified with signtool /pa; timestamp: $timestampStatus)"
[pscustomobject]@{
    Signed = $true
    Timestamped = -not $skipTimestamp
    TimestampUrl = if ($skipTimestamp) { '' } else { $TimestampUrl }
    Files = $Files
    SignTool = $signToolPath
}