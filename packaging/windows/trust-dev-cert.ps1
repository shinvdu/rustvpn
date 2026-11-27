# Trust (or remove) a development Authenticode certificate in the machine
# certificate stores used by Windows Authenticode verification.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File trust-dev-cert.ps1 `
#       -CertFile C:\rustvpn-signing\rustvpn-dev.cer
#
#   powershell ... -File trust-dev-cert.ps1 `
#       -CertFile .\rustvpn-dev.cer -Remove
#
# Root is required for the chain to validate; TrustedPublisher is required for
# the Windows Authenticode publisher/SmartScreen policy.  The operation is
# idempotent: importing an already trusted certificate reports it and changes
# nothing.  Must run elevated.
#
# Only the public .cer is imported.  The script refuses a file that carries a
# private key, so a PFX cannot be installed into the machine trust stores by
# accident.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CertFile,

    [switch]$Remove,

    [ValidateSet('Root', 'TrustedPublisher', 'TrustedPeople')]
    [string[]]$Stores = @('Root', 'TrustedPublisher')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'trust-dev-cert.ps1 must run from an elevated (Administrator) PowerShell session.'
    }
}

Assert-Admin

if (-not (Test-Path -LiteralPath $CertFile)) {
    throw "certificate file does not exist: $CertFile"
}
$resolved = (Resolve-Path -LiteralPath $CertFile).Path
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($resolved)

if ($certificate.HasPrivateKey) {
    throw "refusing to import a certificate that carries a private key; pass the exported .cer, not the .pfx"
}

$ekuExtension = $certificate.Extensions |
    Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
    Select-Object -First 1
if (-not $ekuExtension) {
    throw "refusing to trust a certificate without an Extended Key Usage extension: $resolved"
}
$eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
    $ekuExtension, $false)
$ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
if ($ekuOids -notcontains '1.3.6.1.5.5.7.3.3') {
    throw "refusing to trust a certificate without the Code Signing EKU: $resolved"
}

Write-Host "certificate subject: $($certificate.Subject)"
Write-Host "certificate valid until: $($certificate.NotAfter.ToString('yyyy-MM-dd'))"
if (-not $certificate.Subject.ToLowerInvariant().Contains('rustvpn')) {
    Write-Host 'WARNING: the subject does not contain "RustVPN"; this does not look like the development certificate.'
}

foreach ($storeName in $Stores) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $existing = @($store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint })

        if ($Remove) {
            if ($existing.Count -eq 0) {
                Write-Host "LocalMachine\${storeName}: certificate was not present"
            } else {
                foreach ($item in $existing) { $store.Remove($item) }
                Write-Host "LocalMachine\${storeName}: removed development certificate"
            }
        } else {
            if ($existing.Count -gt 0) {
                Write-Host "LocalMachine\${storeName}: certificate already trusted (no change)"
            } else {
                $store.Add($certificate)
                Write-Host "LocalMachine\${storeName}: imported development certificate"
            }
        }
    } finally {
        $store.Close()
    }
}

Write-Host 'done'