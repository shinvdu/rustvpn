# Create a self-signed Authenticode code-signing certificate for local
# development and test builds of the RustVPN Windows client.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File create-dev-cert.ps1
#
# This is a DEVELOPMENT tool.  A self-signed certificate is trusted only on
# hosts that explicitly import the exported .cer into their machine trust
# stores.  It must not be used for public distribution; production releases
# need an EV/OV code-signing certificate and publisher pinning.
#
# Outputs (default C:\rustvpn-signing):
#   rustvpn-dev.pfx       PFX with the private key (never commit/copy to a VM)
#   rustvpn-dev.cer       public certificate for trust import
#   dev-cert.password     generated PFX password (protected file)
#
# The output directory and files are ACL-restricted to Administrators and
# SYSTEM.  The password is never printed to the console or a log file.
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\rustvpn-signing',
    [string]$Subject = 'CN=RustVPN Development, O=RustVPN, C=US',
    [ValidateRange(1, 5)]
    [int]$ValidityYears = 3,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'create-dev-cert.ps1 must run from an elevated (Administrator) PowerShell session.'
    }
}

function Set-ProtectedDirectoryAcl([string]$Path) {
    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                   [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $administrators, $rights, $inheritance, $propagation, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $system, $rights, $inheritance, $propagation, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProtectedFileAcl([string]$Path) {
    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $administrators, $rights, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $system, $rights, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-RandomPassword([int]$Length = 40) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $chars = New-Object char[] $Length
    for ($index = 0; $index -lt $Length; $index++) {
        $chars[$index] = $alphabet[$bytes[$index] % $alphabet.Length]
    }
    return (-join $chars)
}

function Test-CodeSigningUsage([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $ekuExtension = $Cert.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        Select-Object -First 1
    if (-not $ekuExtension) {
        throw 'certificate does not carry an Extended Key Usage extension'
    }
    $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
        $ekuExtension, $false)
    $ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
    if ($ekuOids -notcontains '1.3.6.1.5.5.7.3.3') {
        throw 'certificate does not carry the Code Signing EKU (1.3.6.1.5.5.7.3.3)'
    }

    $keyUsageExtension = $Cert.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.15' } |
        Select-Object -First 1
    if (-not $keyUsageExtension) {
        throw 'certificate does not carry a Key Usage extension'
    }
    $keyUsage = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
        $keyUsageExtension, $false)
    $digitalSignature = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
    if (($keyUsage.KeyUsages -band $digitalSignature) -eq 0) {
        throw 'certificate Key Usage does not include DigitalSignature'
    }
}

function Find-RepoRoot([string]$Start) {
    $directory = [IO.Path]::GetFullPath($Start)
    while ($directory) {
        if ((Test-Path -LiteralPath (Join-Path $directory 'Cargo.toml')) -and
                (Test-Path -LiteralPath (Join-Path $directory 'packaging\windows'))) {
            return $directory
        }
        $parent = [IO.Directory]::GetParent($directory)
        if ($null -eq $parent -or $parent.FullName -eq $directory) {
            return $null
        }
        $directory = $parent.FullName
    }
    return $null
}

Assert-Admin

$repoRoot = Find-RepoRoot $PSScriptRoot
$outDirFull = [IO.Path]::GetFullPath($OutDir)
if ($repoRoot -and $outDirFull.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to store signing material inside the repository: $outDirFull"
}

$pfxPath = Join-Path $outDirFull 'rustvpn-dev.pfx'
$cerPath = Join-Path $outDirFull 'rustvpn-dev.cer'
$passwordPath = Join-Path $outDirFull 'dev-cert.password'

New-Item -ItemType Directory -Force -Path $outDirFull | Out-Null
Set-ProtectedDirectoryAcl $outDirFull

$certificate = $null
$password = $null

# Reuse a matching PFX only when the stored password still opens it and the
# certificate is still comfortably valid.  This keeps repeated builds stable.
if (-not $Force -and (Test-Path -LiteralPath $pfxPath) -and (Test-Path -LiteralPath $passwordPath)) {
    $candidatePassword = (Get-Content -LiteralPath $passwordPath -Raw).Trim()
    try {
        $candidate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $pfxPath,
            $candidatePassword,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        if ($candidate.HasPrivateKey -and
                $candidate.Subject -eq $Subject -and
                $candidate.NotAfter -gt (Get-Date).AddDays(30)) {
            Test-CodeSigningUsage $candidate
            $certificate = $candidate
            $password = $candidatePassword
        }
    } catch {
        Write-Host "existing PFX is not reusable: $($_.Exception.Message)"
    }
}

if (-not $certificate) {
    $stored = $null
    if (-not $Force) {
        $stored = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object {
                $_.HasPrivateKey -and
                $_.Subject -eq $Subject -and
                $_.NotAfter -gt (Get-Date).AddDays(30)
            } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1
    }

    if ($stored) {
        $certificate = $stored
        Write-Host 'reusing the existing code-signing certificate from Cert:\CurrentUser\My'
    } else {
        $now = Get-Date
        $certificate = New-SelfSignedCertificate `
            -Subject $Subject `
            -Type CodeSigningCert `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy Exportable `
            -NotBefore $now.AddDays(-1) `
            -NotAfter $now.AddYears($ValidityYears) `
            -CertStoreLocation 'Cert:\CurrentUser\My'
        Write-Host 'created a new self-signed code-signing certificate in Cert:\CurrentUser\My'
    }

    Test-CodeSigningUsage $certificate
    if (-not $certificate.Subject.ToLowerInvariant().Contains('rustvpn')) {
        throw "certificate subject does not name RustVPN: $($certificate.Subject)"
    }

    $password = New-RandomPassword
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $securePassword -Force |
        Out-Null
    Set-Content -LiteralPath $passwordPath -Value $password -NoNewline -Encoding ASCII
    Set-ProtectedFileAcl $pfxPath
    Set-ProtectedFileAcl $passwordPath
}

# Always refresh the public certificate so it matches the PFX.
[IO.File]::WriteAllBytes($cerPath, $certificate.RawData)
Set-ProtectedFileAcl $cerPath

Write-Host 'development code-signing certificate ready'
Write-Host "  Subject:      $($certificate.Subject)"
Write-Host "  Valid until:  $($certificate.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  PFX:          $pfxPath"
Write-Host "  CER:          $cerPath"
Write-Host "  Password file:$passwordPath"
Write-Host 'The PFX password and private key are only in the protected signing directory.'
Write-Host 'Never commit or copy the PFX/password to the repository or a test VM.'

[pscustomobject]@{
    Subject = $certificate.Subject
    NotAfter = $certificate.NotAfter
    Pfx = $pfxPath
    Cer = $cerPath
    PasswordFile = $passwordPath
}