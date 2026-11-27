# Inspect a RustVPN MSI without installing the service.
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\verify-msi.ps1 `
#       -MsiPath dist\windows\RustVPN-0.2.0-beta.1-x64.msi
#
# It performs an administrative install (`msiexec /a`) to a temporary folder
# and decompiles the package with WiX dark.exe to assert the service/upgrade
# tables and payload.  No service is registered and no machine state changes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,
    [string]$ExtractDir = '',
    [string]$DarkExe = '',
    [string]$ExpectedMsiVersion = ''
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $MsiPath)) { throw "MSI not found: $MsiPath" }
$msi = (Resolve-Path -LiteralPath $MsiPath).Path
$explicitExtract = -not [string]::IsNullOrWhiteSpace($ExtractDir)
$work = if ($explicitExtract) {
    [IO.Path]::GetFullPath($ExtractDir)
} else {
    Join-Path ([IO.Path]::GetTempPath()) ("rustvpn-msi-inspect-" + [guid]::NewGuid().ToString('N'))
}
if (-not $explicitExtract) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $work
}
New-Item -ItemType Directory -Force -Path $work | Out-Null
$extract = Join-Path $work 'payload'
$darkOut = Join-Path $work 'dark'
# An explicit ExtractDir is caller-owned; only clear the subdirectories this
# script fills, so stale payload files cannot make a missing-file check pass.
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $extract, $darkOut
New-Item -ItemType Directory -Force -Path $extract, $darkOut | Out-Null

function Write-Step([string]$Message) { Write-Host "==> $Message" }

if (-not $DarkExe) {
    $command = Get-Command dark.exe -ErrorAction SilentlyContinue
    if ($command) {
        $DarkExe = $command.Source
    } else {
        foreach ($candidate in @(
                'C:\Program Files (x86)\WiX Toolset v3.14\bin\dark.exe',
                'C:\Program Files\WiX Toolset v3.14\bin\dark.exe')) {
            if (Test-Path -LiteralPath $candidate) { $DarkExe = $candidate; break }
        }
    }
}
if (-not $DarkExe) { throw 'dark.exe not found; install WiX Toolset 3.14 or pass -DarkExe' }

Write-Step 'administrative install (msiexec /a)'
$msiLog = Join-Path $work 'admin-install.log'
$process = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -NoNewWindow -ArgumentList @(
    '/a', "`"$msi`"", '/qn',
    "TARGETDIR=`"$extract`"",
    'WEBVIEW2X86=1',
    '/l*v', "`"$msiLog`""
)
if ($process.ExitCode -ne 0) {
    $tail = Get-Content -LiteralPath $msiLog -Tail 40 -ErrorAction SilentlyContinue
    throw "msiexec /a failed with $($process.ExitCode):`n$($tail -join [Environment]::NewLine)"
}

$files = Get-ChildItem -LiteralPath $extract -Recurse -File
$byName = @{}
foreach ($file in $files) { $byName[$file.Name] = $file.FullName }
foreach ($required in @(
        'rustvpn-client-ui.exe',
        'rustvpn-clientd.exe',
        'wintun.dll',
        'COPYING',
        'windows-install.md',
        'wintun-LICENSE.txt',
        'wintun-VERSION.txt',
        'wintun-SHA256SUMS.txt',
        'setup-group.ps1',
        'VERSION.txt',
        'SIGNING.txt')) {
    if (-not $byName.ContainsKey($required)) {
        throw "administrative install is missing $required"
    }
}
Write-Host 'payload files present:'
$files | ForEach-Object { '  ' + $_.FullName.Substring($extract.Length + 1) }

Write-Step 'decompiling with dark.exe'
$darkWxs = Join-Path $darkOut 'product.wxs'
$previous = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & $DarkExe -nologo -o $darkWxs -x $darkOut $msi
    $darkExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previous
}
if ($darkExit -ne 0) { throw "dark.exe failed with $darkExit" }
if (-not (Test-Path -LiteralPath $darkWxs)) { throw 'dark.exe produced no .wxs output' }
$text = Get-Content -LiteralPath $darkWxs -Raw

$checks = [ordered]@{
    'ServiceInstall rustvpn-clientd' = 'Name="rustvpn-clientd"'
    'service arguments --service' = 'Arguments="--service"'
    'LocalSystem service account' = 'Account="LocalSystem"'
    'automatic start' = 'Start="auto"'
    'stop before replace' = 'Stop="both"'
    'start after install' = 'Start="install"'
    'remove service on uninstall' = 'Remove="uninstall"'
    'uninstall network cleanup' = '--cleanup'
    'failure recovery 5s' = 'restart/5000'
    'failure recovery 10s' = 'restart/10000'
    'failure recovery 30s' = 'restart/30000'
    'start menu shortcut' = 'StartMenuShortcut'
    'optional desktop shortcut' = 'INSTALLDESKTOPSHORTCUT'
    'RustVPN group helper' = 'setup-group.ps1'
    'x64 package' = 'Platform="x64"'
    'major upgrade' = 'MajorUpgrade'
}
$failures = @()
foreach ($entry in $checks.GetEnumerator()) {
    if ($text -notmatch [regex]::Escape($entry.Value)) {
        $failures += $entry.Key
    } else {
        Write-Host "  ok: $($entry.Key)"
    }
}

Write-Step 'reading MSI tables directly'
# Return a PSCustomObject rather than an array: PowerShell 5.1 unrolls arrays
# returned from functions, and MSI Record objects are enumerable too.
function Get-MsiQuery {
    param($Database, [string]$Query, [int]$ColumnCount)
    $view = $Database.OpenView($Query)
    try {
        [void]$view.Execute()
        $count = 0
        $first = @()
        while ($true) {
            $record = $view.Fetch()
            if (-not $record) { break }
            $count = $count + 1
            if ($count -eq 1) {
                $values = @()
                for ($index = 0; $index -lt $ColumnCount; $index = $index + 1) {
                    $values += [string]$record.StringData($index + 1)
                }
                $first = $values
            }
        }
        return [pscustomobject]@{ Count = $count; First = $first }
    } finally {
        [void]$view.Close()
    }
}

$installer = New-Object -ComObject WindowsInstaller.Installer
try {
    $database = $installer.OpenDatabase($msi, 0)

    $versionQuery = Get-MsiQuery $database `
        "SELECT Value FROM Property WHERE Property='ProductVersion'" 1
    $productVersion = if ($versionQuery.Count -gt 0) { $versionQuery.First[0] } else { '' }
    if ($ExpectedMsiVersion -and $productVersion -ne $ExpectedMsiVersion) {
        $failures += "ProductVersion $productVersion != $ExpectedMsiVersion"
    } else {
        Write-Host "  ok: MSI ProductVersion $productVersion"
    }

    $allUsersQuery = Get-MsiQuery $database `
        "SELECT Value FROM Property WHERE Property='ALLUSERS'" 1
    $allUsers = if ($allUsersQuery.Count -gt 0) { $allUsersQuery.First[0] } else { '' }
    if ($allUsers -ne '1') {
        $failures += "ALLUSERS is '$allUsers' (expected 1 for per-machine)"
    } else {
        Write-Host '  ok: ALLUSERS=1 (per-machine)'
    }
    $perUserQuery = Get-MsiQuery $database `
        "SELECT Value FROM Property WHERE Property='MSIINSTALLPERUSER'" 1
    if ($perUserQuery.Count -ne 0) {
        $failures += "MSIINSTALLPERUSER is set ('$($perUserQuery.First[0])'); expected per-machine"
    }

    $serviceQuery = Get-MsiQuery $database `
        "SELECT Name, StartType, StartName, Arguments FROM ServiceInstall" 4
    if ($serviceQuery.Count -ne 1) {
        $failures += "ServiceInstall has $($serviceQuery.Count) rows (expected 1)"
    } else {
        $service = $serviceQuery.First
        if ($service[0] -ne 'rustvpn-clientd') { $failures += "ServiceInstall name $($service[0])" }
        if ([int]$service[1] -ne 2) {
            $failures += "ServiceInstall StartType $($service[1]) (expected 2 auto)"
        }
        if ($service[2] -ne 'LocalSystem') { $failures += "ServiceInstall StartName $($service[2])" }
        if ($service[3] -ne '--service') { $failures += "ServiceInstall Arguments $($service[3])" }
        Write-Host "  ok: ServiceInstall $($service[0]) StartType=$($service[1]) StartName=$($service[2]) Args=$($service[3])"
    }

    $controlQuery = Get-MsiQuery $database `
        "SELECT Name, Event FROM ServiceControl" 2
    if ($controlQuery.Count -ne 1) {
        $failures += "ServiceControl has $($controlQuery.Count) rows (expected 1)"
    } else {
        $control = $controlQuery.First
        $event = [int]$control[1]
        # Stop-on-install (0x1) and start-on-install (0x2) are the bits that
        # make an upgrade stop the old daemon and start the new one.  WiX also
        # emits the uninstall stop/remove bits; dark.exe output is checked for
        # Stop="both", Start="install" and Remove="uninstall".
        if (($event -band 1) -eq 0 -or ($event -band 2) -eq 0) {
            $failures += "ServiceControl Event $event lacks stop/start-on-install bits"
        } else {
            Write-Host "  ok: ServiceControl $($control[0]) Event=$event"
        }
    }

} finally {
    if ($database) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) }
    if ($installer) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
}

if ($failures.Count -gt 0) {
    throw "MSI verification failed: $($failures -join '; ')"
}

Write-Host 'MSI verification passed.'
Write-Host "Inspection directory: $work"
[pscustomobject]@{
    Msi = $msi
    ProductVersion = if ($ExpectedMsiVersion) { $ExpectedMsiVersion } else { '' }
    Files = $files.FullName
    WorkDir = $work
}