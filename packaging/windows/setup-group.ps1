# Create the local RustVPN group and add the installing user.
#
# The MSI runs this before StartServices so `rustvpn-clientd --service` sees
# the group and restricts the named pipe to it.  The script never fails the
# installation:
#   * if the group already exists it is reused;
#   * if the user cannot be added, the group is kept (empty if necessary) so
#     the fail-closed service can still start; the account must be added
#     manually and must re-login before its token carries the group;
#   * membership becomes effective at the next logon for an account whose
#     token was created before this run (a re-login is documented).
param(
    [string]$User = ''
)

$ErrorActionPreference = 'Continue'
$group = 'RustVPN'
$log = Join-Path $env:TEMP 'RustVPN-setup-group.log'
$net = Join-Path $env:SystemRoot 'System32\net.exe'

function Write-Log([string]$Message) {
    $line = '{0:o} {1}' -f (Get-Date), $Message
    Write-Output $line
    try { Add-Content -Path $log -Value $line -ErrorAction SilentlyContinue } catch { }
}

function Test-Group([string]$Name) {
    & $net localgroup $Name *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-Members([string]$Name) {
    try {
        return @(Get-LocalGroupMember -Group $Name -ErrorAction Stop |
            ForEach-Object { $_.Name })
    } catch {
        # Fall back to parsing `net localgroup` output for domain/older SKUs.
        $lines = @(& $net localgroup $Name 2>$null)
        if ($LASTEXITCODE -ne 0) { return @() }
        $members = @()
        $inMembers = $false
        foreach ($line in $lines) {
            if ($line -match '^-+$') { $inMembers = $true; continue }
            if ($inMembers) {
                if ($line -match '^The command completed successfully') { break }
                if ($line.Trim()) { $members += $line.Trim() }
            }
        }
        return $members
    }
}

function Test-Member([string[]]$Members, [string]$Name) {
    $leaf = ($Name -split '\\')[-1]
    foreach ($member in $Members) {
        if ($member -ieq $Name) { return $true }
        if (($member -split '\\')[-1] -ieq $leaf) { return $true }
    }
    return $false
}

Write-Log "starting group setup for user '$User'"

# `$`, SYSTEM and service accounts cannot be local-group members in a useful
# way; a silent deployment can pass RUSTVPN_USER explicitly instead.
$skip = @('', 'SYSTEM', '$', 'LocalSystem', 'NT AUTHORITY\SYSTEM',
    'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
if ($skip -contains $User) {
    if (-not (Test-Group $group)) {
        & $net localgroup $group /add /comment:"RustVPN client users" *>> $log
        if ($LASTEXITCODE -ne 0 -or -not (Test-Group $group)) {
            Write-Log 'no interactive user and cannot create the RustVPN group; service will fail closed'
            exit 0
        }
        Write-Log 'no interactive user; created an empty RustVPN group for the fail-closed service'
    } else {
        Write-Log 'no interactive user to add; existing RustVPN group left unchanged'
    }
    exit 0
}
if ($User -match '["\r\n]') {
    if (-not (Test-Group $group)) {
        & $net localgroup $group /add /comment:"RustVPN client users" *>> $log
        if (-not (Test-Group $group)) {
            Write-Log 'refusing an invalid user name and cannot create the RustVPN group; service will fail closed'
            exit 0
        }
    }
    Write-Log 'refusing a user name containing quotes or newlines; group left present for the service'
    exit 0
}

if (-not (Test-Group $group)) {
    & $net localgroup $group /add /comment:"RustVPN client users" *>> $log
    if ($LASTEXITCODE -ne 0 -or -not (Test-Group $group)) {
        Write-Log 'cannot create the RustVPN group (domain policy?); service will fail closed until the group exists'
        exit 0
    }
    Write-Log 'created local group RustVPN'
}

$members = Get-Members $group
if (Test-Member $members $User) {
    Write-Log "user '$User' is already a member of $group"
    exit 0
}

& $net localgroup $group $User /add *>> $log
$members = Get-Members $group
if (Test-Member $members $User) {
    Write-Log "added '$User' to $group; the account must log on again for its token to include the group"
    exit 0
}

Write-Log "failed to add '$User' to $group; kept the group so the service can start (add the account manually and re-login)"
exit 0
