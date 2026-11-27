# Verify the installed daemon from the *current* Windows account.
#
# Run this as an unprivileged user to test the real M5 security boundary:
#   1. the named-pipe DACL accepts the account (RustVPN group membership),
#   2. the daemon process allows PROCESS_QUERY_LIMITED_INFORMATION + READ_CONTROL,
#   3. QueryFullProcessImageNameW resolves the installed daemon image,
#   4. the process owner SID is LocalSystem (the service account),
#   5. a protocol-v2 Hello round-trip succeeds.
#
# The GUI performs steps 2-3 before sending a passphrase; this script is the
# manual acceptance check for that path.  It never connects a tunnel.
[CmdletBinding()]
param(
    [string]$PipeName = 'rustvpn-clientd',
    [string]$ExpectedInstallDir = (Join-Path $env:ProgramFiles 'RustVPN'),
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = 'Stop'

$source = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class RustVPNPipeProbe
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool QueryFullProcessImageNameW(
        IntPtr process, uint flags, StringBuilder buffer, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetSecurityInfo(
        IntPtr handle, int objectType, uint securityInfo,
        out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl,
        out IntPtr descriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr memory);
}
'@

if (-not ('RustVPNPipeProbe' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
    '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
$serverPid = 0
$image = ''
try {
    $pipe.Connect($TimeoutMs)
    $connectedAt = [DateTime]::UtcNow
    Write-Host "connected to \\.\pipe\$PipeName (client PID $PID)"

    [uint32]$serverProcessId = 0
    $handle = $pipe.SafePipeHandle.DangerousGetHandle()
    if (-not [RustVPNPipeProbe]::GetNamedPipeServerProcessId($handle, [ref]$serverProcessId)) {
        throw "GetNamedPipeServerProcessId failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $serverPid = $serverProcessId
    Write-Host "server PID: $serverPid"

    # PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL.  A LocalSystem service
    # is not openable by a standard user unless the daemon granted these
    # rights (M5/M6).
    $process = [RustVPNPipeProbe]::OpenProcess(0x21000, $false, $serverPid)
    if ($process -eq [IntPtr]::Zero) {
        throw "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    try {
        $buffer = New-Object System.Text.StringBuilder 32768
        [uint32]$size = 32768
        if (-not [RustVPNPipeProbe]::QueryFullProcessImageNameW(
                $process, 0, $buffer, [ref]$size)) {
            throw "QueryFullProcessImageNameW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $image = $buffer.ToString()
        [IntPtr]$owner = [IntPtr]::Zero
        [IntPtr]$descriptor = [IntPtr]::Zero
        $securityStatus = [RustVPNPipeProbe]::GetSecurityInfo(
            $process, 6, 1, [ref]$owner, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$descriptor)
        if ($securityStatus -ne 0 -or $owner -eq [IntPtr]::Zero) {
            throw "GetSecurityInfo(owner) failed: $securityStatus"
        }
        try {
            [IntPtr]$ownerText = [IntPtr]::Zero
            if (-not [RustVPNPipeProbe]::ConvertSidToStringSidW($owner, [ref]$ownerText)) {
                throw "ConvertSidToStringSidW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            try {
                $ownerSid = [Runtime.InteropServices.Marshal]::PtrToStringUni($ownerText)
            } finally {
                [void][RustVPNPipeProbe]::LocalFree($ownerText)
            }
        } finally {
            [void][RustVPNPipeProbe]::LocalFree($descriptor)
        }
    } finally {
        [void][RustVPNPipeProbe]::CloseHandle($process)
    }
    Write-Host "server image: $image"
    Write-Host "server owner SID: $ownerSid"
    if ($ownerSid -ne 'S-1-5-18') {
        throw "server owner SID is $ownerSid, expected LocalSystem S-1-5-18"
    }
    Write-Host ("process query completed after {0:N3}s" -f ([DateTime]::UtcNow - $connectedAt).TotalSeconds)

    $normalizedImage = $image.Replace('/', '\')
    $expected = (Join-Path $ExpectedInstallDir 'rustvpn-clientd.exe').TrimEnd('\')
    if (-not $normalizedImage.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "server image '$image' is not the installed daemon '$expected'"
    }

    # 4-byte big-endian length + JSON, exactly like rustvpn-client-ipc.
    $payload = [Text.Encoding]::UTF8.GetBytes('{"op":"hello","version":2}')
    $header = [byte[]]@(
        [byte](($payload.Length -shr 24) -band 0xFF),
        [byte](($payload.Length -shr 16) -band 0xFF),
        [byte](($payload.Length -shr 8) -band 0xFF),
        [byte]($payload.Length -band 0xFF)
    )
    Write-Host ("writing Hello after {0:N3}s" -f ([DateTime]::UtcNow - $connectedAt).TotalSeconds)
    $pipe.Write($header, 0, $header.Length)
    $pipe.Write($payload, 0, $payload.Length)
    $pipe.Flush()

    $readHeader = New-Object byte[] 4
    $offset = 0
    while ($offset -lt 4) {
        $read = $pipe.Read($readHeader, $offset, 4 - $offset)
        if ($read -le 0) { throw 'pipe closed before the Hello response' }
        $offset += $read
    }
    $length = ([int]$readHeader[0] -shl 24) -bor
              ([int]$readHeader[1] -shl 16) -bor
              ([int]$readHeader[2] -shl 8) -bor
              [int]$readHeader[3]
    if ($length -le 0 -or $length -gt 1048576) { throw "invalid response length $length" }
    $response = New-Object byte[] $length
    $offset = 0
    while ($offset -lt $length) {
        $read = $pipe.Read($response, $offset, $length - $offset)
        if ($read -le 0) { throw 'pipe closed during the Hello response' }
        $offset += $read
    }
    $text = [Text.Encoding]::UTF8.GetString($response)
    Write-Host "Hello response: $text"
    $parsed = $text | ConvertFrom-Json
    if ($parsed.op -ne 'hello' -or $parsed.version -ne 2) {
        throw "unexpected Hello response"
    }
    Write-Host 'RESULT: OK (pipe, process query, installed image, SYSTEM owner and Hello v2 all verified)'
    exit 0
} catch {
    Write-Host "RESULT: FAIL - $($_.Exception.Message)"
    exit 1
} finally {
    $pipe.Dispose()
}