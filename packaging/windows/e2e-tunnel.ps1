# Manual end-to-end tunnel harness for the RustVPN Windows client.
#
# This script is NOT part of the default CI or installer.  It runs on an
# elevated Windows host against a reachable rustvpn-server, drives the
# installed rustvpn-clientd over the named pipe, and reports the Windows
# status/routes/DNS/NRPT/IPv6 state before, during and after a connection.
#
# Safety:
#   * Split-tunnel routes are the default.  Installing a default route or the
#     kill switch requires -AllowFullTunnel and can cut RDP/SSH access.
#   * The script never writes a passphrase itself; it reads a caller-provided
#     file (create it with restricted ACLs and delete it afterwards).
#   * It never changes the default route, DNS, NRPT or firewall itself.  The
#     daemon applies the profile; the script only reports the result.
#
# Phases:
#   status       Hello + Status, print the daemon status JSON.
#   snapshot     Report routes/DNS/NRPT/IPv6 firewall/adapters/netstate.
#   connect      Send Connect, wait for "connected", report before/after.
#   pingtcp      Ping -PingTargets and optionally read a TCP banner.
#   disconnect   Send Disconnect, wait for "idle", report cleanup state.
#   crash        Kill rustvpn-clientd, capture stale state, wait for the SCM
#                restart and capture the recovery result.
#
# Example (split tunnel):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\e2e-tunnel.ps1 `
#     -Phase connect -Remote 192.0.2.10:1194 -ShortVerifier '<verifier>' `
#     -PasswordFile C:\temp\rustvpn-pass.txt -Address 10.88.0.2/24 `
#     -Gateway 10.88.0.1 -Routes 10.88.0.0/24,10.88.1.0/24 `
#     -PingTargets 10.88.0.1,10.88.1.1 -TcpTarget 10.88.0.1 -TcpPort 22
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('status', 'snapshot', 'connect', 'pingtcp', 'disconnect', 'crash')]
    [string]$Phase,
    [string]$PipeName = 'rustvpn-clientd',
    [string]$Remote,
    [string]$ShortVerifier,
    [string]$PasswordFile,
    [string]$Iface = 'rsvpn-e2e',
    [string]$Address,
    [string]$Gateway,
    [string[]]$Routes = @(),
    [string[]]$Dns = @(),
    [int]$Mtu = 1515,
    [string[]]$PingTargets = @(),
    [string]$TcpTarget,
    [int]$TcpPort = 22,
    [string]$OuterEndpoint,
    [switch]$AllowFullTunnel,
    [int]$WaitSeconds = 60,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

function Write-Frame([System.IO.Pipes.NamedPipeClientStream]$Pipe, [string]$Json) {
    $payload = [Text.Encoding]::UTF8.GetBytes($Json)
    $len = $payload.Length
    $header = [byte[]]@(
        [byte](($len -shr 24) -band 0xFF), [byte](($len -shr 16) -band 0xFF),
        [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF))
    $Pipe.Write($header, 0, 4)
    $Pipe.Write($payload, 0, $len)
    $Pipe.Flush()
}

function Read-Frame([System.IO.Pipes.NamedPipeClientStream]$Pipe) {
    $h = New-Object byte[] 4
    $off = 0
    while ($off -lt 4) {
        $n = $Pipe.Read($h, $off, 4 - $off)
        if ($n -le 0) { throw 'pipe closed before the frame header' }
        $off += $n
    }
    $len = ([int]$h[0] -shl 24) -bor ([int]$h[1] -shl 16) -bor
           ([int]$h[2] -shl 8) -bor [int]$h[3]
    if ($len -le 0 -or $len -gt 1048576) { throw "invalid frame length $len" }
    $buf = New-Object byte[] $len
    $off = 0
    while ($off -lt $len) {
        $n = $Pipe.Read($buf, $off, $len - $off)
        if ($n -le 0) { throw 'pipe closed in the middle of a frame' }
        $off += $n
    }
    return [Text.Encoding]::UTF8.GetString($buf)
}

function Open-Client {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(5000)
    Write-Frame $pipe '{"op":"hello","version":2}'
    $hello = Read-Frame $pipe | ConvertFrom-Json
    if ($hello.op -ne 'hello' -or $hello.version -ne 2) {
        throw "unexpected Hello reply: $($hello | ConvertTo-Json -Compress)"
    }
    return $pipe
}

function Invoke-Op([System.IO.Pipes.NamedPipeClientStream]$Pipe, [string]$Json) {
    Write-Frame $Pipe $Json
    return (Read-Frame $Pipe | ConvertFrom-Json)
}

# 4-byte big-endian length + JSON, exactly like rustvpn-client-ipc.
function Get-ProfileJson {
    if (-not $Remote) { throw '-Remote is required' }
    if (-not $ShortVerifier) { throw '-ShortVerifier is required' }
    if (-not $Address) { throw '-Address is required' }
    if ($Routes.Count -eq 0) { throw '-Routes is required (defaults are intentionally not applied)' }
    # Any prefix-0 spelling is a default route; the daemon canonicalises these
    # too, so a raw string comparison would be bypassable.
    $hasDefault = @($Routes | Where-Object {
        $route = $_.Trim()
        $route -ieq 'default' -or $route -match '^[0-9.]+/0+$'
    }).Count -gt 0
    if ($hasDefault -and -not $AllowFullTunnel) {
        throw 'a default route can cut RDP/SSH; pass -AllowFullTunnel if that is intentional'
    }
    $spec = [ordered]@{
        name = 'e2e'; remote = $Remote; proto = 'udp'; verifier = $ShortVerifier
        mtu = $Mtu; mss_clamp = $false; kill_switch = $false
        keepalive = 0; rekey_time = 0; rekey_jitter = 0
        timeout = 60; timesync = 0; noise = $false; encless = $false; cpr = 0
        proxy = ''; proxy_auth = ''; iface = $Iface
        address = $Address; gateway = $Gateway; dns = @($Dns); routes = @($Routes)
        ipv6 = $false
    }
    return ($spec | ConvertTo-Json -Compress)
}

function Get-WintunIndex {
    $adapter = Get-NetAdapter -Name $Iface -ErrorAction SilentlyContinue
    if ($null -eq $adapter) { return $null }
    return [int]$adapter.ifIndex
}

function Get-Snapshot {
    $wintun = Get-NetAdapter -Name $Iface -ErrorAction SilentlyContinue
    $widx = if ($wintun) { [int]$wintun.ifIndex } else { $null }
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Sort-Object DestinationPrefix, InterfaceIndex, NextHop |
        ForEach-Object {
            [pscustomobject]@{
                Dest = $_.DestinationPrefix; IfIndex = $_.InterfaceIndex
                NextHop = $_.NextHop; Metric = $_.RouteMetric
            }
        })
    $defaults = @($routes | Where-Object { $_.Dest -eq '0.0.0.0/0' })
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                IfIndex = $_.InterfaceIndex; Alias = $_.InterfaceAlias
                Servers = @($_.ServerAddresses)
            }
        })
    $addresses = @()
    $wintunRoutes = @()
    if ($widx) {
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $widx `
            -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject]@{ Address = $_.IPAddress; Prefix = $_.PrefixLength } })
        $wintunRoutes = @($routes | Where-Object { $_.IfIndex -eq $widx })
    }
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name; InterfaceIndex = [int]$_.InterfaceIndex
                Status = [string]$_.Status; MacAddress = [string]$_.MacAddress
            }
        })
    $nrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name; Display = $_.DisplayName
                Namespace = $_.Namespace; Servers = @($_.NameServers)
            }
        })
    # Filter by DisplayName server-side; enumerating every rule is slow.
    $firewall = @(Get-NetFirewallRule -DisplayName 'RustVPN*' -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Direction, Action, Enabled)
    $statePath = 'C:\ProgramData\RustVPN\netstate.json'
    $stateExists = Test-Path -LiteralPath $statePath
    $state = $null
    if ($stateExists) {
        # Summarize rather than embed the raw JSON string: Windows PowerShell
        # 5.1's ConvertTo-Json re-escapes it pathologically slowly.
        $raw = Get-Content -LiteralPath $statePath -Raw -ErrorAction SilentlyContinue
        if ($raw) {
            try {
                $st = $raw | ConvertFrom-Json
                $state = [pscustomobject]@{
                    schema = [int]$st.schema; ownerPid = [int]$st.owner.pid
                    iface = [string]$st.iface; adapterIndex = [int]$st.adapter_index
                    address = if ($st.address) {
                        "$($st.address.address)/$($st.address.prefix_len)"
                    } else { $null }
                    routes = @($st.routes | ForEach-Object { "$($_.dest)@$($_.ifindex)" })
                    hasDns = ($null -ne $st.dns); hasNrpt = ($null -ne $st.nrpt)
                }
            } catch {
                $state = [pscustomobject]@{ parseError = "$($_.Exception.Message)" }
            }
        }
    }
    $outerRoute = @()
    if ($OuterEndpoint) {
        $outerRoute = @($routes | Where-Object { $_.Dest -eq "$OuterEndpoint/32" })
    }
    return [pscustomobject]@{
        DefaultRoutes = $defaults
        WintunIndex = $widx
        WintunAddresses = $addresses
        WintunRoutes = $wintunRoutes
        OuterEndpointRoute = $outerRoute
        Dns = $dns
        Nrpt = $nrpt
        IpV6Firewall = $firewall
        Adapters = $adapters
        NetstateExists = $stateExists
        Netstate = $state
        AllRoutes = $routes
    }
}

function Ping-Summary([string]$Target) {
    $pinger = New-Object System.Net.NetworkInformation.Ping
    $replies = @()
    for ($i = 0; $i -lt 4; $i++) {
        try {
            $reply = $pinger.Send($Target, 1500)
            $replies += [pscustomobject]@{
                Status = $reply.Status.ToString(); Ms = $reply.RoundtripTime
            }
        } catch {
            $replies += [pscustomobject]@{
                Status = 'Error'; Ms = $null; Error = "$($_.Exception.Message)"
            }
        }
        Start-Sleep -Milliseconds 200
    }
    $received = @($replies | Where-Object { $_.Status -eq 'Success' }).Count
    return [pscustomobject]@{
        Target = $Target; Sent = $replies.Count; Received = $received
        Lost = $replies.Count - $received; Replies = $replies
    }
}

function Tcp-Banner([string]$Target, [int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Target, $Port)
        if (-not $task.Wait(5000)) { throw "connect timeout to ${Target}:$Port" }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $buf = New-Object byte[] 512
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { throw 'no banner bytes' }
        return [pscustomobject]@{
            Target = $Target; Port = $Port
            Banner = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
        }
    } finally {
        $client.Close()
    }
}

function Wait-State([System.IO.Pipes.NamedPipeClientStream]$Pipe, [string]$Wanted, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $last = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $reply = Invoke-Op $Pipe '{"op":"status"}'
        if ($reply.op -eq 'error') { throw "status error: $($reply.message)" }
        $last = $reply.status
        if ($last.state -eq $Wanted) { return $last }
        Start-Sleep -Milliseconds 750
    }
    throw "timed out waiting for state '$Wanted'; last state '$($last.state)' error '$($last.last_error)'"
}

$result = [ordered]@{
    phase = $Phase; host = $env:COMPUTERNAME
    time = (Get-Date).ToUniversalTime().ToString('o')
}

switch ($Phase) {
    'status' {
        $pipe = Open-Client
        try {
            $reply = Invoke-Op $pipe '{"op":"status"}'
            $result.status = $reply.status
        } finally {
            $pipe.Dispose()
        }
    }
    'snapshot' {
        $result.snapshot = Get-Snapshot
        if ($PingTargets.Count -gt 0) {
            $result.pings = @($PingTargets | ForEach-Object { Ping-Summary $_ })
        }
    }
    'pingtcp' {
        $result.pings = @($PingTargets | ForEach-Object { Ping-Summary $_ })
        if ($TcpTarget) {
            try {
                $result.tcp = Tcp-Banner $TcpTarget $TcpPort
            } catch {
                $result.tcpError = "$_"
            }
        }
    }
    'connect' {
        if (-not (Test-Path -LiteralPath $PasswordFile)) {
            throw "password file not found: $PasswordFile"
        }
        $pw = (Get-Content -LiteralPath $PasswordFile -Raw).Trim()
        $profile = Get-ProfileJson
        $before = Get-Snapshot
        $pipe = Open-Client
        try {
            $request = (@{
                op = 'connect'; profile = ($profile | ConvertFrom-Json); password = $pw
            } | ConvertTo-Json -Compress -Depth 10)
            $reply = Invoke-Op $pipe $request
            if ($reply.op -eq 'error') { throw "connect error: $($reply.message)" }
            $result.connected = Wait-State $pipe 'connected' $WaitSeconds
            $result.before = $before
            $result.afterConnect = Get-Snapshot
            if ($PingTargets.Count -gt 0) {
                $result.pings = @($PingTargets | ForEach-Object { Ping-Summary $_ })
            }
            if ($TcpTarget) {
                try {
                    $result.tcp = Tcp-Banner $TcpTarget $TcpPort
                } catch {
                    $result.tcpError = "$_"
                }
            }
        } finally {
            $pipe.Dispose()
        }
    }
    'disconnect' {
        $pipe = Open-Client
        try {
            $reply = Invoke-Op $pipe '{"op":"disconnect"}'
            if ($reply.op -eq 'error') { throw "disconnect error: $($reply.message)" }
            Start-Sleep -Seconds 1
            $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
            $last = $null
            while ([DateTime]::UtcNow -lt $deadline) {
                $status = Invoke-Op $pipe '{"op":"status"}'
                $last = $status.status
                if ($last.state -eq 'idle') { break }
                Start-Sleep -Milliseconds 750
            }
            $result.status = $last
            $result.after = Get-Snapshot
        } finally {
            $pipe.Dispose()
        }
    }
    'crash' {
        $result.before = Get-Snapshot
        $proc = Get-Process rustvpn-clientd -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) { throw 'rustvpn-clientd is not running' }
        $result.killedPid = $proc.Id
        # Crash (not Stop-Service): the SCM failure actions restart the service.
        Stop-Process -Id $proc.Id -Force
        Start-Sleep -Milliseconds 500
        $result.immediatelyAfterKill = Get-Snapshot
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        $service = Get-Service rustvpn-clientd
        while ($service.Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 1
            $service.Refresh()
        }
        Start-Sleep -Seconds 4
        $service.Refresh()
        $result.serviceStatus = $service.Status.ToString()
        $result.afterRestart = Get-Snapshot
    }
}

$json = $result | ConvertTo-Json -Depth 12
if ($OutFile) {
    $json | Set-Content -LiteralPath $OutFile -Encoding UTF8
}
$json