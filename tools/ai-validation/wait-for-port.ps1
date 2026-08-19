[CmdletBinding()]
param(
    [Alias('Host')]
    [string]$TargetHost = '127.0.0.1',
    [object[]]$Port = @(4499),
    [int]$TimeoutSeconds = 15,
    [int]$IntervalMs = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ports = [System.Collections.Generic.List[int]]::new()
foreach ($entry in $Port) {
    foreach ($part in ([string]$entry).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $ports.Add([int]($part.Trim()))
    }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$portStates = [System.Collections.Generic.List[object]]::new()
$allReady = $true

foreach ($p in $ports) {
    $ready = $false
    $attempts = 0
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $attempts++
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($TargetHost, $p)
            if ($task.Wait(500) -and $client.Connected) {
                $ready = $true
                break
            }
        }
        catch { }
        finally { $client.Dispose() }
        if (-not $ready) { Start-Sleep -Milliseconds $IntervalMs }
    }
    if (-not $ready) { $allReady = $false }
    $portStates.Add([pscustomobject]@{
        host = $TargetHost
        port = $p
        ready = $ready
        attempts = $attempts
    })
}

$sw.Stop()
[pscustomobject]@{
    portReady = $allReady
    elapsedMs = $sw.ElapsedMilliseconds
    ports = @($portStates)
} | ConvertTo-Json -Depth 5

if (-not $allReady) { exit 1 }