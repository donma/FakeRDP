[CmdletBinding()]
param(
    [string]$TargetHost = '127.0.0.1',
    [int]$Port = 13390,
    [string]$LogDirectory = 'bin/Release/net10.0/resource-regression-logs',
    [int]$Connections = 10,
    [string]$ResultPath = 'tools/scanner-test/results/resource-result.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-Exact {
    param([System.IO.Stream]$Stream, [int]$Count)
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -eq 0) { throw 'connection closed' }
        $offset += $read
    }
    return $buffer
}

[byte[]]$probe = @(
    0x03, 0x00, 0x00, 0x13,
    0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00
)

$before = @((Get-ChildItem -LiteralPath $LogDirectory -Directory -Filter 'session_*' -ErrorAction SilentlyContinue)).Count
$hold = [System.Net.Sockets.TcpClient]::new()
$hold.Connect($TargetHost, $Port)
$holdStream = $hold.GetStream()
$holdStream.Write($probe, 0, $probe.Length)
$holdHeader = Read-Exact $holdStream 4
$holdBodyLength = ($holdHeader[2] -shl 8) -bor $holdHeader[3]
$null = Read-Exact $holdStream ($holdBodyLength - 4)

$results = [System.Collections.Generic.List[object]]::new()
try {
    for ($i = 0; $i -lt $Connections; $i++) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect($TargetHost, $Port)
            $stream = $client.GetStream()
            $stream.Write($probe, 0, $probe.Length)
            $header = Read-Exact $stream 4
            $length = ($header[2] -shl 8) -bor $header[3]
            $null = Read-Exact $stream ($length - 4)
            $results.Add([pscustomobject]@{ Tcp = $true; X224 = ($length -ge 19); Length = $length })
        }
        catch {
            $results.Add([pscustomobject]@{ Tcp = $false; X224 = $false; Length = 0 })
        }
        finally { $client.Dispose() }
    }
}
finally {
    $hold.Dispose()
}
$after = @((Get-ChildItem -LiteralPath $LogDirectory -Directory -Filter 'session_*' -ErrorAction SilentlyContinue)).Count
$allX224 = @($results | Where-Object { $_.Tcp -and $_.X224 }).Count -eq $Connections
$noUnexpectedBurst = ($after - $before) -le 1
$result = [ordered]@{
    timestamp = [DateTime]::UtcNow.ToString('O')
    host = $TargetHost
    port = $Port
    sessionLimit = $noUnexpectedBurst
    lightweightX224 = $allX224
    sessionDirectoryBounded = $noUnexpectedBurst
    beforeSessionDirectories = $before
    afterSessionDirectories = $after
    probeCount = $Connections
}
$resultDirectory = Split-Path -Parent $ResultPath
if (-not (Test-Path -LiteralPath $resultDirectory)) {
    New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
}
$result | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding utf8
[pscustomobject]$result | Format-List
if (-not ($allX224 -and $noUnexpectedBurst)) { exit 1 }
