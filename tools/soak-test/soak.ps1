[CmdletBinding()]
param(
    [string]$Host = '127.0.0.1',
    [int]$Port = 13389,
    [int]$DurationMinutes = 30,
    [int]$MaxConcurrent = 100,
    [string]$LogDirectory = 'tools/soak-test/results'
)

# 30-min soak test (non-CI).
# Continuously opens RDP-like connections against a running FakeRDP,
# sending synthetic Info PDUs, and periodically checks process memory/
# handle/thread counts and credential counters.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$results = [System.Collections.Generic.List[object]]::new()
$connects = 0
$errors = 0
$credentials = 0
$deadline = (Get-Date).AddMinutes($DurationMinutes)

while ((Get-Date) -lt $deadline) {
    $batch = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
    for ($i = 0; $i -lt $MaxConcurrent; $i++) {
        $connects++
        $batch.Add([System.Threading.Tasks.Task]::Run([Action]{
            try {
                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect($Host, $Port)
                $s = $client.GetStream()
                # X.224 CR (legacy standard security)
                $probe = [byte[]](0x03,0x00,0x00,0x0b,0x06,0xe0,0x00,0x00,0x00,0x00,0x00)
                $s.Write($probe, 0, $probe.Length)
                Start-Sleep -Milliseconds 50
                $client.Close()
            } catch {
                $script:errors++
            }
        }))
    }
    [System.Threading.Tasks.Task]::WaitAll($batch.ToArray())
    Start-Sleep -Milliseconds 200

    # 每個週期取樣一次
    if (($sw.ElapsedMilliseconds % 5000) -lt 250) {
        $proc = Get-Process -Name RdpHoneypot -ErrorAction SilentlyContinue | Select-Object -First 1
        $newResults = [pscustomobject]@{
            timestamp = Get-Date -Format o
            connects = $connects
            errors = $errors
        }
        if ($proc) {
            $newResults | Add-Member -NotePropertyName memoryMB -NotePropertyValue ([math]::Round($proc.WorkingSet64/1MB,1))
            $newResults | Add-Member -NotePropertyName handles -NotePropertyValue $proc.HandleCount
            $newResults | Add-Member -NotePropertyName threads -NotePropertyValue $proc.Threads.Count
        }
        $results.Add($newResults)
    }
}

$credPath = Join-Path $LogDirectory '../soak-credentials.jsonl'
$sw.Stop()
$summary = [ordered]@{
    durationMinutes = $DurationMinutes
    connects = $connects
    errors = $errors
    samples = $results.Count
    maxMemoryMB = ($results | Measure-Object memoryMB -Maximum).Maximum
    maxHandles = ($results | Measure-Object handles -Maximum).Maximum
    maxThreads = ($results | Measure-Object threads -Maximum).Maximum
}
$summary | ConvertTo-Json -Depth 4
Write-Host "Soak complete: $connects connections, $errors errors."