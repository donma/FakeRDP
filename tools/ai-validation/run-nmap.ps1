[CmdletBinding()]
param(
    [Alias('Host')]
    [string]$TargetHost = '127.0.0.1',
    [object[]]$Port = @(4499),
    [string]$OutputDirectory = 'tools/ai-validation/results',
    [int]$CommandTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$parseScript = Join-Path $scriptDir 'parse-nmap.ps1'

$ports = [System.Collections.Generic.List[int]]::new()
foreach ($entry in $Port) {
    foreach ($part in ([string]$entry).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $ports.Add([int]($part.Trim()))
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$nmapPath = Get-Command nmap -ErrorAction SilentlyContinue

$summary = [ordered]@{
    timestamp = [DateTime]::UtcNow.ToString('O')
    host = $TargetHost
    nmapAvailable = ($null -ne $nmapPath)
    nmapVersion = ''
    reason = ''
    ports = [ordered]@{}
}

if ($nmapPath) {
    $versionLine = (& nmap --version 2>&1 | Select-Object -First 1 | Out-String).Trim()
    $summary.nmapVersion = $versionLine
}

# Runs a native command with a hard timeout; returns exit code, output text.
function Invoke-NmapCommand {
    param([string[]]$Arguments, [int]$TimeoutMs)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'nmap'
    $psi.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($TimeoutMs)) {
        try { $proc.Kill($true) } catch { }
        $proc.WaitForExit()
        return [pscustomobject]@{ ExitCode = 124; Output = $outTask.GetAwaiter().GetResult() + $errTask.GetAwaiter().GetResult(); TimedOut = $true }
    }
    return [pscustomobject]@{ ExitCode = $proc.ExitCode; Output = $outTask.GetAwaiter().GetResult() + $errTask.GetAwaiter().GetResult(); TimedOut = $false }
}

$specs = @(
    [pscustomobject]@{ Key = 'tcp'; File = 'nmap-tcp.txt'; Args = $null },
    [pscustomobject]@{ Key = 'service'; File = 'nmap-service.txt'; Args = $null },
    [pscustomobject]@{ Key = 'versionAll'; File = 'nmap-version-all.txt'; Args = $null },
    [pscustomobject]@{ Key = 'rdpEnumEncryption'; File = 'nmap-rdp-enum-encryption.txt'; Args = $null },
    [pscustomobject]@{ Key = 'sslCert'; File = 'nmap-ssl-cert.txt'; Args = $null }
)

foreach ($p in $ports) {
    $dir = Join-Path $OutputDirectory "$p"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $portResult = [ordered]@{
        nmapStatus = ''
        reason = ''
        tcp = ''
        service = ''
        versionAll = ''
        rdpEnumEncryption = ''
        sslCert = ''
    }

    if ($null -eq $nmapPath) {
        $portResult.nmapStatus = 'SKIPPED'
        $portResult.reason = 'NMAP NOT INSTALLED'
        $portResult.tcp = 'SKIPPED'
        $portResult.service = 'SKIPPED'
        $portResult.versionAll = 'SKIPPED'
        $portResult.rdpEnumEncryption = 'SKIPPED'
        $portResult.sslCert = 'SKIPPED'
        foreach ($spec in $specs) {
            Set-Content -LiteralPath (Join-Path $dir $spec.File) -Value 'SKIPPED - NMAP NOT INSTALLED' -Encoding utf8
        }
        $summary.ports["$p"] = $portResult
        continue
    }

    $portResult.nmapStatus = 'EXECUTED'
    # rdp-enum-encryption requires the port service to be identified as
    # ms-wbt-server (portrule) on non-3389 ports, so it must run with -sV.
    $argSpecs = @(
        [pscustomobject]@{ Key = 'tcp'; File = 'nmap-tcp.txt'; Args = @('-Pn', '-p', "$p", $TargetHost) },
        [pscustomobject]@{ Key = 'service'; File = 'nmap-service.txt'; Args = @('-Pn', '-sV', '-p', "$p", $TargetHost) },
        [pscustomobject]@{ Key = 'versionAll'; File = 'nmap-version-all.txt'; Args = @('-Pn', '-sV', '--version-all', '-p', "$p", $TargetHost) },
        [pscustomobject]@{ Key = 'rdpEnumEncryption'; File = 'nmap-rdp-enum-encryption.txt'; Args = @('-Pn', '-sV', '-p', "$p", '--script', 'rdp-enum-encryption', '--script-timeout', '120s', $TargetHost) },
        [pscustomobject]@{ Key = 'sslCert'; File = 'nmap-ssl-cert.txt'; Args = @('-Pn', '-p', "$p", '--script', 'ssl-cert', $TargetHost) }
    )

    foreach ($spec in $argSpecs) {
        $timeoutMs = if ($spec.Key -eq 'rdpEnumEncryption') { $CommandTimeoutSeconds * 1000 } else { 120000 }
        $run = Invoke-NmapCommand -Arguments $spec.Args -TimeoutMs $timeoutMs
        $exitCode = $run.ExitCode
        $text = $run.Output.Trim()
        $file = Join-Path $dir $spec.File
        Set-Content -LiteralPath $file -Value $text -Encoding utf8
        if ($run.TimedOut) { $text = $text + "`n`n[validation] TIMEOUT after $($CommandTimeoutSeconds)s" }

        $parsed = $null
        try {
            $parsed = & $parseScript -Path $file -Port $p -TargetHost $TargetHost | ConvertFrom-Json
        }
        catch {
            Write-Warning "parse-nmap failed for $file : $($_.Exception.Message)"
        }

        $portState = if ($parsed) { [string]$parsed.portState } else { 'unknown' }
        $service = if ($parsed) { [string]$parsed.service } else { '' }
        $result = 'FAIL'

        switch ($spec.Key) {
            'tcp' {
                if ($exitCode -eq 0 -and $portState -eq 'open') { $result = 'PASS' }
            }
            'service' {
                if ($exitCode -eq 0 -and $portState -eq 'open' -and
                    $service -match '(?i)ms-wbt-server|microsoft\s*terminal\s*services|remote\s*desktop|terminal\s*services|rdp') { $result = 'PASS' }
                elseif ($portState -eq 'open') { $result = 'PARTIAL' }
                elseif ($portState -match 'closed|filtered|tcpwrapped') { $result = 'FAIL' }
                else { $result = 'PARTIAL' }
            }
            'versionAll' {
                if ($exitCode -eq 0 -and $portState -eq 'open' -and
                    $service -match '(?i)ms-wbt-server|microsoft\s*terminal\s*services|remote\s*desktop|terminal\s*services|rdp') { $result = 'PASS' }
                elseif ($portState -eq 'open') { $result = 'PARTIAL' }
                else { $result = 'FAIL' }
            }
            'rdpEnumEncryption' {
                $hasScript = $text -match '(?i)rdp-enum-encryption'
                $hasCapability = $text -match '(?i)CredSSP|NLA|SSL|TLS|Native RDP|RDP Encryption|Security layer'
                $hasError = $text -match '(?i)NSE failed|script error|error while executing|timed out|\[validation\] TIMEOUT'
                if ($exitCode -eq 0 -and $hasScript -and $hasCapability -and -not $hasError) { $result = 'PASS' }
                elseif ($text -match '(?i)NMAP NOT INSTALLED|skipped') { $result = 'SKIPPED' }
                else { $result = 'FAIL' }
            }
            'sslCert' {
                $hasCert = $text -match '(?i)Subject:|Issuer:|Public Key Algorithm:|SHA-256|MD5:|RSA Public Key'
                $hasError = $text -match '(?i)NSE failed|script error|error while executing|timed out|\[validation\] TIMEOUT'
                if ($exitCode -eq 0 -and $hasCert -and -not $hasError) { $result = 'PASS' }
                elseif ($portState -eq 'open') { $result = 'PARTIAL' }
                else { $result = 'FAIL' }
            }
        }
        $portResult[$spec.Key] = $result
    }
    $summary.ports["$p"] = $portResult
}

$summaryJson = Join-Path $OutputDirectory 'nmap-summary.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryJson -Encoding utf8
$summary | ConvertTo-Json -Depth 8