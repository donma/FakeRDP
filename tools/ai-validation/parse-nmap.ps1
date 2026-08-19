[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [int]$Port,
    [string]$TargetHost = '127.0.0.1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Nmap output file not found: $Path"
}

$text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop

$result = [ordered]@{
    file = $Path
    host = $TargetHost
    port = $Port
    portState = 'unknown'
    service = ''
    version = ''
    scriptSections = @()
    errors = @()
    rawHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# 1) Port state line, e.g. "4499/tcp open  ms-wbt-server  Microsoft Terminal Services"
$portLine = [regex]::Match($text, '(?m)^\s*' + [regex]::Escape("$Port") + '/tcp\s+(\w+)(?:\s+([^\s]+))?(?:\s+(.*))?$')
if ($portLine.Success) {
    $result.portState = $portLine.Groups[1].Value
    if ($portLine.Groups[2].Success) { $result.service = $portLine.Groups[2].Value }
    if ($portLine.Groups[3].Success) { $result.version = $portLine.Groups[3].Value.Trim() }
}

# 2) Service family fallback when the state line does not carry a product name
if (-not $result.service) {
    $family = [regex]::Match($text, '(?im)^\|?\s*(ms-wbt-server|Microsoft\s+Terminal\s+Services|Remote\s+Desktop|Terminal\s+Services)\b')
    if ($family.Success) { $result.service = $family.Groups[1].Value }
}

# 3) Script section lines (NSE script blocks such as rdp-enum-encryption, ssl-cert)
$scriptLines = [System.Collections.Generic.List[object]]::new()
foreach ($m in [regex]::Matches($text, '(?im)^\s*\|?\s*([_a-z0-9\-]+):\s*(.+)$')) {
    $name = $m.Groups[1].Value.Trim()
    if ($name -match '(?i)rdp|ssl|cert|script|nse|http|smb') {
        $scriptLines.Add([pscustomobject]@{ name = $name; value = $m.Groups[2].Value.Trim() })
    }
}
$result.scriptSections = @($scriptLines)

# 4) Error indicators
$errorMatches = [regex]::Matches($text, '(?i)(NSE failed|script error|error while executing|timed out|timeout|connection refused|closed|tcpwrapped)')
$errors = @($errorMatches | ForEach-Object { $_.Value } | Select-Object -Unique)
$result.errors = $errors

$result | ConvertTo-Json -Depth 6