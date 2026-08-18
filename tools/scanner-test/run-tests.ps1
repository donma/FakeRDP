[CmdletBinding()]
param(
    [Alias('Host')]
    [string]$TargetHost = '127.0.0.1',
    [object[]]$Port = @(4499),
    [string]$OutputDirectory,
    [switch]$SkipNmap
)

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'results'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

function Read-Exact {
    param([System.IO.Stream]$Stream, [int]$Count, [int]$TimeoutMs = 5000)
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $readTask = $Stream.ReadAsync($buffer, $offset, $Count - $offset)
        if (-not $readTask.Wait($TimeoutMs)) { throw "read timeout" }
        $read = $readTask.Result
        if ($read -eq 0) { throw "connection closed" }
        $offset += $read
    }
    return $buffer
}

function Write-Tpkt {
    param([System.IO.Stream]$Stream, [byte[]]$Payload)
    $length = 4 + $Payload.Length
    [byte[]]$packet = @(
        0x03, 0x00, [byte]($length -shr 8), [byte]$length
    ) + $Payload
    $Stream.Write($packet, 0, $packet.Length)
}

function Read-Tpkt {
    param([System.IO.Stream]$Stream)
    $header = Read-Exact $Stream 4
    $responseLength = ($header[2] -shl 8) -bor $header[3]
    if ($responseLength -lt 4 -or $responseLength -gt 262144) { throw "invalid TPKT response length $responseLength" }
    return [byte[]]($header + (Read-Exact $Stream ($responseLength - 4)))
}

function Send-Tpkt {
    param([System.IO.Stream]$Stream, [byte[]]$Payload)
    Write-Tpkt $Stream $Payload
    return Read-Tpkt $Stream
}

function Build-Der {
    param([byte]$Tag, [byte[]]$Content)
    if ($Content.Length -lt 128) {
        return [byte[]]($Tag, [byte]$Content.Length) + $Content
    }
    return [byte[]]($Tag, 0x82, [byte]($Content.Length -shr 8), [byte]$Content.Length) + $Content
}

function Read-DerMessage {
    param([System.IO.Stream]$Stream)
    $first = Read-Exact $Stream 2
    if ($first[0] -ne 0x30) { throw 'CredSSP response is not DER SEQUENCE' }
    $length = $first[1]
    $lengthBytes = @()
    if (($length -band 0x80) -ne 0) {
        $count = $length -band 0x7F
        if ($count -lt 1 -or $count -gt 2) { throw 'Unsupported DER length' }
        $lengthBytes = Read-Exact $Stream $count
        $length = 0
        foreach ($b in $lengthBytes) { $length = ($length -shl 8) -bor $b }
    }
    return [byte[]]($first + $lengthBytes + (Read-Exact $Stream $length))
}

function Test-CredSspChallenge {
    param([System.Net.Security.SslStream]$Stream)
    [byte[]]$ntlmType1 = @(
        0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00,
        0x01,0x00,0x00,0x00,
        0xB2,0x88,0x02,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    )
    $version = Build-Der 0xA0 ([byte[]](0x02,0x01,0x05))
    $token = Build-Der 0xA1 (Build-Der 0x04 $ntlmType1)
    $request = Build-Der 0x30 ($version + $token)
    $Stream.Write($request, 0, $request.Length)
    $response = Read-DerMessage $Stream
    for ($i = 0; $i -le $response.Length - 12; $i++) {
        if ($response[$i] -eq 0x4E -and $response[$i + 1] -eq 0x54 -and
            $response[$i + 8] -eq 0x02) { return $true }
    }
    return $false
}

function Test-McsTls {
    param([string]$TargetHost, [int]$TargetPort)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($TargetHost, $TargetPort)
        if (-not $connect.Wait(3000)) { throw 'MCS TCP connect timeout' }
        $raw = $client.GetStream()
        $negotiation = Send-X224Probe $raw 0x01
        if ($negotiation.SelectedProtocol -ne 0x01) { return $false }
        $callback = [System.Net.Security.RemoteCertificateValidationCallback]{ param($sender, $certificate, $chain, $errors) $true }
        $ssl = [System.Net.Security.SslStream]::new($raw, $false, $callback)
        $ssl.AuthenticateAsClient($TargetHost, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        if (-not $ssl.IsAuthenticated) { return $false }

        # Minimal ordinary MCS sequence used only to verify the server's named
        # response builders: Connect Initial, Erect Domain, Attach User, Join Global.
        $connectResponse = Send-Tpkt $ssl ([byte[]](0x02,0xF0,0x80,0x7F,0x65,0x00))
        if ($connectResponse.Length -lt 12 -or $connectResponse[0] -ne 0x03) { return $false }
        Write-Tpkt $ssl ([byte[]](0x02,0xF0,0x80,0x04,0x00,0x00,0x00,0x00))
        $attachResponse = Send-Tpkt $ssl ([byte[]](0x02,0xF0,0x80,0x28,0x00,0x00,0x03,0xEA))
        if ($attachResponse.Length -lt 11 -or $attachResponse[7] -ne 0x2E) { return $false }
        $joinResponse = Send-Tpkt $ssl ([byte[]](0x02,0xF0,0x80,0x38,0x00,0x00,0x03,0xEB))
        return $joinResponse.Length -ge 15 -and $joinResponse[7] -eq 0x3E
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Send-X224Probe {
    param([System.Net.Sockets.NetworkStream]$Stream, [uint32]$RequestedProtocols)
    [byte[]]$probe = @(
        0x03, 0x00, 0x00, 0x13,
        0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00,
        [byte]$RequestedProtocols,
        [byte]($RequestedProtocols -shr 8),
        [byte]($RequestedProtocols -shr 16),
        [byte]($RequestedProtocols -shr 24)
    )
    $Stream.Write($probe, 0, $probe.Length)
    $header = Read-Exact $Stream 4
    $length = ($header[2] -shl 8) -bor $header[3]
    if ($length -lt 4 -or $length -gt 262144) { throw "invalid TPKT length $length" }
    $body = Read-Exact $Stream ($length - 4)
    [byte[]]$response = $header + $body
    $selected = 0
    $isFailure = $false
    if ($response.Length -ge 19 -and $response[11] -eq 0x03) { $isFailure = $true }
    if ($response.Length -ge 19 -and $response[11] -eq 0x02) {
        $selected = [uint32]($response[15] -bor ($response[16] -shl 8) -bor ($response[17] -shl 16) -bor ($response[18] -shl 24))
    }
    return [pscustomobject]@{
        Response = $response
        SelectedProtocol = $selected
        Failure = $isFailure
    }
}

function Test-Port {
    param([string]$TargetHost, [int]$TargetPort)
    $result = [ordered]@{
        port = $TargetPort
        tcp = $false
        x224 = $false
        rdpDetected = $false
        tls = $false
        certificate = $false
        nla = $false
        mcs = $false
        credentialRegression = $false
        nmap = @{}
        error = $null
    }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($TargetHost, $TargetPort)
        if (-not $connect.Wait(3000)) { throw 'TCP connect timeout' }
        $result.tcp = $true
        $stream = $client.GetStream()
        $negotiation = Send-X224Probe $stream 0x03
        $result.x224 = $negotiation.Response.Length -ge 19 -and -not $negotiation.Failure
        $result.rdpDetected = $result.x224
        $result.nla = $negotiation.SelectedProtocol -eq 0x02
        if ($negotiation.SelectedProtocol -in @(0x01, 0x02)) {
            $callback = [System.Net.Security.RemoteCertificateValidationCallback]{ param($sender, $certificate, $chain, $errors) $true }
            $ssl = [System.Net.Security.SslStream]::new($stream, $false, $callback)
            $ssl.AuthenticateAsClient($TargetHost, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            $result.tls = $ssl.IsAuthenticated
            $result.certificate = $ssl.RemoteCertificate -ne $null
            if ($negotiation.SelectedProtocol -eq 0x02) {
                $result.nla = Test-CredSspChallenge $ssl
            }
            $ssl.Dispose()
        }
        $result.mcs = Test-McsTls -TargetHost $TargetHost -TargetPort $TargetPort
    }
    catch {
        $result.error = $_.Exception.Message
    }
    finally {
        $client.Dispose()
    }

    if (-not $SkipNmap -and (Get-Command nmap -ErrorAction SilentlyContinue)) {
        $nmapResults = [ordered]@{}
        foreach ($arguments in @(
            @('-Pn', '-p', "$TargetPort", $TargetHost),
            @('-Pn', '-sV', '-p', "$TargetPort", $TargetHost),
            @('-Pn', '-sV', '--version-all', '-p', "$TargetPort", $TargetHost),
            @('-Pn', '-p', "$TargetPort", '--script', 'rdp-enum-encryption', $TargetHost),
            @('-Pn', '-p', "$TargetPort", '--script', 'ssl-cert', $TargetHost)
        )) {
            $key = ($arguments -join ' ').Replace(' ', '_').Replace('--', '')
            $nmapResults[$key] = (& nmap @arguments 2>&1 | Out-String).Trim()
        }
        $result.nmap = $nmapResults
    }
    else {
        $result.nmap = @{ status = 'NOT_RUN'; reason = 'nmap executable not installed or SkipNmap was specified' }
    }
    return [pscustomobject]$result
}

$portValues = foreach ($entry in $Port) {
    foreach ($value in ([string]$entry).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        [int]$value.Trim()
    }
}
$results = foreach ($p in $portValues) {
    Write-Host "Testing $TargetHost`:$p"
    Test-Port -TargetHost $TargetHost -TargetPort $p
}

$output = [ordered]@{
    generatedAt = [DateTime]::UtcNow.ToString('O')
    host = $TargetHost
    results = @($results)
}
$jsonPath = Join-Path $OutputDirectory 'scanner-result.json'
$output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding utf8
$results | Format-Table port,tcp,x224,rdpDetected,tls,certificate,nla,mcs,credentialRegression,error
Write-Host "Result: $jsonPath"
