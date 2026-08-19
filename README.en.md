# RDP Honeypot (Defensive RDP Honeypot)

A defensive RDP honeypot written in C#/.NET 10. Deploy it only on networks and hosts that you own or are explicitly authorized to monitor. It is designed to expose an RDP-like service to authorized scanners and record connection attempts for security analysis.

> **Important legal and security notice:** This project is for defensive security research and authorized monitoring only. Unauthorized interception or collection of login credentials may violate computer-use, privacy, and data-protection laws. Credential records may contain passwords and must be treated as sensitive data.
>
> Do not deploy this service on a production RDP host or port. Do not upload real credentials, real client data, private customer information, or production private keys to a public repository.

**Language:** [繁體中文 README](README.md) | **English**

---

## Features

- **Multiple listening ports:** Listen on multiple non-standard ports such as `4499, 4500, and 4501`.
- **RDP protocol fingerprint:** X.224 negotiation, TLS 1.2, MCS Connect Response, Erect Domain, Attach User, Channel Join, Security Exchange, and Info PDU handling.
- **Security modes:**
  - Standard RDP Security with RSA/RC4 support.
  - SSL/TLS with an RSA server certificate.
  - Partial NLA/CredSSP handling for NTLM Type 1/2/3 and account observation.
- **Credential telemetry:** Records source IP, source port, target port, username, password, domain, client cookie, timestamp, and session ID.
- **Resource protection:**
  - Global concurrent-session limit.
  - Per-IP and per-/24 limits.
  - Lightweight X.224 response when admission limits are reached.
  - Lazy session-directory creation.
  - TPKT and DER packet-size limits.
  - Per-stage timeout protection against slow clients.
  - Raw packet capture disabled by default.
- **Background event pipeline:** Credential events are sent to a bounded `Channel<T>` and written by a background recorder instead of making the network session wait for aggregate file I/O.
- **Server profiles:** Configure the simulated computer name, domain, supported security modes, certificate identity, response jitter, and disconnect behavior.
- **Profile consistency validation:** Startup rejects contradictory settings such as NLA without TLS, unimplemented Hybrid-Ex/RDSTLS, invalid certificate parameters, or mismatched certificate identity.
- **Structured protocol telemetry:** Session logs include requested/selected RDP protocols, cookies, TLS protocol/cipher suite, certificate thumbprint, and state transitions without exposing passwords by default.
- **Real-time console telemetry:** Credential events show source IP, source port, target port, username, domain, and password in the console; passwords are masked by default and may be explicitly enabled for authorized tests with `consoleCredentialMode=full`.
- **Console log level:** `consoleLogLevel` controls high-frequency console output with `None`, `Error`, `Credential`, `Connection`, `Protocol`, and `Debug`; session logs still retain protocol details.
- **Scanner compatibility harness:** PowerShell tools cover X.224, TLS, CredSSP challenge, MCS, multi-port probing, and resource-limit regression.
- **Automated regression executable:** `RdpHoneypot.Tests` covers protocol selection, RDP_NEG_FAILURE, certificate persistence, MCS builders, credential parsing, and resource limits (21/21 tests passing).
- **Synthetic credential integration:** `--integration --mode standard|tls|nla` verifies the Standard Security, TLS Info PDU, and NLA/NTLM credential-capture paths with synthetic credentials.
- **No production-system modification:** The program does not create Windows services, modify the registry, or change firewall rules.

---

## Requirements

- .NET SDK 10 or later.
- Windows 10/11 or Windows Server 2019 or later.
- Administrator rights are normally not required for the default high ports. Required permissions depend on the selected ports and local policy.
- Schannel-compatible Windows TLS support.

---

## Quick Start

### 1. Build

From the repository root:

```powershell
dotnet build -c Release
```

The executable is created at:

```text
bin\Release\net10.0\RdpHoneypot.exe
```

### 2. Copy the configuration next to the executable

```powershell
Copy-Item .\config.json .\bin\Release\net10.0\config.json -Force
```

The application loads `config.json` from the current working directory. When launching the executable, use the executable directory as the working directory, or provide `--config` explicitly.

### 3. Start the honeypot

```powershell
Set-Location .\bin\Release\net10.0
.\RdpHoneypot.exe
```

Or start it from the project root with an explicit configuration path:

```powershell
.\bin\Release\net10.0\RdpHoneypot.exe --config .\config.json
```

By default, logs are written beside the executable:

```text
bin\Release\net10.0\
```

### 4. Confirm that the ports are listening

```powershell
Get-NetTCPConnection -LocalPort 4499,4500,4501 -State Listen
```

For an authorized remote host:

```powershell
Test-NetConnection -ComputerName <AUTHORIZED_HOST> -Port 4499
```

---

## Authorized RDP Client Test

Use a test account and a test password only:

```powershell
mstsc /v:<AUTHORIZED_HOST>:4499
```

If Windows displays a self-signed certificate warning, verify the destination and continue only in the authorized test environment.

After the client sends a supported Info PDU, the honeypot:

1. Logs the protocol stages.
2. Displays a credential-capture event in the console.
3. Sends the event through the background recorder.
4. Writes the aggregate JSONL record and per-session credential file.
5. Applies the configured disconnect mode.

The honeypot does not provide a complete Windows desktop session.

---

## RDP Scanner Validation

Run scanners only against systems and ports that you own or are explicitly authorized to test.

Example with Nmap:

```powershell
nmap -Pn -p 4499 --script rdp-enum-encryption <AUTHORIZED_HOST>
```

A useful validation sequence is:

```text
TCP reachability
  -> X.224 Connection Confirm
  -> RDP negotiation response
  -> TLS server certificate
  -> MCS response
  -> security protocol information
```

A scanner identifying the service as RDP does not mean that a full Windows desktop or authentication subsystem is implemented. The project intentionally stops after the protocol stages needed for defensive observation.

See [`docs/scanner-compatibility.md`](docs/scanner-compatibility.md) for the scanner baseline, measured results, and limitations. The repeatable PowerShell harness is in [`tools/scanner-test/`](tools/scanner-test/). Run the protocol and resource regression executable with:

```powershell
dotnet run --project .\RdpHoneypot.Tests -c Release
```

Scanner harness:

```powershell
.\tools\scanner-test\run-tests.ps1 `
    -TargetHost 127.0.0.1 `
    -Port '4499,4500,13389' `
    -SkipNmap
```

If Nmap is installed, omit `-SkipNmap` to run:

```text
nmap -Pn -p PORT HOST
nmap -Pn -sV -p PORT HOST
nmap -Pn -sV --version-all -p PORT HOST
nmap -Pn -p PORT --script rdp-enum-encryption HOST
nmap -Pn -p PORT --script ssl-cert HOST
```

Results are written to `tools/scanner-test/results/scanner-result.json`. Checks that are unavailable or not executed are recorded as `NOT_RUN`, never as a false PASS.

Synthetic credential integration (synthetic credentials only; start the server first):

```powershell
dotnet bin\Release\net10.0\RdpHoneypot.dll --config .\config.json --port 13389

# Standard Security credential capture
dotnet run --project .\RdpHoneypot.Tests -c Release -- --integration `
    --mode standard --host 127.0.0.1 --port 13389 --log-dir .\bin\Release\net10.0\integration-test-logs

# TLS Info PDU credential capture
dotnet run --project .\RdpHoneypot.Tests -c Release -- --integration `
    --mode tls --host 127.0.0.1 --port 13389 --log-dir .\bin\Release\net10.0\integration-test-logs

# NLA / NTLM account capture
dotnet run --project .\RdpHoneypot.Tests -c Release -- --integration `
    --mode nla --host 127.0.0.1 --port 13389 --log-dir .\bin\Release\net10.0\integration-test-logs
```

Do not scan or lure unauthorized external systems.

---

## Command-Line Options

| Option | Description |
|---|---|
| `--config <path>` | Configuration file path. Default: `./config.json`. |
| `--port <p1,p2,...>` | Overrides the configured listening ports. |
| `--output <directory>` | Overrides the configured log directory. |
| `--help`, `-h` | Displays help. |

Examples:

```powershell
# Use config.json
RdpHoneypot.exe

# Use another configuration file
RdpHoneypot.exe --config .\configs\lab.json

# Override ports and output directory
RdpHoneypot.exe --port 4499,4500 --output D:\honeypot-logs
```

Port safeguards reject port `3389`, port `3388`, and ports below `1024`.

---

## Configuration

Current `config.json` example:

```json
{
  "ports": [4499, 4500, 4501],
  "maxConcurrentSessions": 2000,
  "maxConcurrentPerIp": 8,
  "maxConcurrentPerSubnet": 150,
  "maxPacketBytes": 262144,
  "maxRawCaptureBytesPerSession": 4194304,
  "x224TimeoutSeconds": 3,
  "tlsTimeoutSeconds": 5,
  "mcsTimeoutSeconds": 5,
  "credSspTimeoutSeconds": 10,
  "idleTimeoutSeconds": 20,
  "eventQueueCapacity": 100000,
  "enableRawCapture": false,
  "consoleCredentialMode": "full",
  "consoleLogLevel": "Credential",
  "logDir": null,
  "profile": {
    "computerName": "WIN-SRV01",
    "domainName": "WORKGROUP",
    "enableTls": true,
    "enableNla": true,
    "enableStandardSecurity": true,
    "enableHybridEx": false,
    "certificateSubject": "CN=WIN-SRV01",
    "certificatePath": "certs/test-rdp.pfx",
    "sanDnsNames": [],
    "rsaKeySize": 2048,
    "persistCertificate": true,
    "certificateLifetimeDays": 365,
    "certificateRenewalDays": 30,
    "responseDelayMinMs": 20,
    "responseDelayMaxMs": 120,
    "disconnectMode": "capture_and_close",
    "disconnectDelayMs": 0
  }
}
```

### Core options

| Field | Default | Description |
|---|---:|---|
| `ports` | `[4499,4500,4501]` | Listening ports. Port safeguards still apply. |
| `maxConcurrentSessions` | `2000` | Global deep-session limit. |
| `maxConcurrentPerIp` | `8` | Maximum deep sessions per source IP. |
| `maxConcurrentPerSubnet` | `150` | Maximum deep sessions per IPv4 /24. |
| `maxPacketBytes` | `262144` | Maximum DER/session packet size accepted by parsers. |
| `maxRawCaptureBytesPerSession` | `4194304` | Raw capture limit when enabled. |
| `x224TimeoutSeconds` | `3` | X.224 read timeout. |
| `tlsTimeoutSeconds` | `5` | TLS handshake timeout. |
| `mcsTimeoutSeconds` | `5` | MCS-stage timeout. |
| `credSspTimeoutSeconds` | `10` | Reserved CredSSP timeout setting. |
| `idleTimeoutSeconds` | `20` | Timeout for later idle stages. |
| `eventQueueCapacity` | `100000` | Bounded background event queue capacity. |
| `enableRawCapture` | `false` | Creates per-session `raw.bin` files when enabled. |
| `consoleCredentialMode` | `masked` | Console password display mode: `masked` by default; set to `full` only for authorized testing. |
| `consoleLogLevel` | `Credential` | Console verbosity: `None`, `Error`, `Credential`, `Connection`, `Protocol`, or `Debug`. |
| `logDir` | `null` | Output directory. `null` means the executable directory. |

### Profile options

| Field | Default | Description |
|---|---:|---|
| `computerName` | `WIN-SRV01` | Simulated computer name and default certificate SAN. |
| `domainName` | `WORKGROUP` | Simulated domain label. |
| `enableTls` | `true` | Accept TLS/SSL negotiation. |
| `enableNla` | `true` | Accept partial HYBRID/NLA negotiation. |
| `enableStandardSecurity` | `true` | Accept legacy requests without RDP negotiation. |
| `enableHybridEx` | `false` | Reserved for future Hybrid-Ex support; disabled by default. |
| `certificateSubject` | `CN=WIN-SRV01` | TLS certificate subject. |
| `certificatePath` | `certs/test-rdp.pfx` | PFX path; relative paths are resolved from the launch directory. |
| `sanDnsNames` | `[]` | Additional DNS SANs; `computerName` remains the primary SAN. |
| `rsaKeySize` | `2048` | Current implementation requires RSA 2048. |
| `persistCertificate` | `true` | Save or reuse the TLS PFX. |
| `certificateLifetimeDays` | `365` | Lifetime for a newly generated certificate. |
| `certificateRenewalDays` | `30` | Regenerate when the certificate is close to expiry. |
| `responseDelayMinMs` | `20` | Lower response jitter bound. |
| `responseDelayMaxMs` | `120` | Upper response jitter bound. |
| `disconnectMode` | `capture_and_close` | Post-capture connection behavior. |
| `disconnectDelayMs` | `0` | Delay before closing, from 0 to 10000 ms. |

> The repository `config.json` currently uses `consoleCredentialMode=full` for the authorized interactive test. Use `masked` for normal deployments; `full` should be limited to isolated, explicitly authorized testing.

### Disconnect modes

- `capture_and_close`: record the event and close the honeypot connection.
- `capture_and_graceful_close`: record the event, wait for `disconnectDelayMs`, then close normally.
- `shutdown_like`: use a delayed close sequence that resembles a server-side termination timing. It does not inject text into another host and cannot guarantee that `mstsc.exe` displays the exact localized message “The remote computer is shutting down.”

The text and error code shown by the Windows RDP client are selected by the client from the protocol state. The honeypot cannot force an arbitrary client UI string by sending plain text.

---

## Added Tests and Tools

This enhancement adds:

- `RdpProtocol.cs`: typed requested/selected protocol values and negotiation failure reasons.
- `RdpServerProfileValidator.cs`: startup validation for Profile, TLS/NLA capabilities, and certificate identity consistency.
- `RdpHoneypot.Tests/`: a .NET regression executable with no third-party test framework dependency.
- `RdpHoneypot.Tests/IntegrationRunner.cs`: synthetic credential-capture integration covering Standard Security, TLS Info PDU, and NLA/NTLM (`--mode standard|tls|nla`).
- `docs/scanner-compatibility.md`: scanner baseline, measured results, and limitations.
- `tools/scanner-test/run-tests.ps1`: TCP, X.224, TLS, CredSSP, MCS, and optional Nmap probes.
- `tools/scanner-test/resource-regression.ps1`: global session-limit and lightweight X.224 response test; writes JSON results to `tools/scanner-test/results/resource-result.json`.
- `FakeRDP.slnx`: solution file including the main project and test project; `dotnet build/test FakeRDP.slnx -c Release` builds and runs everything at once.

Run the local regression suite:

```powershell
dotnet build -c Release
dotnet run --project .\RdpHoneypot.Tests -c Release
```

### Latest Validation Status (2026-08-19)

Local validation on `127.0.0.1` (Nmap is not installed, so Nmap checks are marked SKIPPED):

| Check | Result |
|---|---|
| `dotnet build FakeRDP.slnx -c Release` | PASS (0 warnings / 0 errors) |
| `dotnet test FakeRDP.slnx -c Release` | PASS (21/21 tests passing) |
| Standard Security integration (synthetic credentials) | PASS (credential written to `captured_creds.jsonl`) |
| TLS Info PDU integration (synthetic credentials) | PASS |
| NLA / NTLM account integration (synthetic credentials) | PASS (account written to `nla_accounts.jsonl`) |
| Scanner harness (4499 / 4500 / 13389) | PASS (tcp, x224, rdpDetected, tls, certificate, nla, mcs all true) |
| Resource regression (13390, 10 probes) | PASS (sessionLimit / lightweightX224 / sessionDirectoryBounded all true) |
| Live scanner capture (4499) | PASS (`192.168.121.153` sent `testaccount:123`, captured and shown in the console) |

---

## Logs and Credential Records

Default output directory:

```text
bin\Release\net10.0\
├── honeypot.log
├── captured_creds.jsonl
├── nla_accounts.jsonl
├── certs\test-rdp.pfx         # public test PFX; contains a test private key
└── session_000001\
    ├── session.log
    ├── credential.json
    ├── nla_credential.json
    └── raw.bin                 # only when enableRawCapture=true
```

`captured_creds.jsonl` contains one compact JSON object per line. Example values below are synthetic:

```json
{"session_id":42,"timestamp":"2026-01-01T00:00:00Z","source_ip":"10.0.0.100","source_port":55000,"target_port":4499,"username":"test-user","password":"example-password","domain":"WORKGROUP","client_info":"cookie='Cookie: mstshash=test-user'"}
```

Read the latest record in PowerShell:

```powershell
Get-Content .\captured_creds.jsonl | Select-Object -Last 1
```

Read the latest session:

```powershell
$latest = Get-ChildItem .\session_* -Directory |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Get-Content "$($latest.FullName)\session.log"
Get-Content "$($latest.FullName)\credential.json"
```

NLA account observations are written to:

```text
nla_accounts.jsonl
```

An NTLM Type 3 message proves that a client sent an authentication attempt. It does not prove that an external Windows domain controller validated the account.

### Sensitive-file handling

- Restrict access to `captured_creds.jsonl`, `nla_accounts.jsonl`, session directories, and `raw.bin`.
- Do not commit these files to Git.
- `certs/test-rdp.pfx` is intentionally included as a public test certificate and contains a private key. Anyone can use it to impersonate the test service; use it only in an isolated lab.
- For production or customer deployments, delete the test PFX, configure a deployment-specific certificate, and add that PFX to `.gitignore`.
- Disable raw capture after protocol analysis.
- Delete or encrypt test records according to the customer’s retention policy.

---

## Troubleshooting

### The port is not reachable

Check all of the following:

1. The process is running.
2. `config.json` is in the working directory used to start the process.
3. Windows Firewall and any upstream firewall allow the selected test port.
4. The target host is reachable from the authorized test machine.
5. The port is not blocked by another process.

### mstsc shows a certificate warning

The default certificate is self-signed. Confirm the destination and continue only in the isolated test environment. Do not install or trust the certificate globally unless that is an explicit, controlled test requirement.

### mstsc disconnects before credential capture

Modern clients normally prefer NLA/CredSSP. The honeypot has partial CredSSP support. If the client rejects the SPNEGO exchange, it may disconnect after the NTLM account message. The TLS/Info-PDU path is the primary tested credential-observation path.

### A scanner sees an open port but not RDP

Confirm that the scanner can receive the X.224 response and that the selected profile enables the protocol requested by the scanner. Use a packet capture only in an authorized lab.

---

## Architecture

```text
HoneypotServer
  └─ RdpSession state machine
       ├─ X224Handler
       ├─ TLS / profile negotiation
       ├─ McsHandler
       ├─ StandardSecurityHandler
       ├─ CredSspHandler
       └─ EventRecorder (bounded Channel<T>)
```

The service intentionally does not implement a complete Windows desktop, graphics pipeline, or Windows authentication subsystem.

---

## Security and Legal Guidance

- Deploy only in an isolated or controlled honeypot segment.
- Do not use the production RDP port `3389`.
- Do not forward captured credentials to a real authentication service.
- Do not scan or lure unauthorized systems.
- Treat all remote input as untrusted and keep parser limits enabled.
- Use customer-approved retention, access control, and incident-response procedures.

---

## References

- [MS-RDPBCGR: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [MS-NLMP: NT LAN Manager Authentication Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [MS-CSSP: Credential Security Support Provider Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)
