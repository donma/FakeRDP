# RDP Honeypot (Defensive RDP Honeypot)

A defensive RDP honeypot written in C# / .NET 10. Deploy it only on networks and hosts that you own or are explicitly authorized to monitor. It exposes an RDP-like service on non-standard ports and records **source IP, username, password, domain, and metadata** from connection attempts.

> **Important legal notice:** This project is for defensive security research and authorized monitoring only. Unauthorized interception of login credentials may violate computer-use, privacy, and data-protection laws. Credential records are sensitive — restrict access, encrypt the disk, and clean periodically.

**Language:** [繁體中文 README](README.md) | **English**

---

## Features

- **Multi-port listening** — Listen on multiple non-standard ports (e.g., `4499, 4500, 4501`) to simulate multiple targets
- **Three security modes** — Standard RDP Security (RSA/RC4), SSL/TLS (TLS 1.2 + ECDHE), NLA/CredSSP (NTLM account/domain capture)
- **Full credential capture** — Records source IP (from the actual TCP socket peer), source port, target port, username, password, domain, cookie, and timestamp
- **Real-time console alerts** — Red-highlighted credential capture events with optional password masking (`consoleCredentialMode`)
- **Protocol telemetry** — TLS cipher suite, certificate thumbprint, negotiation state, and state transitions logged per session
- **Resource protection** — Global session limit, per-IP / per-/24 limits; overloaded connections receive a lightweight X.224 response only
- **Credential safety** — Credential events are never silently dropped (`CredentialEventsDropped = 0`); a dedicated `CompleteAsync` drain guarantees persistence on shutdown, verified by a 50-round race test
- **Zero system intrusion** — Does not modify Windows services, firewall rules, or the registry; rejects ports below 1024
- **Automated validation** — 30/30 unit tests + integration tests (standard/tls/nla) + AI validation harness

---

## Quick Start

### 1. Build

```bash
cd RdpHoneypot
dotnet build -c Release
```

### 2. Run

```bash
bin\Release\net10.0\RdpHoneypot.exe --port 4499,4500,4501
```

Or with a configuration file:

```bash
bin\Release\net10.0\RdpHoneypot.exe --config config.json
```

### 3. Test with mstsc

```bash
mstsc /v:<SERVER_IP>:4499
```

Enter any test credentials. The honeypot will display the captured values in the console and write them to `captured_creds.jsonl`.

### 4. Scanner verification

```bash
nmap -Pn -sV -p 4499 <AUTHORIZED_HOST>
```

Expected output: `4499/tcp open  ms-wbt-server xrdp`.

---

## Command-Line Options

| Option | Description |
|---|---|
| `--config <path>` | Configuration file path (default: `./config.json`) |
| `--port <p1,p2,...>` | Override listening ports |
| `--output <dir>` | Override log directory |
| `--help` / `-h` | Show help |

---

## Configuration

```json
{
  "ports": [4499, 4500, 4501],
  "maxConcurrentSessions": 2000,
  "maxConcurrentPerIp": 8,
  "enableRawCapture": false,
  "consoleCredentialMode": "masked",
  "consoleLogLevel": "Credential",
  "logDir": null,
  "profile": {
    "computerName": "WIN-SRV01",
    "domainName": "WORKGROUP",
    "enableTls": true,
    "enableNla": true,
    "enableStandardSecurity": true,
    "certificatePath": "certs/test-rdp.pfx",
    "rsaKeySize": 2048,
    "persistCertificate": true,
    "disconnectMode": "capture_and_close"
  }
}
```

Port `3389` and ports below `1024` are rejected for safety.

---

## Log Structure

```
<logDir>
├── captured_creds.jsonl          # All captured credentials (JSONL)
├── nla_accounts.jsonl            # NLA account records
├── session_000001/
│   ├── session.log               # Protocol stage text log
│   ├── credential.json           # Standard/TLS credential (if captured)
│   ├── nla_credential.json       # NLA credential (if captured)
│   └── raw.bin                   # Raw packet data (enableRawCapture=true)
├── honeypot.log                  # Start/stop log
└── certs/test-rdp.pfx            # Public test certificate (lab use only)
```

---

## Architecture

```
Attacker (mstsc / scanner) ──TCP──▶ RdpHoneypot.exe
                                    │
                                    ├─ Multi-port parallel listener
                                    │
                                    └─ Per-connection: RdpSession state machine
                                         ├─ X.224 negotiation (RDP_NEG_REQ / RSP)
                                         ├─ (Optional) TLS 1.2 handshake
                                         ├─ (Optional) NLA/CredSSP: NTLM Type 1/2/3
                                         ├─ MCS Connect / Erect / Attach / Channel Join
                                         ├─ Security Exchange (standard security)
                                         └─ Info PDU → credential parse → EventRecorder → JSONL
```

### Credential Flow

```
RdpSession (immutable metadata: SessionId, SourceIp, SourcePort, TargetPort)
    ↓
SaveCredentialAsync
    ↓
TryWriteCredentialAsync (bounded 2s timeout, never silently dropped)
    ↓
EventRecorder (dedicated channel, FullMode.Wait)
    ↓
captured_creds.jsonl / nla_accounts.jsonl / per-session credential.json
```

---

## Security & Legal

- **Authorized environment only** — Isolated lab segment or DMZ honeypot zone
- **Source IP** — Taken from the actual TCP socket peer; never trusts `X-Forwarded-For` or client-provided headers
- **Console masking** — Passwords are displayed as `********` by default; the full value is always preserved in the event
- **Firewall** — Restrict incoming access to the honeypot ports to expected sources only
- **Data retention** — Review and purge credential records per your organization's retention policy
- **Test certificate** — `certs/test-rdp.pfx` is a public test certificate containing a private key; use only in an isolated lab

---

## Limitations

| Limitation | Description |
|---|---|
| NLA password not captured | Modern mstsc rejects SPNEGO accept due to mechListMIC validation; only account/domain is obtained |
| Schannel-dependent TLS | Non-Windows platforms may behave differently |
| No desktop session | The honeypot stops after the authentication phase; no full RDP desktop |
| Self-signed certificate | Clients will see a certificate warning |

---

## References

- [MS-RDPBCGR: Remote Desktop Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [MS-NLMP: NT LAN Manager (NTLM) Authentication Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [MS-CSSP: CredSSP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)
- [pyRDP](https://github.com/GoSecure/pyrdp) (Python RDP honeypot, conceptual reference)