# FakeRDP Scanner Compatibility

This document records the scanner compatibility baseline and the checks run for the current FakeRDP build. Tests are restricted to the local authorized test service.

## Environment

| Field | Value |
|---|---|
| FakeRDP commit | `67ba002` baseline before this validation round |
| .NET SDK | `10.0.202` |
| OS | Windows 10 build 22000 |
| Nmap | `SKIPPED - NMAP NOT INSTALLED` |
| FreeRDP | `SKIPPED - FREERDP NOT INSTALLED` |
| mstsc | `C:\\Windows\\System32\\mstsc.exe` available; manual interaction required |
| Test date | 2026-08-18 |

## Scope and limitations

FakeRDP is an RDP protocol honeypot, not a Windows desktop or authentication service. It intentionally implements the protocol stages needed for defensive observation and credential telemetry. A scanner identifying RDP does not imply that a full desktop session is available.

The test host used for the local checks was `127.0.0.1`. The accepted service ports were `4499`, `4500`, and `4501`; port `3389` remains reserved for a real Windows RDP service and is rejected by the application.

## Commands

For each authorized target and port, run:

```text
nmap -Pn -p PORT HOST
nmap -Pn -sV -p PORT HOST
nmap -Pn -sV --version-all -p PORT HOST
nmap -Pn -p PORT --script rdp-enum-encryption HOST
nmap -Pn -p PORT --script ssl-cert HOST
```

The repository harness runs the same commands when `nmap.exe` is available:

```powershell
.\tools\scanner-test\run-tests.ps1 -TargetHost 127.0.0.1 -Port '4499,4500,13389'
```

Use `-SkipNmap` only when Nmap is unavailable. Results are written to `tools/scanner-test/results/scanner-result.json`, which is intentionally ignored by Git because it is a local test artifact. Raw command output is saved per port under:

```text
tools/scanner-test/results/port-4499/
├── tcp.txt
├── service-version.txt
├── service-version-all.txt
├── rdp-enum-encryption.txt
└── ssl-cert.txt
```

When Nmap is unavailable, each file contains `SKIPPED - NMAP NOT INSTALLED`; no fake scanner result is generated.

## Baseline recorded before protocol changes

| Test | Port | Result | Evidence / limitation |
|---|---:|---|---|
| TCP reachability | 4499 | PASS | Local listener accepted TCP. |
| X.224 negotiation | 4499 | PASS | 19-byte RDP negotiation probe received X.224 CC. |
| TCP reachability | 4500 | PASS | Local listener accepted TCP. |
| X.224 negotiation | 4500 | PASS | Same ordinary protocol probe received X.224 CC. |
| TCP reachability | 4501 | PASS | Local listener accepted TCP. |
| X.224 negotiation | 4501 | PASS | Same ordinary protocol probe received X.224 CC. |
| TLS handshake | 4499/4500/4501 | PASS | Local Schannel client completed TLS 1.2 in the manual probe. |
| Certificate present | 4499/4500/4501 | PASS | Server presented the persistent test PFX certificate. |
| NLA selected | 4499/4500/4501 | PASS | Requesting SSL + HYBRID selected HYBRID. |
| MCS | 4499/4500/4501 | NOT RUN | Requires a full RDP client or an MCS test vector; the local baseline harness did not claim this result. |
| Credential regression | 4499/4500/4501 | NOT RUN | Requires an authorized mstsc/standard-security test vector with synthetic credentials. |
| Nmap `-sV` | all | NOT RUN | `nmap.exe` was not installed on the test host. |
| Nmap `rdp-enum-encryption` | all | NOT RUN | `nmap.exe` was not installed on the test host. |
| Nmap `ssl-cert` | all | NOT RUN | `nmap.exe` was not installed on the test host. |
| mstsc | 4499 | NOT RUN | `mstsc.exe` exists, but no interactive client credentials were entered in this automated run. |
| Standard Security credential integration | 13389 | PASS | Synthetic domain/user/password reached `captured_creds.jsonl`; target port was 13389. |
| Certificate restart #1/#2/#3 | 13389 | PASS | Thumbprint remained `39A6A9CF0FFA8E85CE99B6BD6524A1B31F79809F` across three restarts. |
| Global resource limit | 13390 | PASS | `maxConcurrentSessions=1`, ten X.224 probes, one deep session directory. |

The baseline intentionally distinguishes protocol evidence from unavailable external-tool evidence. It must not be reported as an Nmap PASS without actually running Nmap.

## Current compatibility results

The local PowerShell harness was run after the changes with:

```powershell
.\tools\scanner-test\run-tests.ps1 -TargetHost 127.0.0.1 -Port '4499,4500,13389' -SkipNmap
```

All three configured non-standard ports completed the native protocol probe:

| Test | 4499 | 4500 | 13389 |
|---|---|---|---|
| TCP | PASS | PASS | PASS |
| X.224 / RDP detection | PASS | PASS | PASS |
| TLS 1.2 / certificate | PASS | PASS | PASS |
| CredSSP challenge | PASS | PASS | PASS |
| MCS probe | PASS | PASS | PASS |
| Nmap commands | SKIPPED - NMAP NOT INSTALLED | SKIPPED - NMAP NOT INSTALLED | SKIPPED - NMAP NOT INSTALLED |

Raw command result files were written under `tools/scanner-test/results/port-4499/`, `port-4500/`, and `port-13389/`.

Nmap was not installed on the test host, so no Nmap service-name claim is made. The harness JSON recorded native TCP, X.224, TLS, certificate, NLA, and MCS probe results for all three local ports. `credentialRegression` remains false in the scanner harness because it does not fabricate or store credentials; credential capture is verified by the dedicated integration runner below.

## Current compatibility checks

The local `RdpHoneypot.Tests` executable covers:

- Standard, SSL, HYBRID, disabled HYBRID_EX, malformed/unsupported negotiation decisions.
- Typed RDP negotiation failure responses.
- X.224 cookie and `mstshash` telemetry parsing.
- TPKT/MCS response length consistency.
- Named MCS Attach User and Channel Join response builders.
- Standard credential parser regression with synthetic domain, username, and password.
- Certificate persistence, RSA 2048, subject/SAN and Server Authentication EKU validation.
- Global session admission, per-IP admission and release behavior.
- Max packet length rejection.

The global resource regression was also run with `maxConcurrentSessions=1` and ten probes. Result: **PASS** — all probes received a lightweight X.224 response and only one deep session directory was created.

Run it with:

```powershell
dotnet run --project .\RdpHoneypot.Tests -c Release
```

## PASS / PARTIAL / FAIL

- **PASS**: the protocol probe completed the relevant stage, such as X.224 negotiation, TLS, or MCS/security capability response.
- **PARTIAL**: the scanner completed earlier stages but stopped at a later stage; record the last state instead of calling the entire test a failure.
- **FAIL**: malformed response, immediate reset, timeout, unhandled exception, or other protocol failure.

## mstsc Regression Record

`mstsc.exe` was verified interactively by the operator in an authorized lab (not automated by this harness). Result:

```text
mstsc = MANUAL PASS
```

## AI Validation Record (2026-08-19)

Executed with `tools/ai-validation/run-validation.ps1` on `127.0.0.1` (ports 4499, 4500, 13389). Raw evidence is under `tools/ai-validation/results/`.

| Field | Value |
|---|---|
| Git commit | `77626be` (master) |
| OS / Architecture | Windows 10 2009 (22000) / x64 |
| .NET SDK | 10.0.202 |
| Nmap | 7.991 (available; Npcap not installed → connect() mode) |
| Date | 2026-08-19 |
| Ports | 4499, 4500, 13389 |

| Port | TCP | Native X.224 | Native TLS | Native Cert | Native MCS | Native NLA | Nmap -sV | Nmap --version-all | rdp-enum-encryption | ssl-cert |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4499 | PASS | PASS | PASS | PASS | PASS | PASS | PASS (`ms-wbt-server xrdp`) | PASS | FAIL (NSE timeout) | PARTIAL |
| 4500 | PASS | PASS | PASS | PASS | PASS | PASS | PASS (`ms-wbt-server xrdp`) | PASS | FAIL (NSE timeout) | PARTIAL |
| 13389 | PASS | PASS | PASS | PASS | PASS | PASS | PASS (`ms-wbt-server xrdp`) | PASS | FAIL (NSE timeout) | PARTIAL |

Raw Nmap output: `tools/ai-validation/results/<port>/nmap-service.txt`, `nmap-version-all.txt`, `nmap-rdp-enum-encryption.txt`, `nmap-ssl-cert.txt`.

Notes:
- **Nmap Service Detection and `--version-all` identify the service as RDP (`ms-wbt-server`) on all three non-standard ports** — the primary third-party scanner acceptance evidence.
- **rdp-enum-encryption**: the NSE script did not complete within the bounded validation run on this host (Nmap 7.991 in connect() mode without Npcap). The packet trace in the raw evidence shows the server returns valid RDP_NEG_RSP (`selectedProtocol=1` for SSL, `2` for CredSSP/NLA) and valid MCS Connect Responses, so the protocol responses are correct; the script execution is slow in this environment. Re-run on a host with Npcap for a full result.
- **ssl-cert** is PARTIAL because RDP requires an X.224 negotiation before TLS, so the certificate cannot be read directly on a non-standard port; the certificate is instead verified by the native TLS probe (`nativeTls` / `nativeCertificate` = PASS), reported separately from `NmapSslCert`.

Other automated results in `summary.json` / `validation-report.md`:
- Build: PASS. Unit tests: 21/21 PASS. Regression executable: PASS.
- Credential regression: PASS (standard / TLS / NLA with synthetic credentials).
- Resource regression: PASS. Certificate persistence: PASS (thumbprint stable across 3 restarts).
- Overall: **PARTIAL** (all locally verifiable checks and Nmap Service Detection pass; rdp-enum-encryption could not be completed on this host, so per policy it is not reported as PASS).

## Credential Capture Regression

| Mode | Source IP | Username | Password | Domain | Auth Mode | Result |
|---|---|---|---|---|---|---|
| Standard Security | PASS (`127.0.0.1`) | PASS (`test-standard-user`) | PASS (`Standard-Pass-123!`) | PASS (`TESTDOMAIN`) | `standard` | **PASS** |
| TLS Info PDU | PASS (`127.0.0.1`) | PASS (`test-tls-user`) | PASS (`TLS-Pass-123!`) | PASS (`TESTDOMAIN`) | `tls` | **PASS** |
| NLA / NTLM | PASS (`127.0.0.1`) | PASS (`test-nla-user`) | N/A (null) | PASS (`TESTDOMAIN`) | `nla` | **PASS** |

All credential events include the unified schema (§3): `event: "credential_captured"`, `auth_mode`, `requested_protocol`, `selected_protocol`, `cookie`, `computer_name`. Password is `null` for NLA paths where the client does not provide plaintext TSCredentials. Console masking (`consoleCredentialMode: masked`) replaces the password with `********` but does not alter the stored event. `CredentialEventsDropped` counters are verified to be `0`.

## FreeRDP Regression Record

```text
SKIPPED - FREERDP NOT INSTALLED
```

## Interpretation

- A successful X.224 response on a non-standard port demonstrates protocol behavior independent of port 3389.
- TLS is advertised only when the profile can actually establish TLS 1.2.
- HYBRID/NLA is selected only when both NLA and TLS are enabled.
- HYBRID_EX and RDSTLS are not selected because they are not implemented.
- Resource limits remain active. Connections rejected by admission control receive only the lightweight X.224 response and do not create deep session directories.
- Credential records and any raw captures are sensitive. Use synthetic credentials in tests and clean test output afterward.
