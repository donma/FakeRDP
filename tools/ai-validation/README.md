# AI Validation Harness

Automated build / protocol / scanner / credential / resource acceptance harness for FakeRDP.

## Files

```
tools/ai-validation/
├── run-validation.ps1          # main entry (19-step pipeline)
├── run-nmap.ps1                # per-port Nmap TCP / -sV / --version-all / rdp-enum-encryption / ssl-cert
├── wait-for-port.ps1           # poll TCP connect until a port is ready
├── parse-nmap.ps1              # parse a saved Nmap output file into structured JSON
├── runtime-config.json         # generated main test configuration (never edits config.json)
├── runtime-resource-config.json# generated resource-limit test configuration
├── runtime-cert-config.json    # generated certificate-persistence test configuration
└── results/                    # outputs (gitignored artifacts)
    ├── summary.json
    ├── validation-report.md
    ├── build.txt
    ├── dotnet-test.txt
    ├── fakerdp-stdout.txt
    ├── fakerdp-stderr.txt
    ├── <port>/native-probe.txt
    ├── <port>/nmap-*.txt
    └── ...
```

## Usage

```powershell
.\tools\ai-validation\run-validation.ps1 -Host 127.0.0.1 -Ports 4499,4500,13389
```

Parameters:

| Parameter | Default | Description |
|---|---|---|
| `-Host` / `-TargetHost` | `127.0.0.1` | Host to probe |
| `-Ports` | `4499,4500,13389` | Comma-separated test ports |
| `-RepoRoot` | repo root (auto) | FakeRDP repository root |
| `-ResultsDir` | `tools/ai-validation/results` | Output directory |

## Pipeline

1. Environment check (OS / .NET / Nmap / Git)
2. `dotnet clean`
3. `dotnet restore`
4. `dotnet build -c Release`
5. `dotnet test -c Release --no-build` (TRX totals) + regression executable
6. Port safety check (rejects 3389/3388/<1024; uses backup ports for occupied non-owned ports)
7. Start FakeRDP (process ID + stdout/stderr captured)
8. Wait for port readiness (max 15 s)
9. Native protocol probe (reuses `tools/scanner-test/run-tests.ps1`)
10. Nmap TCP scan
11. Nmap service detection (`-sV`)
12. Nmap full version detection (`--version-all`)
13. Nmap `rdp-enum-encryption`
14. Nmap `ssl-cert`
15. Credential regression (`--integration --mode standard|tls|nla`, synthetic credentials)
16. Resource regression (`maxConcurrentSessions=1`, 10 probes)
17. Stop FakeRDP (only PIDs started by this harness)
18. JSON report (`summary.json`)
19. Markdown report (`validation-report.md`)

## Policy

- Nmap results come only from real `nmap` output saved to `results/<port>/nmap-*.txt`.
- If Nmap is not installed, every Nmap check is `SKIPPED` and the overall result is `PARTIAL`; no output is faked.
- Native probes are reported as `nativeX224` / `nativeTls` / `nativeMcs`, never as third-party scanner detection.
- Credential tests use synthetic credentials only.
- The harness never kills a process it did not start unless that process is a FakeRDP instance started by a prior validation run.