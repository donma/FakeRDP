# FakeRDP Scanner Compatibility Harness

Use this harness only against a FakeRDP instance that you own or are explicitly authorized to test.

## Run

From the repository root:

```powershell
.\tools\scanner-test\run-tests.ps1 -TargetHost 127.0.0.1 -Port 4499 -SkipNmap
```

The `-Host` alias is also supported. Run one invocation per port, or pass an integer array from PowerShell:

```powershell
.\tools\scanner-test\run-tests.ps1 -TargetHost 127.0.0.1 -Port @(4499,4500,4501)
```

The script performs a TCP connection and an X.224 RDP negotiation probe. If `nmap.exe` is installed and `-SkipNmap` is omitted, it also runs:

```text
nmap -Pn -p PORT HOST
nmap -Pn -sV -p PORT HOST
nmap -Pn -sV --version-all -p PORT HOST
nmap -Pn -p PORT --script rdp-enum-encryption HOST
nmap -Pn -p PORT --script ssl-cert HOST
```

Results are written to `results/scanner-result.json`. The JSON records unavailable checks as `NOT_RUN`; it does not claim Nmap or MCS/credential success when those tools or probes were not executed.

For a synthetic Standard Security credential regression against a running local instance, use the dedicated integration runner:

```powershell
dotnet run --project .\RdpHoneypot.Tests -c Release -- --integration `
    --host 127.0.0.1 --port 13389 `
    --log-dir .\bin\Release\net10.0\integration-test-logs
```

The runner uses synthetic values only and verifies the aggregate record and target port.

## Expected environment

- Start FakeRDP with `config.json` or an explicit configuration.
- Keep FakeRDP on non-standard ports such as 4499, 4500, or 13389.
- Use synthetic credentials only.
- Do not add scanner-specific response branches. The harness sends ordinary RDP protocol probes.
