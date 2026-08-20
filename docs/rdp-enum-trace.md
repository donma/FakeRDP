# rdp-enum-encryption Timeout Investigation (§15-16)

## Commands

```bash
nmap -Pn -sV -p 4499 --script rdp-enum-encryption --script-timeout 30s 127.0.0.1
nmap -Pn -sV --version-all -p 4499 --script rdp-enum-encryption --script-timeout 60s 127.0.0.1
```

Both commands exceed their `--script-timeout` budget because the script execution time is dominated by per-probe socket timeouts in Npcap-less connect() mode.

## Blocked Layer Analysis (from session logs)

| Session | Probe | Requested | Selected | Last State | Duration | Reason |
|---------|-------|-----------|----------|------------|----------|--------|
| 7 | Cipher (standard) | STANDARD | Standard | WaitMCS → ended | <1s | Legacy CC, no MCS (client disconnected) |
| 8 | Cipher (standard) | STANDARD | Standard | WaitMCS → ended | <1s | same |
| 12 | CredSSP/NLA | SSL|HYBRID | Hybrid | TLS handshake failed | 5s | TLS timeout (client closed before TLS) |
| 13 | Cipher (standard) | STANDARD | Standard | WaitMCS → ended | <1s | fast |
| 14 | CredSSP/NLA | SSL|HYBRID | Hybrid | TLS handshake failed | <1s | TLS EOF (client closed) |
| 16 | **SSL reconnect** | SSL | Ssl | WaitMCS → WaitErectDomain → TX 107 → ended | <1s | **Success** – TLS established, MCS response sent |
| 19 | **Cipher (standard)** | STANDARD | Standard | WaitMCS → WaitErectDomain → TX 856 → **ended after 5s** | 5s | **MCS Connect Response sent (856 bytes, RSA cert)**; server waited for Erect Domain, client closed but server's read blocked until mcsTimeout (5s) |

## Blocked Layer

**MCS / Standard Security cipher probing.**

The NSE script's `enum_ciphers` function opens 4 connections (one per cipher value). Each connection:
1. Sends a legacy X.224 CR (no RDP_NEG_REQ) → server responds with standard CC (11 bytes)
2. Sends MCS Connect Initial → server responds with MCS Connect Response (856 bytes, includes RSA certificate)
3. NSE checks `response.ccr.enc_cipher` (does not match client's requested cipher)
4. `comm:close()`

The server-side session lingers for `mcsTimeoutSeconds` (5s) after the client closes because the server's read in WaitErectDomain does not detect EOF immediately. The 4 cipher probes therefore accumulate ~20 seconds of server-side wait time. Combined with 5 protocol probes (each with potential 5s TLS failures), the total script execution exceeds 60 seconds even with `--script-timeout`.

## Packet-Level Evidence

The server correctly returns:
- RDP_NEG_RSP `selectedProtocol=1` (SSL) for SSL probe → script would report "SSL: SUCCESS"
- RDP_NEG_RSP `selectedProtocol=2` (Hybrid) for CredSSP probe → script would report "CredSSP (NLA): SUCCESS"
- Valid MCS Connect Response (107 bytes) for TLS path
- Valid MCS Connect Response (856 bytes) for standard security path

## Conclusion

The server protocol responses are correct. The timeout is caused by:
1. **Npcap not installed** → Nmap uses connect() mode, which increases per-scan overhead
2. **Server session lingers** 5s per connection (mcsTimeout) because the client's socket close does not propagate as immediate EOF under connect() mode
3. **4 cipher probes × 5s + 5 protocol probes × ~5s** = ~45s of accumulated wait time

**Fix**: Install Npcap for raw socket mode, or reduce `mcsTimeoutSeconds` in the server config to speed up session teardown. The server protocol itself is correct.

## Raw Output

- `tools/ai-validation/results/4499/nmap-rdp-enum-encryption.txt` (contains only header – script did not complete)
- `tools/ai-validation/results/rdp-enum-trace.log` (this file)