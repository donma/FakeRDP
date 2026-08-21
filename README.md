# RDP Honeypot（防禦型 RDP 蜜罐）

以 C# (.NET 10) 撰寫的防禦型 RDP 蜜罐，部署於授權網路環境，用於**偵測並記錄掃描器與攻擊者的 RDP 連線嘗試**，並擷取所使用的帳號與密碼。

> **⚠ 重要聲明**：僅限部署在您擁有或明確授權的網路環境。未經授權攔截他人憑證可能觸法，請遵守當地法規。憑證資料為高度敏感，儲存時請確保存取權限最小化、硬碟加密、定期清除。

---

## 功能特色

- **多連接埠監聽**：同時監聽多個非標準埠（如 `4499, 4500, 4501`），模擬多個目標
- **三種安全模式**：標準 RDP（RSA/RC4）、SSL/TLS（TLS 1.2 + ECDHE）、NLA/CredSSP（NTLM 帳號網域擷取）
- **完整憑證擷取**：記錄來源 IP、Port、帳號、密碼、網域、Cookie、時間戳，來源 IP 以實際 TCP socket peer 為準
- **Console 即時顯示**：成功擷取時紅字顯示，密碼可遮罩或明文（`consoleCredentialMode`）
- **協定遙測**：TLS cipher suite、certificate thumbprint、協商狀態、state transition 完整記錄
- **資源保護**：全域 Session 上限、Per-IP / Per-/24 限制、超限自動降級為輕量回應（僅回 X.224 CC）
- **憑證保護**：Credential 事件絕不靜默丟棄（`CredentialEventsDropped = 0`），shutdown 瞬間也不遺失（`CompleteAsync` drain）
- **零系統侵入**：不修改 Windows 服務、防火牆、登錄檔；不接受低於 1024 的系統連接埠
- **自動化驗收**：30 項單元測試 + 整合測試（standard/tls/nla）＋ AI 驗證 harness

## 測試狀態

| 項目 | 結果 |
|---|---|
| 單元測試 | 38/38 PASS |
| Standard Security 憑證擷取 | PASS |
| TLS Info PDU 憑證擷取 | PASS |
| NLA / NTLM 帳號擷取 | PASS |
| 100 條並行 Session 映射（無串線） | PASS |
| 100 輪 Shutdown 瞬間不丟帳密 | PASS（producer 完成後才 CompleteAsync） |
| Server shutdown 等待 active session（兩階段 shutdown） | PASS（grace → force → CompleteAsync） |
| CredentialWriteAfterClose（shutdown ordering bug 指標） | 0（正常 shutdown 不發生） |
| Source IP 正常化（null / IPv4-mapped IPv6） | PASS |
| Nmap 服務偵測（`-sV`） | PASS（`ms-wbt-server`） |

---

## 快速開始

### 1. 編譯

```bash
cd RdpHoneypot
dotnet build -c Release
```

### 2. 執行

```bash
bin\Release\net10.0\RdpHoneypot.exe --port 4499,4500,4501
```

或使用設定檔：

```bash
bin\Release\net10.0\RdpHoneypot.exe --config config.json
```

### 3. 測試連線

```bash
mstsc /v:<伺服器IP>:4499
```

輸入帳號密碼後，蜜罐會即時顯示擷取到的帳密，並寫入 `captured_creds.jsonl`。

### 4. 掃描器驗證

```bash
nmap -Pn -sV -p 4499 <AUTHORIZED_HOST>
```

預期結果：`4499/tcp open  ms-wbt-server xrdp`。

---

## 命令列參數

| 參數 | 說明 |
|---|---|
| `--config <path>` | 設定檔路徑（預設 `./config.json`） |
| `--port <p1,p2,...>` | 覆寫監聽連接埠 |
| `--output <dir>` | 覆寫記錄目錄 |
| `--help` / `-h` | 顯示說明 |

---

## 設定檔格式

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

完整欄位說明請見 `config.json` 註解。禁止使用 `3389` 或低於 `1024` 的連接埠。

---

## 記錄檔結構

```
<logDir>
├── captured_creds.jsonl          # 所有成功擷取的憑證（JSONL）
├── nla_accounts.jsonl            # NLA 路徑擷取的帳號
├── session_000001/
│   ├── session.log               # 協定階段文字紀錄
│   ├── credential.json           # 標準/TLS 憑證（若成功）
│   ├── nla_credential.json       # NLA 帳號（若成功）
│   └── raw.bin                   # 原始封包（僅 enableRawCapture=true）
├── honeypot.log                  # 啟動/停止紀錄
└── certs/test-rdp.pfx            # 公開測試憑證（僅供隔離測試）
```

---

## 技術架構

```
攻擊者 (mstsc / 掃描器) ──TCP──▶ RdpHoneypot.exe
                                   │
                                   ├─ 多連接埠並行監聽
                                   │
                                   └─ 每個連線：RdpSession 狀態機
                                        ├─ X.224 協商（RDP_NEG_REQ / RSP）
                                        ├─ (選擇性) TLS 1.2 握手
                                        ├─ (選擇性) NLA/CredSSP：NTLM Type 1/2/3
                                        ├─ MCS Connect / Erect / Attach / Channel Join
                                        ├─ Security Exchange（標準安全模式解密）
                                        └─ Info PDU → 憑證解析 → EventRecorder → JSONL
```

### 憑證事件流程

```
RdpSession（immutable metadata: SessionId, SourceIp, SourcePort, TargetPort）
    ↓
SaveCredentialAsync
    ↓
TryWriteCredentialAsync（bounded timeout 2s，絕不丟棄）
    ↓
EventRecorder（dedicated channel，FullMode.Wait）
    ↓
captured_creds.jsonl / nla_accounts.jsonl / per-session credential.json
```

---

## 安全注意事項

- **僅限授權環境部署**：隔離測試網段或 DMZ 蜜罐區
- **來源 IP**：以實際 TCP socket peer 為準，不採信 X-Forwarded-For 或 client payload
- **憑證遮罩**：Console 預設以 `********` 顯示密碼，原始事件保留完整值
- **防火牆**：僅允許預期來源連入蜜罐連接埠
- **定期清除**：憑證記錄定期檢視與清除，遵守組織 retention policy
- **測試憑證**：`certs/test-rdp.pfx` 是公開測試憑證，含私鑰，僅供隔離測試

---

## 限制

| 限制 | 說明 |
|---|---|
| NLA 密碼未擷取 | 現代 mstsc 因 mechListMIC 拒絕 SPNEGO accept，僅取得帳號/網域 |
| TLS 依賴 Schannel | 非 Windows 平台 TLS 行為可能不同 |
| 無真實桌面 | 蜜罐不提供完整 RDP 桌面會話，僅完成認證階段 |
| 憑證為自簽 | 連線方會看到憑證警告 |

---

## 參考

- [MS-RDPBCGR: Remote Desktop Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [MS-NLMP: NT LAN Manager (NTLM) Authentication Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [MS-CSSP: CredSSP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)
- [pyRDP](https://github.com/GoSecure/pyrdp) (Python RDP 蜜罐，概念參考)