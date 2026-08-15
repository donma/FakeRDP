# RDP Honeypot（防禦型 RDP 蜜罐）

以 C# 撰寫的防禦型 RDP 蜜罐（Honeypot）。部署在您擁有或授權的網路上，用於**偵測、記錄試圖連線到您的伺服器的掃描器與攻擊者**，並擷取他們嘗試使用的帳號密碼。

> **⚠ 重要聲明**：本工具僅供**防禦用途**，僅限部署在您擁有或明確授權的網路環境中。未經授權攔截他人登入憑證，在台灣可能觸犯《刑法》第 358–363 條（妨害電腦使用罪）及《個人資料保護法》，在其他司法管轄區亦有相應罰則。請勿將本工具用於欺騙或竊取真實使用者的憑證。

---

## 功能特色

- **多連接埠監聽**：可同時監聽多個連接埠（例如 `4499, 4500, 4501`），模擬多個服務吸引攻擊者
- **JSON 設定檔**：啟動時從 `config.json` 讀取監聽連接埠與記錄目錄，亦可使用命令列覆寫
- **雙安全模式支援**：
  - **標準 RDP 安全**（無 NLA）：RSA 金鑰交換 + RC4 加密 → 可解密擷取明文帳號密碼
  - **SSL/TLS 安全**（`RDP_NEG_RSP` 回覆 `0x01`）：TLS 1.2 通道 → 憑證握手後直接讀取明文憑證
- **完整擷取資訊**：來源 IP、來源連接埠、目標連接埠、帳號、密碼、網域、Cookie、時間戳
- **檔案式記錄**：JSONL 匯總檔 + 每 session 獨立目錄（文字日誌 + 原始封包）
- **安全防護機制**：拒絕監聽 `3389`（正常 Windows RDP）與所有低於 `1024` 的系統連接埠，確保絕不與正式服務衝突
- **零系統侵入**：不改寫 Windows 服務、防火牆規則或登錄檔

---

## 系統需求

- .NET SDK 10 或更新版本（執行時期可為自包含發布）
- Windows 10/11 或 Windows Server 2019+（TLS 功能依賴 Schannel）
- 執行需要系統管理員權限（僅當要監聽需要權限的連接埠時；預設連接埠通常不需要）

---

## 編譯

```bash
cd RdpHoneypot
dotnet build -c Release
```

編譯產物位於 `bin/Release/net10.0/RdpHoneypot.exe`。

---

## 使用方式

### 直接執行（使用預設 `config.json`）

```bash
RdpHoneypot.exe
```

程式會在**目前工作目錄**尋找 `config.json`。若找不到則使用預設值（`4499`、`logs`）。

### 指定設定檔

```bash
RdpHoneypot.exe --config my-config.json
```

### 命令列覆寫

命令列參數優先於設定檔：

```bash
RdpHoneypot.exe --port 4499,4500,4501 --output logs
```

### 完整參數

| 參數 | 說明 |
|------|------|
| `--config <path>` | 設定檔路徑（預設 `./config.json`） |
| `--port <p1,p2,...>` | 覆寫監聽連接埠（逗號分隔） |
| `--output <dir>` | 覆寫記錄目錄 |
| `--help` / `-h` | 顯示說明 |

---

## 設定檔格式（JSON）

`config.json`：

```json
{
  "ports": [4499, 4500, 4501],
  "logDir": "logs"
}
```

| 欄位 | 型別 | 說明 |
|------|------|------|
| `ports` | 整數陣列 | 要監聽的連接埠清單。禁止使用 3389、3388 及 <1024 的連接埠 |
| `logDir` | 字串 | 記錄輸出目錄。支援相對路徑（相對於目前工作目錄）或絕對路徑 |

> **注意**：JSON 中 Windows 絕對路徑的反斜線必須跳脫（`C:\\logs`）或改用正斜線（`C:/logs`）。

---

## 記錄檔結構

```
logs/
├── honeypot.log              # 啟動/停止紀錄
├── captured_creds.jsonl      # 所有擷取憑證（JSONL，每行一筆）
└── session_000001/
    ├── session.log           # 該連線的協定階段文字紀錄
    ├── raw.bin               # 原始封包資料（除錯用）
    └── credential.json       # 該次擷取的憑證（若成功）
```

`captured_creds.jsonl` 範例：

```json
{
  "session_id": 2,
  "timestamp": "2026-08-13T08:14:31.9916297Z",
  "source_ip": "127.0.0.1",
  "source_port": 50984,
  "target_port": 4499,
  "username": "tlsadmin",
  "password": "TlsP@ss456",
  "domain": "CORP",
  "client_info": "cookie='Cookie: mstshash=test'"
}
```

---

## 技術細節

### 整體架構

```
攻擊者 (mstsc / 掃描器) ──TCP──▶ RdpHoneypot.exe
                                  │
                                  ├─ 多連接埠並行監聽 (TcpListener x N)
                                  │
                                  └─ 每個連線: RdpSession
                                       ├─ X.224 協商
                                       ├─ (選擇性) TLS 1.2 握手
                                       ├─ MCS Connect 交換
                                       ├─ Security Exchange (RSA)
                                       └─ Info PDU → 憑證解析 → JSONL 記錄
```

### RDP 協定流程（標準安全模式）

```
1. Client 送出 X.224 Connection Request
2. Server 回覆 X.224 Connection Confirm
3. Client 送出 MCS Connect Initial（BER 編碼）
4. Server 回覆 MCS Connect Response
   ├─ Server Core Data
   └─ Server Security Data
        ├─ encryptionMethod = 7 (40/56/128-bit RC4)
        ├─ encryptionLevel = 2 (client-requested)
        ├─ ServerRandom (32 bytes)
        └─ Server Certificate (RSA 2048)
5. Client 送出 Security Exchange PDU
   └─ ClientRandom 以伺服器 RSA 公鑰加密 (PKCS#1 v1.5)
6. Server 以 RSA 私鑰解密 ClientRandom
7. 雙方以 MD5 衍生 RC4 Session Keys
   ├─ SessionKeyBlob = MD5(ClientRandom + ServerRandom + ClientRandom)
   ├─ DecryptKey = MD5(SessionKeyBlob + pad(0x5C))
   └─ EncryptKey = MD5(SessionKeyBlob + pad(0x36))
8. Client 送出 Info PDU（RC4 加密）
   └─ 內含 Domain / UserName / Password (UTF-16)
9. Server 以 RC4 解密並解析 → 擷取帳號密碼
```

### RDP 協定流程（SSL/TLS 模式）

```
1. Client 送出 X.224 CR + RDP_NEG_REQ (requestedProtocols 含 0x01)
2. Server 回覆 X.224 CC + RDP_NEG_RSP (selectedProtocol = 0x01 SSL)
3. TLS 1.2 握手（ECDSA 憑證，ECDHE 金鑰交換）
4. 後續 MCS / Security Exchange / Info PDU 全部在 TLS 通道內
5. Info PDU 以明文（TLS 已提供加密）→ 直接解析擷取
```

### 雙憑證架構

| 用途 | 演算法 | 說明 |
|------|--------|------|
| TLS 握手 | **ECDSA P-256** | 支援 ECDHE 金鑰交換（Windows Schannel 相容） |
| RDP 安全交換 | **RSA 2048** | 加密/解密 ClientRandom（內嵌於 MCS Response） |

### 關鍵技術重點

1. **Windows Schannel 相容性**：.NET 產生的記憶體金鑰無法直接被 Schannel 存取，導致 `platform does not support ephemeral keys` 錯誤。解法是將 ECDSA 自簽憑證匯出為 PFX 後，以 `X509KeyStorageFlags.PersistKeySet` 重新載入，註冊到 Windows 金鑰存放區。

2. **TPKT 長度正確性**：RDP 每個封包的 TPKT 長度欄位（bytes 2-3，Big-Endian）必須與實際封包長度完全一致，否則殘留位元組會造成後續封包讀取錯位。

3. **BER 編碼**：MCS Connect Response 的 BER 長度欄位使用 Big-Endian（`0x82 + 2 bytes`），與 GCC 資料內部使用的 Little-Endian 欄位不同，兩者不可混淆。

4. **Info PDU 雙模式解析**：自動嘗試「明文解析」（TLS 通道已解密）與「RC4 解密後解析」（標準安全），兩種模式皆可擷取。

---

## 安全注意事項

### 為什麼 mstsc 連線可能失敗？

- 現代 Windows mstsc **預設啟用 NLA（CredSSP）**。當蜜罐回覆 `RDP_NEG_RSP` 為標準安全或 SSL（非 CredSSP）時，mstsc 可能拒絕連線或顯示錯誤。
- 若需支援 NLA，需實作完整 CredSSP 協定（SPNEGO / NTLM / Kerberos），這是數千行程式碼的工程。pyRDP 的 MITM 模式透過轉發到真實伺服器繞過此問題。
- 當 mstsc 顯示自簽憑證警告時，使用者需按「是」才能繼續。

### 部署建議

- **僅部署在隔離/受控網路**（內部測試網段、DMZ 的蜜罐區）
- 建議搭配防火牆規則，僅允許預期的來源連入蜜罐連接埠
- 定期檢視 `captured_creds.jsonl`，比對是否有內部帳號被嘗試（可偵測密碼噴灑攻擊）

### 法律與倫理

- 此工具模擬 RDP 服務並記錄登入嘗試，**僅限防禦與資安研究**
- 用於未授權的憑證攔截屬違法行為
- 請遵守您所在地區的電腦使用與資料保護相關法規

---

## 限制與未來方向

| 限制 | 說明 |
|------|------|
| NLA (CredSSP) 不支援 | 現代 mstsc 預設 NLA 時無法連線；需 CredSSP 實作或 MITM 模式 |
| TLS 依賴 Schannel | 在非 Windows 平台（Linux/macOS）TLS 行為可能不同 |
| 無真實桌面回應 | 蜜罐不提供完整 RDP 桌面會話，僅完成認證階段 |
| 憑證為自簽 | 連線方會看到憑證警告 |

**未來可能方向**：
- 實作 CredSSP / NTLM 支援以相容 NLA
- MITM 模式（轉發到真實 RDP 伺服器，如 pyRDP）
- Web 管理介面檢視擷取結果
- 匯出為 SIEM 格式（CEF / Syslog）

---

## 參考

- [MS-RDPBCGR: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)（RDP 協定規格）
- [pyRDP](https://github.com/GoSecure/pyrdp)（Python RDP 蜜罐/MITM，本專案概念參考來源）
- [fake-rdp](https://github.com/cheeseandcereal/fake-rdp)（簡易 RDP 偽裝伺服器）
