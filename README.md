# RDP Honeypot（防禦型 RDP 蜜罐）

以 C# (.NET 10) 撰寫的防禦型 RDP 蜜罐，部署在您擁有或授權的網路上，用於**偵測、記錄試圖連線到您的伺服器的掃描器與攻擊者**，並擷取他們嘗試使用的帳號密碼，藉以分辨漏洞利用與字典攻擊。

> **⚠ 重要聲明**：本工具僅供**防禦用途**，僅限部署在您擁有或明確授權的網路環境中。未經授權攔截他人登入憑證，在台灣可能觸犯《刑法》第 358–363 條（妨害電腦使用罪）及《個人資料保護法》，在其他司法管轄區亦有相應罰則。請勿將本工具用於欺騙或竊取真實使用者的憑證。
>
> 憑證資料（含密碼）為高度敏感資料，儲存時請確保：檔案存取權限設為最小化、硬碟加密、定期清除、勿上傳至公共環境。

---

## 功能特色

- **多連接埠監聽**：同時監聽多個連接埠（例如 `4499, 4500, 4501`），模擬多個目標吸引攻擊者
- **JSON 設定檔**：從 `config.json` 讀取設定，亦可使用命令列覆寫
- **三種安全模式支援**：
  - **標準 RDP 安全**（無 TLS/NLA）：RSA 金鑰交換 + RC4 加密 → 解密擷取帳號密碼
  - **SSL/TLS 安全**：TLS 1.2（RSA 憑證 + ECDHE）→ TLS 通道內直接讀取 Info PDU
  - **NLA/CredSSP（部分）**：處理 NTLM Type 1/2/3，擷取 **帳號與網域**（密碼需 TSCredentials，現代 mstsc 因 SPNEGO mechListMIC 通常拒絕後續交換）
- **完整擷取資訊**：來源 IP、來源連接埠、目標連接埠、帳號、密碼、網域、Cookie、時間戳
- **Console 即時顯示**：成功擷取憑證時以紅字顯示在終端機
- **雙檔記錄**：JSONL 匯總檔 + 每 session 獨立目錄（文字日誌 + 原始封包）
- **資源保護（高併發防耗盡）**：
  - 全域 Session 上限（`SessionLimiter`，預設 2000 併發）
  - Per-IP / Per-/24 併發限制（`IpConnectionTracker`，預設 8 / 150）
  - 超過限制時自動降級為**輕量回應**：仍回應 X.224 CC（讓掃描器看到 RDP banner），但不再投入 TLS / 記憶體 / 磁碟資源
  - Lazy 建檔：只有進入深度處理的連線才建立 session 目錄
  - Packet 硬限制：TPKT ≤ 256 KB、DER 長度上限，惡意超大宣告立即關閉
  - Per-state Timeout：X.224=3s、TLS=5s、MCS=5s、Idle=20s（Slowloris 防護）
  - Raw capture 預設關閉（`enableRawCapture: false`），避免磁碟反壓
- **安全防護機制**：拒絕監聽 `3389`（正常 Windows RDP）、`3388` 與所有低於 `1024` 的系統連接埠，確保不與正式服務衝突
- **零系統侵入**：不改寫 Windows 服務、防火牆規則或登錄檔

---

## 系統需求

- .NET SDK 10 或更新版本（執行時期可為自包含發布）
- Windows 10/11 或 Windows Server 2019+（TLS 依賴 Schannel）
- 執行通常不需系統管理員權限（除非要監聽需要權限的連接埠）

---

## 快速開始

### 1. 編譯

```bash
cd RdpHoneypot
dotnet build -c Release
```

編譯產物位於 `bin\Release\net10.0\RdpHoneypot.exe`。

### 2. 執行

```bash
bin\Release\net10.0\RdpHoneypot.exe --port 4499,4500,4501
```

Log 預設寫在 **exe 同層目錄**（`bin\Release\net10.0\`），感謝您並未指定 `--output`。

### 3. 測試連線

```text
mstsc /v:<伺服器IP>:4499
```

輸入帳號密碼後，蜜罐會在 console 以紅字顯示擷取到的帳密。

---

## 命令列參數

| 參數 | 說明 |
|------|------|
| `--config <path>` | 設定檔路徑（預設 `./config.json`） |
| `--port <p1,p2,...>` | 覆寫監聽連接埠（逗號分隔） |
| `--output <dir>` | 覆寫記錄目錄（預設 = exe 所在目錄） |
| `--help` / `-h` | 顯示說明 |

```bash
# 使用設定檔（預設行為）
RdpHoneypot.exe

# 指定設定檔
RdpHoneypot.exe --config my-config.json

# 命令列覆寫（優先於設定檔）
RdpHoneypot.exe --port 4499,4500,4501 --output D:\honeypot-logs
```

---

## 設定檔格式（JSON）

`config.json`：

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
  "logDir": null
}
```

| 欄位 | 型別 | 預設值 | 說明 |
|------|------|--------|------|
| `ports` | 整數陣列 | `[4499, 4500, 4501]` | 要監聽的連接埠清單。禁止使用 3389、3388 及 <1024 的連接埠 |
| `maxConcurrentSessions` | 整數 | `2000` | 全域最大深度連線數（超過則走輕量回應） |
| `maxConcurrentPerIp` | 整數 | `8` | 單一 IP 最大深度連線數 |
| `maxConcurrentPerSubnet` | 整數 | `150` | 單一 /24 subnet 最大深度連線數 |
| `maxPacketBytes` | 整數 | `262144` | 單一封包最大 byte 數（超過立即關閉） |
| `maxRawCaptureBytesPerSession` | 整數 | `4194304` | 每 session raw capture 上限（啟用時） |
| `x224TimeoutSeconds` | 整數 | `3` | X.224 階段讀取逾時 |
| `tlsTimeoutSeconds` | 整數 | `5` | TLS 握手逾時 |
| `mcsTimeoutSeconds` | 整數 | `5` | MCS 階段讀取逾時 |
| `credSspTimeoutSeconds` | 整數 | `10` | CredSSP/NTLM 階段逾時 |
| `idleTimeoutSeconds` | 整數 | `20` | 其他階段閒置逾時 |
| `eventQueueCapacity` | 整數 | `100000` | 事件佇列容量（預留 Wave 2 使用） |
| `enableRawCapture` | 布林 | `false` | 是否記錄原始封包（預設關閉，避免磁碟反壓） |
| `logDir` | 字串或 null | `null` | 記錄輸出目錄（null = exe 所在目錄） |

> **注意**：JSON 中 Windows 絕對路徑的反斜線必須跳脫（`"D:\\logs"`）或改用正斜線（`"D:/logs"`）。

> **資源降級行為**：當 `maxConcurrentSessions`、`maxConcurrentPerIp` 或 `maxConcurrentPerSubnet` 任一達上限時，新連線仍會收到 X.224 Connection Confirm（掃描器看到 RDP 服務），但不會繼續 TLS/MCS/Info PDU 處理，也不會建立 session 目錄或寫入任何檔案。

---

## 記錄檔結構

```
<logDir>  (預設 = exe 所在目錄)
├── honeypot.log                  # 啟動/停止紀錄
├── captured_creds.jsonl          # 所有成功擷取的憑證（JSONL，每行一筆）
├── nla_accounts.jsonl            # NLA 路徑擷取的帳號（含網域與 IP）
└── session_000001/               # 僅深度連線建立（lazy）
    ├── session.log               # 該連線的協定階段文字紀錄
    ├── raw.bin                   # 原始封包資料（僅 enableRawCapture=true）
    ├── credential.json           # 標準/TLS 路徑擷取的憑證（若成功）
    └── nla_credential.json       # NLA 路徑擷取的帳號/密碼（若成功）
```

### captured_creds.jsonl 範例（標準 / TLS 安全模式）

```json
{
  "session_id": 3,
  "timestamp": "2026-08-17T05:02:12.6674375Z",
  "source_ip": "192.168.121.153",
  "source_port": 6263,
  "target_port": 4499,
  "username": "no2somdej@hotmail.com",
  "password": "123456",
  "domain": "",
  "client_info": "cookie='Cookie: mstshash=no2somdej'"
}
```

### nla_accounts.jsonl 範例（NLA / CredSSP 安全模式）

```json
{
  "session_id": 1,
  "timestamp": "2026-08-17T03:35:16.2561128Z",
  "source_ip": "192.168.121.153",
  "source_port": 13526,
  "target_port": 4499,
  "domain": "",
  "username": "no2somdej@hotmail.com"
}
```

---

## 如何使用擷取結果判斷攻擊類型

| 觀察到的模式 | 推斷 |
|--------------|------|
| 同一 IP、同一帳號、多組不同密碼 | **字典攻擊**（密碼噴灑） |
| 同一 IP、多組不同帳號 | **帳號清單掃描** |
| 大量不同 IP、偶發常見帳號（`admin`/`administrator`） | **網際網路掃描 / 蠕蟲** |
| NLA 路徑重複收到 NTLM Type 3 | **有人掌握有效網域帳號** |
| 成功登入後的動作 | 需搭配 Windows Event Log 4624/4625 綜合判斷 |

> 建議搭配 **Windows 事件檢視器**：`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 中的 4624（登入成功）與 4625（登入失敗）事件，可確認真正的「成功入侵」與「嘗試失敗」。

---

## 技術細節

### 整體架構

```
攻擊者 (mstsc / 掃描器) ──TCP──▶ RdpHoneypot.exe
                                  │
                                  ├─ 多連接埠並行監聽 (TcpListener x N)
                                  │
                                  └─ 每個連線: HandleSessionAsync
                                       ├─ X.224 協商（RDP_NEG_REQ / RSP）
                                       ├─ (選擇性) TLS 1.2 握手（RSA 憑證 + ECDHE）
                                       ├─ (選擇性) NLA/CredSSP：NTLM Type 1/2/3
                                       ├─ MCS Connect 交換
                                       ├─ MCS Erect Domain / Attach User / Channel Join
                                       ├─ Security Exchange（標準安全模式解密 ClientRandom）
                                       └─ Info PDU → 憑證解析 → Console + JSONL 記錄
```

### RDP 協定流程（TLS 模式，最常用）

```
1. Client 送出 X.224 CR + RDP_NEG_REQ (requestedProtocols 含 0x01)
2. Server 回覆 X.224 CC + RDP_NEG_RSP (selectedProtocol)
3. TLS 1.2 握手（RSA 2048 憑證，ECDHE 金鑰交換）
4. MCS Connect Initial → Server 回覆 Connect Response
5. MCS Erect Domain Request（無回應）
6. MCS Attach User Request → Server 回覆 Attach User Confirm
7. MCS Channel Join Request（IO channel 1003）→ Server 回覆 Channel Join Confirm
8. Info PDU（TLS 通道明文）→ 解析 Domain / UserName / Password (UTF-16)
   └─ 若 client 跳過 Security Exchange 直接送 Info PDU，Server 會自動偵測 SEC_INFO_PKT flag
```

### RDP 協定流程（標準安全模式，無 TLS）

```
1. X.224 CR/CC（不含 TLS）
2. MCS Connect Initial → Response（內含 ServerRandom + RSA 2048 憑證）
3. MCS Erect Domain / Attach User / Channel Join（同上）
4. Security Exchange PDU：ClientRandom 以 RSA 公鑰加密
5. Server 以 RSA 私鑰解密 ClientRandom → 衍生 RC4 Session Keys
   ├─ SessionKeyBlob = MD5(ClientRandom + ServerRandom + ClientRandom)
   └─ DecryptKey = MD5(SessionKeyBlob + pad(0x5C))
6. Info PDU（RC4 加密）→ 先 RC4 解密再解析
```

### NLA / CredSSP 流程（部分支援）

```
1. X.224 CR 含 requestedProtocols 0x04 (HYBRID/NLA)
2. Server 回覆 selectedProtocol = 0x02（CredSSP 通道）
3. TLS 1.2 握手
4. Client 送 TSRequest（內含 SPNEGO/NTLM Type 1）
5. Server 回覆 TSRequest（內含 NTLM Type 2 Challenge）
6. Client 送 TSRequest（內含 NTLM Type 3 → Username/Domain）
7. Server 解析並記錄帳號/網域
8. Server 嘗試送出 SPNEGO accept-completed，希望收到 TSCredentials（含密碼）
   └─ 現代 mstsc 驗證 mechListMIC：因 Server 無密碼 hash 無法計算，
       故通常在此中斷 → 僅能取得帳號/網域，無法取得明文密碼
```

### 雙憑證架構

| 用途 | 演算法 | 說明 |
|------|--------|------|
| TLS 握手 | **RSA 2048** | 支援 ECDHE 金鑰交換；其私鑰亦可用於 CredSSP TSCredentials 解密 |
| RDP 安全交換 | **RSA 2048** | 加密/解密 ClientRandom（內嵌於 MCS Response） |

### 關鍵技術重點

1. **階層式 Session 資源保護**：每條連線分為**輕量路徑**（Tier 0/1）與**深度路徑**（Tier 2+）。輕量路徑只做 TCP accept + X.224 CC 回應（成本極低，讓掃描器看到 RDP 服務），深度路徑才做 TLS、MCS、Info PDU 解析。`SessionLimiter`（全域 SemaphoreSlim）與 `IpConnectionTracker`（Per-IP / /24 限制）共同控制深度路徑的准入，超限連線自動走輕量路徑，確保攻擊者消耗的成本遠高於蜜罐。

2. **Windows Schannel 相容性**：.NET 產生的記憶體金鑰無法直接被 Schannel 存取，導致 `platform does not support ephemeral keys` 錯誤。解法是將自簽憑證匯出為 PFX 後，以 `X509KeyStorageFlags.PersistKeySet` 重新載入，註冊到 Windows 金鑰存放區。

2. **RDP 協商位元**：`RDP_NEG_REQ.requestedProtocols` 的位元定義為 `0x01=Standard`、`0x02=TLS`、`0x04=NLA (HYBRID)`。選擇協定時依此正確對應，避免把 TLS 誤判為 NLA。

3. **MCS 完整握手**：除 Connect Initial/Response 外，還需處理 **Erect Domain Request → Attach User Request → Channel Join Request** 等階段，client 才會送出含憑證的 Info PDU。

4. **TPKT/X.224 偏移**：X.224 Data header 為 `02 F0 80`（LI + PDU type + EOT），從 `0xF0` 起只需再跳過 2 bytes，多跳 1 byte 會導致封包解析錯位。

5. **Info PDU 解析**：payload 在 security header 後可能有 1-byte padding，且各字串（domain/username/password）間有空字元 terminator。解析器需嘗試 offset 0/1 並跳過欄位間 null bytes。

6. **MCS Send Data Request (0x64) vs Send Data Indication (0x04)**：TLS 模式的 Info PDU 通常以 `0x64`（Send Data Request）傳送，需正確跳過其 header（choice + initiator + channel + priority + segmentation = 7 bytes）。

7. **BER 編碼**：MCS Connect Response 的 BER 長度欄位使用 Big-Endian（`0x82 + 2 bytes`），與 GCC 資料內部使用的 Little-Endian 欄位不同，兩者不可混淆。

---

## 安全注意事項

### 為什麼 mstsc 連線可能失敗？

- 現代 Windows mstsc **預設啟用 NLA（CredSSP）**。蜜罐對 NLA 只做到 NTLM Type 3（取得帳號），無法完成 SPNEGO 的 mechListMIC 驗證，因此 mstsc 在 TSCredentials 階段會中斷。
- 若 mstsc 在 NLA 失敗後自動 fallback 到 TLS/標準安全（視本機設定而定），蜜罐即可完整擷取帳號密碼。
- 當 mstsc 顯示自簽憑證警告時，使用者需按「是」才能繼續。

### 部署建議

- **僅部署在隔離/受控網路**（內部測試網段、DMZ 的蜜罐區）
- 搭配防火牆規則，僅允許預期的來源連入蜜罐連接埠
- 定期檢視 `captured_creds.jsonl` 與 `nla_accounts.jsonl`，比對是否有內部帳號被嘗試（可偵測密碼噴灑）
- 憑證檔案視為機密，限制檔案系統權限並定期輪替清除

### 法律與倫理

- 此工具模擬 RDP 服務並記錄登入嘗試，**僅限防禦與資安研究**
- 用於未授權的憑證攔截屬違法行為
- 請遵守您所在地區的電腦使用與資料保護相關法規

---

## 限制與未來方向

| 限制 | 說明 |
|------|------|
| NLA (CredSSP) 密碼未擷取 | 現代 mstsc 因 mechListMIC 拒絕 SPNEGO accept，無法取得 TSCredentials（明文密碼），僅取得帳號/網域 |
| TLS 依賴 Schannel | 在非 Windows 平台（Linux/macOS）TLS 行為可能不同 |
| 無真實桌面回應 | 蜜罐不提供完整 RDP 桌面會話，僅完成認證階段 |
| 憑證為自簽 | 連線方會看到憑證警告 |

**未來可能方向**：
- 完成 NLA/CredSSP：使用 `NegotiateAuthentication` 或自訂 NTLM Session Key 衍生產生有效 mechListMIC
- MITM 模式（轉發到真實 RDP 伺服器，如 pyRDP）
- 以 `netstat` / Windows ETW 補足來源 GeoIP / ASN 資訊
- Web 管理介面檢視擷取結果
- 匯出為 SIEM 格式（CEF / Syslog）

---

## 參考

- [MS-RDPBCGR: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)（RDP 協定規格）
- [MS-NLMP: NT LAN Manager (NTLM) Authentication Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)（NTLM Type 1/2/3 結構）
- [MS-CSSP: CredSSP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)（TSCredentials 加密）
- [pyRDP](https://github.com/GoSecure/pyrdp)（Python RDP 蜜罐/MITM，本專案概念參考來源）
- [FreeRDP mcs.c](https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/mcs.c)（T.125 MCS 訊息格式參考）