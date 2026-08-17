using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace RdpHoneypot;

/// <summary>
/// 防禦型 RDP 蜜罐 ─ 僅限在您擁有或授權的網路上使用。
/// 攔截攻擊者連線，記錄 IP、嘗試的帳號密碼，並存檔。
/// 
/// 參考: RDPy (Python honeypot), MS-RDPBCGR 協定規格
/// </summary>
sealed class HoneypotServer
{
    readonly IReadOnlyList<int> _ports;
    readonly string _logDir;
    readonly X509Certificate2 _serverCert;   // RSA 憑證 (內嵌 MCS Response，RDP 安全交換)
    readonly X509Certificate2 _tlsCert;      // RSA 憑證 (TLS 握手 + CredSSP TSCredentials 解密)
    readonly RSA _rsaKey;
    readonly RSA _tlsRsaKey;                 // TLS 憑證的 RSA 私鑰 (用於 CredSSP 解密)
    readonly byte[] _serverRandom;

    long _sessionCounter;

    public HoneypotServer(IReadOnlyList<int> ports, string logDir)
    {
        _ports = ports;
        _logDir = logDir;
        Directory.CreateDirectory(logDir);

        // 產生 RSA 2048-bit 金鑰 + 自簽憑證 (供 RDP 安全協商使用)
        (_rsaKey, _serverCert) = CryptoHelper.CreateRsaCert();
        // 產生 RSA 自簽憑證 (供 TLS 握手 + CredSSP TSCredentials 解密使用)
        _tlsCert = CryptoHelper.CreateRsaCertForTls();
        _tlsRsaKey = _tlsCert.GetRSAPrivateKey()!;
        _serverRandom = CryptoHelper.GenerateRandom(32);
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        // 為每個連接埠建立監聽器
        var listeners = new List<TcpListener>();
        try
        {
            foreach (var port in _ports)
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                listeners.Add(listener);
                Console.WriteLine($"[啟動] 監聽 port {port}");
            }
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"[錯誤] 無法監聽連接埠: {ex.Message}");
            foreach (var l in listeners) l.Stop();
            return;
        }

        Console.WriteLine(@$"
╔══════════════════════════════════════════════════╗
║     RDP Honeypot (防禦型蜜罐)                     ║
║     Listening on ports: {string.Join(", ", _ports)}     ║
║     Log dir: {Path.GetFullPath(_logDir)} ║
║     ⚠ 僅限在您擁有或授權的網路上使用               ║
║     ✓ 不影響正常 RDP (3389)                       ║
╚══════════════════════════════════════════════════╝
");

        await File.AppendAllTextAsync(Path.Combine(_logDir, "honeypot.log"),
            $"=== Honeypot started on ports [{string.Join(", ", _ports)}] at {DateTime.UtcNow:O} ===\n", ct);

        // 每個監聽器獨立接受連線 (並行)
        var acceptTasks = listeners.Select(l => AcceptLoopAsync(l, ct)).ToArray();

        // 等待任一工作取消
        try { await Task.WhenAll(acceptTasks); }
        catch (OperationCanceledException) { }

        foreach (var l in listeners) l.Stop();
    }

    /// <summary>單一監聽器的接受迴圈</summary>
    async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        int localPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                if (ct.IsCancellationRequested)
                {
                    client.Close();
                    break;
                }
                var id = Interlocked.Increment(ref _sessionCounter);
                var ep = (IPEndPoint)client.Client.RemoteEndPoint!;
                Console.WriteLine($"[{id}] + Connection from {ep} -> port {localPort}");

                _ = HandleSessionAsync(id, ep, localPort, client, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Accept error (port {localPort}): {ex.Message}");
            }
        }
    }

    async Task HandleSessionAsync(long id, IPEndPoint ep, int localPort, TcpClient client, CancellationToken ct)
    {
        var sessionDir = Path.Combine(_logDir, $"session_{id:D6}");
        Directory.CreateDirectory(sessionDir);

        var rawLog = new FileStream(Path.Combine(sessionDir, "raw.bin"), FileMode.Create, FileAccess.Write);
        var textLog = new StreamWriter(Path.Combine(sessionDir, "session.log"), false, Encoding.UTF8) { AutoFlush = true };

        await LogText(textLog, $"Session {id} from {ep} -> port {localPort} at {DateTime.UtcNow:O}");

        try
        {
            using (client)
            using (rawLog)
            using (textLog)
            {
                var rawStream = client.GetStream();
                rawStream.ReadTimeout = 15000;
                rawStream.WriteTimeout = 5000;

                Stream stream = rawStream;
                var state = new RdpSessionState();

                // ── Phase 1: X.224 Connection Request ──
                var x224 = await ReadTpktAsync(rawStream, rawLog, ct);
                if (x224 == null) { await LogText(textLog, "  (client disconnected before X.224)"); return; }

                await LogText(textLog, $"  ([{SessionPhase.WaitX224}] RX {x224.Length} bytes)");

                // 解析 client 是否要求協商 (NEG_REQ)
                var clientProtocols = RdpPacket.TryParseNegotiationRequest(x224);
                bool useNla = (clientProtocols & 0x02) != 0;
                bool useTls = (clientProtocols & 0x01) != 0;
                bool useSecureChannel = useTls || useNla;
                state.UseNla = useNla;

                // 提取 cookie
                if (x224.Length > 11)
                {
                    state.ClientInfo = $"cookie='{Encoding.ASCII.GetString(x224, 11, x224.Length - 11).TrimEnd('\0')}'";
                }

                // 回應 X.224 CC (含或不含 NEG_RSP)
                // Prefer CredSSP/NLA when the client advertises it; otherwise use SSL.
                uint selectedProtocol = useNla ? 0x02u : 0x01u;
                var cc = RdpPacket.BuildX224ConnectionConfirm(useSecureChannel, selectedProtocol);
                await LogText(textLog, $"  ([{SessionPhase.WaitX224}] TX {cc.Length} bytes{(useNla ? ", CredSSP/NLA" : useTls ? ", SSL/TLS" : ", standard")})");
                await rawLog.WriteAsync(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(cc.Length)), ct);
                await rawLog.WriteAsync(cc, ct);
                await rawLog.FlushAsync(ct);
                await rawStream.WriteAsync(cc, ct);

                // ── Phase 2: TLS 握手 (如果 client 要求) ──
                if (useSecureChannel)
                {
                    try
                    {
                        // ECDSA 憑證 + TLS 1.2 (ECDHE 金鑰交換)
                        // 注意: 不要嘗試降級 — 失敗後重試會導致 stream 狀態不一致
                        var ssl = new SslStream(rawStream, true);
                        var certContext = SslStreamCertificateContext.Create(_tlsCert, null);
                        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                        {
                            ServerCertificateContext = certContext,
                            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                            ClientCertificateRequired = false,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                        });
                        stream = ssl;
                        state.UseTls = true;
                        await LogText(textLog, $"  (TLS handshake established: {ssl.NegotiatedCipherSuite})");
                    }
                    catch (Exception ex)
                    {
                        await LogText(textLog, $"  (!) TLS handshake failed: {ex.Message}");
                        state.Phase = SessionPhase.Error;
                    }
                }

// CredSSP runs inside TLS before the MCS Connect Initial.
                if (useNla && state.Phase != SessionPhase.Error)
                {
                    var creds = await HandleNlaCredentialsAsync(stream, ct, textLog);
                    if (creds != null)
                    {
                        await SaveNlaCredentialAsync(id, ep, localPort, creds.Value.domain, creds.Value.username, creds.Value.password, ct);
                        var msg = creds.Value.password != null
                            ? $"  >>> NLA credential: {creds.Value.domain}\\{creds.Value.username}:{creds.Value.password}"
                            : $"  >>> NLA account: {creds.Value.domain}\\{creds.Value.username}";
                        await LogText(textLog, msg);
                    }

                    state.Phase = SessionPhase.Done;
                }

                // ── Phase 3+: 主循環 (MCS 握手 → 安全交換 → Info PDU) ──
                if (!useNla)
                    state.Phase = SessionPhase.WaitMCS;

                while (!ct.IsCancellationRequested &&
                       state.Phase != SessionPhase.Error &&
                       state.Phase != SessionPhase.Done)
                {
                    var tpkt = await ReadTpktAsync(stream, rawLog, ct);
                    if (tpkt == null) break;

                    await LogText(textLog, $"  ([{state.Phase}] RX {tpkt.Length} bytes)");

                    var response = await ProcessPacketAsync(state, tpkt);

                    if (response != null)
                    {
                        await LogText(textLog, $"  ([{state.Phase}] TX {response.Length} bytes)");
                        await rawLog.WriteAsync(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(response.Length)), ct);
                        await rawLog.WriteAsync(response, ct);
                        await rawLog.FlushAsync(ct);
                        await stream.WriteAsync(response, ct);
                        await Task.Delay(100, ct);
                    }

                    // 檢查憑證擷取
                    if (state.Credential != null)
                    {
                        await LogText(textLog, $"  >>> CAPTURED credential: {state.Credential}");
                        await SaveCredentialAsync(id, ep, localPort, state.Credential, ct);
                        state.Credential = null;
                    }

                    if (state.Phase == SessionPhase.Done || state.Phase == SessionPhase.Error)
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            await LogText(textLog, $"  [!] Error: {ex.Message}");
            Console.WriteLine($"[{id}] ! Error: {ex.Message}");
        }

        await LogText(textLog, $"Session {id} ended at {DateTime.UtcNow:O}");
        Console.WriteLine($"[{id}] - Connection closed");
    }

/// <summary>
    /// NLA 完整流程：NTLM Type 1/2/3 → SPNEGO accept → TSCredentials 解密
    /// 記錄 domain/username/password（不保存 NTLM hash）
    /// </summary>
    async Task<(string domain, string username, string? password)?> HandleNlaCredentialsAsync(
        Stream stream, CancellationToken ct, StreamWriter textLog)
    {
        for (var attempt = 0; attempt < 4 && !ct.IsCancellationRequested; attempt++)
        {
            var request = await ReadDerMessageAsync(stream, ct);
            if (request == null)
                return null;

            var ntlmOffset = IndexOf(request, "NTLMSSP\0"u8.ToArray());
            if (ntlmOffset < 0 || ntlmOffset + 12 > request.Length)
            {
                await LogText(textLog, $"  (NLA TSRequest {request.Length} bytes; NTLM token not found)");
                continue;
            }

            var messageType = ReadUInt32LE(request, ntlmOffset + 8);
            await LogText(textLog, $"  (NLA NTLM message type {messageType})");

            if (messageType == 1)
            {
                var challenge = BuildCredSspChallenge();
                await stream.WriteAsync(challenge, ct);
                await LogText(textLog, $"  (NLA NTLM challenge sent: {challenge.Length} bytes)");
                continue;
            }

            if (messageType == 3)
            {
                var domain = ReadNtlmUnicodeField(request, ntlmOffset, 28) ?? "";
                var username = ReadNtlmUnicodeField(request, ntlmOffset, 36) ?? "";
                if (string.IsNullOrWhiteSpace(username))
                    return null;

                // 寄出 SPNEGO accept-completed 讓 client 送出 TSCredentials
                var accept = BuildSpnegoAcceptResponse();
                await stream.WriteAsync(accept, ct);
                await LogText(textLog, $"  (SPNEGO accept-completed sent: {accept.Length} bytes)");

                // 讀取 TSCredentials TSRequest
                var tsCreds = await ReadDerMessageAsync(stream, ct);
                if (tsCreds == null)
                {
                    await LogText(textLog, $"  (no TSCredentials received)");
                    return (domain, username, null);
                }

                // 從 TSRequest 中提取 authInfo 內容
                var authInfo = ExtractAuthInfo(tsCreds);
                if (authInfo == null || authInfo.Length < 256)
                {
                    await LogText(textLog, $"  (authInfo too short: {authInfo?.Length ?? 0} bytes)");
                    return (domain, username, null);
                }

                // 解密 TSCredentials
                var password = DecryptTSCredentials(authInfo, _tlsRsaKey);
                if (password != null)
                {
                    await LogText(textLog, $"  >>> TSCredentials password: {password}");
                }
                else
                {
                    await LogText(textLog, $"  (TSCredentials decryption failed, saving raw)");
                    var raw = Path.Combine(_logDir, $"session_{_sessionCounter:D6}", "authInfo_raw.bin");
                    await File.WriteAllBytesAsync(raw, authInfo, ct);
                }

                return (domain, username, password);
            }
        }

        return null;
    }

    /// <summary>從 TSRequest DER 中提取 [2] authInfo OCTET STRING 的內容</summary>
    static byte[]? ExtractAuthInfo(byte[] tsRequest)
    {
        // 簡單搜尋：找 0xA2 (context-specific tag 2, constructed) 後跟長度，再跟 0x04 (OCTET STRING)
        for (var i = 0; i < tsRequest.Length - 2; i++)
        {
            if (tsRequest[i] == 0xA2)
            {
                // 解析長度
                int lenStart = i + 1;
                int contentLen;
                int dataStart;
                if ((tsRequest[lenStart] & 0x80) == 0)
                {
                    contentLen = tsRequest[lenStart];
                    dataStart = lenStart + 1;
                }
                else
                {
                    var numBytes = tsRequest[lenStart] & 0x7F;
                    if (numBytes == 0 || numBytes > 2) continue;
                    contentLen = 0;
                    for (var j = 0; j < numBytes; j++)
                        contentLen = (contentLen << 8) | tsRequest[lenStart + 1 + j];
                    dataStart = lenStart + 1 + numBytes;
                }

                // 內部應有 0x04 (OCTET STRING)
                if (dataStart < tsRequest.Length && tsRequest[dataStart] == 0x04)
                {
                    int octetLenStart = dataStart + 1;
                    int octetLen;
                    int octetData;
                    if ((tsRequest[octetLenStart] & 0x80) == 0)
                    {
                        octetLen = tsRequest[octetLenStart];
                        octetData = octetLenStart + 1;
                    }
                    else
                    {
                        var numBytes = tsRequest[octetLenStart] & 0x7F;
                        if (numBytes == 0 || numBytes > 2) continue;
                        octetLen = 0;
                        for (var j = 0; j < numBytes; j++)
                            octetLen = (octetLen << 8) | tsRequest[octetLenStart + 1 + j];
                        octetData = octetLenStart + 1 + numBytes;
                    }

                    if (octetData + octetLen <= tsRequest.Length)
                        return tsRequest[octetData..(octetData + octetLen)];
                }
            }
        }
        return null;
    }

    /// <summary>
    /// 解密 TSCredentials：
    /// authInfo = OAEP-SHA256-RSA 加密的 TSCredentialsKey (256 bytes) || AES-128-CBC 加密的 TSCredentials
    /// AES key = SHA-256(TSCredentialsKey || "CredSSP1")[0..15]
    /// AES IV  = SHA-256(TSCredentialsKey || "CredSSP1")[16..31]
    /// </summary>
    static string? DecryptTSCredentials(byte[] authInfo, RSA rsaKey)
    {
        try
        {
            // 前 256 bytes = 加密的 TSCredentialsKey (RSA-2048)
            var encryptedKey = authInfo[..256];
            var encryptedData = authInfo[256..];

            // RSA-OAEP-SHA256 解密
            var tsCredsKey = rsaKey.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);

            // 衍生 AES key + IV
            var label = "CredSSP1"u8.ToArray();
            var material = new byte[tsCredsKey.Length + label.Length];
            Array.Copy(tsCredsKey, material, tsCredsKey.Length);
            Array.Copy(label, 0, material, tsCredsKey.Length, label.Length);
            var hash = SHA256.HashData(material);

            var aesKey = hash[..16];
            var aesIv = hash[16..32];

            // AES-128-CBC 解密
            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = aesIv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            var decrypted = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            // 解析 TSPasswordCreds
            return ParseTSPasswordCreds(decrypted);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] TSCredentials decryption failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// 解析 TSCredentials ASN.1 → TSPasswordCreds
    /// TSCredentials ::= SEQUENCE {
    ///   credType    [0] INTEGER,
    ///   credentials [1] OCTET STRING  -- TSPasswordCreds
    /// }
    /// TSPasswordCreds ::= SEQUENCE {
    ///   domainName  [0] OCTET STRING,
    ///   userName    [1] OCTET STRING,
    ///   password    [2] OCTET STRING
    /// }
    /// </summary>
    static string? ParseTSPasswordCreds(byte[] der)
    {
        // 非常簡易的 ASN.1 解析：找到 [2] OCTET STRING 的內容
        // 依序搜尋 0xA0, 0xA1, 0xA2 context tags
        var password = FindContextOctetString(der, 0x02);
        return password != null ? Encoding.Unicode.GetString(password).TrimEnd('\0') : null;
    }

    /// <summary>在 DER 中搜尋 context tag [n] 內的 OCTET STRING 內容</summary>
    static byte[]? FindContextOctetString(byte[] data, int contextTag)
    {
        var tag = (byte)(0xA0 | contextTag);
        for (var i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == tag)
            {
                int lenStart = i + 1;
                int len;
                int contentStart;
                if ((data[lenStart] & 0x80) == 0)
                {
                    len = data[lenStart];
                    contentStart = lenStart + 1;
                }
                else
                {
                    var numBytes = data[lenStart] & 0x7F;
                    if (numBytes == 0 || numBytes > 2) continue;
                    len = 0;
                    for (var j = 0; j < numBytes; j++)
                        len = (len << 8) | data[lenStart + 1 + j];
                    contentStart = lenStart + 1 + numBytes;
                }

                // 內容應為 0x04 (OCTET STRING) 或直接是內容
                if (contentStart < data.Length && data[contentStart] == 0x04)
                {
                    int olStart = contentStart + 1;
                    int ol;
                    int od;
                    if ((data[olStart] & 0x80) == 0)
                    {
                        ol = data[olStart];
                        od = olStart + 1;
                    }
                    else
                    {
                        var nb = data[olStart] & 0x7F;
                        if (nb == 0 || nb > 2) continue;
                        ol = 0;
                        for (var j = 0; j < nb; j++)
                            ol = (ol << 8) | data[olStart + 1 + j];
                        od = olStart + 1 + nb;
                    }
                    if (od + ol <= data.Length)
                        return data[od..(od + ol)];
                }
            }
        }
        return null;
    }

    /// <summary>建構 SPNEGO accept-completed 包在 TSRequest 中</summary>
    static byte[] BuildSpnegoAcceptResponse()
    {
        // SPNEGO NegTokenResp: SEQUENCE { [0] ENUMERATED 0 (accept-completed) }
        // Without mechListMIC (may work on some clients)
        var negResult = Der(0xA0, [0x0A, 0x01, 0x00]); // [0] ENUMERATED 0
        var spnego = Der(0x30, negResult); // NegTokenResp

        // 包在 TSRequest 的 negoTokens 中
        var octet = Der(0x04, spnego);
        var token = Der(0xA0, octet);
        var item = Der(0x30, token);
        var tokenList = Der(0x30, item);
        var negoTokens = Der(0xA1, tokenList);
        var version = Der(0xA0, [0x02, 0x01, 0x05]);
        return Der(0x30, [.. version, .. negoTokens]);
    }

    /// <summary>儲存 NLA 帳號 + 密碼</summary>
    async Task SaveNlaCredentialAsync(
        long id, IPEndPoint ep, int localPort, string domain, string username, string? password, CancellationToken ct)
    {
        var entry = new
        {
            session_id = id,
            timestamp = DateTime.UtcNow,
            source_ip = ep.Address.ToString(),
            source_port = ep.Port,
            target_port = localPort,
            domain,
            username,
            password
        };

        var json = JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true });
        await File.AppendAllTextAsync(Path.Combine(_logDir, "nla_accounts.jsonl"), json + "\n", ct);
        await File.WriteAllTextAsync(
            Path.Combine(_logDir, $"session_{id:D6}", "nla_credential.json"), json, ct);

        if (!string.IsNullOrEmpty(password))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ═══ NLA CREDENTIAL CAPTURED ═══");
            Console.WriteLine($"  IP: {ep.Address}:{ep.Port} -> port {localPort}");
            Console.WriteLine($"  User: {username}");
            Console.WriteLine($"  Pass: {password}");
            Console.WriteLine($"  Domain: {domain}");
            Console.ResetColor();
        }
    }

    static async Task<byte[]?> ReadDerMessageAsync(Stream stream, CancellationToken ct)
    {
        var first = new byte[2];
        if (!await ReadExactlyAsync(stream, first, ct)) return null;
        if (first[0] != 0x30) return null;

        var lengthBytes = new List<byte> { first[1] };
        var length = (int)first[1];
        if ((length & 0x80) != 0)
        {
            var count = length & 0x7F;
            if (count is < 1 or > 2) return null;
            var extended = new byte[count];
            if (!await ReadExactlyAsync(stream, extended, ct)) return null;
            lengthBytes.AddRange(extended);
            length = 0;
            foreach (var b in extended) length = (length << 8) | b;
        }

        if (length > 1024 * 1024) return null;
        var body = new byte[length];
        if (!await ReadExactlyAsync(stream, body, ct)) return null;
        return [first[0], .. lengthBytes, .. body];
    }

    static async Task<bool> ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }

    static int IndexOf(byte[] data, byte[] needle)
    {
        for (var i = 0; i <= data.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (data[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    static uint ReadUInt32LE(byte[] data, int offset)
    {
        if (offset < 0 || offset + 4 > data.Length) return 0;
        return (uint)(data[offset] | (data[offset + 1] << 8) |
                      (data[offset + 2] << 16) | (data[offset + 3] << 24));
    }

    static string? ReadNtlmUnicodeField(byte[] message, int ntlmOffset, int relativeFieldOffset)
    {
        var fieldOffset = ntlmOffset + relativeFieldOffset;
        if (fieldOffset < 0 || fieldOffset + 8 > message.Length) return null;
        var length = message[fieldOffset] | (message[fieldOffset + 1] << 8);
        // NTLM security-buffer offsets are relative to the NTLMSSP message start.
        var offset = ntlmOffset + (int)ReadUInt32LE(message, fieldOffset + 4);
        if (length == 0 || offset < 0 || offset + length > message.Length || (length & 1) != 0)
            return null;
        return Encoding.Unicode.GetString(message, offset, length).TrimEnd('\0');
    }

    static byte[] BuildCredSspChallenge()
    {
        var workstation = Encoding.Unicode.GetBytes("WINNT");
        var avPairs = new MemoryStream();
        var av = new BinaryWriter(avPairs);
        foreach (var id in new ushort[] { 2, 1, 4, 3, 5 })
        {
            av.Write(id);
            av.Write((ushort)workstation.Length);
            av.Write(workstation);
        }
        av.Write((ushort)0); // MsvAvEOL
        av.Write((ushort)0);

        var targetInfo = avPairs.ToArray();
        var targetInfoOffset = 0x38 + workstation.Length;
        var ntlm = new byte[targetInfoOffset + targetInfo.Length];
        var signature = Encoding.ASCII.GetBytes("NTLMSSP\0");
        Array.Copy(signature, ntlm, signature.Length);
        WriteUInt32LE(ntlm, 8, 2); // CHALLENGE_MESSAGE
        WriteUInt16LE(ntlm, 12, (ushort)workstation.Length);
        WriteUInt16LE(ntlm, 14, (ushort)workstation.Length);
        WriteUInt32LE(ntlm, 16, 0x38);
        WriteUInt32LE(ntlm, 20, 0xE28A8215);
        RandomNumberGenerator.Fill(ntlm.AsSpan(24, 8));
        // reserved[8] remains zero
        WriteUInt16LE(ntlm, 40, (ushort)targetInfo.Length);
        WriteUInt16LE(ntlm, 42, (ushort)targetInfo.Length);
        WriteUInt32LE(ntlm, 44, (uint)targetInfoOffset);
        ntlm[48] = 0x06; ntlm[49] = 0x02;
        WriteUInt16LE(ntlm, 50, 0x0ECE);
        ntlm[52] = 0; ntlm[53] = 0; ntlm[54] = 0; ntlm[55] = 0x0F;
        Array.Copy(workstation, 0, ntlm, 0x38, workstation.Length);
        Array.Copy(targetInfo, 0, ntlm, targetInfoOffset, targetInfo.Length);

        // TSRequest with version=5 and negoTokens containing the NTLM challenge.
        var octet = Der(0x04, ntlm);
        var token = Der(0xA0, octet);
        var item = Der(0x30, token);
        var tokenList = Der(0x30, item);
        var negoTokens = Der(0xA1, tokenList);
        var version = Der(0xA0, [0x02, 0x01, 0x05]);
        return Der(0x30, [.. version, .. negoTokens]);
    }

    static byte[] Der(byte tag, byte[] content)
    {
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);
        bw.Write(tag);
        if (content.Length < 128) bw.Write((byte)content.Length);
        else { bw.Write((byte)0x82); bw.Write((byte)(content.Length >> 8)); bw.Write((byte)content.Length); }
        bw.Write(content);
        return ms.ToArray();
    }

    static void WriteUInt16LE(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
    }

    static void WriteUInt32LE(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
        data[offset + 2] = (byte)(value >> 16);
        data[offset + 3] = (byte)(value >> 24);
    }

    /// <summary>讀取一個完整的 TPKT 封包 (支援泛用 Stream)</summary>
    static async Task<byte[]?> ReadTpktAsync(Stream stream, FileStream rawLog, CancellationToken ct)
    {
        // TPKT header: 4 bytes (version, reserved, length big-endian)
        var header = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = await stream.ReadAsync(header, read, 4 - read, ct);
            if (n == 0) return null;
            read += n;
        }

        await rawLog.WriteAsync(header, ct);

        int length = (header[2] << 8) | header[3];
        if (length < 4) return null;

        var body = new byte[length - 4];
        read = 0;
        while (read < body.Length)
        {
            int n = await stream.ReadAsync(body, read, body.Length - read, ct);
            if (n == 0) return null;
            read += n;
        }

        await rawLog.WriteAsync(body, ct);
        await rawLog.FlushAsync(ct);

        return [.. header, .. body];
    }

    /// <summary>根據目前階段處理封包並產生回應</summary>
    Task<byte[]?> ProcessPacketAsync(RdpSessionState state, byte[] packet)
    {
        return state.Phase switch
        {
            SessionPhase.WaitMCS => Task.FromResult(HandleMCSConnectInitial(state, packet)),
            SessionPhase.WaitErectDomain => Task.FromResult(HandleErectDomainRequest(state, packet)),
            SessionPhase.WaitAttachUser => Task.FromResult(HandleAttachUserRequest(state, packet)),
            SessionPhase.WaitChannelJoin => Task.FromResult(HandleChannelJoinRequest(state, packet)),
            SessionPhase.WaitSecurityExchange => HandleSecurityExchange(state, packet),
            SessionPhase.WaitInfo => Task.FromResult(HandleInfoPDU(state, packet)),
            _ => Task.FromResult<byte[]?>(null)
        };
    }

    /// <summary>MCS Erect Domain Request → 不回應，直接進下一個階段</summary>
    byte[]? HandleErectDomainRequest(RdpSessionState state, byte[] packet)
    {
        // 確認是 Erect Domain Request (0x04)
        if (packet.Length < 8 || packet[7] != 0x04)
        {
            // 不是 Erect Domain Request，可能 client 直接跳過了
            // 把這個封包當作 Attach User Request 重新處理
            state.Phase = SessionPhase.WaitAttachUser;
            return HandleAttachUserRequest(state, packet);
        }

        // Erect Domain Request 不需要回應，直接進 Attach User 階段
        state.Phase = SessionPhase.WaitAttachUser;
        return null; // 不回傳任何東西
    }

    /// <summary>MCS Attach User Request → Attach User Confirm</summary>
    byte[]? HandleAttachUserRequest(RdpSessionState state, byte[] packet)
    {
        // 確認是 Attach User Request (0x28)
        if (packet.Length < 8 || packet[7] != 0x28)
        {
            state.Phase = SessionPhase.Error;
            return null;
        }

        // 建構 Attach User Confirm:
        // TPKT(4) + X.224(3) + MCS header(0x2E) + result(1) + user_id(2)
        var confirm = new byte[] {
            0x03, 0x00, 0x00, 0x0B, // TPKT length 11
            0x02, 0xF0, 0x80,       // X.224 Data
            0x2E,                   // MCS AttachUserConfirm, options=2 (end)
            0x00,                   // result = 0 (success)
            0x00, 0x01              // user_id = 1002 - 1001 (MCS_BASE_CHANNEL_ID)
        };

        state.Phase = SessionPhase.WaitChannelJoin;
        return confirm;
    }

    /// <summary>MCS Channel Join Request → Channel Join Confirm</summary>
    byte[]? HandleChannelJoinRequest(RdpSessionState state, byte[] packet)
    {
        // 確認是 Channel Join Request (0x38)
        if (packet.Length < 8 || packet[7] != 0x38)
        {
            state.Phase = SessionPhase.Error;
            return null;
        }

        // 解析 channel_id (從 PER 編碼中)
        // 格式: 0x38 + initiator(2 bytes) + channel_id(2 bytes)
        if (packet.Length < 12)
        {
            state.Phase = SessionPhase.Error;
            return null;
        }

        var requestedChannel = (ushort)((packet[10] << 8) | packet[11]);
        state.ChannelId = requestedChannel;

        // 建構 Channel Join Confirm:
        // TPKT(4) + X.224(3) + MCS header(0x3E) + result(1) + initiator(2) + requested(2) + channelId(2)
        var confirm = new byte[] {
            0x03, 0x00, 0x00, 0x0F, // TPKT length 15
            0x02, 0xF0, 0x80,       // X.224 Data
            0x3E,                   // MCS ChannelJoinConfirm, options=2 (end)
            0x00,                   // result = 0 (success)
            0x00, 0x01,             // initiator = 1002 - 1001
            (byte)(requestedChannel >> 8), (byte)requestedChannel, // requested channel
            (byte)(requestedChannel >> 8), (byte)requestedChannel  // assigned channel (same)
        };

        // 注意：如果 client 有多個 channel 要 join，我們需要繼續等待
        // 如果 join 的是 global channel (1003)，則進入 Security Exchange 階段
        state.Phase = (requestedChannel == 1003)
            ? SessionPhase.WaitSecurityExchange
            : SessionPhase.WaitChannelJoin; // 繼續等待其他 channel join

        return confirm;
    }

    /// <summary>MCS Connect Initial → 回傳 Connect Response (含 Server 憑證)</summary>
    byte[]? HandleMCSConnectInitial(RdpSessionState state, byte[] packet)
    {
        try
        {
            // 嘗試從 MCS Connect Initial 中提取 client 資訊
            var info = RdpPacket.ParseMCSConnectInitial(packet);
            state.ClientInfo = string.IsNullOrEmpty(state.ClientInfo)
                ? info
                : $"{state.ClientInfo}; {info}";
        }
        catch { /* 忽略解析失敗 */ }

        // [DEBUG] 輸出 MCS Connect Initial 內容
        Console.WriteLine($"  [DBG] MCS Connect Initial: {packet.Length} bytes");
        Console.WriteLine($"  [DBG] First 80: {Convert.ToHexString(packet[..Math.Min(80, packet.Length)])}");

        // 建構 MCS Connect Response (含 server 憑證與 random)
        // TLS 模式下不包含 RSA 憑證 (TLS 已提供加密)
        var response = RdpPacket.BuildMCSConnectResponse(_serverCert, _rsaKey, _serverRandom, state.UseTls);
        Console.WriteLine($"  [DBG] MCS Connect Response built: {response.Length} bytes");
        Console.WriteLine($"  [DBG] Response first 120: {Convert.ToHexString(response[..Math.Min(120, response.Length)])}");

        state.Phase = SessionPhase.WaitErectDomain;
        return response;
    }

    /// <summary>Security Exchange PDU → 解密 client random，推算 RC4 金鑰</summary>
    async Task<byte[]?> HandleSecurityExchange(RdpSessionState state, byte[] packet)
    {
        try
        {
            // 實際封包結構 (client → server):
            // TPKT + X.224 Data + MCS Send Data Request (0x64) + RDP security header + payload
            // TLS 模式下 client 可能直接送 Info PDU (SEC_INFO_PKT)，沒有 Security Exchange
            var payload = RdpPacket.ExtractPayloadForTls(packet);
            if (payload == null || payload.Length == 0)
            {
                // 沒有 payload → 當作標準 Security Exchange (空) 處理
            }
            else
            {
                // 檢查 RDP security flags
                var flags = ExtractSecurityFlags(packet);
                bool isInfoPdu = (flags & 0x0040) != 0; // SEC_INFO_PKT

                if (isInfoPdu)
                {
                    // 這是 Info PDU，不是 Security Exchange！
                    await LogInfoPduAsync(packet, state, payload);
                    state.Phase = SessionPhase.Done;
                    return RdpPacket.BuildDataAck();
                }

                // 標準 Security Exchange: 解密 client random (RSA 2048)
                var clientRandom = CryptoHelper.DecryptClientRandom(payload, _rsaKey);

                if (clientRandom != null && clientRandom.Length == 32)
                {
                    state.ClientRandom = clientRandom;

                    // 衍生 RC4 session keys
                    var (decryptKey, encryptKey) = CryptoHelper.DeriveSessionKeys(
                        clientRandom, _serverRandom);

                    state.DecryptKey = decryptKey;
                    state.EncryptKey = encryptKey;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Security exchange parse error: {ex.Message}");
            state.Phase = SessionPhase.Error;
            return null;
        }

        // 回應一個空的 Data Ack (讓 client 繼續)
        var ack = RdpPacket.BuildDataAck();
        state.Phase = SessionPhase.WaitInfo;
        return ack;
    }

    /// <summary>從封包中提取 RDP security header 的 flags (16-bit little-endian)</summary>
    static ushort ExtractSecurityFlags(byte[] packet)
    {
        // 找 MCS choice byte (0x64 = Send Data Request) 之後的 dataPriority + segmentation
        for (var i = 6; i < packet.Length - 6; i++)
        {
            if (packet[i] == 0x64 && packet[i + 1] != 0xFF)
            {
                // MCS: choice(1) + initiator(2) + channel(2) + priority(1) + segmentation(1)
                int p = i + 1 + 2 + 2 + 1 + 1;
                if (p + 4 <= packet.Length)
                {
                    return (ushort)(packet[p] | (packet[p + 1] << 8));
                }
            }
        }
        return 0;
    }

    /// <summary>直接處理 Info PDU payload 並紀錄帳密</summary>
    async Task LogInfoPduAsync(byte[] packet, RdpSessionState state, byte[] payload)
    {
        try
        {
            var cred = RdpPacket.ParseInfoPDU(payload);
            if (cred != null)
            {
                state.Credential = cred with { ClientInfo = state.ClientInfo };
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ═══ CREDENTIAL CAPTURED ═══");
                Console.WriteLine($"  User: {cred.Username}");
                Console.WriteLine($"  Pass: {cred.Password}");
                Console.WriteLine($"  Domain: {cred.Domain}");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine($"  [!] Info PDU parse failed (payload={payload.Length} bytes)");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Info PDU parse error: {ex.Message}");
        }
    }

    /// <summary>Info PDU → 解密並提取帳號密碼 (支援 TLS 明文與 RC4 兩種)</summary>
    byte[]? HandleInfoPDU(RdpSessionState state, byte[] packet)
    {
        try
        {
            var payload = RdpPacket.ExtractPayloadForTls(packet);
            if (payload == null || payload.Length == 0)
            {
                Console.WriteLine("  [!] Info PDU: 無法提取 payload");
                state.Phase = SessionPhase.Error;
                return null;
            }

            // 方式 1: 直接當明文解析 (TLS 通道已解密，或未加密)
            var cred = RdpPacket.ParseInfoPDU(payload);

            // 方式 2: 若明文解析失敗且有 RC4 key，嘗試 RC4 解密後再解析
            if (cred == null && state.DecryptKey != null)
            {
                var decrypted = CryptoHelper.RC4Decrypt(state.DecryptKey, payload);
                cred = RdpPacket.ParseInfoPDU(decrypted);
            }

            if (cred != null)
            {
                state.Credential = cred with { ClientInfo = state.ClientInfo };
            }
            else
            {
                Console.WriteLine($"  [!] Info PDU: 解析失敗 (payload={payload.Length} bytes, hasKey={state.DecryptKey != null})");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Info PDU parse error: {ex.Message}");
        }

        // 回應一個 Data Ack (或關閉連線)
        state.Phase = SessionPhase.Done;
        return RdpPacket.BuildDataAck();
    }

    async Task LogText(StreamWriter w, string line)
    {
        await w.WriteLineAsync(line);
        Console.WriteLine($"  {line}");
    }

    async Task SaveCredentialAsync(long id, IPEndPoint ep, int localPort, CapturedCredential cred, CancellationToken ct)
    {
        var entry = new
        {
            session_id = id,
            timestamp = DateTime.UtcNow,
            source_ip = ep.Address.ToString(),
            source_port = ep.Port,
            target_port = localPort,
            username = cred.Username,
            password = cred.Password,
            domain = cred.Domain,
            client_info = cred.ClientInfo
        };

        var json = JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true });
        var path = Path.Combine(_logDir, "captured_creds.jsonl");
        await File.AppendAllTextAsync(path, json + "\n", ct);

        // 也存單獨檔案
        var credPath = Path.Combine(_logDir, $"session_{id:D6}", "credential.json");
        await File.WriteAllTextAsync(credPath, json, ct);

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ═══ CREDENTIAL CAPTURED ═══");
        Console.WriteLine($"  IP: {ep.Address}:{ep.Port} -> port {localPort}");
        Console.WriteLine($"  User: {cred.Username}");
        Console.WriteLine($"  Pass: {cred.Password}");
        Console.WriteLine($"  Domain: {cred.Domain}");
        Console.ResetColor();
    }
}

/// <summary>RDP 連線狀態</summary>
enum SessionPhase
{
    WaitX224,
    WaitMCS,
    WaitErectDomain,
    WaitAttachUser,
    WaitChannelJoin,
    WaitSecurityExchange,
    WaitInfo,
    Done,
    Error
}

/// <summary>單一連線階段的狀態</summary>
class RdpSessionState
{
    public SessionPhase Phase { get; set; } = SessionPhase.WaitX224;
    public string? ClientInfo { get; set; }
    public byte[]? ClientRandom { get; set; }
    public byte[]? DecryptKey { get; set; }
    public byte[]? EncryptKey { get; set; }
    public bool UseTls { get; set; }
    public bool UseNla { get; set; }
    public ushort UserId { get; set; }
    public ushort ChannelId { get; set; }
    public CapturedCredential? Credential { get; set; }
}

/// <summary>擷取到的憑證資訊</summary>
record CapturedCredential(string? Username, string? Password, string? Domain, string? ClientInfo);
