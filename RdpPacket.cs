using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RdpHoneypot;

/// <summary>
/// RDP 協定封包建構與解析 (參考 MS-RDPBCGR)
/// 防禦型蜜罐用途，僅限授權環境使用
/// </summary>
static class RdpPacket
{
    /// <summary>
    /// 建構 X.224 Connection Confirm (含 MCS Connect Response 起始)
    /// 該封包讓 mstsc 願意繼續握手流程
    /// </summary>
    public static byte[] BuildX224ConnectionConfirm(bool includeSslNegotiation = false, uint selectedProtocol = 0x01)
    {
        if (includeSslNegotiation)
        {
            // 標準格式 (MS-RDPBCGR 2.2.1.2): 19 bytes
            // TPKT(4) + LI=0x0E(1) + CC=0xD0(1) + DST(2) + SRC(2) + Class(1) + RDP_NEG_RSP(8)
            // RDP_NEG_RSP: type=0x02, flags=0x00, length=0x0008, selectedProtocol=0x00000001 (SSL)
            return
            [
                0x03, 0x00, 0x00, 0x13, // TPKT (length 19)
                0x0E,                   // X.224 LI = 14
                0xD0,                   // X.224 Connection Confirm
                0x00, 0x00,             // DST reference
                0x00, 0x00,             // SRC reference
                0x00,                   // Class & options
                // RDP_NEG_RSP: selectedProtocol (0x01 = SSL, 0x02 = CredSSP/NLA)
                0x02, 0x00, 0x08, 0x00,
                (byte)(selectedProtocol & 0xFF),
                (byte)((selectedProtocol >> 8) & 0xFF),
                (byte)((selectedProtocol >> 16) & 0xFF),
                (byte)((selectedProtocol >> 24) & 0xFF)
            ];
        }

        // TPKT header (03 00) + 長度 + X.224 CC (0x0E) + MCS Connect Response 簡化版
        // 這個封包結構是基於 RDP 協定標準的簡化實現
        return
        [
            // TPKT + X.224 CC
            0x03, 0x00, 0x00, 0x14, // TPKT (length 20 = 此陣列實際長度)
            0x0E,                   // X.224 Connection Confirm (DT)
            0xD0, 0x00,             // DST reference
            0x00, 0x00,             // SRC reference
            0x12, 0x34,             // Class & options
            0x00,                   // Extended options
            // MCS Connect Response fragment (讓 client 繼續握手)
            0x02, 0x09, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00
        ];
    }

    /// <summary>
    /// 建構 X.224 Connection Confirm with RDP_NEG_FAILURE。
    /// </summary>
    public static byte[] BuildX224ConnectionFailure(uint failureCode)
    {
        return
        [
            0x03, 0x00, 0x00, 0x13,
            0x0E, 0xD0,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x03, 0x00, 0x08, 0x00,
            (byte)(failureCode & 0xFF),
            (byte)((failureCode >> 8) & 0xFF),
            (byte)((failureCode >> 16) & 0xFF),
            (byte)((failureCode >> 24) & 0xFF)
        ];
    }

    /// <summary>
    /// 嘗試從 X.224 Connection Request 中解析 RDP_NEG_REQ
    /// 回傳 client 要求協商的協定 bitmask (0 = 無協商要求)
    /// RDP_NEG_REQ 位於 X.224 CR 的**最後 8 bytes**
    /// </summary>
    public static uint TryParseNegotiationRequest(byte[] packet)
    {
        if (packet.Length < 19) return 0;

        int offset = packet.Length - 8;
        if (offset < 0) return 0;

        // RDP_NEG_REQ 結構 (8 bytes):
        //   type (1) = 0x01, flags (1) = 0x00
        //   length (2) = 0x0008
        //   requestedProtocols (4) = bitmask (不能用 0x0000)
        if (packet[offset] == 0x01 && packet[offset + 1] == 0x00 &&
            packet[offset + 2] == 0x08 && packet[offset + 3] == 0x00)
        {
            uint protocols = BitConverter.ToUInt32(packet, offset + 4);
            // 已知協定位元：SSL/TLS=0x01、HYBRID/NLA=0x02、
            // RDSTLS=0x04、HYBRID_EX=0x08。
            // 本蜜罐只會選擇實際支援的 SSL/HYBRID，其他位元保留給選擇器判斷。
            if ((protocols & 0x0F) != 0)
                return protocols;
        }
        return 0;
    }

    /// <summary>
    /// 從 MCS Connect Initial 中提取 client 資訊 (hostname, 使用者等)
    /// </summary>
    public static string ParseMCSConnectInitial(byte[] data)
    {
        // MCS Connect Initial 封包中包含 GCC client data
        // 其中包含 hostname 等資訊，以 ASCII 編碼
        var parts = new List<string>();

        // 搜尋可讀字串 (hostname, 版本等)
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] >= 0x20 && data[i] <= 0x7E &&
                data[i + 1] >= 0x20 && data[i + 1] <= 0x7E &&
                data[i + 2] >= 0x20 && data[i + 2] <= 0x7E)
            {
                var sb = new StringBuilder();
                while (i < data.Length && data[i] >= 0x20 && data[i] <= 0x7E)
                {
                    sb.Append((char)data[i]);
                    i++;
                }
                var token = sb.ToString();
                if (token.Length >= 4 && !parts.Contains(token))
                    parts.Add(token);
            }
        }

        return parts.Count > 0 ? string.Join(", ", parts) : "(no readable data)";
    }

    /// <summary>
    /// 建構 MCS Connect Response (含 Server Security Data / 憑證 / ServerRandom)
    /// 這是 RDP 握手最關鍵的封包
    /// 
    /// useTls=true 時: TLS 已提供加密，Server Security Data 不包含 RSA 憑證 (certLen=0)
    /// </summary>
    public static byte[] BuildMCSConnectResponse(X509Certificate2 cert, RSA rsaKey, byte[] serverRandom, bool useTls = false)
    {
        // 1. 建構 Server Security Data。
        // TLS/SSL 模式只包含 method + level；RDP 標準安全模式另外包含
        // 4-byte random length、4-byte certificate length、random 與 certificate。
        var certDer = cert.Export(X509ContentType.Cert);

        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);

        // TLS 模式：ENCRYPTION_METHOD_NONE / ENCRYPTION_LEVEL_NONE。
        bw.Write(useTls ? 0u : 7u);
        bw.Write(useTls ? 0u : 2u);
        if (!useTls)
        {
            // MS-RDPBCGR 使用 4-byte 長度欄位，不是 2-byte。
            bw.Write((uint)serverRandom.Length);
            bw.Write((uint)certDer.Length);
            bw.Write(serverRandom);
            bw.Write(certDer);
        }

        var serverSecurityData = ms.ToArray();

        // 4. 建構 GCC Server Data (Domain Parameters 的 BER 編碼)
        // 標準 RDP domain parameters (MS-RDPBCGR):
        //   maxChannelIds=1001, maxUserIds=3, maxTokenIds=4, numPriorities=1,
        //   minThroughput=0, maxHeight=1, maxMCSPDUsize=65535, protocolVersion=2
        // 注意: SEQUENCE (universal, construct) = 0x30
        var domainParams = new byte[]
        {
            0x30, 0x1D,                    // SEQUENCE (29 bytes)
            0x02, 0x02, 0x03, 0xE9,        // maxChannelIds = 1001
            0x02, 0x02, 0x00, 0x03,        // maxUserIds = 3
            0x02, 0x02, 0x00, 0x04,        // maxTokenIds = 4
            0x02, 0x01, 0x01,              // numPriorities = 1
            0x02, 0x01, 0x00,              // minThroughput = 0
            0x02, 0x01, 0x01,              // maxHeight = 1
            0x02, 0x03, 0x00, 0xFF, 0xFF,  // maxMCSPDUsize = 65535
            0x02, 0x01, 0x02               // protocolVersion = 2
        };

        // 5. 建構 GCC blocks，再包成 T.124 ConferenceCreateResponse。
        var serverDataBlocks = BuildGCCUserData(serverSecurityData, useTls);
        var gccConferenceResponse = BuildGccConferenceCreateResponse(serverDataBlocks);

        // 6. 建構完整的 MCS Connect Response (含 X.224 Data + MCS 封裝)
        // 格式 (參考 pyRDP / MS-RDPBCGR):
        //   TPKT(4) + X.224 Data(02 F0 80) + MCS(7F 66) + BER length + content
        //   content = ENUMERATED result + INTEGER calledConnectID + domainParams + OCTET STRING userData
        var mcsResponse = BuildMCSConnectResponsePDU(domainParams, gccConferenceResponse);

        // 7. 完整封裝: TPKT + X.224 Data + MCS Response
        // X.224 Data PDU: LI=0x02, header=0xF0 (Data, roa=0), eot=0x80
        var payload = new byte[3 + mcsResponse.Length];
        payload[0] = 0x02;   // X.224 LI
        payload[1] = 0xF0;   // X.224 Data TPDU
        payload[2] = 0x80;   // EOT flag
        Array.Copy(mcsResponse, 0, payload, 3, mcsResponse.Length);

        var tpkt = new byte[4 + payload.Length];
        tpkt[0] = 0x03; // TPKT version
        tpkt[1] = 0x00; // Reserved
        tpkt[2] = (byte)((tpkt.Length >> 8) & 0xFF);
        tpkt[3] = (byte)(tpkt.Length & 0xFF);
        Array.Copy(payload, 0, tpkt, 4, payload.Length);

        return tpkt;
    }

    /// <summary>建構 GCC Server Data blocks (FreeRDP 順序: Core、Network、Security)</summary>
    static byte[] BuildGCCUserData(byte[] serverSecurityData, bool useTls)
    {
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);

        // Server Core Data (SC_CORE = 0x0C01)。FreeRDP 寫入 16 bytes：
        // version + clientRequestedProtocols + earlyCapabilityFlags。
        bw.Write((ushort)0x0C01);
        bw.Write((ushort)16);
        bw.Write(0x00080004);
        bw.Write(useTls ? 1u : 0u); // PROTOCOL_SSL / PROTOCOL_RDP
        bw.Write(0u);               // earlyCapabilityFlags

        // Server Network Data (SC_NET = 0x0C03)。MCS global channel 是 1003。
        bw.Write((ushort)0x0C03);
        bw.Write((ushort)8);
        bw.Write((ushort)1003); // MCS_GLOBAL_CHANNEL_ID
        bw.Write((ushort)0);    // channelCount = 0

        // Server Security Data (SC_SECURITY = 0x0C02)
        bw.Write((ushort)0x0C02);
        bw.Write((ushort)(4 + serverSecurityData.Length)); // type/length header included
        bw.Write(serverSecurityData);

        // 加上 Pad 到 4-byte 對齊
        while (ms.Length % 4 != 0)
            bw.Write((byte)0);

        return ms.ToArray();
    }

    /// <summary>
    /// T.124 ConferenceCreateResponse wrapper around the server GCC data blocks.
    /// This PER structure is the payload of the MCS userData OCTET STRING.
    /// </summary>
    static byte[] BuildGccConferenceCreateResponse(byte[] serverDataBlocks)
    {
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);

        // ConnectData: h221NonStandard identifier.
        bw.Write((byte)0x00); // select object identifier
        bw.Write((byte)0x05); // OID length
        bw.Write((byte)0x00); // 0.0
        bw.Write((byte)0x14); // 20
        bw.Write((byte)0x7C); // 124
        bw.Write((byte)0x00); // version
        bw.Write((byte)0x01); // revision

        // FreeRDP emits this legacy connectPDU length and Microsoft ignores it.
        bw.Write((byte)0x2A);
        // ConferenceCreateResponse choice.
        bw.Write((byte)0x14);
        // nodeID relative to MCS base channel 1001.
        WritePerInteger16(bw, 0x79F3, 1001);
        // Conference response tag.
        WritePerInteger(bw, 1);
        // MCS result: successful.
        bw.Write((byte)0x00);
        // One UserData set, value present and h221NonStandard selected.
        bw.Write((byte)0x01);
        bw.Write((byte)0xC0);
        // Server-to-client H.221 key: "McDn".
        WritePerOctetString(bw, Encoding.ASCII.GetBytes("McDn"), 4);
        // GCC server data blocks.
        WritePerOctetString(bw, serverDataBlocks, 0);

        return ms.ToArray();
    }

    static void WritePerLength(BinaryWriter bw, int length)
    {
        if (length > 0x7F)
        {
            bw.Write((byte)(0x80 | ((length >> 8) & 0x7F)));
            bw.Write((byte)(length & 0xFF));
        }
        else
        {
            bw.Write((byte)length);
        }
    }

    static void WritePerInteger(BinaryWriter bw, uint value)
    {
        if (value <= byte.MaxValue)
        {
            bw.Write((byte)1);
            bw.Write((byte)value);
        }
        else if (value <= ushort.MaxValue)
        {
            bw.Write((byte)2);
            WriteBigEndianUInt16(bw, (ushort)value);
        }
        else
        {
            bw.Write((byte)4);
            bw.Write((byte)(value >> 24));
            bw.Write((byte)(value >> 16));
            bw.Write((byte)(value >> 8));
            bw.Write((byte)value);
        }
    }

    static void WritePerInteger16(BinaryWriter bw, ushort value, ushort minimum)
    {
        WriteBigEndianUInt16(bw, (ushort)(value - minimum));
    }

    static void WritePerOctetString(BinaryWriter bw, byte[] value, ushort minimum)
    {
        WritePerLength(bw, Math.Max(0, value.Length - minimum));
        bw.Write(value);
    }

    static void WriteBigEndianUInt16(BinaryWriter bw, ushort value)
    {
        bw.Write((byte)(value >> 8));
        bw.Write((byte)value);
    }

    /// <summary>
    /// 建構 MCS Connect Response PDU (T.125 BER 編碼，參考 pyRDP)
    /// 
    /// 格式:
    ///   7F 66 [BER length] [content]
    ///   content = ENUMERATED result + INTEGER calledConnectID + domainParameters + OCTET STRING userData
    /// 
    /// 注意: 沒有 SEQUENCE 外層包裝！各欄位直接依序排列，外面只包 BER length。
    /// </summary>
    static byte[] BuildMCSConnectResponsePDU(byte[] domainParams, byte[] gccUserData)
    {
        // UserData OCTET STRING (04 [len] [data])
        var userDataBer = EncodeBEROctetString(gccUserData);

        // 內容 (依序排列，無 SEQUENCE):
        using var inner = new MemoryStream();
        var ibw = new BinaryWriter(inner);

        // result = RT_SUCCESSFUL (ENUMERATED): 0A 01 00
        ibw.Write((byte)0x0A); ibw.Write((byte)0x01); ibw.Write((byte)0x00);
        // calledConnectId = 1 (INTEGER): 02 01 01
        ibw.Write((byte)0x02); ibw.Write((byte)0x01); ibw.Write((byte)0x01);
        // Domain Parameters (已含 SEQUENCE 0x30 包裝)
        ibw.Write(domainParams);
        // User Data (OCTET STRING)
        ibw.Write(userDataBer);

        var content = inner.ToArray();

        // MCS Connect Response PDU:
        // 7F (BER_CLASS_APPL | BER_CONSTRUCT | BER_TAG_MASK) + 66 (CONNECT_RESPONSE header) + BER length + content
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);

        bw.Write((byte)0x7F);   // application tag (construct)
        bw.Write((byte)0x66);   // MCS Connect Response PDU header (CONNECT_RESPONSE = 0x66)
        WriteBERLength(bw, content.Length);
        bw.Write(content);

        return ms.ToArray();
    }

    /// <summary>BER 長度編碼 (小於 128 用 1 byte，否則 0x82 + 2 bytes big-endian)</summary>
    static void WriteBERLength(BinaryWriter bw, int length)
    {
        if (length < 128)
        {
            bw.Write((byte)length);
        }
        else
        {
            bw.Write((byte)0x82);
            bw.Write((byte)((length >> 8) & 0xFF));
            bw.Write((byte)(length & 0xFF));
        }
    }

    /// <summary>BER OCTET STRING 編碼</summary>
    static byte[] EncodeBEROctetString(byte[] data)
    {
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);

        bw.Write((byte)0x04); // OCTET STRING tag
        WriteBERLength(bw, data.Length);
        bw.Write(data);

        return ms.ToArray();
    }

    /// <summary>
    /// 從 TLS 模式的 RDP 封包中提取真正的 payload，
    /// 跳過 TPKT + X.224 + MCS Send Data Request/Indication + RDP security header。
    /// 支援 0x64 (Send Data Request) 與 0x04 (Send Data Indication) 兩種 MCS 類型。
    /// </summary>
    public static byte[]? ExtractPayloadForTls(byte[] packet)
    {
        if (packet.Length < 15) return null;

        // TPKT (4) + X.224 Data (3)
        int pos = 4;
        while (pos < packet.Length && packet[pos] != 0xF0)
            pos++;
        if (pos >= packet.Length - 1) return null;
        pos += 2; // skip PDU type (0xF0) + EOT flag (1 byte each)

        if (pos >= packet.Length) return null;

        // MCS 類型判斷
        byte mcsType = packet[pos];
        if (mcsType == 0x64) // Send Data Request
        {
            // choice(1) + initiator(2) + channel(2) + priority(1) + segmentation(1) = 7
            if (pos + 7 > packet.Length) return null;
            pos += 7;
        }
        else if (mcsType == 0x04) // Send Data Indication
        {
            // type(1) + initiator(2) + channel(2) + segmentation(1) = 6
            // (priority is often combined with segmentation in 1 byte)
            if (pos + 6 > packet.Length) return null;
            pos += 6;
        }
        else
        {
            // 未知 MCS 類型，直接回傳剩下的資料
            return packet[pos..];
        }

        // 跳過 RDP security header (4 bytes: flags + flagsHi)
        if (pos + 4 > packet.Length) return null;
        pos += 4;

        if (pos >= packet.Length) return null;
        return packet[pos..];
    }

    /// <summary>
    /// 建構 Data Ack 回應 (讓 client 繼續流程)
    /// </summary>
    public static byte[] BuildDataAck()
    {
        // 標準 Data Ack
        // TPKT + X.224 DT (02 F0 80) + MCS Send Data Indication + empty
        return
        [
            0x03, 0x00, 0x00, 0x0B, // TPKT (length 11)
            0x02, 0xF0, 0x80,       // X.224 Data (LI=2, DT, eot)
            0x04, 0x00, 0x00, 0x00  // MCS empty data
        ];
    }

    /// <summary>
    /// 解析 Info PDU (TS_INFO_PACKET) 提取帳號/密碼/網域
    /// 參考 MS-RDPBCGR 2.2.1.11.1.1.1
    /// </summary>
    public static CapturedCredential? ParseInfoPDU(byte[] data)
    {
        try
        {
            // Info PDU 結構 (TS_INFO_PACKET):
            //   codePage (4 bytes) - 通常 0 或系統 code page
            //   flags (4 bytes) - INFO flags
            //   cbDomain (2 bytes) - domain 長度 (bytes)
            //   cbUserName (2 bytes) - username 長度 (bytes)
            //   cbPassword (2 bytes) - password 長度 (bytes)
            //   cbAlternateShell (2 bytes)
            //   cbWorkingDir (2 bytes)
            //   Domain (Unicode, cbDomain bytes)
            //   UserName (Unicode, cbUserName bytes)
            //   Password (Unicode, cbPassword bytes)
            //   AlternateShell (Unicode)
            //   WorkingDir (Unicode)
            //
            // 注意：有些 client 會在 security header 後加 1-byte padding (0x00)，
            // 所以 TS_INFO_PACKET 可能從 offset 0 或 offset 1 開始。
            // 此外，在 cb 欄位與字串之間可能有額外的 padding byte。

            if (data.Length < 20)
                return null;

            // 嘗試從 offset 0 和 offset 1 解析
            for (int startOff = 0; startOff <= 1; startOff++)
            {
                if (startOff + 18 > data.Length)
                    break;

                int cbDomain = BitConverter.ToUInt16(data, startOff + 8);
                int cbUserName = BitConverter.ToUInt16(data, startOff + 10);
                int cbPassword = BitConverter.ToUInt16(data, startOff + 12);
                int cbAltShell = BitConverter.ToUInt16(data, startOff + 14);
                int cbWorkingDir = BitConverter.ToUInt16(data, startOff + 16);

                // 驗證 cb 值是否合理
                if (cbUserName <= 0 || cbUserName > 512) continue;
                if (cbPassword < 0 || cbPassword > 512) continue;
                if (cbDomain < 0 || cbDomain > 512) continue;

                // 從 cb 欄位結束處開始找字串起始 (跳過可能的 padding)
                int strStart = startOff + 18;
                while (strStart < data.Length && data[strStart] == 0)
                    strStart++;

                // 確保有足夠空間容納所有字串
                int totalStrLen = cbDomain + cbUserName + cbPassword + cbAltShell + cbWorkingDir;
                if (strStart + totalStrLen + 16 > data.Length)
                    continue;

                var domain = cbDomain > 0
                    ? Encoding.Unicode.GetString(data, strStart, cbDomain).TrimEnd('\0')
                    : "";
                strStart += cbDomain;
                // 跳過字串間的 null terminator/padding
                while (strStart < data.Length && data[strStart] == 0) strStart++;

                var username = cbUserName > 0
                    ? Encoding.Unicode.GetString(data, strStart, cbUserName).TrimEnd('\0')
                    : "";
                strStart += cbUserName;
                // 跳過字串間的 null terminator/padding
                while (strStart < data.Length && data[strStart] == 0) strStart++;

                var password = cbPassword > 0
                    ? Encoding.Unicode.GetString(data, strStart, cbPassword).TrimEnd('\0')
                    : "";

                // 剔除無效的 uniCode 填充
                username = SanitizeString(username);
                password = SanitizeString(password);
                domain = SanitizeString(domain);

                if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
                    return new CapturedCredential(username, password, domain, null);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    static string SanitizeString(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        // 只保留可列印字元，過濾掉亂碼/二進位
        return new string(s.Where(c => c >= 0x20 && c <= 0x7E || c >= 0x4E00).ToArray());
    }
}
