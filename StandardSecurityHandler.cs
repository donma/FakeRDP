namespace RdpHoneypot;

/// <summary>
/// RDP 標準安全交換與 Info PDU 處理。
/// Security Exchange（RSA 解密 ClientRandom → RC4 金鑰衍生）
/// 與 Info PDU（帳號/密碼/網域解析）。
/// </summary>
static class StandardSecurityHandler
{
    /// <summary>處理 Security Exchange PDU 或直接偵測 Info PDU</summary>
    public static Task<byte[]?> HandleSecurityExchangeAsync(RdpSession session, byte[] packet)
    {
        var state = session.State;
        try
        {
            var payload = RdpPacket.ExtractPayloadForTls(packet);
            if (payload != null && payload.Length > 0)
            {
                var flags = ExtractSecurityFlags(packet);
                if ((flags & 0x0040) != 0)
                {
                    LogInfoPdu(session, payload);
                    state.Phase = SessionPhase.Done;
                    return Task.FromResult<byte[]?>(RdpPacket.BuildDataAck());
                }

                var clientRandom = CryptoHelper.DecryptClientRandom(payload, session.RsaKey);
                if (clientRandom != null && clientRandom.Length == 32)
                {
                    state.ClientRandom = clientRandom;
                    var (decryptKey, encryptKey) = CryptoHelper.DeriveSessionKeys(
                        clientRandom, session.ServerRandom);
                    state.DecryptKey = decryptKey;
                    state.EncryptKey = encryptKey;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Security exchange parse error: {ex.Message}");
            state.Phase = SessionPhase.Error;
            return Task.FromResult<byte[]?>(null);
        }

        state.Phase = SessionPhase.WaitInfo;
        return Task.FromResult<byte[]?>(RdpPacket.BuildDataAck());
    }

    /// <summary>處理 Info PDU 並嘗試擷取帳號密碼</summary>
    public static byte[]? HandleInfoPDU(RdpSession session, byte[] packet)
    {
        var state = session.State;
        try
        {
            var payload = RdpPacket.ExtractPayloadForTls(packet);
            if (payload == null || payload.Length == 0)
            {
                Console.WriteLine("  [!] Info PDU: 無法提取 payload");
                state.Phase = SessionPhase.Error;
                return null;
            }

            var cred = RdpPacket.ParseInfoPDU(payload);
            if (cred == null && state.DecryptKey != null)
            {
                var decrypted = CryptoHelper.RC4Decrypt(state.DecryptKey, payload);
                cred = RdpPacket.ParseInfoPDU(decrypted);
            }

            if (cred != null)
                state.Credential = cred with { ClientInfo = state.ClientInfo };
            else
                Console.WriteLine($"  [!] Info PDU: 解析失敗 (payload={payload.Length} bytes, hasKey={state.DecryptKey != null})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Info PDU parse error: {ex.Message}");
        }

        state.Phase = SessionPhase.Done;
        return RdpPacket.BuildDataAck();
    }

    static ushort ExtractSecurityFlags(byte[] packet)
    {
        for (var i = 6; i < packet.Length - 6; i++)
        {
            if (packet[i] == 0x64 && packet[i + 1] != 0xFF)
            {
                int p = i + 1 + 2 + 2 + 1 + 1;
                if (p + 4 <= packet.Length)
                    return (ushort)(packet[p] | (packet[p + 1] << 8));
            }
        }
        return 0;
    }

    static void LogInfoPdu(RdpSession session, byte[] payload)
    {
        var state = session.State;
        try
        {
            var cred = RdpPacket.ParseInfoPDU(payload);
            if (cred != null)
            {
                state.Credential = cred with { ClientInfo = state.ClientInfo };
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ═══ CREDENTIAL CAPTURED ═══");
                Console.WriteLine($"  User: {cred.Username}");
                Console.WriteLine($"  Pass: {session.DisplaySecretForLog(cred.Password)}");
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
}