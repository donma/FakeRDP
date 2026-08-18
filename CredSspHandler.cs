using System.Security.Cryptography;
using System.Text;

namespace RdpHoneypot;

/// <summary>
/// CredSSP / NLA / NTLM 協定處理。
/// 負責 NTLM Type 1/2/3 交換、SPNEGO accept-completed、
/// 與 TSCredentials 解密（RSA-OAEP + AES-128-CBC）。
/// </summary>
static class CredSspHandler
{
    /// <summary>NLA 完整流程</summary>
    public static async Task<(string domain, string username, string? password)?> HandleNlaAsync(
        RdpSession session, Stream stream, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 4 && !ct.IsCancellationRequested; attempt++)
        {
            var request = await ReadDerMessageAsync(stream, session.Options.MaxPacketBytes, ct);
            if (request == null) return null;

            var ntlmOffset = IndexOf(request, "NTLMSSP\0"u8.ToArray());
            if (ntlmOffset < 0 || ntlmOffset + 12 > request.Length)
            {
                await session.LogAsync($"  (NLA TSRequest {request.Length} bytes; NTLM token not found)");
                continue;
            }

            var messageType = ReadUInt32LE(request, ntlmOffset + 8);
            await session.LogAsync($"  (NLA NTLM message type {messageType})");

            if (messageType == 1)
            {
                var challenge = BuildCredSspChallenge();
                await stream.WriteAsync(challenge, ct);
                await session.LogAsync($"  (NLA NTLM challenge sent: {challenge.Length} bytes)");
                continue;
            }

            if (messageType == 3)
            {
                var domain = ReadNtlmUnicodeField(request, ntlmOffset, 28) ?? "";
                var username = ReadNtlmUnicodeField(request, ntlmOffset, 36) ?? "";
                if (string.IsNullOrWhiteSpace(username)) return null;

                var accept = BuildSpnegoAcceptResponse();
                await stream.WriteAsync(accept, ct);
                await session.LogAsync($"  (SPNEGO accept-completed sent: {accept.Length} bytes)");

                var tsCreds = await ReadDerMessageAsync(stream, session.Options.MaxPacketBytes, ct);
                if (tsCreds == null)
                {
                    await session.LogAsync($"  (no TSCredentials received)");
                    return (domain, username, null);
                }

                var authInfo = ExtractAuthInfo(tsCreds);
                if (authInfo == null || authInfo.Length < 256)
                {
                    await session.LogAsync($"  (authInfo too short: {authInfo?.Length ?? 0} bytes)");
                    return (domain, username, null);
                }

                var password = DecryptTSCredentials(authInfo, session.TlsRsaKey);
                if (password != null)
                    await session.LogAsync($"  >>> TSCredentials password: {password}");
                else
                {
                    await session.LogAsync($"  (TSCredentials decryption failed, saving raw)");
                    var raw = Path.Combine(session.LogDir, $"session_{session.SessionId:D6}", "authInfo_raw.bin");
                    await File.WriteAllBytesAsync(raw, authInfo, ct);
                }

                return (domain, username, password);
            }
        }
        return null;
    }

    // ── ASN.1 / DER helpers ──

    public static async Task<byte[]?> ReadDerMessageAsync(Stream stream, int maxPacketBytes, CancellationToken ct)
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

        if (length > maxPacketBytes) return null;

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

    static byte[]? ExtractAuthInfo(byte[] tsRequest)
    {
        for (var i = 0; i < tsRequest.Length - 2; i++)
        {
            if (tsRequest[i] == 0xA2)
            {
                int lenStart = i + 1;
                int contentLen, dataStart;
                if ((tsRequest[lenStart] & 0x80) == 0)
                { contentLen = tsRequest[lenStart]; dataStart = lenStart + 1; }
                else
                {
                    var numBytes = tsRequest[lenStart] & 0x7F;
                    if (numBytes == 0 || numBytes > 2) continue;
                    contentLen = 0;
                    for (var j = 0; j < numBytes; j++)
                        contentLen = (contentLen << 8) | tsRequest[lenStart + 1 + j];
                    dataStart = lenStart + 1 + numBytes;
                }
                if (dataStart < tsRequest.Length && tsRequest[dataStart] == 0x04)
                {
                    int octetLenStart = dataStart + 1;
                    int octetLen, octetData;
                    if ((tsRequest[octetLenStart] & 0x80) == 0)
                    { octetLen = tsRequest[octetLenStart]; octetData = octetLenStart + 1; }
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

    static string? DecryptTSCredentials(byte[] authInfo, RSA rsaKey)
    {
        try
        {
            var encryptedKey = authInfo[..256];
            var encryptedData = authInfo[256..];
            var tsCredsKey = rsaKey.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
            var label = "CredSSP1"u8.ToArray();
            var material = new byte[tsCredsKey.Length + label.Length];
            Array.Copy(tsCredsKey, material, tsCredsKey.Length);
            Array.Copy(label, 0, material, tsCredsKey.Length, label.Length);
            var hash = SHA256.HashData(material);
            using var aes = Aes.Create();
            aes.Key = hash[..16];
            aes.IV = hash[16..32];
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var decryptor = aes.CreateDecryptor();
            var decrypted = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return ParseTSPasswordCreds(decrypted);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] TSCredentials decryption failed: {ex.Message}");
            return null;
        }
    }

    static string? ParseTSPasswordCreds(byte[] der) =>
        FindContextOctetString(der, 0x02) is { } pwd
            ? Encoding.Unicode.GetString(pwd).TrimEnd('\0')
            : null;

    static byte[]? FindContextOctetString(byte[] data, int contextTag)
    {
        var tag = (byte)(0xA0 | contextTag);
        for (var i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == tag)
            {
                int lenStart = i + 1;
                int len, contentStart;
                if ((data[lenStart] & 0x80) == 0)
                { len = data[lenStart]; contentStart = lenStart + 1; }
                else
                {
                    var numBytes = data[lenStart] & 0x7F;
                    if (numBytes == 0 || numBytes > 2) continue;
                    len = 0;
                    for (var j = 0; j < numBytes; j++)
                        len = (len << 8) | data[lenStart + 1 + j];
                    contentStart = lenStart + 1 + numBytes;
                }
                if (contentStart < data.Length && data[contentStart] == 0x04)
                {
                    int olStart = contentStart + 1;
                    int ol, od;
                    if ((data[olStart] & 0x80) == 0)
                    { ol = data[olStart]; od = olStart + 1; }
                    else
                    {
                        var nb = data[olStart] & 0x7F;
                        if (nb == 0 || nb > 2) continue;
                        ol = 0;
                        for (var j = 0; j < nb; j++)
                            ol = (ol << 8) | data[olStart + 1 + j];
                        od = olStart + 1 + nb;
                    }
                    if (od + ol <= data.Length) return data[od..(od + ol)];
                }
            }
        }
        return null;
    }

    static byte[] BuildSpnegoAcceptResponse()
    {
        var negResult = Der(0xA0, [0x0A, 0x01, 0x00]);
        var spnego = Der(0x30, negResult);
        var octet = Der(0x04, spnego);
        var token = Der(0xA0, octet);
        var item = Der(0x30, token);
        var tokenList = Der(0x30, item);
        var negoTokens = Der(0xA1, tokenList);
        var version = Der(0xA0, [0x02, 0x01, 0x05]);
        return Der(0x30, [.. version, .. negoTokens]);
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
        av.Write((ushort)0);
        av.Write((ushort)0);

        var targetInfo = avPairs.ToArray();
        var targetInfoOffset = 0x38 + workstation.Length;
        var ntlm = new byte[targetInfoOffset + targetInfo.Length];
        var signature = Encoding.ASCII.GetBytes("NTLMSSP\0");
        Array.Copy(signature, ntlm, signature.Length);
        WriteUInt32LE(ntlm, 8, 2);
        WriteUInt16LE(ntlm, 12, (ushort)workstation.Length);
        WriteUInt16LE(ntlm, 14, (ushort)workstation.Length);
        WriteUInt32LE(ntlm, 16, 0x38);
        WriteUInt32LE(ntlm, 20, 0xE28A8215);
        RandomNumberGenerator.Fill(ntlm.AsSpan(24, 8));
        WriteUInt16LE(ntlm, 40, (ushort)targetInfo.Length);
        WriteUInt16LE(ntlm, 42, (ushort)targetInfo.Length);
        WriteUInt32LE(ntlm, 44, (uint)targetInfoOffset);
        ntlm[48] = 0x06; ntlm[49] = 0x02;
        WriteUInt16LE(ntlm, 50, 0x0ECE);
        ntlm[52] = 0; ntlm[53] = 0; ntlm[54] = 0; ntlm[55] = 0x0F;
        Array.Copy(workstation, 0, ntlm, 0x38, workstation.Length);
        Array.Copy(targetInfo, 0, ntlm, targetInfoOffset, targetInfo.Length);

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

    static int IndexOf(byte[] data, byte[] needle)
    {
        for (var i = 0; i <= data.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
                if (data[i + j] != needle[j]) { match = false; break; }
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
        var offset = ntlmOffset + (int)ReadUInt32LE(message, fieldOffset + 4);
        if (length == 0 || offset < 0 || offset + length > message.Length || (length & 1) != 0)
            return null;
        return Encoding.Unicode.GetString(message, offset, length).TrimEnd('\0');
    }
}