using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RdpHoneypot;

/// <summary>
/// RDP 加密相關工具 (參考 MS-RDPBCGR 5.3.5 金鑰衍生演算法)
/// - RSA 2048 金鑰產生 + 自簽憑證
/// - RC4 實作 (.NET 未內建)
/// - Session Keys 衍生 (40/56/128-bit)
/// </summary>
static class CryptoHelper
{
    static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    /// <summary>產生 32 bytes 隨機資料</summary>
    public static byte[] GenerateRandom(int length)
    {
        var buf = new byte[length];
        Rng.GetBytes(buf);
        return buf;
    }

    /// <summary>
    /// 產生 RSA 2048-bit 金鑰並建立自簽憑證
    /// 用於 RDP 標準安全交換 (RSA 加密 client random)
    /// </summary>
    public static (RSA key, X509Certificate2 cert) CreateRsaCert()
    {
        var rsa = RSA.Create(2048);

        var req = new CertificateRequest(
            "CN=MS-Server, O=Microsoft Corporation",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        return (rsa, cert);
    }

    /// <summary>
    /// 建立或載入持久化 RSA TLS 憑證。
    /// 憑證檔案只在需要時建立；私鑰以 PFX + PersistKeySet 載入，
    /// 讓 Schannel/CNG 可使用，也可供 CredSSP TSCredentials 解密。
    /// </summary>
    public static X509Certificate2 CreateRsaCertForTls(
        string subject,
        string sanName,
        string? certificatePath,
        int lifetimeDays,
        int renewalDays,
        bool persist)
    {
        if (persist && !string.IsNullOrWhiteSpace(certificatePath) && File.Exists(certificatePath))
        {
            try
            {
                var existing = X509CertificateLoader.LoadPkcs12(
                    File.ReadAllBytes(certificatePath),
                    null,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                var subjectMatches = existing.Subject.Equals(subject, StringComparison.OrdinalIgnoreCase);
                if (existing.HasPrivateKey && subjectMatches &&
                    existing.NotAfter > DateTime.UtcNow.AddDays(renewalDays))
                    return existing;
                existing.Dispose();
            }
            catch
            {
                // 檔案損壞或非預期格式時重新建立，不讓 listener 啟動失敗。
            }
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            subject,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                false));
        var sanBuilder = new SubjectAlternativeNameBuilder();
        var defaultName = subject.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
            ? subject[3..].Split(',', 2)[0].Trim()
            : subject;
        sanBuilder.AddDnsName(string.IsNullOrWhiteSpace(sanName) ? defaultName : sanName);
        req.CertificateExtensions.Add(
            new X509SubjectAlternativeNameExtension(sanBuilder.Build().RawData, false));

        var lifetime = Math.Clamp(lifetimeDays, 1, 3650);
        using var generated = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(lifetime));
        var pfx = generated.Export(X509ContentType.Pfx, (string?)null);
        var loaded = X509CertificateLoader.LoadPkcs12(
            pfx, null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        if (persist && !string.IsNullOrWhiteSpace(certificatePath))
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(certificatePath));
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);
            File.WriteAllBytes(certificatePath, pfx);
        }

        return loaded;
    }
    /// 用於 TLS 握手 (支援 ECDHE 金鑰交換，Windows Schannel 相容)
    /// 關鍵: 以 PFX + PersistKeySet 重新載入，讓 Schannel/CNG 能存取私鑰
    /// </summary>
    public static X509Certificate2 CreateEcdsaCert()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var req = new CertificateRequest(
            "CN=MS-Server, O=Microsoft Corporation",
            ecdsa,
            HashAlgorithmName.SHA256);

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement,
                false));

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // serverAuth
                false));

        var tempCert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        // 關鍵修復: 匯出 PFX 後以 PersistKeySet 重新載入，
        // 讓 Windows Schannel (CNG) 能存取私鑰完成 ECDHE 握手
        var pfx = tempCert.Export(X509ContentType.Pfx, "honeypot-pw");
        return X509CertificateLoader.LoadPkcs12(
            pfx, "honeypot-pw",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    /// <summary>
    /// 解密 client random (使用 server 私鑰, RSA-OAEP 或 PKCS1)
    /// RDP Security Exchange PDU 中的加密資料
    /// </summary>
    public static byte[]? DecryptClientRandom(byte[] encrypted, RSA rsa)
    {
        try
        {
            // MS-RDPBCGR: 使用 PKCS#1 v1.5 padding
            // 有些 client 用 небольшой 資料 (32 bytes + padding = 256 bytes for 2048-bit key)
            if (encrypted.Length <= 256)
            {
                return rsa.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
            }

            // 若是 RSAPKCS1 的大小不符，回傳 null
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// 衍生 RC4 Session Keys (參考 MS-RDPBCGR 5.3.5.1)
    /// 
    /// 演算法:
    ///   1. SessionKeyBlob = MD5(ClientRandom + ServerRandom + ClientRandom)
    ///   2. 使用 128-bit key: 
    ///      - ServerEncryptKey = MD5(SessionKeyBlob + 6 bytes padding)
    ///      - 詳細算法見 MS-RDPBCGR
    /// 
    /// 本實作針對 128-bit encryption:
    ///   - 讀取金鑰 (client→server 資料解密): (SessionKeyBlob + pad1) 
    ///   - 寫入金鑰 (server→client 資料加密): (SessionKeyBlob + pad2)
    /// </summary>
    public static (byte[] decryptKey, byte[] encryptKey) DeriveSessionKeys(
        byte[] clientRandom, byte[] serverRandom)
    {
        // 適用於 128-bit RC4
        // 參考: MS-RDPBCGR 5.3.5.1.2

        // 1. SessionKeyBlob = MD5(ClientRandom(32) + ServerRandom(32) + ClientRandom(32))
        var md5 = MD5.Create();
        var input = new byte[96];
        Array.Copy(clientRandom, 0, input, 0, 32);
        Array.Copy(serverRandom, 0, input, 32, 32);
        Array.Copy(clientRandom, 0, input, 64, 32);
        var sessionKeyBlob = md5.ComputeHash(input); // 16 bytes

        // 2. 衍生 server→client 與 client→server 金鑰 (各 16 bytes)
        //    使用 pad 讓金鑰不同 (0x36 與 0x5C 是 HMAC 的標準 pad)
        //    參考公開的 RDP 金鑰衍生實作
        var pad1 = new byte[40];
        Array.Fill(pad1, (byte)0x36);

        var pad2 = new byte[40];
        Array.Fill(pad2, (byte)0x5C);

        var k1Input = new byte[56];
        Array.Copy(sessionKeyBlob, 0, k1Input, 0, 16);
        Array.Copy(pad1, 0, k1Input, 16, 40);
        var key1 = md5.ComputeHash(k1Input); // server→client (讀取用)

        var k2Input = new byte[56];
        Array.Copy(sessionKeyBlob, 0, k2Input, 0, 16);
        Array.Copy(pad2, 0, k2Input, 16, 40);
        var key2 = md5.ComputeHash(k2Input); // client→server

        // 依 RDP 慣例:
        // - decryptKey (client→server 資料解密用) = key2
        // - encryptKey (server→client 資料加密用) = key1
        return (key2, key1);
    }

    /// <summary>
    /// RC4 加解密 (對稱，加密=解密)
    /// </summary>
    public static byte[] RC4Decrypt(byte[] key, byte[] data)
    {
        return RC4(key, data);
    }

    public static byte[] RC4Encrypt(byte[] key, byte[] data)
    {
        return RC4(key, data);
    }

    static byte[] RC4(byte[] key, byte[] data)
    {
        if (key == null || key.Length == 0 || data == null || data.Length == 0)
            return data ?? [];

        // KSA (Key Scheduling Algorithm)
        var s = new byte[256];
        for (int i = 0; i < 256; i++)
            s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
        }

        // PRGA (Pseudo-Random Generation Algorithm)
        var result = new byte[data.Length];
        int a = 0, b = 0;

        for (int k = 0; k < data.Length; k++)
        {
            a = (a + 1) & 0xFF;
            b = (b + s[a]) & 0xFF;
            (s[a], s[b]) = (s[b], s[a]);
            var keystream = s[(s[a] + s[b]) & 0xFF];
            result[k] = (byte)(data[k] ^ keystream);
        }

        return result;
    }
}