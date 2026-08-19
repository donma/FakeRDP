using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace RdpHoneypot.Tests;

public static class IntegrationRunner
{
    public static Task<int> RunAsync(string[] args)
    {
        var mode = GetOption(args, "--mode")?.ToLowerInvariant() ?? "standard";
        return mode switch
        {
            "standard" => RunStandardAsync(args),
            "tls" => RunTlsAsync(args),
            "nla" => RunNlaAsync(args),
            _ => throw new ArgumentException("--mode must be standard, tls, or nla")
        };
    }

    static async Task<int> RunStandardAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");

        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var stream = client.GetStream();

        await WriteTpktAsync(stream, [
            0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        _ = await ReadTpktAsync(stream);

        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
        var mcsResponse = await ReadTpktAsync(stream);
        using var certificate = ExtractCertificate(mcsResponse, out var certificateIndex);
        using var rsa = certificate.GetRSAPublicKey() ?? throw new InvalidOperationException("MCS response certificate has no RSA key");
        var clientRandom = RandomNumberGenerator.GetBytes(32);
        var encryptedRandom = rsa.Encrypt(clientRandom, RSAEncryptionPadding.Pkcs1);

        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00]);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0x00, 0x00, 0x03, 0xEA]);
        _ = await ReadTpktAsync(stream);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0x00, 0x00, 0x03, 0xEB]);
        _ = await ReadTpktAsync(stream);

        await WriteTpktAsync(stream, BuildDataPacket(0x0001, encryptedRandom));
        _ = await ReadTpktAsync(stream);

        var domain = Encoding.Unicode.GetBytes("WORKGROUP\0");
        var username = Encoding.Unicode.GetBytes("integration-user\0");
        var password = Encoding.Unicode.GetBytes("integration-password\0");
        var info = new byte[18 + domain.Length + username.Length + password.Length + 16];
        BitConverter.GetBytes(0u).CopyTo(info, 0);
        BitConverter.GetBytes(0u).CopyTo(info, 4);
        BitConverter.GetBytes((ushort)domain.Length).CopyTo(info, 8);
        BitConverter.GetBytes((ushort)username.Length).CopyTo(info, 10);
        BitConverter.GetBytes((ushort)password.Length).CopyTo(info, 12);
        domain.CopyTo(info, 18);
        username.CopyTo(info, 18 + domain.Length);
        password.CopyTo(info, 18 + domain.Length + username.Length);

        await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
        _ = await ReadTpktAsync(stream);
        client.Close();

        var recordPath = Path.Combine(logDir, "captured_creds.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(3);
        JsonDocument? record = null;
        while (DateTime.UtcNow < deadline && record is null)
        {
            if (File.Exists(recordPath))
            {
                foreach (var line in await File.ReadAllLinesAsync(recordPath))
                {
                    try
                    {
                        using var parsed = JsonDocument.Parse(line);
                        var root = parsed.RootElement;
                        if (root.TryGetProperty("username", out var user) &&
                            user.GetString() == "integration-user")
                        {
                            record = JsonDocument.Parse(line);
                            break;
                        }
                    }
                    catch (JsonException) { }
                }
            }
            if (record is null)
                await Task.Delay(50);
        }

        var passed = record is not null &&
            record.RootElement.GetProperty("password").GetString() == "integration-password" &&
            record.RootElement.GetProperty("target_port").GetInt32() == port;
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} Standard Security credential capture integration");
        return passed ? 0 : 1;
    }

    static async Task<int> RunTlsAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var raw = client.GetStream();
        var stream = await NegotiateTlsAsync(raw, host, 0x01);
        await RunMcsToSecurityAsync(stream);
        // The current session state keeps the common Security Exchange stage
        // before Info PDU even on TLS; send a bounded synthetic exchange first.
        await WriteTpktAsync(stream, BuildDataPacket(0x0001, RandomNumberGenerator.GetBytes(256)));
        _ = await ReadTpktAsync(stream);
        var domain = Encoding.Unicode.GetBytes("WORKGROUP\0");
        var username = Encoding.Unicode.GetBytes("tls-integration-user\0");
        var password = Encoding.Unicode.GetBytes("tls-integration-password\0");
        var info = BuildInfoPdu(domain, username, password);
        await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
        _ = await ReadTpktAsync(stream);
        client.Close();
        var passed = await WaitForCredentialAsync(logDir, "tls-integration-user", "tls-integration-password", port);
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} TLS Info PDU credential capture integration");
        return passed ? 0 : 1;
    }

    static async Task<int> RunNlaAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var raw = client.GetStream();
        var stream = await NegotiateTlsAsync(raw, host, 0x02);
        var type1 = BuildNtlmType1();
        await stream.WriteAsync(BuildTsRequest(type1));
        var challenge = await ReadDerMessageAsync(stream);
        if (!ContainsNtlmType(challenge, 2))
            throw new InvalidDataException("NLA challenge was not received.");
        var type3 = BuildNtlmType3("nla-integration-user", "WORKGROUP");
        await stream.WriteAsync(BuildTsRequest(type3));
        _ = await ReadDerMessageAsync(stream);
        await stream.WriteAsync(new byte[] { 0x30, 0x00 });
        var account = await WaitForNlaAccountAsync(logDir, "nla-integration-user", port);
        client.Close();
        Console.WriteLine($"{(account ? "PASS" : "FAIL")} NLA account capture integration");
        return account ? 0 : 1;
    }

    static async Task<SslStream> NegotiateTlsAsync(NetworkStream raw, string host, uint protocol)
    {
        var request = protocol == 0x02 ? 0x02u : 0x01u;
        await WriteTpktAsync(raw, BuildNegotiationRequest(request));
        var response = await ReadTpktAsync(raw);
        if (response.Length < 19 || response[11] != 0x02)
            throw new InvalidDataException("RDP negotiation did not select TLS/HYBRID.");
        var callback = new RemoteCertificateValidationCallback((_, _, _, _) => true);
        var ssl = new SslStream(raw, false, callback);
        await ssl.AuthenticateAsClientAsync(host, null, System.Security.Authentication.SslProtocols.Tls12, false);
        return ssl;
    }

    static byte[] BuildNegotiationRequest(uint protocol)
        => [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0, 0, 0, 0, 0,
            0x01, 0, 8, 0, (byte)protocol, (byte)(protocol >> 8), 0, 0];

    static async Task RunMcsToSecurityAsync(Stream stream)
    {
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
        _ = await ReadTpktAsync(stream);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0, 0, 0, 0]);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0, 0, 0x03, 0xEA]);
        _ = await ReadTpktAsync(stream);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0, 0, 0x03, 0xEB]);
        _ = await ReadTpktAsync(stream);
    }

    static byte[] BuildInfoPdu(byte[] domain, byte[] username, byte[] password)
    {
        var info = new byte[18 + domain.Length + username.Length + password.Length + 16];
        BitConverter.GetBytes(0u).CopyTo(info, 0);
        BitConverter.GetBytes(0u).CopyTo(info, 4);
        BitConverter.GetBytes((ushort)domain.Length).CopyTo(info, 8);
        BitConverter.GetBytes((ushort)username.Length).CopyTo(info, 10);
        BitConverter.GetBytes((ushort)password.Length).CopyTo(info, 12);
        domain.CopyTo(info, 18);
        username.CopyTo(info, 18 + domain.Length);
        password.CopyTo(info, 18 + domain.Length + username.Length);
        return info;
    }

    static async Task<bool> WaitForCredentialAsync(string logDir, string username, string password, int port)
    {
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        var root = json.RootElement;
                        if (root.GetProperty("username").GetString() == username &&
                            root.GetProperty("password").GetString() == password &&
                            root.GetProperty("target_port").GetInt32() == port)
                            return true;
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }
        return false;
    }

    static async Task<bool> WaitForNlaAccountAsync(string logDir, string username, int port)
    {
        var path = Path.Combine(logDir, "nla_accounts.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        var root = json.RootElement;
                        if (root.GetProperty("username").GetString() == username &&
                            root.GetProperty("target_port").GetInt32() == port)
                            return true;
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }
        return false;
    }

    static byte[] BuildNtlmType1()
        => [0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00, 1,0,0,0,
            0xB2,0x88,0x02,0x00, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];

    static byte[] BuildNtlmType3(string username, string domain)
    {
        var domainBytes = Encoding.Unicode.GetBytes(domain);
        var userBytes = Encoding.Unicode.GetBytes(username);
        var workstationBytes = Encoding.Unicode.GetBytes("TESTCLIENT");
        var message = new byte[64 + domainBytes.Length + userBytes.Length + workstationBytes.Length];
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(message, 0);
        BitConverter.GetBytes(3u).CopyTo(message, 8);
        WriteSecurityBuffer(message, 28, domainBytes, 64);
        WriteSecurityBuffer(message, 36, userBytes, 64 + domainBytes.Length);
        WriteSecurityBuffer(message, 44, workstationBytes, 64 + domainBytes.Length + userBytes.Length);
        return message;
    }

    static void WriteSecurityBuffer(byte[] target, int offset, byte[] value, int dataOffset)
    {
        BitConverter.GetBytes((ushort)value.Length).CopyTo(target, offset);
        BitConverter.GetBytes((ushort)value.Length).CopyTo(target, offset + 2);
        BitConverter.GetBytes(dataOffset).CopyTo(target, offset + 4);
        value.CopyTo(target, dataOffset);
    }

    static byte[] BuildTsRequest(byte[] ntlm)
    {
        var version = Der(0xA0, [0x02, 0x01, 0x05]);
        var token = Der(0xA1, Der(0x04, ntlm));
        return Der(0x30, [.. version, .. token]);
    }

    static byte[] Der(byte tag, byte[] content)
        => content.Length < 128
            ? [tag, (byte)content.Length, .. content]
            : [tag, 0x82, (byte)(content.Length >> 8), (byte)content.Length, .. content];

    static async Task<byte[]> ReadDerMessageAsync(Stream stream)
    {
        var first = await ReadExactlyAsync(stream, 2);
        var length = (int)first[1];
        var lengthBytes = Array.Empty<byte>();
        if ((length & 0x80) != 0)
        {
            var count = length & 0x7F;
            lengthBytes = await ReadExactlyAsync(stream, count);
            length = 0;
            foreach (var value in lengthBytes) length = (length << 8) | value;
        }
        return [.. first, .. lengthBytes, .. await ReadExactlyAsync(stream, length)];
    }

    static bool ContainsNtlmType(byte[] data, uint type)
    {
        for (var i = 0; i + 12 <= data.Length; i++)
        {
            if (Encoding.ASCII.GetString(data, i, 8) == "NTLMSSP\0" &&
                BitConverter.ToUInt32(data, i + 8) == type)
                return true;
        }
        return false;
    }

    static byte[] BuildDataPacket(ushort flags, byte[] payload)
    {
        var body = new byte[3 + 7 + 4 + payload.Length];
        body[0] = 0x02; body[1] = 0xF0; body[2] = 0x80;
        body[3] = 0x64;
        body[10] = 0x00;
        body[11] = (byte)(flags & 0xFF);
        body[12] = (byte)(flags >> 8);
        Array.Copy(payload, 0, body, 14, payload.Length);
        var packet = new byte[4 + body.Length];
        packet[0] = 0x03;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        Array.Copy(body, 0, packet, 4, body.Length);
        return packet;
    }

    static async Task WriteTpktAsync(Stream stream, byte[] payload)
    {
        var packet = new byte[4 + payload.Length];
        packet[0] = 0x03;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        Array.Copy(payload, 0, packet, 4, payload.Length);
        await stream.WriteAsync(packet);
    }

    static async Task<byte[]> ReadTpktAsync(Stream stream)
    {
        var header = await ReadExactlyAsync(stream, 4);
        var length = (header[2] << 8) | header[3];
        if (length < 4 || length > 262144)
            throw new InvalidDataException("Invalid TPKT response length.");
        return [.. header, .. await ReadExactlyAsync(stream, length - 4)];
    }

    static async Task<byte[]> ReadExactlyAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset));
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        return buffer;
    }

    static X509Certificate2 ExtractCertificate(byte[] packet, out int certificateIndex)
    {
        for (var offset = 0; offset < packet.Length - 4; offset++)
        {
            if (packet[offset] != 0x30) continue;
            if (!TryDerLength(packet, offset, out var totalLength) || offset + totalLength > packet.Length)
                continue;
            try
            {
                var certificate = X509CertificateLoader.LoadCertificate(packet[offset..(offset + totalLength)]);
                if (certificate.GetRSAPublicKey() is not null)
                {
                    certificateIndex = offset;
                    return certificate;
                }
                certificate.Dispose();
            }
            catch { }
        }
        throw new InvalidDataException("No X.509 certificate found in MCS response.");
    }

    static bool TryDerLength(byte[] data, int offset, out int totalLength)
    {
        totalLength = 0;
        if (offset + 2 > data.Length) return false;
        var lengthByte = data[offset + 1];
        var length = (int)lengthByte;
        var headerLength = 2;
        if ((lengthByte & 0x80) != 0)
        {
            var count = lengthByte & 0x7F;
            if (count is < 1 or > 3 || offset + 2 + count > data.Length) return false;
            length = 0;
            for (var i = 0; i < count; i++)
                length = (length << 8) | data[offset + 2 + i];
            headerLength += count;
        }
        totalLength = headerLength + length;
        return totalLength > headerLength;
    }

    static string? GetOption(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
