using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace RdpHoneypot.Tests;

public static class IntegrationRunner
{
    public static async Task<int> RunAsync(string[] args)
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

    static async Task WriteTpktAsync(NetworkStream stream, byte[] payload)
    {
        var packet = new byte[4 + payload.Length];
        packet[0] = 0x03;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        Array.Copy(payload, 0, packet, 4, payload.Length);
        await stream.WriteAsync(packet);
    }

    static async Task<byte[]> ReadTpktAsync(NetworkStream stream)
    {
        var header = await ReadExactlyAsync(stream, 4);
        var length = (header[2] << 8) | header[3];
        if (length < 4 || length > 262144)
            throw new InvalidDataException("Invalid TPKT response length.");
        return [.. header, .. await ReadExactlyAsync(stream, length - 4)];
    }

    static async Task<byte[]> ReadExactlyAsync(NetworkStream stream, int count)
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
