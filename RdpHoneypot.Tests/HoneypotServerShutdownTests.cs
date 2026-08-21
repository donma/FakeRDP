using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

/// <summary>
/// P0-2: Server shutdown lifecycle integration tests.
/// 使用真實 HoneypotServer + 真實 RdpSession（不 mock），
/// 驗證 shutdown 順序：stop accept → wait sessions → CompleteAsync。
/// </summary>
public sealed class HoneypotServerShutdownTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
    }

    string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"fakerdp-srv-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    HoneypotOptions CreateOptions(string logDir, int port)
    {
        var certPath = Path.Combine(logDir, "cert.pfx");
        return new HoneypotOptions
        {
            Ports = [port],
            LogDir = logDir,
            ConsoleLogLevel = "Error",
            EnableRawCapture = false,
            MaxConcurrentSessions = 500,
            MaxConcurrentPerIp = 100,
            Profile = new RdpServerProfile
            {
                ComputerName = "WIN-SRV01",
                DomainName = "WORKGROUP",
                EnableTls = true,
                EnableNla = true,
                EnableStandardSecurity = true,
                CertificateSubject = "CN=WIN-SRV01",
                CertificatePath = certPath,
                PersistCertificate = true,
                ResponseDelayMinMs = 0,
                ResponseDelayMaxMs = 0,
            }
        };
    }

    static async Task<bool> WaitForPortAsync(string host, int port, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            try { using var c = new TcpClient(); await c.ConnectAsync(host, port); return true; }
            catch { await Task.Delay(50); }
        }
        return false;
    }

/// <summary>
    /// 驗證 server shutdown 會等待 active session 完成後才 CompleteAsync。
    /// 建立 session → 開始 shutdown → 確認 session 仍 active → 關閉 client → session 結束 → shutdown 完成。
    /// </summary>
    [Fact]
    public async Task ServerShutdown_WaitsForActiveSessionsBeforeCompletingRecorder()
    {
        var dir = CreateTempDir();
        var port = 14450;
        var options = CreateOptions(dir, port);
        var server = new HoneypotServer(options);
        var cts = new CancellationTokenSource();
        var serverTask = Task.Run(() => server.RunAsync(cts.Token));

        // 等待 server 啟動（不使用 TCP probe 避免建立殘留 session）
        await Task.Delay(3000);

        // 建立一條真實 session，但只走到 MCS（不送 Info PDU），讓 session 保持 active
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", port);
        var stream = client.GetStream();
        // X.224 CR (legacy standard)
        await stream.WriteAsync(new byte[] { 0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 });
        var cc = new byte[32]; await stream.ReadAsync(cc, 0, 32); // CC
        // MCS Connect Initial
        await stream.WriteAsync(new byte[] { 0x03, 0x00, 0x00, 0x06, 0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00 });
        var mcs = new byte[1024]; var n = await stream.ReadAsync(mcs, 0, 1024); // MCS response
        // Session 在 WaitErectDomain 等待（保持 active）
        Assert.True(server.ActiveSessionCount > 0, "A session should be active");

        // 開始 shutdown
        cts.Cancel();
        await Task.Delay(200);
        Assert.True(server.ActiveSessionCount > 0, "Session should still be active during shutdown wait");

        // 關閉 client → session 偵測到 EOF 後結束（mcsTimeout 預設 5s）
        client.Close();
        await serverTask;

Assert.Equal(0, server.ActiveSessionCount);
    }

    /// <summary>
    /// P0-2 (§40): Grace timeout 後 server 必須 force-stop 剩餘 session，才 CompleteAsync。
    /// 使用 injectable 短 grace timeout，不真的等 30 秒。
    /// </summary>
    [Fact]
    public async Task ServerShutdown_GraceTimeout_StopsRemainingSessionsBeforeRecorderCompletion()
    {
        var dir = CreateTempDir();
        var port = 14452;
        var options = CreateOptions(dir, port);
        options.X224TimeoutSeconds = 30; // 讓 session 長時間保持 active
        // 短 grace timeout (300ms)，加速測試
        var server = new HoneypotServer(options, TimeSpan.FromMilliseconds(300));
        var cts = new CancellationTokenSource();
        var serverTask = Task.Run(() => server.RunAsync(cts.Token));

        await Task.Delay(3000);

        // 建立一條 TCP session 但不送資料 → session 停在 WaitX224（x224Timeout=30s），保持 active
        var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", port);
        await Task.Delay(200);
        Assert.True(server.ActiveSessionCount > 0, "A session should be active");

        // 觸發 shutdown → Phase 1 grace 300ms timeout → Phase 2 force-stop session
        cts.Cancel();
        await serverTask;

        // 驗證：force-stop 後 ActiveSessions == 0（不等待完整 30s）
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (server.ActiveSessionCount > 0 && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        Assert.Equal(0, server.ActiveSessionCount);
        client.Close();
    }

    /// <summary>
    /// P0-3 (§18, §23): 100 條真實 session 完成 credential capture 後 shutdown，
    /// 驗證 100/100 persisted。使用正確 TPKT 封包流程（同 IntegrationRunner）。
    /// </summary>
    [Fact]
    public async Task ServerShutdown_100ConcurrentSessions_Persists100Credentials()
    {
        var dir = CreateTempDir();
        var port = 14453;
        var options = CreateOptions(dir, port);
        options.McsTimeoutSeconds = 5;
        var server = new HoneypotServer(options);
        var cts = new CancellationTokenSource();
        var serverTask = Task.Run(() => server.RunAsync(cts.Token));

        await Task.Delay(3000);
        const int count = 100;

        var clients = new List<TcpClient>();
        var tasks = new List<Task>();
        var expected = Enumerable.Range(1, count).Select(i => (User: $"srv-u-{i:D3}", Pass: $"srv-p-{i:D3}")).ToArray();

        for (var i = 0; i < count; i++)
        {
            var (user, pass) = expected[i];
            var idx = i;
            tasks.Add(Task.Run(async () =>
            {
                var c = new TcpClient();
                clients.Add(c);
                await c.ConnectAsync("127.0.0.1", port);
                var s = c.GetStream();
                // CR
                await WriteTpktAsync(s, new byte[] { 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 });
                _ = await ReadTpktAsync(s);
                // MCS Connect Initial
                await WriteTpktAsync(s, new byte[] { 0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00 });
                _ = await ReadTpktAsync(s);
                // Erect Domain
                await WriteTpktAsync(s, new byte[] { 0x02, 0xF0, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00 });
                // Attach User
                await WriteTpktAsync(s, new byte[] { 0x02, 0xF0, 0x80, 0x28, 0x00, 0x00, 0x03, 0xEA });
                _ = await ReadTpktAsync(s);
                // Channel Join
                await WriteTpktAsync(s, new byte[] { 0x02, 0xF0, 0x80, 0x38, 0x00, 0x00, 0x03, 0xEB });
                _ = await ReadTpktAsync(s);
                // Security Exchange (假 random)
                await WriteTpktAsync(s, BuildDataPacket(0x0001, new byte[32]));
                _ = await ReadTpktAsync(s);
                // Info PDU
                var domainB = System.Text.Encoding.Unicode.GetBytes("TESTDOMAIN\0");
                var userB = System.Text.Encoding.Unicode.GetBytes($"{user}\0");
                var passB = System.Text.Encoding.Unicode.GetBytes($"{pass}\0");
                var info = new byte[18 + domainB.Length + userB.Length + passB.Length + 16];
                BitConverter.GetBytes(0u).CopyTo(info, 0);
                BitConverter.GetBytes(0u).CopyTo(info, 4);
                BitConverter.GetBytes((ushort)domainB.Length).CopyTo(info, 8);
                BitConverter.GetBytes((ushort)userB.Length).CopyTo(info, 10);
                BitConverter.GetBytes((ushort)passB.Length).CopyTo(info, 12);
                domainB.CopyTo(info, 18); userB.CopyTo(info, 18 + domainB.Length); passB.CopyTo(info, 18 + domainB.Length + userB.Length);
                await WriteTpktAsync(s, BuildDataPacket(0x0040, info));
                _ = await ReadTpktAsync(s);
            }));
        }

        await Task.WhenAll(tasks);
        // 等待背景 flush
        await Task.Delay(2000);

        // shutdown
        cts.Cancel();
        await serverTask;

        // 驗證 100/100 persisted
        var path = Path.Combine(dir, "captured_creds.jsonl");
        var records = new List<string>();
        if (File.Exists(path))
            foreach (var line in await File.ReadAllLinesAsync(path))
                records.Add(line);

        Assert.Equal(count, records.Count);
        foreach (var rec in records)
        {
            using var json = JsonDocument.Parse(rec);
            var u = json.RootElement.GetProperty("username").GetString()!;
            var p = json.RootElement.GetProperty("password").GetString()!;
            var idx = int.Parse(u.Replace("srv-u-", ""));
            Assert.Equal($"srv-p-{idx:D3}", p);
        }

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (server.ActiveSessionCount > 0 && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        Assert.Equal(0, server.ActiveSessionCount);
        foreach (var c in clients) c.Dispose();
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
        var header = new byte[4];
        var got = 0;
        while (got < 4)
        {
            var n = await stream.ReadAsync(header, got, 4 - got);
            if (n == 0) throw new EndOfStreamException();
            got += n;
        }
        var length = (header[2] << 8) | header[3];
        if (length < 4 || length > 262144) throw new InvalidDataException("bad TPKT");
        var body = new byte[length - 4];
        got = 0;
        while (got < body.Length)
        {
            var n = await stream.ReadAsync(body, got, body.Length - got);
            if (n == 0) throw new EndOfStreamException();
            got += n;
        }
        return [.. header, .. body];
    }

    static byte[] BuildDataPacket(ushort flags, byte[] payload)
    {
        var body = new byte[3 + 7 + 4 + payload.Length];
        body[0] = 0x02; body[1] = 0xF0; body[2] = 0x80;
        body[3] = 0x64; body[10] = 0x00;
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
}
