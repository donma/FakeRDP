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
}
