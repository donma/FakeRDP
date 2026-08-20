using System.Net;
using System.Text.Json;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

public sealed class CredentialHardGateTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
            catch { }
        }
    }

    string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"fakerdp-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    static async Task<string> WaitForFileAsync(string path, int timeoutMs = 3000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path)) return await File.ReadAllTextAsync(path);
            await Task.Delay(50);
        }
        throw new FileNotFoundException($"File not found: {path}", path);
    }

    /// <summary>EventRecorder 正確序列化統一 credential schema（§3）</summary>
    [Fact]
    public async Task CredentialEventSchema_ContainsAllFields()
    {
        var dir = CreateTempDir();
        using var recorder = new EventRecorder(64, dir);
        var evt = new HoneypotEvent
        {
            EventType = "credential",
            Event = "credential_captured",
            SessionId = 123,
            Timestamp = DateTime.UtcNow,
            SourceIp = "203.0.113.10",
            SourcePort = 51234,
            TargetPort = 4499,
            Domain = "WORKGROUP",
            Username = "administrator",
            Password = "test-password",
            AuthMode = "standard",
            RequestedProtocol = "SSL|HYBRID",
            SelectedProtocol = "SSL",
            Cookie = "mstshash=admin",
            ComputerName = "WIN-SRV01"
        };
        var ok = await recorder.TryWriteCredentialAsync(evt);
        Assert.True(ok, "TryWriteCredentialAsync should succeed");

        // wait for background recorder to flush the event
        var path = Path.Combine(dir, "captured_creds.jsonl");
        var line = await WaitForFileAsync(path);
        using var json = JsonDocument.Parse(line);
        var root = json.RootElement;

        Assert.Equal("credential_captured", root.GetProperty("event").GetString());
        Assert.Equal(123, root.GetProperty("session_id").GetInt64());
        Assert.Equal("203.0.113.10", root.GetProperty("source_ip").GetString());
        Assert.Equal(51234, root.GetProperty("source_port").GetInt32());
        Assert.Equal(4499, root.GetProperty("target_port").GetInt32());
        Assert.Equal("WORKGROUP", root.GetProperty("domain").GetString());
        Assert.Equal("administrator", root.GetProperty("username").GetString());
        Assert.Equal("test-password", root.GetProperty("password").GetString());
        Assert.Equal("standard", root.GetProperty("auth_mode").GetString());
        Assert.Equal("SSL|HYBRID", root.GetProperty("requested_protocol").GetString());
        Assert.Equal("SSL", root.GetProperty("selected_protocol").GetString());
        Assert.Equal("mstshash=admin", root.GetProperty("cookie").GetString());
        Assert.Equal("WIN-SRV01", root.GetProperty("computer_name").GetString());
    }

    /// <summary>NLA 事件 password 為 null 時序列化為 JSON null，非空字串（§8）</summary>
    [Fact]
    public async Task NlaEvent_PasswordNull_SerializesAsNull()
    {
        var dir = CreateTempDir();
        using var recorder = new EventRecorder(64, dir);
        var evt = new HoneypotEvent
        {
            EventType = "nla_credential",
            Event = "credential_captured",
            SessionId = 1,
            Timestamp = DateTime.UtcNow,
            SourceIp = "127.0.0.1",
            SourcePort = 50000,
            TargetPort = 4499,
            Domain = "TESTDOMAIN",
            Username = "test-nla-user",
            Password = null,
            AuthMode = "nla"
        };
        var ok = await recorder.TryWriteCredentialAsync(evt);
        Assert.True(ok, "TryWriteCredentialAsync should succeed");

        var path = Path.Combine(dir, "nla_accounts.jsonl");
        var line = await WaitForFileAsync(path);
        using var json = JsonDocument.Parse(line);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
    }

    /// <summary>Console 遮罩不修改 stored credential（§9）</summary>
    [Fact]
    public void ConsoleMaskingDoesNotModifyStoredCredential()
    {
        const string original = "SuperSecret123!";
        var masked = CredentialMasking.Display(original, "masked");
        Assert.Equal("********", masked);
        Assert.Equal("SuperSecret123!", original);
        var full = CredentialMasking.Display(original, "full");
        Assert.Equal(original, full);
        Assert.Equal("********", CredentialMasking.Mask(null));
    }

    /// <summary>Source IP normalize（§23）：IPv4-mapped IPv6 → IPv4</summary>
    [Fact]
    public void SourceIpNormalize_MappedToIPv6()
    {
        var mapped = IPAddress.Parse("::ffff:203.0.113.10");
        Assert.Equal("203.0.113.10", SourceIpNormalizer.Normalize(mapped));
    }

    [Fact]
    public void SourceIpNormalize_IPv4_Unchanged()
    {
        var ipv4 = IPAddress.Parse("10.0.0.1");
        Assert.Equal("10.0.0.1", SourceIpNormalizer.Normalize(ipv4));
    }

    [Fact]
    public void SourceIpNormalize_Null_ReturnsNull()
    {
        Assert.Null(SourceIpNormalizer.Normalize(null));
    }

    /// <summary>CredentialEventsDropped 正常為 0（§11）</summary>
    [Fact]
    public async Task CredentialEventsDropped_Zero_UnderNormalLoad()
    {
        var dir = CreateTempDir();
        using var recorder = new EventRecorder(1024, dir);
        for (var i = 0; i < 50; i++)
        {
            var evt = new HoneypotEvent
            {
                EventType = "credential",
                Event = "credential_captured",
                SessionId = i,
                Timestamp = DateTime.UtcNow,
                SourceIp = "127.0.0.1",
                SourcePort = 50000 + i,
                TargetPort = 4499,
                Domain = "TEST",
                Username = $"user-{i:D3}",
                Password = $"pass-{i:D3}",
                AuthMode = "standard"
            };
            var ok = await recorder.TryWriteCredentialAsync(evt);
            Assert.True(ok, $"Credential {i} should not be dropped");
        }
        // let the background loop process all events
        await Task.Delay(500);
        Assert.Equal(0, recorder.CredentialEventsDropped);
        Assert.Equal(50, recorder.CredentialEventsAccepted);
    }

    /// <summary>
    /// Shutdown flush（第 3 點驗證）：enqueue credential 後立即 Dispose，
    /// 最後 credentials 檔案仍存在（即時 shutdown 不丟帳密）。
    /// </summary>
    [Fact]
    public async Task CredentialFlushOnShutdown_DoesNotLoseCredential()
    {
        var dir = CreateTempDir();
        var recorder = new EventRecorder(64, dir);
        // 模擬：Parse password → enqueue → 立即 shutdown（不等待背景 flush）
        var evt = new HoneypotEvent
        {
            EventType = "credential",
            Event = "credential_captured",
            SessionId = 42,
            Timestamp = DateTime.UtcNow,
            SourceIp = "192.168.1.10",
            SourcePort = 51000,
            TargetPort = 4499,
            Domain = "TESTDOMAIN",
            Username = "shutdown-user",
            Password = "Shutdown-Pass-999!",
            AuthMode = "standard"
        };
        var ok = await recorder.TryWriteCredentialAsync(evt);
        Assert.True(ok, "enqueue should succeed");

        // 立即 Dispose（等同 OS service stop 瞬間），不 sleep
        recorder.Dispose();

        // 檔案必須存在且含完整密碼
        var path = Path.Combine(dir, "captured_creds.jsonl");
        Assert.True(File.Exists(path), "credential file must exist after immediate Dispose");
        var content = await File.ReadAllTextAsync(path);
        Assert.Contains("shutdown-user", content);
        Assert.Contains("Shutdown-Pass-999!", content);
        Assert.Equal(0, recorder.CredentialEventsDropped);
    }
}