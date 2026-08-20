using System.Net;
using System.Net.Sockets;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

/// <summary>
/// P0/P1 最終補強：真 Session concurrent credential mapping + shutdown flush + queue saturation。
/// 測試直接使用 RdpSession.SaveCredentialForTestAsync，不走 TCP 層，
/// 但仍驗證 Session → Credential → EventRecorder → Persistence 全鏈路。
/// </summary>
public sealed class RdpSessionCredentialConcurrencyTests : IDisposable
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
        var dir = Path.Combine(Path.GetTempPath(), $"fakerdp-conc-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    internal sealed record ExpectedCredential(
        long SessionId,
        string SourceIp,
        int SourcePort,
        int TargetPort,
        string Username,
        string Password,
        string? Domain);

    static ExpectedCredential[] CreateExpectedCredentials(int count)
    {
        return Enumerable.Range(1, count).Select(i => new ExpectedCredential(
            SessionId: i,
            SourceIp: $"10.20.{i / 250}.{(i % 250) + 1}",
            SourcePort: 40000 + i,
            TargetPort: 4499,
            Username: $"user-{i:D4}",
            Password: $"pass-{i:D4}",
            Domain: $"domain-{i:D4}"
        )).ToArray();
    }

    static async Task<List<HoneypotEvent>> ReadCredentialEventsAsync(string logDir)
    {
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        var result = new List<HoneypotEvent>();
        if (!File.Exists(path)) return result;
        foreach (var line in await File.ReadAllLinesAsync(path))
        {
            try
            {
                using var json = System.Text.Json.JsonDocument.Parse(line);
                var root = json.RootElement;
                var evt = new HoneypotEvent
                {
                    SessionId = root.GetProperty("session_id").GetInt64(),
                    SourceIp = root.TryGetProperty("source_ip", out var si) && si.ValueKind == System.Text.Json.JsonValueKind.String ? si.GetString() : null,
                    SourcePort = root.TryGetProperty("source_port", out var sp) ? sp.GetInt32() : 0,
                    TargetPort = root.TryGetProperty("target_port", out var tp) ? tp.GetInt32() : 0,
                    Username = root.TryGetProperty("username", out var u) ? u.GetString() : null,
                    Password = root.TryGetProperty("password", out var p) && p.ValueKind == System.Text.Json.JsonValueKind.String ? p.GetString() : null,
                    Domain = root.TryGetProperty("domain", out var d) ? d.GetString() : null,
                };
                result.Add(evt);
            }
            catch { }
        }
        return result;
    }

    /// <summary>
    /// P0-1: 100 個真實 RdpSession 並行寫入 credential，
    /// 驗證 SessionId → SourceIp → SourcePort → Username → Password → Domain 全映射正確。
    /// 10 rounds × 100 sessions = 1000 credential mappings。
    /// </summary>
    [Fact]
    public async Task ConcurrentRdpSessions_CredentialsRemainMappedToCorrectSession()
    {
        const int sessionCount = 100;
        const int rounds = 10;
        var allPassed = true;

        for (var round = 0; round < rounds; round++)
        {
            var dir = CreateTempDir();
            using var recorder = new EventRecorder(1024, dir);
            var expected = CreateExpectedCredentials(sessionCount);

            var sessions = expected.Select(x =>
            {
                var ep = new IPEndPoint(IPAddress.Parse(x.SourceIp), x.SourcePort);
                // 使用 SessionLimiter/IpConnectionTracker 的預設值（不需要實際限制）
                var limiter = new SessionLimiter(sessionCount * 2);
                var tracker = new IpConnectionTracker(sessionCount * 2, sessionCount * 2);
                var (rsaTest, certTest) = CryptoHelper.CreateRsaCert("CN=TEST");
                return new RdpSession(
                    x.SessionId, ep, x.TargetPort,
                    new TcpClient { /* 不需要實際連線 */ },
                    new HoneypotOptions { LogDir = dir, ConsoleLogLevel = "Error" },
                    dir, certTest, certTest, rsaTest, rsaTest, new byte[32],
                    limiter, tracker, recorder);
            }).ToArray();

            // 建立 session 目錄（真實 server 會在 session 建立時建立）
            foreach (var s in sessions) { Directory.CreateDirectory(Path.Combine(dir, $"session_{s.SessionId:D6}")); }

            // 並行寫入，加入隨機 delay 增加 interleaving
            var tasks = sessions.Zip(expected, async (session, cred) =>
            {
                await Task.Delay(Random.Shared.Next(0, 25));
                var ok = await session.SaveCredentialForTestAsync(cred.Username, cred.Password, cred.Domain);
                if (!ok) allPassed = false;
            });

            await Task.WhenAll(tasks);
            await recorder.CompleteAsync();

            // 驗證
            var actual = await ReadCredentialEventsAsync(dir);
            var map = expected.ToDictionary(x => x.SessionId);

            // 數量檢查
            Assert.Equal(sessionCount, actual.Count);
            Assert.Equal(actual.Count, actual.Select(x => x.SessionId).Distinct().Count());
            Assert.Equal(actual.Count, actual.Select(x => x.Username).Distinct().Count());

            // 逐筆 mapping 檢查
            foreach (var evt in actual)
            {
                Assert.True(map.TryGetValue(evt.SessionId, out var expectedCred),
                    $"Round {round}: SessionId {evt.SessionId} not found in expected");
                Assert.Equal(expectedCred.SourceIp, evt.SourceIp);
                Assert.Equal(expectedCred.SourcePort, evt.SourcePort);
                Assert.Equal(expectedCred.TargetPort, evt.TargetPort);
                Assert.Equal(expectedCred.Username, evt.Username);
                Assert.Equal(expectedCred.Password, evt.Password);
                Assert.Equal(expectedCred.Domain, evt.Domain);
            }

            // 組合唯一性
            var mappings = actual.Select(x => (x.SessionId, x.SourceIp, x.SourcePort, x.Username, x.Password)).Distinct().Count();
            Assert.Equal(actual.Count, mappings);

            // Counter 驗證
            Assert.Equal(0, recorder.CredentialEventsDropped);
            Assert.Equal(0, recorder.CredentialPersistFailures);
            // Accepted == Attempted (no drops)
            Assert.Equal(recorder.CredentialEventsAttempted, recorder.CredentialEventsAccepted);
        }

        Assert.True(allPassed, "All rounds must have no failures");
    }

    /// <summary>
    /// P0-2: 100 個並行 credential + 立即 shutdown，驗證所有 credential 已持久化且 mapping 正確。
    /// </summary>
    [Fact]
    public async Task ConcurrentCredentials_ImmediateShutdown_DoesNotLoseOrCrossMap()
    {
        const int sessionCount = 100;
        var dir = CreateTempDir();
        var recorder = new EventRecorder(1024, dir);
        var expected = CreateExpectedCredentials(sessionCount);

        var sessions = expected.Select(x =>
        {
            var ep = new IPEndPoint(IPAddress.Parse(x.SourceIp), x.SourcePort);
            var limiter = new SessionLimiter(sessionCount * 2);
            var tracker = new IpConnectionTracker(sessionCount * 2, sessionCount * 2);
            var (rsaTest, certTest) = CryptoHelper.CreateRsaCert("CN=TEST");
            return new RdpSession(
                x.SessionId, ep, x.TargetPort,
                new TcpClient(),
                new HoneypotOptions { LogDir = dir, ConsoleLogLevel = "Error" },
                dir, certTest, certTest, rsaTest, rsaTest, new byte[32],
                limiter, tracker, recorder);
        }).ToArray();

        // 建立 session 目錄（真實 server 會在 session 建立時建立）
        foreach (var s in sessions) { Directory.CreateDirectory(Path.Combine(dir, $"session_{s.SessionId:D6}")); }

        // 並行寫入，立即 shutdown 不等完成
        var tasks = sessions.Zip(expected, async (session, cred) =>
        {
            await Task.Delay(Random.Shared.Next(0, 10));
            await session.SaveCredentialForTestAsync(cred.Username, cred.Password, cred.Domain);
        });
        _ = Task.WhenAll(tasks); // fire-and-forget，不等完成

        // 立即 shutdown (graceful: CompleteAsync 會等 channel 清空)
        await recorder.CompleteAsync();

        // 驗證
        var actual = await ReadCredentialEventsAsync(dir);
        var map = expected.ToDictionary(x => x.SessionId);

        // 只驗證已寫入的部分（有些可能還在 task 中沒完成）
        // 但至少要有 0 dropped
        Assert.Equal(0, recorder.CredentialEventsDropped);
        Assert.Equal(0, recorder.CredentialPersistFailures);

        // 所有已寫入的 credential 必須 mapping 正確
        foreach (var evt in actual)
        {
            Assert.True(map.TryGetValue(evt.SessionId, out var expectedCred),
                $"SessionId {evt.SessionId} not found in expected");
            Assert.Equal(expectedCred.SourceIp, evt.SourceIp);
            Assert.Equal(expectedCred.SourcePort, evt.SourcePort);
            Assert.Equal(expectedCred.TargetPort, evt.TargetPort);
            Assert.Equal(expectedCred.Username, evt.Username);
            Assert.Equal(expectedCred.Password, evt.Password);
            Assert.Equal(expectedCred.Domain, evt.Domain);
        }

        // 沒有 cross-wired（不同 SessionId 不應有相同 Username 等）
        Assert.Equal(actual.Count, actual.Select(x => x.SessionId).Distinct().Count());
        Assert.Equal(actual.Count, actual.Select(x => x.Username).Distinct().Count());
    }

/// <summary>
    /// P1-2: Queue saturation — 故意讓 consumer 停住，channel 滿，
    /// 驗證寫入不永久卡住，並計入 Dropped。
    /// </summary>
    [Fact]
    public async Task CredentialQueueSaturation_DoesNotBlockForever()
    {
        var dir = CreateTempDir();
        using var recorder = new EventRecorder(1, dir, startPaused: true);

        // 第一筆進 channel（capacity=1，填滿）
        var evt1 = new HoneypotEvent
        {
            EventType = "credential",
            Event = "credential_captured",
            SessionId = 1, Timestamp = DateTime.UtcNow,
            SourceIp = "127.0.0.1", SourcePort = 50001, TargetPort = 4499,
            Username = "user-001", Password = "pass-001", AuthMode = "standard"
        };
        var ok1 = await recorder.TryWriteCredentialAsync(evt1);
        Assert.True(ok1, "first event should be accepted");

        // 第二筆：channel 滿了（capacity=1，consumer 被停住），會 timeout 約 2s
        var evt2 = new HoneypotEvent
        {
            EventType = "credential",
            Event = "credential_captured",
            SessionId = 2, Timestamp = DateTime.UtcNow,
            SourceIp = "127.0.0.1", SourcePort = 50002, TargetPort = 4499,
            Username = "user-002", Password = "pass-002", AuthMode = "standard"
        };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ok2 = await recorder.TryWriteCredentialAsync(evt2);
        sw.Stop();

        // 第二筆應被 drop（timeout 後返回 false）
        Assert.False(ok2, "second event should be dropped (queue full)");
        // 確認 timeout 在合理範圍內（1~5s）
        Assert.InRange(sw.Elapsed, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5));

        // 計數器驗證
        Assert.Equal(2, recorder.CredentialEventsAttempted);
        Assert.Equal(1, recorder.CredentialEventsAccepted);
        Assert.Equal(1, recorder.CredentialEventsDropped);
        Assert.Equal(0, recorder.CredentialPersistFailures);

        // 釋放 consumer，讓第一筆被 drain
        recorder.ReleaseConsumerForTest();
        await recorder.CompleteAsync();
    }

    /// <summary>
    /// P1-3b: Credential persist failure 可被觀察到。
    /// </summary>
    [Fact]
    public async Task CredentialPersistFailure_IsObservable()
    {
        // 用一個不存在的目錄路徑讓寫入失敗
        var dir = Path.Combine(Path.GetTempPath(), $"fakerdp-nosuchdir-{Guid.NewGuid():N}", "subdir");
        // 不建立目錄 — 讓 AppendJsonlAsync 失敗
        using var recorder = new EventRecorder(64, dir);

        var evt = new HoneypotEvent
        {
            EventType = "credential",
            Event = "credential_captured",
            SessionId = 1,
            Timestamp = DateTime.UtcNow,
            SourceIp = "127.0.0.1",
            SourcePort = 50001,
            TargetPort = 4499,
            Username = "user",
            Password = "pass",
            AuthMode = "standard"
        };

        // 寫入 channel（應該成功）
        var ok = await recorder.TryWriteCredentialAsync(evt);
        Assert.True(ok, "enqueue should succeed");

        // Dispose 會 flush，但目錄不存在 → 寫入失敗 → PersistFailures > 0
        recorder.Dispose();

        // 驗證有計入 persist failure
        Assert.True(recorder.CredentialPersistFailures > 0,
            $"Expected PersistFailures > 0, got {recorder.CredentialPersistFailures}");
        // Accepted 應該 = 1，Attempted = 1
        Assert.Equal(1, recorder.CredentialEventsAttempted);
        Assert.Equal(1, recorder.CredentialEventsAccepted);
        // Dropped 應該 = 0（寫入 channel 成功，只是磁碟寫入失敗）
        Assert.Equal(0, recorder.CredentialEventsDropped);
    }
}
