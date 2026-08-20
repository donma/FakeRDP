using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;

namespace RdpHoneypot;

/// <summary>
/// 結構化事件：憑證擷取、NLA 帳號等。
/// Session path 一律只透過 EventRecorder 寫入，不直接做檔案 I/O。
///
/// 統一 Credential Event Schema（§3）：
///   event / timestamp / sessionId / sourceIp / sourcePort / targetPort /
///   domain / username / password / authMode / requestedProtocol /
///   selectedProtocol / cookie / computerName
///
/// Password 若流程未提供則為 null（不得用空字串、unknown、*** 取代原始資料；
/// 遮罩只作用於 Console，不作用於授權測試用的原始 Credential Event）。
/// </summary>
public sealed record HoneypotEvent
{
    /// <summary>內部路由用："credential" / "nla_credential"（不序列化到檔案）</summary>
    [JsonIgnore]
    public string EventType { get; init; } = "";

    /// <summary>統一 event 名稱，預設 credential_captured</summary>
    public string Event { get; init; } = "credential_captured";

    public long SessionId { get; init; }
    public DateTime Timestamp { get; init; }
    public string? SourceIp { get; init; }
    public int SourcePort { get; init; }
    public int TargetPort { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public string? Domain { get; init; }

    /// <summary>standard / tls / nla</summary>
    public string? AuthMode { get; init; }

    /// <summary>client requested protocols（例如 "SSL|HYBRID"）</summary>
    public string? RequestedProtocol { get; init; }

    /// <summary>server selected protocol（例如 "SSL" / "HYBRID"）</summary>
    public string? SelectedProtocol { get; init; }

    /// <summary>mstshash / cookie</summary>
    public string? Cookie { get; init; }

    public string? ComputerName { get; init; }

    public string? ClientInfo { get; init; }

    /// <summary>內部用來寫 per-session credential.json（不序列化）</summary>
    [JsonIgnore]
    public string? SessionDir { get; init; }
}

/// <summary>
/// 事件管線：bounded Channel + 背景批次寫入器。
/// Session 只呼叫 TryWrite（不阻塞，用於非 credential 事件）；
/// Credential 事件使用 TryWriteCredentialAsync（避免靜默丟棄）。
/// 背景 Recorder 統一批次寫 JSONL，避免高併發時 Disk I/O 反壓 Network。
///
/// 佇列滿時：
///   - 非 credential 事件：DropOldest（記錄 TelemetryEventsDropped）
///   - Credential 事件：WriteAsync 最多等待 2s；仍滿則記錄 CredentialEventsDropped
///     （CredentialEventsDropped 正常應為 0，任何非 0 → Hard Gate FAIL）
/// </summary>
public sealed class EventRecorder : IDisposable
{
    static readonly JsonSerializerOptions JsonlOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false
    };

    static readonly JsonSerializerOptions PrettyOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true
    };

    readonly Channel<HoneypotEvent> _channel;
    readonly CancellationTokenSource _cts;
    readonly Task _loop;
    readonly string _logDir;

    // ── 計數器（§25） ──
    long _credentialAcceptedCount;
    long _credentialDroppedCount;
    long _credentialWithPasswordCount;
    long _credentialWithoutPasswordCount;
    long _telemetryDroppedCount;
    long _processedCount;

    public int Capacity { get; }
    public long CredentialEventsAccepted => Interlocked.Read(ref _credentialAcceptedCount);
    public long CredentialEventsDropped => Interlocked.Read(ref _credentialDroppedCount);
    public long CredentialEventsWithPassword => Interlocked.Read(ref _credentialWithPasswordCount);
    public long CredentialEventsWithoutPassword => Interlocked.Read(ref _credentialWithoutPasswordCount);
    public long TelemetryEventsDropped => Interlocked.Read(ref _telemetryDroppedCount);
    public long ProcessedCount => Interlocked.Read(ref _processedCount);

    // 保留相容性（原 DroppedCount / GetStats 涵蓋所有事件）
    public long DroppedCount => Interlocked.Read(ref _credentialDroppedCount) + Interlocked.Read(ref _telemetryDroppedCount);

    public (long processed, long dropped) GetStats()
        => (Interlocked.Read(ref _processedCount), DroppedCount);

    public EventRecorder(int capacity, string logDir)
    {
        Capacity = capacity;
        _logDir = logDir;
_channel = Channel.CreateBounded<HoneypotEvent>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            // 非 credential 事件使用 DropOldest（telemetry 可丟棄）；
            // Credential 事件改用 TryWriteCredentialAsync（WriteAsync 等待，不丟棄）
            FullMode = BoundedChannelFullMode.Wait
        });
        _cts = new CancellationTokenSource();
        _loop = RecordLoopAsync(_cts.Token);
    }

    /// <summary>非阻塞寫入非 credential 事件。佇列滿時回 false 並累計 telemetry dropped。</summary>
    public bool TryWrite(HoneypotEvent evt)
    {
        bool isCred = evt.EventType is "credential" or "nla_credential";
        if (_channel.Writer.TryWrite(evt))
        {
            if (isCred)
            {
                Interlocked.Increment(ref _credentialAcceptedCount);
                if (!string.IsNullOrEmpty(evt.Password))
                    Interlocked.Increment(ref _credentialWithPasswordCount);
                else
                    Interlocked.Increment(ref _credentialWithoutPasswordCount);
            }
            return true;
        }
        // 滿佇列
        if (isCred)
            Interlocked.Increment(ref _credentialDroppedCount);
        else
            Interlocked.Increment(ref _telemetryDroppedCount);
        return false;
    }

    /// <summary>
    /// 安全寫入 credential 事件：使用 Wait 模式 channel 的 WriteAsync，
    /// 確保不靜默丟棄（除非取消）。正常狀況下 CredentialEventsDropped 應為 0。
    /// </summary>
    public async Task<bool> TryWriteCredentialAsync(HoneypotEvent evt, CancellationToken outerCt = default)
    {
        try
        {
            await _channel.Writer.WriteAsync(evt, outerCt);
            Interlocked.Increment(ref _credentialAcceptedCount);
            if (!string.IsNullOrEmpty(evt.Password))
                Interlocked.Increment(ref _credentialWithPasswordCount);
            else
                Interlocked.Increment(ref _credentialWithoutPasswordCount);
            return true;
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _credentialDroppedCount);
            return false;
        }
    }

    async Task RecordLoopAsync(CancellationToken ct)
    {
        var buffer = new List<HoneypotEvent>(128);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                // 等待第一個事件（項次累加到 buffer；buffer 在成功寫入後才清空）
                var first = await _channel.Reader.ReadAsync(ct);
                buffer.Add(first);

                // 盡量取出更多事件一起批次寫（最多 128 筆）
                while (buffer.Count < 128 && _channel.Reader.TryRead(out var evt))
                    buffer.Add(evt);

                try
                {
                    await WriteBatchAsync(buffer, ct);
                    Interlocked.Add(ref _processedCount, buffer.Count);
                    buffer.Clear(); // 成功寫入後清空，避免 finally 重複寫
                }
                catch (OperationCanceledException)
                {
                    // 取消發生在批次寫入期間：buffer 內的事件不能丟棄，
                    // 交由 finally 以 CancellationToken.None 補寫。
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常關閉路徑
        }
        finally
        {
            // 把「已被 ReadAsync 取出但尚未寫入的 buffer」以及 channel 殘留
            // 一起寫出，確保 shutdown 瞬間不丟失已 enqueue 的 credential。
            var remaining = new List<HoneypotEvent>(buffer);
            while (_channel.Reader.TryRead(out var evt))
                remaining.Add(evt);
            if (remaining.Count > 0)
            {
                try
                {
                    await WriteBatchAsync(remaining, CancellationToken.None);
                    Interlocked.Add(ref _processedCount, remaining.Count);
                }
                catch { /* 最後清空階段不中斷 */ }
            }
        }
    }

    Task WriteBatchAsync(List<HoneypotEvent> batch, CancellationToken ct)
    {
        var tasks = new List<Task>(3);

        // captured_creds.jsonl：標準/TLS 路徑憑證
        var creds = batch.Where(e => e.EventType == "credential").ToList();
        if (creds.Count > 0)
            tasks.Add(AppendJsonlAsync("captured_creds.jsonl", creds, ct));

        // nla_accounts.jsonl：NLA 帳號
        var nlaCreds = batch.Where(e => e.EventType == "nla_credential").ToList();
        if (nlaCreds.Count > 0)
            tasks.Add(AppendJsonlAsync("nla_accounts.jsonl", nlaCreds, ct));

        // 個別 session 的 credential.json / nla_credential.json
        foreach (var e in batch.Where(e => e.SessionDir != null))
        {
            var fileName = e.EventType == "nla_credential"
                ? "nla_credential.json"
                : "credential.json";
            var path = Path.Combine(e.SessionDir!, fileName);
            tasks.Add(File.WriteAllTextAsync(
                path, JsonSerializer.Serialize(e, PrettyOptions), ct));
        }

        return Task.WhenAll(tasks);
    }

    async Task AppendJsonlAsync(string fileName, List<HoneypotEvent> events, CancellationToken ct)
    {
        var path = Path.Combine(_logDir, fileName);
        var sb = new StringBuilder();
        foreach (var e in events)
        {
            sb.AppendLine(JsonSerializer.Serialize(e, JsonlOptions));
        }
        await File.AppendAllTextAsync(path, sb.ToString(), ct);
    }

    bool _disposed;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        // 先等待 loop 完全結束（含 finally drain），再關閉 writer
        try { _loop.GetAwaiter().GetResult(); }
        catch { /* 忽略 shutdown 錯誤 */ }
        _channel.Writer.TryComplete();
        _cts.Dispose();
    }
}