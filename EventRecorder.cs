using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;

namespace RdpHoneypot;

/// <summary>
/// 結構化事件：憑證擷取、NLA 帳號等。
/// Session path 一律只 TryWrite，不直接做檔案 I/O。
/// </summary>
public sealed record HoneypotEvent
{
    /// <summary>內部路由用："credential" / "nla_credential"（不序列化到檔案）</summary>
    [JsonIgnore]
    public string EventType { get; init; } = "";

    public long SessionId { get; init; }
    public DateTime Timestamp { get; init; }
    public string? SourceIp { get; init; }
    public int SourcePort { get; init; }
    public int TargetPort { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public string? Domain { get; init; }
    public string? ClientInfo { get; init; }

    /// <summary>內部用來寫 per-session credential.json（不序列化）</summary>
    [JsonIgnore]
    public string? SessionDir { get; init; }
}

/// <summary>
/// 事件管線：bounded Channel + 背景批次寫入器。
/// Session 只呼叫 TryWrite（不阻塞）；背景 Recorder 統一批次寫 JSONL，
/// 避免高併發時 Disk I/O 反壓 Network。
///
/// 佇列滿時採 DropOldest（舊事件拋棄），並記錄 dropped 計數供監控。
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
    long _droppedCount;
    long _processedCount;

    public int Capacity { get; }
    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long ProcessedCount => Interlocked.Read(ref _processedCount);

    public EventRecorder(int capacity, string logDir)
    {
        Capacity = capacity;
        _logDir = logDir;
        _channel = Channel.CreateBounded<HoneypotEvent>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });
        _cts = new CancellationTokenSource();
        _loop = RecordLoopAsync(_cts.Token);
    }

    /// <summary>非阻塞寫入事件。佇列滿時回 false 並累計 dropped。</summary>
    public bool TryWrite(HoneypotEvent evt)
    {
        if (!_channel.Writer.TryWrite(evt))
        {
            Interlocked.Increment(ref _droppedCount);
            return false;
        }
        return true;
    }

    /// <summary>由 Session 路徑取得目前已處理/捨棄的事件數（供監控）</summary>
    public (long processed, long dropped) GetStats()
        => (Interlocked.Read(ref _processedCount), Interlocked.Read(ref _droppedCount));

    async Task RecordLoopAsync(CancellationToken ct)
    {
        var buffer = new List<HoneypotEvent>(128);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                buffer.Clear();

                // 等待第一個事件
                var first = await _channel.Reader.ReadAsync(ct);
                buffer.Add(first);

                // 盡量取出更多事件一起批次寫（最多 128 筆）
                while (buffer.Count < 128 && _channel.Reader.TryRead(out var evt))
                    buffer.Add(evt);

                await WriteBatchAsync(buffer, ct);
                Interlocked.Add(ref _processedCount, buffer.Count);
            }
        }
        catch (OperationCanceledException)
        {
            // 正常關閉路徑
        }
        finally
        {
            // 關閉前把殘留事件寫完
            while (_channel.Reader.TryRead(out var evt))
            {
                try
                {
                    await WriteBatchAsync([evt], CancellationToken.None);
                    Interlocked.Increment(ref _processedCount);
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

    public void Dispose()
    {
        _cts.Cancel();
        _channel.Writer.TryComplete();
        try { _loop.GetAwaiter().GetResult(); }
        catch { /* 忽略 shutdown 錯誤 */ }
        _cts.Dispose();
    }
}