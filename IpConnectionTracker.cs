using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace RdpHoneypot;

/// <summary>
/// Per-IP / Per-/24 併發連線追蹤器。
/// 避免單一來源吃光全部 Session 配額。
/// 超過限制時仍允許連線但僅走輕量回應（X.224 CC），
/// 不消耗 TLS / 深度處理資源。
/// </summary>
sealed class IpConnectionTracker : IDisposable
{
    sealed class IpEntry
    {
        public int Count;
        public long LastSeenTicks;
    }

    readonly ConcurrentDictionary<string, IpEntry> _entries = new();
    readonly int _maxPerIp;
    readonly int _maxPerSubnet;
    readonly Timer _cleanupTimer;

    public IpConnectionTracker(int maxPerIp, int maxPerSubnet)
    {
        _maxPerIp = maxPerIp;
        _maxPerSubnet = maxPerSubnet;
        // 每 30 秒清理一次 Count=0 且超過 60 秒的 entry
        _cleanupTimer = new Timer(static _ => { }, null,
            Timeout.Infinite, Timeout.Infinite);
        // 使用 Timer 回呼
        _cleanupTimer = new Timer(_ => Cleanup(), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// 嘗試取得深度處理配額。
    /// 回傳 true：可繼續處理（TLS/MCS/…）；回傳 false：應走輕量回應。
    /// </summary>
    public bool TryAcquire(IPAddress addr)
    {
        var ipStr = addr.ToString();
        var subnet = GetSubnet(addr);
        long now = Stopwatch.GetTimestamp();

        var ipEntry = _entries.GetOrAdd(ipStr, _ => new IpEntry());
        var subnetEntry = _entries.GetOrAdd(subnet, _ => new IpEntry());

        // 先 increment 再檢查，超過則 rollback
        int ipCount = Interlocked.Increment(ref ipEntry.Count);
        int subnetCount = Interlocked.Increment(ref subnetEntry.Count);
        ipEntry.LastSeenTicks = now;
        subnetEntry.LastSeenTicks = now;

        if (ipCount > _maxPerIp || subnetCount > _maxPerSubnet)
        {
            // Rollback
            Interlocked.Decrement(ref ipEntry.Count);
            Interlocked.Decrement(ref subnetEntry.Count);
            return false;
        }

        return true;
    }

    /// <summary>歸還 Per-IP / Subnet 配額。必須與 TryAcquire(true) 成對呼叫。</summary>
    public void Release(IPAddress addr)
    {
        var ipStr = addr.ToString();
        var subnet = GetSubnet(addr);

        if (_entries.TryGetValue(ipStr, out var ipEntry))
            Interlocked.Decrement(ref ipEntry.Count);
        if (_entries.TryGetValue(subnet, out var subnetEntry))
            Interlocked.Decrement(ref subnetEntry.Count);
    }

    static string GetSubnet(IPAddress addr)
    {
        var bytes = addr.GetAddressBytes();
        if (bytes.Length == 4)
            return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";
        // IPv6：不分 subnet，以完整 IP 為單位
        return addr.ToString();
    }

    void Cleanup()
    {
        var threshold = Stopwatch.GetTimestamp() - TimeSpan.FromSeconds(60).Ticks;
        foreach (var kvp in _entries)
        {
            if (Volatile.Read(ref kvp.Value.Count) == 0 &&
                Volatile.Read(ref kvp.Value.LastSeenTicks) < threshold)
            {
                _entries.TryRemove(kvp.Key, out _);
            }
        }
    }

    public void Dispose() => _cleanupTimer.Dispose();
}