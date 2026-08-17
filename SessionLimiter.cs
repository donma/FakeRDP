namespace RdpHoneypot;

/// <summary>
/// 全域 Session 配額控制器。
/// 任何進入深度協定處理（TLS/MCS/Info PDU）的連線都必須先 TryEnter。
/// 超出配額時，連線仍可走輕量 X.224 回應（讓 scanner 看見 RDP 服務），
/// 但不會繼續耗費 TLS / RSA / 記憶體等資源。
/// </summary>
sealed class SessionLimiter
{
    readonly SemaphoreSlim _semaphore;

    public int MaxConcurrent { get; }
    public int Available => _semaphore.CurrentCount;

    public SessionLimiter(int maxConcurrent)
    {
        MaxConcurrent = maxConcurrent;
        _semaphore = new SemaphoreSlim(maxConcurrent, maxConcurrent);
    }

    /// <summary>嘗試取得一個 Session 配額。非封鎖，失敗時不等待。</summary>
    public bool TryEnter() => _semaphore.Wait(0);

    /// <summary>歸還 Session 配額。必須與 TryEnter 成對呼叫。</summary>
    public void Exit() => _semaphore.Release();
}