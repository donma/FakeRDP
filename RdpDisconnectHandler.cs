namespace RdpHoneypot;

/// <summary>
/// 連線完成後的安全結束策略。
/// 這裡只處理本 honeypot 自己的 RDP connection，不會向其他主機注入封包。
/// </summary>
static class RdpDisconnectHandler
{
    public static async Task ApplyAfterCaptureAsync(RdpSession session, CancellationToken ct)
    {
        var profile = session.Profile;
        var mode = (profile.DisconnectMode ?? "capture_and_close").Trim().ToLowerInvariant();
        var delay = Math.Clamp(profile.DisconnectDelayMs, 0, 10_000);

        switch (mode)
        {
            case "capture_and_close":
                await session.LogAsync("  (disconnect mode: capture_and_close)");
                return;

            case "capture_and_graceful_close":
                await session.LogAsync($"  (disconnect mode: graceful_close, delay={delay}ms)");
                break;

            case "shutdown_like":
                // RDP client 的視窗文字由 mstsc 依協定狀態自行決定，
                // 不能透過任意字串強制指定。這個模式只模擬「完成回應後延遲、
                // 再由本 honeypot 正常關閉連線」的時序，不會影響其他主機。
                await session.LogAsync(
                    $"  (disconnect mode: shutdown_like; mstsc UI text is client-controlled, delay={delay}ms)");
                break;

            default:
                await session.LogAsync(
                    $"  (disconnect mode: unknown '{profile.DisconnectMode}', fallback=capture_and_close)");
                return;
        }

        if (delay > 0)
            await Task.Delay(delay, ct);
    }
}