using System.Net;

namespace RdpHoneypot;

/// <summary>
/// Session 層級不可變中繼資料（§24）：在 TCP connection 建立後立即 capture RemoteEndPoint，
/// 之後 Credential / Telemetry / Disconnect 全部共用此 metadata。
/// </summary>
internal sealed record RdpSessionMetadata(
    long SessionId,
    IPAddress SourceIp,
    int SourcePort,
    int TargetPort,
    DateTimeOffset ConnectedAt);

/// <summary>
/// 來源 IP normalize 輔助（§23）：
///   - IPv4-mapped IPv6 (::ffff:x.x.x.x) → IPv4
///   - 其餘保持原樣
/// </summary>
internal static class SourceIpNormalizer
{
    public static string Normalize(IPAddress? ip)
    {
        if (ip is null) return "0.0.0.0";
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        return ip.ToString();
    }
}

/// <summary>
/// Console 遮罩與原始憑證分離（§9）。
/// Console 顯示憑證以遮罩模式顯示，但原始 credential event 永遠保留完整值。
/// </summary>
internal static class CredentialMasking
{
    public static string Mask(string? secret) => "********";

    public static string Display(string? secret, string? mode)
        => string.Equals(mode, "full", StringComparison.OrdinalIgnoreCase)
            ? secret ?? "<empty>"
            : Mask(secret);
}