using System.Text;

namespace RdpHoneypot;

/// <summary>
/// X.224 連接階段處理：解析 Connection Request 並依 ServerProfile 選擇實際支援的回應。
/// </summary>
static class X224Handler
{
    public readonly record struct NegotiationResult(
        bool UseNla,
        bool UseTls,
        bool UseStandardSecurity,
        bool IsSupported,
        string? RawCookie,
        string? Mstshash,
        string? ClientInfo,
        RdpRequestedProtocol RequestedProtocols,
        RdpSelectedProtocol SelectedProtocol,
        RdpNegotiationFailureReason? FailureReason);

    public static NegotiationResult ParseConnectionRequest(byte[] packet, RdpServerProfile profile)
    {
        var requested = (RdpRequestedProtocol)RdpPacket.TryParseNegotiationRequest(packet);
        var hasNegotiation = RdpPacket.HasNegotiationRequest(packet);
        var malformedNegotiation = packet.Length >= 19 &&
            packet[^7] == 0x00 && packet[^6] == 0x08 && packet[^5] == 0x00 && !hasNegotiation;
        var rawCookie = ParseCookie(packet);
        var mstshash = ParseMstshash(rawCookie);

        RdpSelectedProtocol selected = RdpSelectedProtocol.Standard;
        var useNla = false;
        var useTls = false;
        var useStandard = false;
        RdpNegotiationFailureReason? failure = null;

        if (!hasNegotiation)
        {
            if (malformedNegotiation)
            {
                failure = RdpNegotiationFailureReason.InconsistentFlags;
            }
            else
            {
                useStandard = profile.EnableStandardSecurity;
            }
            if (!useStandard && failure is null)
                failure = RdpNegotiationFailureReason.SslRequiredByServer;
        }
        else
        {
            // Fixed preference: HYBRID/NLA -> SSL/TLS. Unsupported RDSTLS and
            // HYBRID_EX are never advertised or selected unless fully implemented.
            if ((requested & RdpRequestedProtocol.Hybrid) != 0 &&
                profile.EnableNla && profile.EnableTls)
            {
                selected = RdpSelectedProtocol.Hybrid;
                useNla = true;
                useTls = true;
            }
            else if ((requested & RdpRequestedProtocol.Ssl) != 0 && profile.EnableTls)
            {
                selected = RdpSelectedProtocol.Ssl;
                useTls = true;
            }
            else
            {
                failure = FailureFor(requested, profile);
            }
        }

        var clientInfo = rawCookie is null ? null : $"cookie='{rawCookie}'";
        return new NegotiationResult(
            useNla,
            useTls,
            useStandard,
            failure is null,
            rawCookie,
            mstshash,
            clientInfo,
            requested,
            selected,
            failure);
    }

    public static uint SelectProtocol(NegotiationResult negotiation, RdpServerProfile profile)
        => negotiation.IsSupported ? (uint)negotiation.SelectedProtocol : 0;

    public static byte[] BuildFailureResponse(RdpNegotiationFailureReason reason)
        => RdpPacket.BuildX224ConnectionFailure((uint)reason);

    static RdpNegotiationFailureReason FailureFor(RdpRequestedProtocol requested, RdpServerProfile profile)
    {
        if ((requested & RdpRequestedProtocol.HybridEx) != 0 &&
            (requested & ~(RdpRequestedProtocol.HybridEx)) == 0)
            return RdpNegotiationFailureReason.HybridRequiredByServer;
        if ((requested & RdpRequestedProtocol.RdSTls) != 0 &&
            (requested & ~(RdpRequestedProtocol.RdSTls)) == 0)
            return RdpNegotiationFailureReason.SslRequiredByServer;
        if (!profile.EnableTls && ((requested & (RdpRequestedProtocol.Ssl | RdpRequestedProtocol.Hybrid)) != 0))
            return RdpNegotiationFailureReason.SslNotAllowedByServer;
        return RdpNegotiationFailureReason.InconsistentFlags;
    }

    static string? ParseCookie(byte[] packet)
    {
        if (packet.Length <= 11)
            return null;
        var end = RdpPacket.HasNegotiationRequest(packet) ? packet.Length - 8 : packet.Length;
        if (end <= 11)
            return null;
        const int cookieStart = 11;
        if (end <= cookieStart)
            return null;
        var value = Encoding.ASCII.GetString(packet, cookieStart, end - cookieStart).TrimEnd('\0');
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    static string? ParseMstshash(string? rawCookie)
    {
        if (rawCookie is null)
            return null;
        const string prefix = "Cookie: mstshash=";
        var start = rawCookie.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
            return null;
        var value = rawCookie[(start + prefix.Length)..].Trim();
        return value.Length == 0 ? null : value;
    }
}
