using System.Text;

namespace RdpHoneypot;

/// <summary>
/// X.224 連接階段處理：解析 Connection Request 並依 ServerProfile 選擇回應。
/// </summary>
static class X224Handler
{
    public readonly record struct NegotiationResult(
        bool UseNla, bool UseTls, bool UseStandardSecurity,
        bool IsSupported, string? ClientInfo, uint RequestedProtocols);

    public static NegotiationResult ParseConnectionRequest(byte[] packet, RdpServerProfile profile)
    {
        uint protocols = RdpPacket.TryParseNegotiationRequest(packet);
        bool hasNegotiation = protocols != 0;
        bool requestedTls = (protocols & 0x01) != 0;
        bool requestedNla = (protocols & 0x02) != 0;
        bool requestedHybridEx = (protocols & 0x08) != 0;

        // 沒有 RDP_NEG_REQ 時代表 legacy Standard Security。
        bool useStandard = !hasNegotiation && profile.EnableStandardSecurity;
        bool useNla = requestedNla && profile.EnableNla;
        // HYBRID/NLA 的 CredSSP transport 仍然需要 TLS，即使 client 沒有另外設 0x01。
        bool useTls = (requestedTls || requestedNla) && profile.EnableTls;

        // Profile 關閉 TLS 時，不冒充支援 NLA。
        if (!useTls)
            useNla = false;
        if (requestedHybridEx && !profile.EnableHybridEx)
        {
            // 若同時宣告普通 TLS/NLA，仍可選擇已支援的路徑；只有 Hybrid-Ex 時拒絕。
            if ((protocols & 0x03) == 0)
            {
                useTls = false;
                useNla = false;
            }
        }

        bool supported = useStandard || useTls || useNla;
        string? clientInfo = null;
        if (packet.Length > 11)
        {
            var cookie = Encoding.ASCII.GetString(packet, 11, packet.Length - 11).TrimEnd('\0');
            if (cookie.Length > 0)
                clientInfo = $"cookie='{cookie}'";
        }

        return new NegotiationResult(
            useNla,
            useTls,
            useStandard,
            supported,
            clientInfo,
            protocols);
    }

    public static uint SelectProtocol(NegotiationResult negotiation, RdpServerProfile profile)
    {
        if (!negotiation.IsSupported)
            return 0;
        if (negotiation.UseNla)
            return 0x02;
        if (negotiation.UseTls)
            return 0x01;
        return 0;
    }

    public static byte[] BuildFailureResponse(uint failureCode)
        => RdpPacket.BuildX224ConnectionFailure(failureCode);
}