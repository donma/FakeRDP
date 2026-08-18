namespace RdpHoneypot;

/// <summary>
/// T.125 MCS 階段的封包處理：Connect Initial / Erect Domain / Attach User / Channel Join。
/// 每個方法接收 RdpSession 作為 context（提供金鑰、隨機數、記錄等），純搬移自舊 RdpSession。
/// </summary>
static class McsHandler
{
    public static byte[]? HandleConnect(RdpSession session, byte[] packet)
    {
        var state = session.State;
        try
        {
            var info = RdpPacket.ParseMCSConnectInitial(packet);
            state.ClientInfo = string.IsNullOrEmpty(state.ClientInfo)
                ? info
                : $"{state.ClientInfo}; {info}";
        }
        catch { }

        var response = RdpPacket.BuildMCSConnectResponse(
            session.ServerCert, session.RsaKey, session.ServerRandom, state.UseTls);
        state.Phase = SessionPhase.WaitErectDomain;
        return response;
    }

    public static byte[]? HandleErectDomain(RdpSession session, byte[] packet)
    {
        var state = session.State;
        if (packet.Length < 8 || packet[7] != 0x04)
        {
            state.Phase = SessionPhase.WaitAttachUser;
            return HandleAttachUser(session, packet);
        }
        state.Phase = SessionPhase.WaitAttachUser;
        return null;
    }

    public static byte[]? HandleAttachUser(RdpSession session, byte[] packet)
    {
        var state = session.State;
        if (packet.Length < 8 || packet[7] != 0x28)
        {
            state.Phase = SessionPhase.Error;
            return null;
        }
        state.Phase = SessionPhase.WaitChannelJoin;
        return [0x03, 0x00, 0x00, 0x0B, 0x02, 0xF0, 0x80, 0x2E, 0x00, 0x00, 0x01];
    }

    public static byte[]? HandleChannelJoin(RdpSession session, byte[] packet)
    {
        var state = session.State;
        if (packet.Length < 8 || packet[7] != 0x38 || packet.Length < 12)
        {
            state.Phase = SessionPhase.Error;
            return null;
        }

        var requestedChannel = (ushort)((packet[10] << 8) | packet[11]);
        state.ChannelId = requestedChannel;
        state.Phase = (requestedChannel == 1003)
            ? SessionPhase.WaitSecurityExchange
            : SessionPhase.WaitChannelJoin;

        return [0x03, 0x00, 0x00, 0x0F, 0x02, 0xF0, 0x80, 0x3E, 0x00, 0x00, 0x01,
            (byte)(requestedChannel >> 8), (byte)requestedChannel,
            (byte)(requestedChannel >> 8), (byte)requestedChannel];
    }
}