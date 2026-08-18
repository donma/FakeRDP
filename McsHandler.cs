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
            session.ServerCert, session.RsaKey, session.ServerRandom,
            state.UseTls, state.SelectedProtocol);
        session.TransitionTo(SessionPhase.WaitErectDomain);
        return response;
    }

    public static byte[]? HandleErectDomain(RdpSession session, byte[] packet)
    {
        var state = session.State;
        if (packet.Length < 8 || packet[7] != 0x04)
        {
            session.TransitionTo(SessionPhase.WaitAttachUser);
            return HandleAttachUser(session, packet);
        }
        session.TransitionTo(SessionPhase.WaitAttachUser);
        return null;
    }

    public static byte[]? HandleAttachUser(RdpSession session, byte[] packet)
    {
        var state = session.State;
        if (packet.Length < 8 || packet[7] != 0x28)
        {
            session.TransitionTo(SessionPhase.Error);
            return null;
        }
        if (packet.Length >= 12)
            state.UserId = (ushort)((packet[10] << 8) | packet[11]);
        if (state.UserId == 0)
            state.UserId = 1001;
        session.TransitionTo(SessionPhase.WaitChannelJoin);
        return RdpPacket.BuildMcsAttachUserConfirm(state.UserId);
    }

    public static byte[]? HandleChannelJoin(RdpSession session, byte[] packet)
    {
        var state = session.State;
        if (packet.Length < 8 || packet[7] != 0x38 || packet.Length < 12)
        {
            session.TransitionTo(SessionPhase.Error);
            return null;
        }

        var requestedChannel = (ushort)((packet[10] << 8) | packet[11]);
        state.ChannelId = requestedChannel;
        session.TransitionTo(requestedChannel == 1003
            ? SessionPhase.WaitSecurityExchange
            : SessionPhase.WaitChannelJoin);

        return RdpPacket.BuildMcsChannelJoinConfirm(state.UserId, requestedChannel);
    }
}