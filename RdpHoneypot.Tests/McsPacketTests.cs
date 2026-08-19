using System.Security.Cryptography;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

public sealed class McsPacketTests
{
    [Fact]
    public void Attach_user_confirm_has_valid_tpkt_and_user_id()
    {
        var packet = RdpPacket.BuildMcsAttachUserConfirm(1007);
        Assert.Equal(packet.Length, (packet[2] << 8) | packet[3]);
        Assert.Equal(0xF0, packet[5]);
        Assert.Equal(0x80, packet[6]);
        Assert.Equal(0x2E, packet[7]);
        Assert.Equal(1007, (packet[9] << 8) | packet[10]);
    }

    [Theory]
    [InlineData(1003)]
    [InlineData(1004)]
    public void Channel_join_confirm_echoes_requested_channel(ushort channel)
    {
        var packet = RdpPacket.BuildMcsChannelJoinConfirm(1007, channel);
        Assert.Equal(packet.Length, (packet[2] << 8) | packet[3]);
        Assert.Equal(0x3E, packet[7]);
        Assert.Equal(1007, (packet[9] << 8) | packet[10]);
        Assert.Equal(channel, (ushort)((packet[11] << 8) | packet[12]));
        Assert.Equal(channel, (ushort)((packet[13] << 8) | packet[14]));
    }

    [Fact]
    public void Mcs_connect_response_contains_consistent_tpkt_and_gcc_blocks()
    {
        using var rsa = RSA.Create(2048);
        using var cert = CryptoHelper.CreateRsaCertForTls(
            "CN=WIN-SRV01", "WIN-SRV01", [], null, 365, 30, 2048, false);
        var packet = RdpPacket.BuildMCSConnectResponse(
            cert, rsa, CryptoHelper.GenerateRandom(32), true, RdpSelectedProtocol.Hybrid);

        Assert.Equal(packet.Length, (packet[2] << 8) | packet[3]);
        Assert.Equal(0xF0, packet[5]);
        Assert.Equal(0x80, packet[6]);
        Assert.True(ContainsSequence(packet, [0x01, 0x0C]));
        Assert.True(ContainsSequence(packet, [0x02, 0x0C]));
        Assert.True(ContainsSequence(packet, [0x03, 0x0C]));
    }

    static bool ContainsSequence(byte[] data, byte[] sequence)
    {
        for (var i = 0; i <= data.Length - sequence.Length; i++)
        {
            if (data.AsSpan(i, sequence.Length).SequenceEqual(sequence))
                return true;
        }
        return false;
    }
}
