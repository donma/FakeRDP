using System.Text;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

public sealed class X224NegotiationTests
{
    static byte[] Request(uint protocols, string? cookie = null)
    {
        var cookieBytes = string.IsNullOrEmpty(cookie)
            ? []
            : Encoding.ASCII.GetBytes(cookie);
        var length = 19 + cookieBytes.Length;
        var packet = new byte[length];
        packet[0] = 0x03;
        packet[2] = (byte)(length >> 8);
        packet[3] = (byte)length;
        packet[4] = 0x0E;
        packet[5] = 0xE0;
        cookieBytes.CopyTo(packet, 11);
        var negotiationOffset = 11 + cookieBytes.Length;
        packet[negotiationOffset] = 0x01;
        packet[negotiationOffset + 2] = 0x08;
        BitConverter.GetBytes(protocols).CopyTo(packet, negotiationOffset + 4);
        return packet;
    }

    static RdpServerProfile Profile() => new()
    {
        EnableTls = true,
        EnableNla = true,
        EnableStandardSecurity = true,
        EnableHybridEx = false
    };

    [Theory]
    [InlineData(0x01u, 0x01u)]
    [InlineData(0x02u, 0x02u)]
    [InlineData(0x03u, 0x02u)]
    public void Selects_supported_protocol(uint requested, uint expected)
    {
        var result = X224Handler.ParseConnectionRequest(Request(requested), Profile());
        Assert.True(result.IsSupported);
        Assert.Equal(expected, X224Handler.SelectProtocol(result, Profile()));
        Assert.Equal((RdpSelectedProtocol)expected, result.SelectedProtocol);
    }

    [Theory]
    [InlineData(0x08u)]
    [InlineData(0x04u)]
    [InlineData(0x10u)]
    public void Rejects_unsupported_protocol(uint requested)
    {
        var result = X224Handler.ParseConnectionRequest(Request(requested), Profile());
        Assert.False(result.IsSupported);
        Assert.NotNull(result.FailureReason);
        var failure = X224Handler.BuildFailureResponse(result.FailureReason!.Value);
        Assert.Equal(0x03, failure[0]);
        Assert.Equal(0x00, failure[1]);
        Assert.Equal(failure.Length, (failure[2] << 8) | failure[3]);
        Assert.Equal(0xD0, failure[5]);
        Assert.Equal(0x03, failure[11]);
    }

    [Fact]
    public void Supports_legacy_standard_security_without_negotiation_block()
    {
        var packet = new byte[] { 0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0, 0, 0, 0, 0 };
        var result = X224Handler.ParseConnectionRequest(packet, Profile());
        Assert.True(result.IsSupported);
        Assert.True(result.UseStandardSecurity);
        Assert.Equal(0u, X224Handler.SelectProtocol(result, Profile()));
    }

    [Fact]
    public void Parses_cookie_and_mstshash()
    {
        var packet = Request(0x01, "Cookie: mstshash=probe\r\n");
        var result = X224Handler.ParseConnectionRequest(packet, Profile());
        Assert.Equal("Cookie: mstshash=probe\r\n", result.RawCookie);
        Assert.Equal("probe", result.Mstshash);
    }

    [Fact]
    public void Rejects_malformed_negotiation_block()
    {
        var packet = Request(0x01);
        packet[^8] = 0x02;
        var result = X224Handler.ParseConnectionRequest(packet, Profile());
        Assert.False(result.IsSupported);
        Assert.Equal(RdpNegotiationFailureReason.InconsistentFlags, result.FailureReason);
    }
}
