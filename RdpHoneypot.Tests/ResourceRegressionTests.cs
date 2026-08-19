using System.Net;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

public sealed class ResourceRegressionTests
{
    [Fact]
    public void Session_limiter_releases_and_reuses_capacity()
    {
        var limiter = new SessionLimiter(2);
        Assert.True(limiter.TryEnter());
        Assert.True(limiter.TryEnter());
        Assert.False(limiter.TryEnter());
        limiter.Exit();
        Assert.True(limiter.TryEnter());
        limiter.Exit();
        limiter.Exit();
    }

    [Fact]
    public void Ip_tracker_enforces_ip_and_subnet_and_releases()
    {
        using var tracker = new IpConnectionTracker(2, 2);
        var first = IPAddress.Parse("192.0.2.10");
        var second = IPAddress.Parse("192.0.2.11");
        var third = IPAddress.Parse("192.0.2.12");

        Assert.True(tracker.TryAcquire(first));
        Assert.True(tracker.TryAcquire(first));
        Assert.False(tracker.TryAcquire(first));
        Assert.False(tracker.TryAcquire(second));
        tracker.Release(first);
        Assert.True(tracker.TryAcquire(second));
        Assert.False(tracker.TryAcquire(third));
        tracker.Release(first);
        tracker.Release(first);
        tracker.Release(second);
    }

    [Fact]
    public async Task Tpkt_reader_rejects_over_limit_before_body_allocation()
    {
        var packet = new byte[] { 0x03, 0x00, 0x02, 0x00 };
        await using var stream = new MemoryStream(packet);
        var result = await HoneypotServer.ReadTpktAsync(
            stream, null, CancellationToken.None, 1000, maxPacketBytes: 512);
        Assert.Null(result);
    }

    [Fact]
    public async Task Tpkt_reader_accepts_packet_at_limit()
    {
        var packet = new byte[512];
        packet[0] = 0x03;
        packet[2] = 0x02;
        packet[3] = 0x00;
        await using var stream = new MemoryStream(packet);
        var result = await HoneypotServer.ReadTpktAsync(
            stream, null, CancellationToken.None, 1000, maxPacketBytes: 512);
        Assert.NotNull(result);
        Assert.Equal(512, result.Length);
    }
}
