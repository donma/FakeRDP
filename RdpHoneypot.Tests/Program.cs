using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RdpHoneypot;
using RdpHoneypot.Tests;

if (args.Contains("--integration", StringComparer.OrdinalIgnoreCase))
    return await IntegrationRunner.RunAsync(args);

var failures = new List<string>();

void Check(string name, bool condition, string? detail = null)
{
    if (condition)
        Console.WriteLine($"PASS {name}");
    else
    {
        var message = detail is null ? name : $"{name}: {detail}";
        Console.WriteLine($"FAIL {message}");
        failures.Add(message);
    }
}

var profile = new RdpServerProfile
{
    EnableTls = true,
    EnableNla = true,
    EnableStandardSecurity = true,
    EnableHybridEx = false
};

byte[] Probe(uint protocols) =>
[
    0x03, 0x00, 0x00, 0x13,
    0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00,
    (byte)protocols, (byte)(protocols >> 8), (byte)(protocols >> 16), (byte)(protocols >> 24)
];

var ssl = X224Handler.ParseConnectionRequest(Probe(0x01), profile);
Check("X224 SSL request supported", ssl.IsSupported && ssl.UseTls && !ssl.UseNla);
var cookieProbe = Probe(0x01);
var cookieBytes = System.Text.Encoding.ASCII.GetBytes("Cookie: mstshash=probe");
var cookiePacket = cookieProbe[..11].Concat(cookieBytes).Concat(cookieProbe[^8..]).ToArray();
Check("X224 cookie telemetry", X224Handler.ParseConnectionRequest(cookiePacket, profile).Mstshash == "probe");
Check("SSL selection", X224Handler.SelectProtocol(ssl, profile) == 0x01);

var hybrid = X224Handler.ParseConnectionRequest(Probe(0x02), profile);
Check("X224 HYBRID request supported", hybrid.IsSupported && hybrid.UseTls && hybrid.UseNla);
Check("HYBRID selection", X224Handler.SelectProtocol(hybrid, profile) == 0x02);

var hybridExOnly = X224Handler.ParseConnectionRequest(Probe(0x08), profile);
Check("Disabled HYBRID_EX rejected", !hybridExOnly.IsSupported);
Check("Profile rejects unimplemented HYBRID_EX", RdpServerProfileValidator.Validate(new RdpServerProfile { EnableHybridEx = true }).Count > 0);
Check("Negotiation failure has RDP_NEG_FAILURE", X224Handler.BuildFailureResponse(RdpNegotiationFailureReason.InconsistentFlags).Contains((byte)0x03));

var rdStlsOnly = X224Handler.ParseConnectionRequest(Probe(0x04), profile);
Check("Unimplemented RDSTLS rejected", !rdStlsOnly.IsSupported);
var unknownOnly = X224Handler.ParseConnectionRequest(Probe(0x10), profile);
Check("Unknown protocol rejected", !unknownOnly.IsSupported);
var malformed = Probe(0x01);
malformed[malformed.Length - 8] = 0x02;
Check("Malformed negotiation rejected as legacy request", !X224Handler.ParseConnectionRequest(malformed, profile).IsSupported);

var noNegotiation = X224Handler.ParseConnectionRequest(
[
    0x03, 0x00, 0x00, 0x0B,
    0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00
], profile);
Check("Legacy standard security supported", noNegotiation.IsSupported && noNegotiation.UseStandardSecurity);
Check("Legacy selection is standard", X224Handler.SelectProtocol(noNegotiation, profile) == 0);

using (var rsa = RSA.Create(2048))
using (var cert = CryptoHelper.CreateRsaCertForTls(
    "CN=TEST-RDP", "TEST-RDP", [], null, 365, 30, 2048, false))
{
    var response = RdpPacket.BuildMCSConnectResponse(
        cert, rsa, CryptoHelper.GenerateRandom(32), useTls: true, RdpSelectedProtocol.Ssl);
    Check("MCS Connect Response has TPKT", response.Length > 32 && response[0] == 0x03 && response[1] == 0x00);
    Check("MCS Connect Response length is consistent",
        response.Length == (response[2] << 8 | response[3]));
}

var domainBytes = System.Text.Encoding.Unicode.GetBytes("DOM\0");
var usernameBytes = System.Text.Encoding.Unicode.GetBytes("user\0");
var passwordBytes = System.Text.Encoding.Unicode.GetBytes("secret\0");
var info = new byte[18 + domainBytes.Length + usernameBytes.Length + passwordBytes.Length + 16];
BitConverter.GetBytes(0u).CopyTo(info, 0);
BitConverter.GetBytes(0u).CopyTo(info, 4);
BitConverter.GetBytes((ushort)domainBytes.Length).CopyTo(info, 8);
BitConverter.GetBytes((ushort)usernameBytes.Length).CopyTo(info, 10);
BitConverter.GetBytes((ushort)passwordBytes.Length).CopyTo(info, 12);
BitConverter.GetBytes((ushort)0).CopyTo(info, 14);
BitConverter.GetBytes((ushort)0).CopyTo(info, 16);
domainBytes.CopyTo(info, 18);
usernameBytes.CopyTo(info, 18 + domainBytes.Length);
passwordBytes.CopyTo(info, 18 + domainBytes.Length + usernameBytes.Length);
var parsed = RdpPacket.ParseInfoPDU(info);
Check("Credential parser regression", parsed?.Domain == "DOM" && parsed.Username == "user" && parsed.Password == "secret");

var attachConfirm = RdpPacket.BuildMcsAttachUserConfirm(1007);
Check("MCS Attach User builder", attachConfirm.Length == 11 && attachConfirm[9] == 0x03 && attachConfirm[10] == 0xEF);
var joinConfirm = RdpPacket.BuildMcsChannelJoinConfirm(1007, 1003);
Check("MCS Channel Join builder", joinConfirm.Length == 15 && joinConfirm[9] == 0x03 && joinConfirm[11] == 0x03 && joinConfirm[12] == 0xEB);

var limiter = new SessionLimiter(1);
Check("Session limiter admits first", limiter.TryEnter());
Check("Session limiter rejects second", !limiter.TryEnter());
limiter.Exit();
Check("Session limiter admits after release", limiter.TryEnter());
limiter.Exit();

using (var tracker = new IpConnectionTracker(1, 1))
{
    var ip = IPAddress.Parse("192.0.2.10");
    Check("Per-IP tracker admits first", tracker.TryAcquire(ip));
    Check("Per-IP tracker rejects second", !tracker.TryAcquire(ip));
    tracker.Release(ip);
    Check("Per-IP tracker admits after release", tracker.TryAcquire(ip));
    var sameSubnet = IPAddress.Parse("192.0.2.11");
    Check("Per-/24 tracker limit", !tracker.TryAcquire(sameSubnet));
}

var oversized = new byte[600];
oversized[0] = 0x03;
oversized[2] = 0x02;
oversized[3] = 0x58;
await using (var oversizedStream = new MemoryStream(oversized))
{
    var rejected = await HoneypotServer.ReadTpktAsync(
        oversizedStream, null, CancellationToken.None, 1000, maxPacketBytes: 512);
    Check("Max packet length regression", rejected is null);
}

var temp = Path.Combine(Path.GetTempPath(), $"fakerdp-cert-{Guid.NewGuid():N}.pfx");
try
{
    using var first = CryptoHelper.CreateRsaCertForTls("CN=PERSIST-TEST", "PERSIST-TEST", [], temp, 365, 30, 2048, true);
    var firstThumbprint = first.Thumbprint;
    using var second = CryptoHelper.CreateRsaCertForTls("CN=PERSIST-TEST", "PERSIST-TEST", [], temp, 365, 30, 2048, true);
    Check("Certificate persistence", firstThumbprint == second.Thumbprint && second.HasPrivateKey);
    Check("Certificate subject", second.Subject.Equals("CN=PERSIST-TEST", StringComparison.OrdinalIgnoreCase));
    Check("Certificate SAN", second.Extensions.OfType<X509SubjectAlternativeNameExtension>().Any());
    Check("Certificate profile validation", RdpServerProfileValidator.ValidateCertificate(
        second, "CN=PERSIST-TEST", "PERSIST-TEST").Count == 0);
}
finally
{
    if (File.Exists(temp)) File.Delete(temp);
}

Console.WriteLine($"\n{failures.Count} failure(s)");
return failures.Count == 0 ? 0 : 1;
