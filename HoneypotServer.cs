using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace RdpHoneypot;

/// <summary>
/// 防禦型 RDP 蜜罐主伺服器。
/// 負責監聽、接受連線，建立 RdpSession 後交由 Session 狀態機處理。
/// </summary>
sealed class HoneypotServer
{
    readonly HoneypotOptions _options;
    readonly string _logDir;
    readonly X509Certificate2 _serverCert;   // RSA 憑證 (內嵌 MCS Response，RDP 安全交換)
    readonly X509Certificate2 _tlsCert;      // RSA 憑證 (TLS 握手 + CredSSP TSCredentials 解密)
    readonly RSA _rsaKey;
    readonly RSA _tlsRsaKey;                 // TLS 憑證的 RSA 私鑰 (用於 CredSSP 解密)
    readonly byte[] _serverRandom;

    long _sessionCounter;

    public HoneypotServer(HoneypotOptions options)
    {
        _options = options;
        _logDir = options.LogDir ?? AppContext.BaseDirectory;
        Directory.CreateDirectory(_logDir);

        (_rsaKey, _serverCert) = CryptoHelper.CreateRsaCert();
        var profile = options.Profile ?? new RdpServerProfile();
        var subject = string.IsNullOrWhiteSpace(profile.CertificateSubject)
            ? $"CN={profile.ComputerName}"
            : profile.CertificateSubject;
        var certificatePath = profile.PersistCertificate
            ? ResolveCertificatePath(profile.CertificatePath)
            : null;
        _tlsCert = CryptoHelper.CreateRsaCertForTls(
            subject,
            profile.ComputerName,
            profile.SanDnsNames,
            certificatePath,
            profile.CertificateLifetimeDays,
            profile.CertificateRenewalDays,
            profile.RsaKeySize,
            profile.PersistCertificate);
        var certificateErrors = RdpServerProfileValidator.ValidateCertificate(
            _tlsCert, subject, profile.ComputerName);
        if (certificateErrors.Count > 0)
            throw new InvalidOperationException($"TLS certificate validation failed: {string.Join("; ", certificateErrors)}");
        _tlsRsaKey = _tlsCert.GetRSAPrivateKey()!;
        _serverRandom = CryptoHelper.GenerateRandom(32);
    }

    string? ResolveCertificatePath(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
            return Path.Combine(_logDir, "tls-server.pfx");
        return Path.IsPathFullyQualified(configuredPath)
            ? configuredPath
            : Path.GetFullPath(configuredPath, Environment.CurrentDirectory);
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        using var tracker = new IpConnectionTracker(
            _options.MaxConcurrentPerIp, _options.MaxConcurrentPerSubnet);
        var limiter = new SessionLimiter(_options.MaxConcurrentSessions);
        using var recorder = new EventRecorder(_options.EventQueueCapacity, _logDir);

        var listeners = new List<TcpListener>();
        try
        {
            foreach (var port in _options.Ports)
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                listeners.Add(listener);
                Console.WriteLine($"[啟動] 監聽 port {port}");
            }
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"[錯誤] 無法監聽連接埠: {ex.Message}");
            foreach (var l in listeners) l.Stop();
            return;
        }

        Console.WriteLine(@$"
╔══════════════════════════════════════════════════╗
║     RDP Honeypot (防禦型蜜罐)                     ║
║     Listening on ports: {string.Join(", ", _options.Ports)}     ║
║     Log dir: {Path.GetFullPath(_logDir)} ║
║     Max sessions: {_options.MaxConcurrentSessions}              ║
║     Max per IP: {_options.MaxConcurrentPerIp}                     ║
║     Raw capture: {(_options.EnableRawCapture ? "ON" : "OFF")}                   ║
║     ⚠ 僅限在您擁有或授權的網路上使用               ║
║     ✓ 不影響正常 RDP (3389)                       ║
╚══════════════════════════════════════════════════╝
");

        await File.AppendAllTextAsync(Path.Combine(_logDir, "honeypot.log"),
            $"=== Honeypot started on ports [{string.Join(", ", _options.Ports)}] at {DateTime.UtcNow:O} ===\n", ct);

        var acceptTasks = listeners.Select(l => AcceptLoopAsync(l, limiter, tracker, recorder, ct)).ToArray();

        try { await Task.WhenAll(acceptTasks); }
        catch (OperationCanceledException) { }

        foreach (var l in listeners) l.Stop();
    }

    async Task AcceptLoopAsync(TcpListener listener, SessionLimiter limiter,
        IpConnectionTracker tracker, EventRecorder recorder, CancellationToken ct)
    {
        int localPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                if (ct.IsCancellationRequested) { client.Close(); break; }

                var id = Interlocked.Increment(ref _sessionCounter);
                var ep = (IPEndPoint)client.Client.RemoteEndPoint!;
                Console.WriteLine($"[{id}] + Connection from {ep} -> port {localPort}");

                var session = new RdpSession(id, ep, localPort, client,
                    _options, _logDir,
                    _serverCert, _tlsCert, _rsaKey, _tlsRsaKey, _serverRandom,
                    limiter, tracker, recorder);

                _ = session.RunAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Accept error (port {localPort}): {ex.Message}");
            }
        }
    }

    // ── Static helpers (used by RdpSession) ──

    /// <summary>讀取一個完整的 TPKT 封包，含硬限制與 timeout</summary>
    internal static async Task<byte[]?> ReadTpktAsync(Stream stream, FileStream? rawLog,
        CancellationToken ct, int timeoutMs = 0, int maxPacketBytes = 262_144)
    {
        using var timeoutCts = timeoutMs > 0
            ? CancellationTokenSource.CreateLinkedTokenSource(ct)
            : null;
        if (timeoutCts != null)
            timeoutCts.CancelAfter(timeoutMs);
        var linkedCt = timeoutCts?.Token ?? ct;

        var header = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = await stream.ReadAsync(header.AsMemory(read, 4 - read), linkedCt);
            if (n == 0) return null;
            read += n;
        }

        if (rawLog != null)
            await rawLog.WriteAsync(header, ct);

        int length = (header[2] << 8) | header[3];
        if (length < 4 || length > maxPacketBytes) return null;

        var body = new byte[length - 4];
        read = 0;
        while (read < body.Length)
        {
            int n = await stream.ReadAsync(body.AsMemory(read, body.Length - read), linkedCt);
            if (n == 0) return null;
            read += n;
        }

        if (rawLog != null)
            await rawLog.WriteAsync(body, ct);

        return [.. header, .. body];
    }
}