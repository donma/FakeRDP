using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RdpHoneypot;

/// <summary>
/// 單一 RDP Session 的狀態機。
/// 負責協調 X.224 → TLS → MCS → Info PDU 的完整流程，
/// 實際協定處理委派給各專用 Handler（McsHandler / StandardSecurityHandler / CredSspHandler）。
/// </summary>
sealed class RdpSession
{
    // ── 內部屬性（供 Handler 存取） ──
    internal HoneypotOptions Options => _options;
    internal RdpServerProfile Profile => _options.Profile ?? new RdpServerProfile();
    internal RdpSessionState State => _state;
    internal X509Certificate2 ServerCert => _serverCert;
    internal X509Certificate2 TlsCert => _tlsCert;
    internal RSA RsaKey => _rsaKey;
    internal RSA TlsRsaKey => _tlsRsaKey;
    internal byte[] ServerRandom => _serverRandom;
    internal EventRecorder Recorder => _recorder;
    internal string LogDir => _logDir;
    internal long SessionId => _id;
    internal IPEndPoint RemoteEp => _ep;
    internal int LocalPort => _localPort;

    readonly long _id;
    readonly IPEndPoint _ep;
    readonly int _localPort;
    readonly TcpClient _client;
    readonly HoneypotOptions _options;
    readonly string _logDir;
    readonly X509Certificate2 _serverCert;
    readonly X509Certificate2 _tlsCert;
    readonly RSA _rsaKey;
    readonly RSA _tlsRsaKey;
    readonly byte[] _serverRandom;
    readonly SessionLimiter _limiter;
    readonly IpConnectionTracker _tracker;
    readonly EventRecorder _recorder;

    readonly RdpSessionState _state = new();
    StreamWriter? _textLog;
    FileStream? _rawLog;
    bool _admitted;
    long _rawBytesWritten;

    public RdpSession(long id, IPEndPoint ep, int localPort, TcpClient client,
        HoneypotOptions options, string logDir,
        X509Certificate2 serverCert, X509Certificate2 tlsCert,
        RSA rsaKey, RSA tlsRsaKey, byte[] serverRandom,
        SessionLimiter limiter, IpConnectionTracker tracker, EventRecorder recorder)
    {
        _id = id; _ep = ep; _localPort = localPort; _client = client;
        _options = options; _logDir = logDir;
        _serverCert = serverCert; _tlsCert = tlsCert;
        _rsaKey = rsaKey; _tlsRsaKey = tlsRsaKey; _serverRandom = serverRandom;
        _limiter = limiter; _tracker = tracker; _recorder = recorder;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        try
        {
            using (_client)
            {
                var rawStream = _client.GetStream();

                // ── Phase 1: X.224 Connection Request ──
                var x224 = await HoneypotServer.ReadTpktAsync(rawStream, null, ct,
                    _options.X224TimeoutSeconds * 1000);
                if (x224 == null) return;

                var neg = X224Handler.ParseConnectionRequest(x224, Profile);
                _state.UseNla = neg.UseNla;
                _state.ClientInfo = neg.ClientInfo;
                bool useSecureChannel = neg.UseTls || neg.UseNla;

                if (!neg.IsSupported)
                {
                    var failure = X224Handler.BuildFailureResponse(0x00000002); // HYBRID_REQUIRED / unsupported
                    await rawStream.WriteAsync(failure, ct);
                    return;
                }

                uint selectedProtocol = X224Handler.SelectProtocol(neg, Profile);
                var cc = RdpPacket.BuildX224ConnectionConfirm(useSecureChannel, selectedProtocol);
                await rawStream.WriteAsync(cc, ct);

                // ── Admission Control ──
                _admitted = _limiter.TryEnter() && _tracker.TryAcquire(_ep.Address);
                if (!_admitted)
                {
                    Console.WriteLine($"  [{_id}] Lightweight: admission limit reached, X.224 CC sent");
                    return;
                }

                // ── 深度處理：建立 session 目錄 ──
                var sessionDir = Path.Combine(_logDir, $"session_{_id:D6}");
                Directory.CreateDirectory(sessionDir);
                _textLog = new StreamWriter(Path.Combine(sessionDir, "session.log"),
                    false, Encoding.UTF8) { AutoFlush = true };

                if (_options.EnableRawCapture)
                    _rawLog = new FileStream(Path.Combine(sessionDir, "raw.bin"),
                        FileMode.Create, FileAccess.Write);

                await LogText($"Session {_id} from {_ep} -> port {_localPort} at {DateTime.UtcNow:O}");
                await LogText($"  ([{SessionPhase.WaitX224}] RX {x224.Length} bytes)");
                await LogText($"  ([{SessionPhase.WaitX224}] TX {cc.Length} bytes" +
                    $"{(useSecureChannel ? (neg.UseNla ? ", CredSSP/NLA" : ", SSL/TLS") : ", standard")})");

                // ── Phase 2: TLS 握手 ──
                Stream stream = rawStream;
                if (useSecureChannel)
                {
                    try
                    {
                        using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        tlsCts.CancelAfter(_options.TlsTimeoutSeconds * 1000);

                        var ssl = new SslStream(rawStream, true);
                        var certContext = SslStreamCertificateContext.Create(_tlsCert, null);
                        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                        {
                            ServerCertificateContext = certContext,
                            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                            ClientCertificateRequired = false,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                        }, tlsCts.Token);
                        stream = ssl;
                        _state.UseTls = true;
                        await LogText($"  (TLS handshake established: {ssl.NegotiatedCipherSuite})");
                    }
                    catch (Exception ex)
                    {
                        await LogText($"  (!) TLS handshake failed: {ex.Message}");
                        _state.Phase = SessionPhase.Error;
                    }
                }

                // ── NLA / CredSSP ──
                if (neg.UseNla && _state.Phase != SessionPhase.Error)
                {
                    var creds = await CredSspHandler.HandleNlaAsync(this, stream, ct);
                    if (creds != null)
                    {
                        SaveNlaCredential(creds.Value.domain, creds.Value.username, creds.Value.password);
                        var msg = creds.Value.password != null
                            ? $"  >>> NLA credential: {creds.Value.domain}\\{creds.Value.username}:{creds.Value.password}"
                            : $"  >>> NLA account: {creds.Value.domain}\\{creds.Value.username}";
                        await LogText(msg);
                    }
                    _state.Phase = SessionPhase.Done;
                }

                // ── Phase 3+: 主循環 (MCS → 安全交換 → Info PDU) ──
                if (!neg.UseNla)
                    _state.Phase = SessionPhase.WaitMCS;

                while (!ct.IsCancellationRequested &&
                       _state.Phase != SessionPhase.Error &&
                       _state.Phase != SessionPhase.Done)
                {
                    int phaseTimeoutMs = _state.Phase switch
                    {
                        SessionPhase.WaitMCS or SessionPhase.WaitErectDomain
                            or SessionPhase.WaitAttachUser or SessionPhase.WaitChannelJoin
                            => _options.McsTimeoutSeconds * 1000,
                        _ => _options.IdleTimeoutSeconds * 1000
                    };

                    var tpkt = await HoneypotServer.ReadTpktAsync(stream, _rawLog, ct, phaseTimeoutMs);
                    if (tpkt == null) break;

                    if (_rawLog != null) _rawBytesWritten += tpkt.Length;
                    await LogText($"  ([{_state.Phase}] RX {tpkt.Length} bytes)");

                    var response = await ProcessPacketAsync(tpkt);
                    if (response != null)
                    {
                        await LogText($"  ([{_state.Phase}] TX {response.Length} bytes)");

                        if (_rawLog != null && _rawBytesWritten < _options.MaxRawCaptureBytesPerSession)
                        {
                            await _rawLog.WriteAsync(
                                BitConverter.GetBytes(IPAddress.HostToNetworkOrder(response.Length)), ct);
                            await _rawLog.WriteAsync(response, ct);
                            await _rawLog.FlushAsync(ct);
                            _rawBytesWritten += 4 + response.Length;
                        }

                        await stream.WriteAsync(response, ct);
                        await DelayWithProfileJitterAsync(ct);
                    }

                    if (_state.Credential != null)
                    {
                        await LogText($"  >>> CAPTURED credential: {_state.Credential}");
                        SaveCredential(_state.Credential);
                        await RdpDisconnectHandler.ApplyAfterCaptureAsync(this, ct);
                        _state.Credential = null;
                    }

                    if (_state.Phase is SessionPhase.Done or SessionPhase.Error)
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Console.WriteLine($"  [{_id}] ! Error: {ex.Message}");
        }
        finally { Cleanup(); }
    }

    async Task DelayWithProfileJitterAsync(CancellationToken ct)
    {
        var profile = Profile;
        var min = Math.Clamp(profile.ResponseDelayMinMs, 0, 2000);
        var max = Math.Clamp(profile.ResponseDelayMaxMs, min, 2000);
        if (max == 0)
            return;

        var delay = Random.Shared.Next(min, max + 1);
        await Task.Delay(delay, ct);
    }

    // ── Packet 路由 ──

    Task<byte[]?> ProcessPacketAsync(byte[] packet) => _state.Phase switch
    {
        SessionPhase.WaitMCS => Task.FromResult(McsHandler.HandleConnect(this, packet)),
        SessionPhase.WaitErectDomain => Task.FromResult(McsHandler.HandleErectDomain(this, packet)),
        SessionPhase.WaitAttachUser => Task.FromResult(McsHandler.HandleAttachUser(this, packet)),
        SessionPhase.WaitChannelJoin => Task.FromResult(McsHandler.HandleChannelJoin(this, packet)),
        SessionPhase.WaitSecurityExchange => StandardSecurityHandler.HandleSecurityExchangeAsync(this, packet),
        SessionPhase.WaitInfo => Task.FromResult(StandardSecurityHandler.HandleInfoPDU(this, packet)),
        _ => Task.FromResult<byte[]?>(null)
    };

    // ── 儲存 / 記錄 ──

    void SaveCredential(CapturedCredential cred)
    {
        _recorder.TryWrite(new HoneypotEvent
        {
            EventType = "credential",
            SessionId = _id, Timestamp = DateTime.UtcNow,
            SourceIp = _ep.Address.ToString(), SourcePort = _ep.Port, TargetPort = _localPort,
            Username = cred.Username, Password = cred.Password, Domain = cred.Domain,
            ClientInfo = cred.ClientInfo,
            SessionDir = Path.Combine(_logDir, $"session_{_id:D6}")
        });
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ═══ CREDENTIAL CAPTURED ═══");
        Console.WriteLine($"  IP: {_ep.Address}:{_ep.Port} -> port {_localPort}");
        Console.WriteLine($"  User: {cred.Username}");
        Console.WriteLine($"  Pass: {cred.Password}");
        Console.WriteLine($"  Domain: {cred.Domain}");
        Console.ResetColor();
    }

    void SaveNlaCredential(string domain, string username, string? password)
    {
        _recorder.TryWrite(new HoneypotEvent
        {
            EventType = "nla_credential",
            SessionId = _id, Timestamp = DateTime.UtcNow,
            SourceIp = _ep.Address.ToString(), SourcePort = _ep.Port, TargetPort = _localPort,
            Domain = domain, Username = username, Password = password,
            SessionDir = Path.Combine(_logDir, $"session_{_id:D6}")
        });
        if (!string.IsNullOrEmpty(password))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ═══ NLA CREDENTIAL CAPTURED ═══");
            Console.WriteLine($"  IP: {_ep.Address}:{_ep.Port} -> port {_localPort}");
            Console.WriteLine($"  User: {username}"); Console.WriteLine($"  Pass: {password}");
            Console.WriteLine($"  Domain: {domain}");
            Console.ResetColor();
        }
    }

    internal Task LogAsync(string line) => LogText(line);

    Task LogText(string line)
    {
        Console.WriteLine($"  {line}");
        if (_textLog != null) return _textLog.WriteLineAsync(line);
        return Task.CompletedTask;
    }

    void Cleanup()
    {
        if (_admitted)
        {
            _limiter.Exit();
            _tracker.Release(_ep.Address);
        }
        if (_textLog != null)
        {
            _textLog.WriteLineAsync($"Session {_id} ended at {DateTime.UtcNow:O}")
                .GetAwaiter().GetResult();
            _textLog.Close();
        }
        _rawLog?.Close();
        Console.WriteLine($"[{_id}] - Connection closed");
    }
}

// ── 以下型別共用於 RdpPacket 與各 Handler ──

enum SessionPhase
{
    WaitX224, WaitMCS, WaitErectDomain, WaitAttachUser,
    WaitChannelJoin, WaitSecurityExchange, WaitInfo, Done, Error
}

class RdpSessionState
{
    public SessionPhase Phase { get; set; } = SessionPhase.WaitX224;
    public string? ClientInfo { get; set; }
    public byte[]? ClientRandom { get; set; }
    public byte[]? DecryptKey { get; set; }
    public byte[]? EncryptKey { get; set; }
    public bool UseTls { get; set; }
    public bool UseNla { get; set; }
    public ushort UserId { get; set; }
    public ushort ChannelId { get; set; }
    public CapturedCredential? Credential { get; set; }
}

record CapturedCredential(string? Username, string? Password, string? Domain, string? ClientInfo);