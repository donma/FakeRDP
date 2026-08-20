using System.Threading;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace RdpHoneypot.Tests;

public static class IntegrationRunner
{
    public static Task<int> RunAsync(string[] args)
    {
        var mode = GetOption(args, "--mode")?.ToLowerInvariant() ?? "standard";
        return mode switch
        {
            "standard" => RunStandardAsync(args),
            "tls" => RunTlsAsync(args),
            "nla" => RunNlaAsync(args),
"concurrency" => RunConcurrencyAsync(args),
            "concurrent-mapping" => RunConcurrentMappingAsync(args),
            "shutdown-flush" => RunShutdownFlushAsync(args),
            "sequential-session" => RunSequentialSessionAsync(args),
            _ => throw new ArgumentException("--mode must be standard, tls, nla, concurrency, concurrent-mapping, or sequential-session")
        };
    }

    static async Task<int> RunStandardAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");

        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var stream = client.GetStream();

        await WriteTpktAsync(stream, [
            0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        _ = await ReadTpktAsync(stream);

        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
        var mcsResponse = await ReadTpktAsync(stream);
        using var certificate = ExtractCertificate(mcsResponse, out var certificateIndex);
        using var rsa = certificate.GetRSAPublicKey() ?? throw new InvalidOperationException("MCS response certificate has no RSA key");
        var clientRandom = RandomNumberGenerator.GetBytes(32);
        var encryptedRandom = rsa.Encrypt(clientRandom, RSAEncryptionPadding.Pkcs1);

        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00]);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0x00, 0x00, 0x03, 0xEA]);
        _ = await ReadTpktAsync(stream);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0x00, 0x00, 0x03, 0xEB]);
        _ = await ReadTpktAsync(stream);

        await WriteTpktAsync(stream, BuildDataPacket(0x0001, encryptedRandom));
        _ = await ReadTpktAsync(stream);

        var domain = Encoding.Unicode.GetBytes("TESTDOMAIN\0");
        var username = Encoding.Unicode.GetBytes("test-standard-user\0");
        var password = Encoding.Unicode.GetBytes("Standard-Pass-123!\0");
        var info = BuildInfoPdu(domain, username, password);

        await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
        _ = await ReadTpktAsync(stream);
        client.Close();

        var passed = await VerifyCredentialAsync(logDir, "captured_creds.jsonl",
            "test-standard-user", "Standard-Pass-123!", "TESTDOMAIN", host, port);
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} Standard Security credential capture integration");
        return passed ? 0 : 1;
    }

    static async Task<int> RunTlsAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var raw = client.GetStream();
        var stream = await NegotiateTlsAsync(raw, host, 0x01);
        await RunMcsToSecurityAsync(stream);
        // The current session state keeps the common Security Exchange stage
        // before Info PDU even on TLS; send a bounded synthetic exchange first.
        await WriteTpktAsync(stream, BuildDataPacket(0x0001, RandomNumberGenerator.GetBytes(256)));
        _ = await ReadTpktAsync(stream);
        var domain = Encoding.Unicode.GetBytes("TESTDOMAIN\0");
        var username = Encoding.Unicode.GetBytes("test-tls-user\0");
        var password = Encoding.Unicode.GetBytes("TLS-Pass-123!\0");
        var info = BuildInfoPdu(domain, username, password);
        await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
        _ = await ReadTpktAsync(stream);
        client.Close();
        var passed = await VerifyCredentialAsync(logDir, "captured_creds.jsonl",
            "test-tls-user", "TLS-Pass-123!", "TESTDOMAIN", host, port);
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} TLS Info PDU credential capture integration");
        return passed ? 0 : 1;
    }

    static async Task<int> RunNlaAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var raw = client.GetStream();
        var stream = await NegotiateTlsAsync(raw, host, 0x02);
        var type1 = BuildNtlmType1();
        await stream.WriteAsync(BuildTsRequest(type1));
        var challenge = await ReadDerMessageAsync(stream);
        if (!ContainsNtlmType(challenge, 2))
            throw new InvalidDataException("NLA challenge was not received.");
        var type3 = BuildNtlmType3("test-nla-user", "TESTDOMAIN");
        await stream.WriteAsync(BuildTsRequest(type3));
        _ = await ReadDerMessageAsync(stream);
        await stream.WriteAsync(new byte[] { 0x30, 0x00 });
        var account = await WaitForNlaAccountAsync(logDir, "test-nla-user", port, host, "TESTDOMAIN");
        client.Close();
        Console.WriteLine($"{(account ? "PASS" : "FAIL")} NLA account capture integration");
        return account ? 0 : 1;
    }

    static async Task<SslStream> NegotiateTlsAsync(NetworkStream raw, string host, uint protocol)
    {
        var request = protocol == 0x02 ? 0x02u : 0x01u;
        await WriteTpktAsync(raw, BuildNegotiationRequest(request));
        var response = await ReadTpktAsync(raw);
        if (response.Length < 19 || response[11] != 0x02)
            throw new InvalidDataException("RDP negotiation did not select TLS/HYBRID.");
        var callback = new RemoteCertificateValidationCallback((_, _, _, _) => true);
        var ssl = new SslStream(raw, false, callback);
        await ssl.AuthenticateAsClientAsync(host, null, System.Security.Authentication.SslProtocols.Tls12, false);
        return ssl;
    }

    static byte[] BuildNegotiationRequest(uint protocol)
        => [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0, 0, 0, 0, 0,
            0x01, 0, 8, 0, (byte)protocol, (byte)(protocol >> 8), 0, 0];

    static async Task<int> RunConcurrencyAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        const int count = 50;
        var tasks = new Task<(int index, bool ok)>[count];
        for (var i = 0; i < count; i++)
        {
            var idx = i;
            tasks[i] = Task.Run(async () =>
            {
                var user = $"user-{idx:D3}";
                var pass = $"pass-{idx:D3}";
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync(host, port);
                    using var stream = client.GetStream();
                    await WriteTpktAsync(stream, [0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    _ = await ReadTpktAsync(stream);
                    await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
                    var mcs = await ReadTpktAsync(stream);
                    using var cert = ExtractCertificate(mcs, out _);
                    using var rsa = cert.GetRSAPublicKey()!;
                    var cr = RandomNumberGenerator.GetBytes(32);
                    await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00]);
                    await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0x00, 0x00, 0x03, 0xEA]);
                    _ = await ReadTpktAsync(stream);
                    await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0x00, 0x00, 0x03, 0xEB]);
                    _ = await ReadTpktAsync(stream);
                    var enc = rsa.Encrypt(cr, RSAEncryptionPadding.Pkcs1);
                    await WriteTpktAsync(stream, BuildDataPacket(0x0001, enc));
                    _ = await ReadTpktAsync(stream);
                    var domain = Encoding.Unicode.GetBytes("TESTDOMAIN\0");
                    var username = Encoding.Unicode.GetBytes($"{user}\0");
                    var password = Encoding.Unicode.GetBytes($"{pass}\0");
                    var info = BuildInfoPdu(domain, username, password);
                    await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
                    _ = await ReadTpktAsync(stream);
                    return (idx, true);
                }
                catch
                {
                    return (idx, false);
                }
            });
        }
        var results = await Task.WhenAll(tasks);
        var succeeded = results.Count(r => r.ok);

        // 驗證 captured_creds.jsonl 中有 50 筆不同 user，且密碼正確、無串線
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(5);
        List<JsonDocument> records = [];
        while (DateTime.UtcNow < deadline && records.Count < count)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var parsed = JsonDocument.Parse(line);
                        var root = parsed.RootElement;
                        if (root.TryGetProperty("username", out var u) && u.GetString()?.StartsWith("user-") == true)
                        {
                            // 避免重複加入
                            if (!records.Any(r => r.RootElement.GetProperty("username").GetString() == u.GetString()))
                                records.Add(JsonDocument.Parse(line));
                        }
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }
        var userMap = new Dictionary<string, string>();
        var mismatched = 0;
        foreach (var rec in records)
        {
            var u = rec.RootElement.GetProperty("username").GetString()!;
            var p = rec.RootElement.GetProperty("password").GetString()!;
            var expectedPass = $"pass-{u.Replace("user-", "")}";
            if (userMap.TryGetValue(u, out var existingPass))
            {
                if (existingPass != p) mismatched++;
            }
            else
            {
                userMap[u] = p;
                if (p != expectedPass) mismatched++;
            }
        }
        var passed = succeeded == count && records.Count == count && mismatched == 0;
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} Concurrency credential regression: " +
            $"opened={succeeded}/{count} captured={records.Count} mismatched={mismatched}");
        return passed ? 0 : 1;
    }

    static async Task<int> RunConcurrentMappingAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        var rounds = int.Parse(GetOption(args, "--rounds") ?? "3");
        const int count = 50;

        var allOk = true;
        for (var round = 0; round < rounds; round++)
        {
            var clients = new TcpClient[count];
            var tasks = new Task<(int port, string user, string pass, bool ok)>[count];
            try
            {
                for (var i = 0; i < count; i++)
                {
                    var idx = i;
                    var user = $"map-user-{round:D1}-{idx:D3}";
                    var pass = $"map-pass-{round:D1}-{idx:D3}";
                    tasks[i] = Task.Run(async () =>
                    {
                        var client = new TcpClient();
                        clients[idx] = client;
                        try
                        {
                            await client.ConnectAsync(host, port);
                            var localPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;
                            using var stream = client.GetStream();
                            await WriteTpktAsync(stream, [0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            _ = await ReadTpktAsync(stream);
                            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
                            var mcs = await ReadTpktAsync(stream);
                            using var cert = ExtractCertificate(mcs, out _);
                            using var rsa = cert.GetRSAPublicKey()!;
                            var cr = RandomNumberGenerator.GetBytes(32);
                            var enc = rsa.Encrypt(cr, RSAEncryptionPadding.Pkcs1);
                            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0, 0, 0, 0]);
                            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0, 0, 0x03, 0xEA]);
                            _ = await ReadTpktAsync(stream);
                            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0, 0, 0x03, 0xEB]);
                            _ = await ReadTpktAsync(stream);
                            await WriteTpktAsync(stream, BuildDataPacket(0x0001, enc));
                            _ = await ReadTpktAsync(stream);
                            var domain = Encoding.Unicode.GetBytes("TESTDOMAIN\0");
                            var un = Encoding.Unicode.GetBytes($"{user}\0");
                            var pw = Encoding.Unicode.GetBytes($"{pass}\0");
                            var info = BuildInfoPdu(domain, un, pw);
                            await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
                            _ = await ReadTpktAsync(stream);
                            return (localPort, user, pass, true);
                        }
                        catch { return (0, user, pass, false); }
                    });
                }
                var results = await Task.WhenAll(tasks);
                var expectedByPort = new Dictionary<int, (string user, string pass)>();
                var opened = 0;
                foreach (var r in results) { if (r.ok) { opened++; expectedByPort[r.port] = (r.user, r.pass); } }

var deadline = DateTime.UtcNow.AddSeconds(15);
                while (DateTime.UtcNow < deadline)
                {
                    var credCount = CountCredentialUsers(logDir, $"map-user-{round:D1}-");
                    if (credCount >= count) break;
                    await Task.Delay(50);
                }

                var sessionBySourcePort = BuildSessionBySourcePort(logDir);
                var credBySession = BuildCredentialBySession(logDir, $"map-user-{round:D1}-");

                var mismatched = 0; var missing = 0; var duplicate = 0; var crossWired = 0;
                var uniqueSids = new HashSet<long>(); var uniquePorts = new HashSet<int>();
                var sidsForPort = new Dictionary<int, List<long>>();

                foreach (var (clientPort, expected) in expectedByPort)
                {
                    if (!sessionBySourcePort.TryGetValue(clientPort, out var sid)) { missing++; continue; }
                    var sidCount = sidsForPort.TryGetValue(port, out var list) ? list : (sidsForPort[port] = new List<long>());
                    if (sidCount.Contains(sid)) duplicate++; else { sidCount.Add(sid); uniqueSids.Add(sid); uniquePorts.Add(clientPort); }
                    if (!credBySession.TryGetValue(sid, out var cred)) { missing++; continue; }
                    if (cred.user != expected.user || cred.pass != expected.pass) { mismatched++; crossWired++; }
                    if (cred.sourcePort != 0 && cred.sourcePort != clientPort) { mismatched++; crossWired++; }
                }

                var ok = opened == count && credBySession.Count == count &&
                         mismatched == 0 && missing == 0 && duplicate == 0 && crossWired == 0 &&
                         uniqueSids.Count == count && uniquePorts.Count == count;
                allOk &= ok;
                Console.WriteLine($"{(ok ? "PASS" : "FAIL")} Concurrent(session) mapping round {round + 1}/{rounds}: " +
                    $"opened={opened}/{count} captured={credBySession.Count} uniqueSid={uniqueSids.Count} uniquePort={uniquePorts.Count} " +
                    $"missing={missing} duplicate={duplicate} crossWired={crossWired}");
            }
            finally { foreach (var c in clients) c?.Dispose(); }
        }
        return allOk ? 0 : 1;
    }

static IEnumerable<string> ReadLinesWithRetry(string path, int maxRetries = 20)
    {
        for (var i = 0; i < maxRetries; i++)
        {
            try { return File.ReadAllLines(path); }
            catch (IOException) { Thread.Sleep(50); }
        }
        return File.ReadAllLines(path);
    }

    static int CountCredentialUsers(string logDir, string prefix)
    {
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        if (!File.Exists(path)) return 0;
        var count = 0;
        foreach (var line in ReadLinesWithRetry(path))
        {
            try
            {
                using var json = JsonDocument.Parse(line);
                var u = json.RootElement.GetProperty("username").GetString();
                if (u?.StartsWith(prefix) == true) count++;
            }
            catch (JsonException) { }
        }
        return count;
    }

    static Dictionary<int, long> BuildSessionBySourcePort(string logDir)
    {
        var map = new Dictionary<int, long>();
        foreach (var dir in Directory.GetDirectories(logDir, "session_*"))
        {
            var logPath = Path.Combine(dir, "session.log");
            if (!File.Exists(logPath)) continue;
            var first = File.ReadLines(logPath).FirstOrDefault();
            if (first == null) continue;
            var m = System.Text.RegularExpressions.Regex.Match(first, @"Session (\d+) from [\d.]+:(\d+)");
            if (!m.Success) continue;
            var sid = long.Parse(m.Groups[1].Value);
            var srcPort = int.Parse(m.Groups[2].Value);
            map[srcPort] = sid;
        }
        return map;
    }

    static Dictionary<long, (string user, string pass, int sourcePort)> BuildCredentialBySession(string logDir, string prefix)
    {
        var map = new Dictionary<long, (string user, string pass, int sourcePort)>();
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        if (!File.Exists(path)) return map;
foreach (var line in ReadLinesWithRetry(path))
        {
            try
            {
                using var json = JsonDocument.Parse(line);
                var root = json.RootElement;
                var user = root.GetProperty("username").GetString();
                if (user?.StartsWith(prefix) != true) continue;
                var sid = root.GetProperty("session_id").GetInt64();
                var pass = root.TryGetProperty("password", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
                var srcPort = root.TryGetProperty("source_port", out var sp) ? sp.GetInt32() : 0;
                if (!map.ContainsKey(sid)) map[sid] = (user, pass ?? "", srcPort);
            }
            catch (JsonException) { }
        }
        return map;
    }

    static async Task<int> RunShutdownFlushAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        var rounds = int.Parse(GetOption(args, "--rounds") ?? "50");
        const string user = "flush-user";
        const string pass = "Flush-Pass-000!";
        var failures = 0;

        for (var round = 0; round < rounds; round++)
        {
            var dir = Path.Combine(logDir, $"round_{round:D3}");
            Directory.CreateDirectory(dir);
            var options = new HoneypotOptions();
            options.Ports = [port];
            options.LogDir = dir;
            options.ConsoleLogLevel = "Error";
            options.EnableRawCapture = false;
            options.Profile = new RdpServerProfile
            {
                ComputerName = "WIN-SRV01",
                DomainName = "WORKGROUP",
                EnableTls = true,
                EnableNla = true,
                EnableStandardSecurity = true,
                CertificateSubject = "CN=WIN-SRV01",
                CertificatePath = Path.Combine(dir, "cert.pfx"),
                PersistCertificate = true
            };

            var server = new HoneypotServer(options);
            var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => server.RunAsync(cts.Token));

            // 等待 port ready
            var ready = false;
            for (var i = 0; i < 40 && !ready; i++)
            {
                try { using var t = new TcpClient(); await t.ConnectAsync(host, port); ready = true; }
                catch { await Task.Delay(50); }
            }
            if (!ready) { failures++; Console.WriteLine($"FAIL round {round + 1}: server not ready"); continue; }

            // 完整 standard security 流程，送出 credential
            string? capturedSourcePort = null;
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);
                capturedSourcePort = ((IPEndPoint)client.Client.LocalEndPoint!).Port.ToString();
                using var stream = client.GetStream();
                await WriteTpktAsync(stream, [0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]);
                _ = await ReadTpktAsync(stream);
                await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
                var mcs = await ReadTpktAsync(stream);
                using var cert = ExtractCertificate(mcs, out _);
                using var rsa = cert.GetRSAPublicKey()!;
                var cr = RandomNumberGenerator.GetBytes(32);
                var enc = rsa.Encrypt(cr, RSAEncryptionPadding.Pkcs1);
                await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0, 0, 0, 0]);
                await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0, 0, 0x03, 0xEA]);
                _ = await ReadTpktAsync(stream);
                await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0, 0, 0x03, 0xEB]);
                _ = await ReadTpktAsync(stream);
                await WriteTpktAsync(stream, BuildDataPacket(0x0001, enc));
                _ = await ReadTpktAsync(stream);
                var domain = Encoding.Unicode.GetBytes("TESTDOMAIN\0");
                var un = Encoding.Unicode.GetBytes($"{user}\0");
                var pw = Encoding.Unicode.GetBytes($"{pass}\0");
                var info = BuildInfoPdu(domain, un, pw);
                await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
                // 送出 Info PDU 後不要等回應，立即觸發 shutdown
            }
            catch { /* 連線可能因 shutdown 中斷，視為正常 */ }

            // 立即取消 server → graceful shutdown（await active session + drain recorder）
            cts.Cancel();
            try { await serverTask.WaitAsync(TimeSpan.FromSeconds(20)); }
            catch { failures++; Console.WriteLine($"FAIL round {round + 1}: server shutdown timeout"); continue; }

            // 驗證 credential 已持久化且只出現一次
            var path = Path.Combine(dir, "captured_creds.jsonl");
            var matches = 0;
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    if (line.Contains(user) && line.Contains(pass))
                        matches++;
                }
            }
            var ok = matches == 1;
            if (!ok) failures++;
            Console.WriteLine($"{(ok ? "PASS" : "FAIL")} Shutdown flush round {round + 1}/{rounds}: matches={matches} (expect 1)");
        }
        return failures == 0 ? 0 : 1;
    }
static async Task<int> RunSequentialSessionAsync(string[] args)
    {
        var host = GetOption(args, "--host") ?? "127.0.0.1";
        var port = int.Parse(GetOption(args, "--port") ?? "13389");
        var logDir = GetOption(args, "--log-dir") ?? throw new ArgumentException("--log-dir is required");
        const int count = 50;

        // 順序建立 50 條完整 Standard Security 連線，每條用不同帳密
        // 因是順序執行的，session_id 應依序為 1..50（或與起始偏移對應）
        var expected = new (string user, string pass)[count];
        for (var i = 0; i < count; i++)
        {
            var user = $"session-user-{i:D3}";
            var pass = $"session-pass-{i:D3}";
            expected[i] = (user, pass);

            using var client = new TcpClient();
            await client.ConnectAsync(host, port);
            using var stream = client.GetStream();

            await WriteTpktAsync(stream, [0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]);
            _ = await ReadTpktAsync(stream);

            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
            var mcs = await ReadTpktAsync(stream);
            using var cert = ExtractCertificate(mcs, out _);
            using var rsa = cert.GetRSAPublicKey()!;
            var cr = RandomNumberGenerator.GetBytes(32);
            var enc = rsa.Encrypt(cr, RSAEncryptionPadding.Pkcs1);

            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00]);
            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0x00, 0x00, 0x03, 0xEA]);
            _ = await ReadTpktAsync(stream);
            await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0x00, 0x00, 0x03, 0xEB]);
            _ = await ReadTpktAsync(stream);

            await WriteTpktAsync(stream, BuildDataPacket(0x0001, enc));
            _ = await ReadTpktAsync(stream);

            var domain = Encoding.Unicode.GetBytes("TESTDOMAIN\0");
            var username = Encoding.Unicode.GetBytes($"{user}\0");
            var password = Encoding.Unicode.GetBytes($"{pass}\0");
            var info = BuildInfoPdu(domain, username, password);
            await WriteTpktAsync(stream, BuildDataPacket(0x0040, info));
            _ = await ReadTpktAsync(stream);
            // 關閉連線，讓服務端完成 session
        }

        // 讀取 captured_creds.jsonl，驗證每一筆的 session_id、username、password
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(5);
        var records = new List<JsonDocument>();
        while (DateTime.UtcNow < deadline && records.Count < count)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var parsed = JsonDocument.Parse(line);
                        var root = parsed.RootElement;
                        if (root.TryGetProperty("username", out var u) && u.GetString()?.StartsWith("session-user-") == true)
                        {
                            if (!records.Any(r => r.RootElement.GetProperty("session_id").GetInt64() == root.GetProperty("session_id").GetInt64()))
                                records.Add(JsonDocument.Parse(line));
                        }
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }

        // 排序 by session_id，確認順序映射正確
        records.Sort((a, b) => a.RootElement.GetProperty("session_id").GetInt64().CompareTo(b.RootElement.GetProperty("session_id").GetInt64()));

        var mismatched = 0;
        var missing = 0;
        for (var i = 0; i < count; i++)
        {
            if (i >= records.Count) { missing++; continue; }
            var rec = records[i];
            var sid = rec.RootElement.GetProperty("session_id").GetInt64();
            var u = rec.RootElement.GetProperty("username").GetString();
            var p = rec.RootElement.GetProperty("password").GetString();

            // 由於伺服器可能從 >1 開始計數，取相對位置
            if (u != expected[i].user || p != expected[i].pass)
                mismatched++;
        }

        var passed = records.Count == count && mismatched == 0 && missing == 0;
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} Sequential session credential mapping: " +
            $"count={records.Count}/{count} mismatched={mismatched} missing={missing}");
        return passed ? 0 : 1;
    }

    static async Task RunMcsToSecurityAsync(Stream stream)
    {
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x7F, 0x65, 0x00]);
        _ = await ReadTpktAsync(stream);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x04, 0, 0, 0, 0]);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x28, 0, 0, 0x03, 0xEA]);
        _ = await ReadTpktAsync(stream);
        await WriteTpktAsync(stream, [0x02, 0xF0, 0x80, 0x38, 0, 0, 0x03, 0xEB]);
        _ = await ReadTpktAsync(stream);
    }

    static byte[] BuildInfoPdu(byte[] domain, byte[] username, byte[] password)
    {
        var info = new byte[18 + domain.Length + username.Length + password.Length + 16];
        BitConverter.GetBytes(0u).CopyTo(info, 0);
        BitConverter.GetBytes(0u).CopyTo(info, 4);
        BitConverter.GetBytes((ushort)domain.Length).CopyTo(info, 8);
        BitConverter.GetBytes((ushort)username.Length).CopyTo(info, 10);
        BitConverter.GetBytes((ushort)password.Length).CopyTo(info, 12);
        domain.CopyTo(info, 18);
        username.CopyTo(info, 18 + domain.Length);
        password.CopyTo(info, 18 + domain.Length + username.Length);
        return info;
    }

    static async Task<bool> WaitForCredentialAsync(string logDir, string username, string password, int port)
    {
        var path = Path.Combine(logDir, "captured_creds.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        var root = json.RootElement;
                        if (root.GetProperty("username").GetString() == username &&
                            root.GetProperty("password").GetString() == password &&
                            root.GetProperty("target_port").GetInt32() == port)
                            return true;
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }
        return false;
    }

    /// <summary>
    /// 驗證 captured_creds.jsonl 或 nla_accounts.jsonl 中的一筆 credential event，
    /// 檢查 username、password（若指定非 null）、domain、source_ip、target_port。
    /// </summary>
    static async Task<bool> VerifyCredentialAsync(string logDir, string fileName,
        string username, string? password, string domain, string expectedSourceIp, int expectedPort)
    {
        var path = Path.Combine(logDir, fileName);
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        var root = json.RootElement;
                        // 基本欄位
                        if (root.GetProperty("username").GetString() != username) continue;
                        if (password != null && root.GetProperty("password").GetString() != password) continue;
                        if (root.GetProperty("domain").GetString() != domain) continue;
                        if (root.GetProperty("source_ip").GetString() != expectedSourceIp) continue;
                        if (root.GetProperty("target_port").GetInt32() != expectedPort) continue;
                        // 新 schema 欄位（§3）：event, auth_mode, requested_protocol, selected_protocol, cookie, computer_name
                        string eventVal = "";
                        if (root.TryGetProperty("event", out var evtProp)) eventVal = evtProp.GetString() ?? "";
                        if (eventVal != "credential_captured") continue;
                        // 至少要有 auth_mode
                        if (!root.TryGetProperty("auth_mode", out var authMode) || string.IsNullOrEmpty(authMode.GetString())) continue;
                        // 若 password 為 null（NLA 路徑），確認序列化為 null 而非空字串
                        if (password == null && root.TryGetProperty("password", out var passProp) && passProp.ValueKind != JsonValueKind.Null) continue;
                        return true;
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }
        return false;
    }

    static async Task<bool> WaitForNlaAccountAsync(string logDir, string username, int port, string expectedSourceIp, string expectedDomain)
    {
        var path = Path.Combine(logDir, "nla_accounts.jsonl");
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                foreach (var line in await File.ReadAllLinesAsync(path))
                {
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        var root = json.RootElement;
                        if (root.GetProperty("username").GetString() == username &&
                            root.GetProperty("target_port").GetInt32() == port &&
                            root.GetProperty("source_ip").GetString() == expectedSourceIp &&
                            root.GetProperty("domain").GetString() == expectedDomain)
                            return true;
                    }
                    catch (JsonException) { }
                }
            }
            await Task.Delay(50);
        }
        return false;
    }

    static byte[] BuildNtlmType1()
        => [0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00, 1,0,0,0,
            0xB2,0x88,0x02,0x00, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];

    static byte[] BuildNtlmType3(string username, string domain)
    {
        var domainBytes = Encoding.Unicode.GetBytes(domain);
        var userBytes = Encoding.Unicode.GetBytes(username);
        var workstationBytes = Encoding.Unicode.GetBytes("TESTCLIENT");
        var message = new byte[64 + domainBytes.Length + userBytes.Length + workstationBytes.Length];
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(message, 0);
        BitConverter.GetBytes(3u).CopyTo(message, 8);
        WriteSecurityBuffer(message, 28, domainBytes, 64);
        WriteSecurityBuffer(message, 36, userBytes, 64 + domainBytes.Length);
        WriteSecurityBuffer(message, 44, workstationBytes, 64 + domainBytes.Length + userBytes.Length);
        return message;
    }

    static void WriteSecurityBuffer(byte[] target, int offset, byte[] value, int dataOffset)
    {
        BitConverter.GetBytes((ushort)value.Length).CopyTo(target, offset);
        BitConverter.GetBytes((ushort)value.Length).CopyTo(target, offset + 2);
        BitConverter.GetBytes(dataOffset).CopyTo(target, offset + 4);
        value.CopyTo(target, dataOffset);
    }

    static byte[] BuildTsRequest(byte[] ntlm)
    {
        var version = Der(0xA0, [0x02, 0x01, 0x05]);
        var token = Der(0xA1, Der(0x04, ntlm));
        return Der(0x30, [.. version, .. token]);
    }

    static byte[] Der(byte tag, byte[] content)
        => content.Length < 128
            ? [tag, (byte)content.Length, .. content]
            : [tag, 0x82, (byte)(content.Length >> 8), (byte)content.Length, .. content];

    static async Task<byte[]> ReadDerMessageAsync(Stream stream)
    {
        var first = await ReadExactlyAsync(stream, 2);
        var length = (int)first[1];
        var lengthBytes = Array.Empty<byte>();
        if ((length & 0x80) != 0)
        {
            var count = length & 0x7F;
            lengthBytes = await ReadExactlyAsync(stream, count);
            length = 0;
            foreach (var value in lengthBytes) length = (length << 8) | value;
        }
        return [.. first, .. lengthBytes, .. await ReadExactlyAsync(stream, length)];
    }

    static bool ContainsNtlmType(byte[] data, uint type)
    {
        for (var i = 0; i + 12 <= data.Length; i++)
        {
            if (Encoding.ASCII.GetString(data, i, 8) == "NTLMSSP\0" &&
                BitConverter.ToUInt32(data, i + 8) == type)
                return true;
        }
        return false;
    }

    static byte[] BuildDataPacket(ushort flags, byte[] payload)
    {
        var body = new byte[3 + 7 + 4 + payload.Length];
        body[0] = 0x02; body[1] = 0xF0; body[2] = 0x80;
        body[3] = 0x64;
        body[10] = 0x00;
        body[11] = (byte)(flags & 0xFF);
        body[12] = (byte)(flags >> 8);
        Array.Copy(payload, 0, body, 14, payload.Length);
        var packet = new byte[4 + body.Length];
        packet[0] = 0x03;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        Array.Copy(body, 0, packet, 4, body.Length);
        return packet;
    }

    static async Task WriteTpktAsync(Stream stream, byte[] payload)
    {
        var packet = new byte[4 + payload.Length];
        packet[0] = 0x03;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        Array.Copy(payload, 0, packet, 4, payload.Length);
        await stream.WriteAsync(packet);
    }

    static async Task<byte[]> ReadTpktAsync(Stream stream)
    {
        var header = await ReadExactlyAsync(stream, 4);
        var length = (header[2] << 8) | header[3];
        if (length < 4 || length > 262144)
            throw new InvalidDataException("Invalid TPKT response length.");
        return [.. header, .. await ReadExactlyAsync(stream, length - 4)];
    }

    static async Task<byte[]> ReadExactlyAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset));
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        return buffer;
    }

    static X509Certificate2 ExtractCertificate(byte[] packet, out int certificateIndex)
    {
        for (var offset = 0; offset < packet.Length - 4; offset++)
        {
            if (packet[offset] != 0x30) continue;
            if (!TryDerLength(packet, offset, out var totalLength) || offset + totalLength > packet.Length)
                continue;
            try
            {
                var certificate = X509CertificateLoader.LoadCertificate(packet[offset..(offset + totalLength)]);
                if (certificate.GetRSAPublicKey() is not null)
                {
                    certificateIndex = offset;
                    return certificate;
                }
                certificate.Dispose();
            }
            catch { }
        }
        throw new InvalidDataException("No X.509 certificate found in MCS response.");
    }

    static bool TryDerLength(byte[] data, int offset, out int totalLength)
    {
        totalLength = 0;
        if (offset + 2 > data.Length) return false;
        var lengthByte = data[offset + 1];
        var length = (int)lengthByte;
        var headerLength = 2;
        if ((lengthByte & 0x80) != 0)
        {
            var count = lengthByte & 0x7F;
            if (count is < 1 or > 3 || offset + 2 + count > data.Length) return false;
            length = 0;
            for (var i = 0; i < count; i++)
                length = (length << 8) | data[offset + 2 + i];
            headerLength += count;
        }
        totalLength = headerLength + length;
        return totalLength > headerLength;
    }

    static string? GetOption(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}






