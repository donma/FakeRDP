using System.Text.Json;

namespace RdpHoneypot;

/// <summary>
/// 防禦型 RDP 蜜罐入口 (僅限授權環境使用)
///
/// 用法:
///   RdpHoneypot                      使用 config.json
///   RdpHoneypot --config my.json     使用指定設定檔
///   RdpHoneypot --port 4499,4500     命令列覆寫連接埠
///   RdpHoneypot --output logs        命令列覆寫記錄目錄
///
/// 設定檔格式 (JSON):
/// {
///   "ports": [4499, 4500, 4501],
///   "maxConcurrentSessions": 2000,
///   "maxConcurrentPerIp": 8,
///   "maxConcurrentPerSubnet": 150,
///   "maxPacketBytes": 262144,
///   "maxRawCaptureBytesPerSession": 4194304,
///   "x224TimeoutSeconds": 3,
///   "tlsTimeoutSeconds": 5,
///   "mcsTimeoutSeconds": 5,
///   "credSspTimeoutSeconds": 10,
///   "idleTimeoutSeconds": 20,
///   "eventQueueCapacity": 100000,
///   "enableRawCapture": false,
///   "logDir": null
/// }
/// </summary>
static class Program
{
    static async Task<int> Main(string[] args)
    {
        string configPath = Path.Combine(Environment.CurrentDirectory, "config.json");
        var cliPorts = new List<int>();      // 空 = 未指定
        string? cliOutput = null;            // null = 未指定

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--config" when i + 1 < args.Length:
                    configPath = args[++i];
                    break;

                case "--port" when i + 1 < args.Length:
                    cliPorts = ParsePorts(args[++i]);
                    break;

                case "--output" when i + 1 < args.Length:
                    cliOutput = args[++i];
                    break;

                case "--help":
                case "-h":
                    Console.WriteLine("""
                        RDP Honeypot (防禦型蜜罐)
                        用法:
                          RdpHoneypot [--config config.json] [--port 4499[,4500,...]] [--output logs]
                        設定檔 (JSON):
                          {
                            "ports": [4499, 4500, 4501],
                            "maxConcurrentSessions": 2000,
                            "maxConcurrentPerIp": 8,
                            "maxConcurrentPerSubnet": 150,
                            "maxPacketBytes": 262144,
                            "x224TimeoutSeconds": 3,
                            "tlsTimeoutSeconds": 5,
                            "mcsTimeoutSeconds": 5,
                            "credSspTimeoutSeconds": 10,
                            "idleTimeoutSeconds": 20,
                            "enableRawCapture": false,
                            "consoleCredentialMode": "masked",
                            "profile": {
                              "computerName": "WIN-SRV01",
                              "domainName": "WORKGROUP",
                              "enableTls": true,
                              "enableNla": true,
                              "enableStandardSecurity": true,
                              "certificatePath": "certs/test-rdp.pfx",
                              "sanDnsNames": [],
                              "rsaKeySize": 2048,
                              "persistCertificate": true,
                              "responseDelayMinMs": 20,
                              "responseDelayMaxMs": 120
                            }
                          }
                        參數:
                          --config  設定檔路徑 (預設 ./config.json)
                          --port    覆寫監聽連接埠 (多個用逗號分隔)
                          --output  覆寫記錄目錄
                        """);
                    return 0;
            }
        }

        // ── 讀取設定檔 ──
        var options = new HoneypotOptions();
        if (File.Exists(configPath))
        {
            try
            {
                var loaded = JsonSerializer.Deserialize<HoneypotOptions>(
                    await File.ReadAllTextAsync(configPath),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (loaded != null)
                    options = loaded;
                Console.WriteLine($"[設定] 已讀取設定檔: {configPath}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[錯誤] 設定檔解析失敗: {ex.Message}");
                return 1;
            }
        }
        else
        {
            Console.WriteLine($"[設定] 找不到設定檔 {configPath}，使用預設值。");
        }

        // ── 合併設定: 命令列優先於設定檔 ──
        var ports = cliPorts.Count > 0 ? cliPorts : (options.Ports ?? []);
        if (ports.Count == 0) ports = [4499];

        options.Ports = ports.Distinct().ToList();

        // 命令列 --output 覆寫 logDir
        if (cliOutput != null)
            options.LogDir = cliOutput;

        // ── 驗證連接埠 ──
        foreach (var port in ports)
        {
            if (port < 1 || port > 65535)
            {
                Console.Error.WriteLine($"無效連接埠: {port}");
                return 1;
            }

            // 安全防護：禁止使用 3389 (正常 Windows RDP) 及常用系統連接埠
            if (port == 3389 || port == 3388 || port < 1024)
            {
                Console.Error.WriteLine($"[安全防護] 連接埠 {port} 被拒絕：蜜罐不得使用 3389 (正常 RDP) 或低於 1024 的系統連接埠，避免影響正式服務。");
                Console.Error.WriteLine("請改用其他連接埠，例如預設的 4499。");
                return 1;
            }
        }

        // 參數合理性檢查
        if (options.MaxConcurrentSessions < 1)
        {
            Console.Error.WriteLine("[錯誤] maxConcurrentSessions 必須 >= 1");
            return 1;
        }
        if (options.MaxPacketBytes < 512 || options.MaxPacketBytes > 8 * 1024 * 1024)
        {
            Console.Error.WriteLine("[錯誤] maxPacketBytes 需在 512 ~ 8MB 之間");
            return 1;
        }

        var profile = options.Profile ?? new RdpServerProfile();
        if (string.IsNullOrWhiteSpace(profile.ComputerName) || profile.ComputerName.Length > 63)
        {
            Console.Error.WriteLine("[錯誤] profile.computerName 必須是 1~63 字元");
            return 1;
        }
        options.Profile = profile;
        var profileErrors = RdpServerProfileValidator.Validate(profile);
        if (profileErrors.Count > 0)
        {
            foreach (var error in profileErrors)
                Console.Error.WriteLine($"[設定錯誤] {error}");
            return 1;
        }
        if (!string.Equals(options.ConsoleCredentialMode, "masked", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(options.ConsoleCredentialMode, "full", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("[設定錯誤] consoleCredentialMode 必須是 masked 或 full");
            return 1;
        }

        try
        {
            var server = new HoneypotServer(options);
            await server.RunAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"啟動失敗: {ex.Message}");
            return 1;
        }

        return 0;
    }

    /// <summary>解析逗號分隔的連接埠清單</summary>
    static List<int> ParsePorts(string raw)
    {
        var result = new List<int>();
        foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, out var p))
                result.Add(p);
            else
                Console.Error.WriteLine($"[警告] 忽略無效連接埠: '{part}'");
        }
        return result;
    }
}