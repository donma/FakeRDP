namespace RdpHoneypot;

/// <summary>
/// Honeypot 設定：對應新 config.json schema。
/// 所有欄位都有預設值，欄位名稱與 JSON key 使用 camelCase 對應。
/// </summary>
sealed class HoneypotOptions
{
    public List<int> Ports { get; set; } = [4499, 4500, 4501];
    public int MaxConcurrentSessions { get; set; } = 2000;
    public int MaxConcurrentPerIp { get; set; } = 8;
    public int MaxConcurrentPerSubnet { get; set; } = 150;
    public int MaxPacketBytes { get; set; } = 262_144;
    public int MaxRawCaptureBytesPerSession { get; set; } = 4_194_304;
    public int X224TimeoutSeconds { get; set; } = 3;
    public int TlsTimeoutSeconds { get; set; } = 5;
    public int McsTimeoutSeconds { get; set; } = 5;
    public int CredSspTimeoutSeconds { get; set; } = 10;
    public int IdleTimeoutSeconds { get; set; } = 20;
    public int EventQueueCapacity { get; set; } = 100_000;
    public bool EnableRawCapture { get; set; } = false;
    public string ConsoleCredentialMode { get; set; } = "masked";
    public string ConsoleLogLevel { get; set; } = "Credential";
    public string? LogDir { get; set; }
    public RdpServerProfile Profile { get; set; } = new();
}