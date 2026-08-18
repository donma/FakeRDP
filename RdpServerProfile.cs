namespace RdpHoneypot;

/// <summary>
/// RDP 服務指紋設定。每個部署可用不同名稱、協定組合、憑證與回應時序，
/// 避免所有蜜罐呈現完全相同的固定指紋。
/// </summary>
sealed class RdpServerProfile
{
    public string ComputerName { get; set; } = "WIN-SRV01";
    public string DomainName { get; set; } = "WORKGROUP";

    public bool EnableTls { get; set; } = true;
    public bool EnableNla { get; set; } = true;
    public bool EnableStandardSecurity { get; set; } = true;
    public bool EnableHybridEx { get; set; } = false;

    /// <summary>省略時使用 CN={ComputerName}。</summary>
    public string? CertificateSubject { get; set; }
    /// <summary>相對路徑以啟動程式的工作目錄為基準。</summary>
    public string? CertificatePath { get; set; } = "certs/test-rdp.pfx";
    public bool PersistCertificate { get; set; } = true;
    public int CertificateLifetimeDays { get; set; } = 365;
    public int CertificateRenewalDays { get; set; } = 30;

    /// <summary>
    /// MCS 回應之間的有限 jitter。0/0 代表不額外延遲；最大值不得過大。
    /// </summary>
    public int ResponseDelayMinMs { get; set; } = 20;
    public int ResponseDelayMaxMs { get; set; } = 120;

    /// <summary>
    /// capture_and_close / capture_and_graceful_close / shutdown_like。
    /// shutdown_like 只模擬本 honeypot 的連線結束時序，不保證 mstsc 顯示固定文字。
    /// </summary>
    public string DisconnectMode { get; set; } = "capture_and_close";
    public int DisconnectDelayMs { get; set; } = 0;
}