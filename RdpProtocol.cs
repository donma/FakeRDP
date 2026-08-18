namespace RdpHoneypot;

[Flags]
enum RdpRequestedProtocol : uint
{
    Standard = 0x00000000,
    Ssl = 0x00000001,
    Hybrid = 0x00000002,
    RdSTls = 0x00000004,
    HybridEx = 0x00000008
}

enum RdpSelectedProtocol : uint
{
    Standard = 0x00000000,
    Ssl = 0x00000001,
    Hybrid = 0x00000002
}

enum RdpNegotiationFailureReason : uint
{
    SslRequiredByServer = 0x00000001,
    SslNotAllowedByServer = 0x00000002,
    InconsistentFlags = 0x00000003,
    HybridRequiredByServer = 0x00000004,
    SslWithUserAuthRequiredByServer = 0x00000005
}
