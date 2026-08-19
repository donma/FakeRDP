namespace RdpHoneypot;

/// <summary>
/// Console verbosity. Session files always retain protocol details; this only
/// controls high-frequency operator console output.
/// </summary>
enum ConsoleLogLevel
{
    None = 0,
    Error = 1,
    Credential = 2,
    Connection = 3,
    Protocol = 4,
    Debug = 5
}
