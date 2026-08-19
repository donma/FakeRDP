using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

public sealed class ProfileValidatorTests
{
    [Fact]
    public void Rejects_contradictory_security_and_timing_settings()
    {
        var profile = new RdpServerProfile
        {
            EnableTls = false,
            EnableNla = true,
            EnableHybridEx = true,
            CertificateLifetimeDays = 0,
            CertificateRenewalDays = -1,
            ResponseDelayMinMs = 100,
            ResponseDelayMaxMs = 10,
            DisconnectDelayMs = -1
        };

        var errors = RdpServerProfileValidator.Validate(profile);
        Assert.Contains(errors, error => error.Contains("enableNla"));
        Assert.Contains(errors, error => error.Contains("HybridEx"));
        Assert.Contains(errors, error => error.Contains("certificateLifetimeDays"));
        Assert.Contains(errors, error => error.Contains("certificateRenewalDays"));
        Assert.Contains(errors, error => error.Contains("responseDelay"));
        Assert.Contains(errors, error => error.Contains("disconnectDelay"));
    }

    [Fact]
    public void Rejects_empty_subject_and_invalid_certificate_path()
    {
        var profile = new RdpServerProfile
        {
            CertificateSubject = " ",
            CertificatePath = "\0invalid"
        };

        var errors = RdpServerProfileValidator.Validate(profile);
        Assert.Contains(errors, error => error.Contains("certificateSubject"));
        Assert.Contains(errors, error => error.Contains("certificatePath"));
    }
}
