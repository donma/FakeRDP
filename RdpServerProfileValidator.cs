using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RdpHoneypot;

static class RdpServerProfileValidator
{
    public static IReadOnlyList<string> Validate(RdpServerProfile profile)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(profile.ComputerName) || profile.ComputerName.Length > 63)
            errors.Add("profile.computerName must contain 1-63 characters.");
        if (profile.EnableNla && !profile.EnableTls)
            errors.Add("profile.enableNla requires profile.enableTls=true.");
        if (profile.EnableHybridEx)
            errors.Add("profile.enableHybridEx is not implemented and must remain false.");
        if (profile.CertificateLifetimeDays is < 1 or > 3650)
            errors.Add("profile.certificateLifetimeDays must be between 1 and 3650.");
        if (profile.CertificateRenewalDays < 0 || profile.CertificateRenewalDays >= profile.CertificateLifetimeDays)
            errors.Add("profile.certificateRenewalDays must be >= 0 and less than certificateLifetimeDays.");
        if (profile.RsaKeySize != 2048)
            errors.Add("profile.rsaKeySize must be 2048 for the current RSA/TLS implementation.");
        if (profile.ResponseDelayMinMs is < 0 or > 2000 ||
            profile.ResponseDelayMaxMs is < 0 or > 2000 ||
            profile.ResponseDelayMinMs > profile.ResponseDelayMaxMs)
            errors.Add("profile.responseDelayMinMs/maxMs must be ordered and within 0-2000 ms.");
        if (profile.DisconnectDelayMs is < 0 or > 10000)
            errors.Add("profile.disconnectDelayMs must be between 0 and 10000 ms.");
        if (!string.IsNullOrWhiteSpace(profile.CertificateSubject))
        {
            if (!profile.CertificateSubject.Contains("CN=", StringComparison.OrdinalIgnoreCase))
                errors.Add("profile.certificateSubject must contain a CN when specified.");
            else
            {
                var cnStart = profile.CertificateSubject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) + 3;
                var cn = profile.CertificateSubject[cnStart..].Split(',', 2)[0].Trim();
                if (!cn.Equals(profile.ComputerName, StringComparison.OrdinalIgnoreCase))
                    errors.Add("profile.certificateSubject CN must match profile.computerName.");
            }
        }
        return errors;
    }

    public static IReadOnlyList<string> ValidateCertificate(
        X509Certificate2 certificate, string expectedSubject, string expectedDnsName)
    {
        var errors = new List<string>();
        if (!certificate.HasPrivateKey)
            errors.Add("TLS certificate does not contain a private key.");
        if (!certificate.Subject.Equals(expectedSubject, StringComparison.OrdinalIgnoreCase))
            errors.Add($"TLS certificate subject '{certificate.Subject}' does not match '{expectedSubject}'.");
        var rsa = certificate.GetRSAPublicKey();
        if (rsa is null || rsa.KeySize < 2048)
            errors.Add("TLS certificate must contain an RSA public key of at least 2048 bits.");
        rsa?.Dispose();
        if (!certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(HasServerAuth))
            errors.Add("TLS certificate is missing the Server Authentication EKU.");
        if (!HasDnsName(certificate, expectedDnsName))
            errors.Add($"TLS certificate SAN does not contain '{expectedDnsName}'.");
        return errors;
    }

    static bool HasServerAuth(X509EnhancedKeyUsageExtension extension)
        => extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1");

    static bool HasDnsName(X509Certificate2 certificate, string expected)
    {
        var san = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san is null) return false;
        var dnsNames = san.EnumerateDnsNames();
        return dnsNames.Any(name => name.Equals(expected, StringComparison.OrdinalIgnoreCase));
    }
}
