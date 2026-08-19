using System.Security.Cryptography.X509Certificates;
using RdpHoneypot;
using Xunit;

namespace RdpHoneypot.Tests;

public sealed class CertificateRegressionTests
{
    [Fact]
    public void Persistent_certificate_keeps_thumbprint_and_identity()
    {
        var path = Path.Combine(Path.GetTempPath(), $"fakerdp-{Guid.NewGuid():N}.pfx");
        try
        {
            using var first = CryptoHelper.CreateRsaCertForTls(
                "CN=WIN-SRV01", "WIN-SRV01", [], path, 365, 30, 2048, true);
            using var second = CryptoHelper.CreateRsaCertForTls(
                "CN=WIN-SRV01", "WIN-SRV01", [], path, 365, 30, 2048, true);

            Assert.Equal(first.Thumbprint, second.Thumbprint);
            Assert.True(second.HasPrivateKey);
            Assert.Equal("CN=WIN-SRV01", second.Subject);
            Assert.True(second.GetRSAPublicKey()?.KeySize >= 2048);
            Assert.Contains(second.Extensions.OfType<X509EnhancedKeyUsageExtension>(), extension =>
                extension.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>()
                    .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1"));
            Assert.Empty(RdpServerProfileValidator.ValidateCertificate(
                second, "CN=WIN-SRV01", "WIN-SRV01"));
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public void Near_expiry_certificate_rotates()
    {
        var path = Path.Combine(Path.GetTempPath(), $"fakerdp-{Guid.NewGuid():N}.pfx");
        try
        {
            using var first = CryptoHelper.CreateRsaCertForTls(
                "CN=WIN-SRV01", "WIN-SRV01", [], path, 1, 30, 2048, true);
            var firstThumbprint = first.Thumbprint;
            using var second = CryptoHelper.CreateRsaCertForTls(
                "CN=WIN-SRV01", "WIN-SRV01", [], path, 365, 30, 2048, true);

            Assert.NotEqual(firstThumbprint, second.Thumbprint);
            Assert.True(second.NotAfter > DateTime.UtcNow.AddDays(30));
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }
}
