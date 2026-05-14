using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OrkunPAM.Installer;

/// <summary>
/// Generates self-signed TLS certificates for OrkunPAM services.
/// </summary>
public static class CertificateGenerator
{
    /// <summary>
    /// Generates a self-signed TLS certificate with RSA 4096-bit key,
    /// 2-year validity, and Subject Alternative Names.
    /// </summary>
    public static (string PfxPath, string Password) GenerateSelfSigned(
        string hostname,
        string outputDirectory,
        string? password = null)
    {
        ConsoleHelper.WriteStep("Generating self-signed TLS certificate (RSA 4096, 2 year)...");

        Directory.CreateDirectory(outputDirectory);

        password ??= GenerateSecurePassword();

        using var rsa = RSA.Create(4096);

        var subject = new X500DistinguishedName($"CN={hostname}, O=OrkunPAM, OU=Security");

        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Key Usage
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        // Enhanced Key Usage (Server Authentication + Client Authentication)
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new("1.3.6.1.5.5.7.3.1"), // Server Authentication
                    new("1.3.6.1.5.5.7.3.2")  // Client Authentication
                },
                critical: false));

        // Subject Alternative Names
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(hostname);
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);

        // Add machine name if different from hostname
        if (!string.Equals(hostname, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
        {
            sanBuilder.AddDnsName(Environment.MachineName);
        }

        request.CertificateExtensions.Add(sanBuilder.Build());

        // Basic Constraints (not a CA)
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        // Subject Key Identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        // Create self-signed certificate (2 year validity)
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(2);

        using var cert = request.CreateSelfSigned(notBefore, notAfter);

        // Export as PFX
        var pfxPath = Path.Combine(outputDirectory, "orkunpam-tls.pfx");
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(pfxPath, pfxBytes);

        // Export public cert as CER for distribution
        var cerPath = Path.Combine(outputDirectory, "orkunpam-tls.cer");
        var cerBytes = cert.Export(X509ContentType.Cert);
        File.WriteAllBytes(cerPath, cerBytes);

        // Secure file permissions (Windows only)
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var pfxFileInfo = new FileInfo(pfxPath);
                var security = pfxFileInfo.GetAccessControl();
                ConsoleHelper.WriteInfo($"Certificate files saved with default permissions at: {outputDirectory}");
            }
            catch
            {
                // Ignore ACL errors on non-NTFS
            }
        }

        ConsoleHelper.WriteSuccess($"Self-signed certificate generated:");
        ConsoleHelper.WriteInfo($"  PFX: {pfxPath}");
        ConsoleHelper.WriteInfo($"  CER: {cerPath}");
        ConsoleHelper.WriteInfo($"  Subject: CN={hostname}");
        ConsoleHelper.WriteInfo($"  Key Size: RSA 4096");
        ConsoleHelper.WriteInfo($"  Valid: {notBefore:yyyy-MM-dd} to {notAfter:yyyy-MM-dd}");

        return (pfxPath, password);
    }

    /// <summary>
    /// Validates that a PFX file exists and can be loaded with the given password.
    /// </summary>
    public static bool ValidatePfx(string pfxPath, string password)
    {
        try
        {
            using var cert = new X509Certificate2(pfxPath, password,
                X509KeyStorageFlags.EphemeralKeySet);

            ConsoleHelper.WriteSuccess($"Certificate validated: {cert.Subject}");
            ConsoleHelper.WriteInfo($"  Thumbprint: {cert.Thumbprint}");
            ConsoleHelper.WriteInfo($"  Expires: {cert.NotAfter:yyyy-MM-dd}");

            if (cert.NotAfter < DateTime.Now.AddDays(30))
            {
                ConsoleHelper.WriteWarning("Certificate expires within 30 days!");
            }

            return true;
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Certificate validation failed: {ex.Message}");
            return false;
        }
    }

    private static string GenerateSecurePassword()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes);
    }
}
