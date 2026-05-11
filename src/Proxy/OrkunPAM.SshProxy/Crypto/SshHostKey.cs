using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using OrkunPAM.SshProxy;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.SshProxy.Crypto;

/// <summary>
/// RSA-2048 SSH host key — persisted to disk, used to authenticate server identity.
/// Supports rsa-sha2-256 (RFC 8332) signatures.
/// </summary>
public sealed class SshHostKey : IDisposable
{
    private readonly RSA _rsa;

    public SshHostKey(IOptions<SshProxyOptions> opts)
    {
        var keyDir = opts.Value.KeyDirectory ?? Path.Combine(AppContext.BaseDirectory, "keys");
        Directory.CreateDirectory(keyDir);
        var keyPath = Path.Combine(keyDir, "ssh-host-rsa.xml");

        if (File.Exists(keyPath))
        {
            _rsa = RSA.Create();
            try
            {
                _rsa.FromXmlString(File.ReadAllText(keyPath));
            }
            catch
            {
                _rsa.Dispose();
                _rsa = GenerateAndSave(keyPath);
            }
        }
        else
        {
            _rsa = GenerateAndSave(keyPath);
        }
    }

    private static RSA GenerateAndSave(string keyPath)
    {
        var rsa = RSA.Create(2048);
        File.WriteAllText(keyPath, rsa.ToXmlString(includePrivateParameters: true));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return rsa;
    }

    /// <summary>
    /// SSH wire-format public key blob (ssh-rsa type).
    /// Format: string("ssh-rsa") || mpint(e) || mpint(n)
    /// </summary>
    internal byte[] GetPublicKeyBlob()
    {
        var pub = _rsa.ExportParameters(false);
        using var ms = new MemoryStream();
        SshEncoding.WriteString(ms, "ssh-rsa");
        SshEncoding.WriteMpInt(ms, new System.Numerics.BigInteger(pub.Exponent!, isUnsigned: true, isBigEndian: true));
        SshEncoding.WriteMpInt(ms, new System.Numerics.BigInteger(pub.Modulus!, isUnsigned: true, isBigEndian: true));
        return ms.ToArray();
    }

    /// <summary>
    /// Sign data using RSASSA-PKCS1-v1_5 with SHA-256 (rsa-sha2-256).
    /// Returns SSH signature blob: string("rsa-sha2-256") || string(raw_signature_bytes).
    /// </summary>
    internal byte[] Sign(byte[] data)
    {
        var sigBytes = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ms = new MemoryStream();
        SshEncoding.WriteString(ms, "rsa-sha2-256");
        SshEncoding.WriteByteString(ms, sigBytes);
        return ms.ToArray();
    }

    public void Dispose() => _rsa.Dispose();
}
