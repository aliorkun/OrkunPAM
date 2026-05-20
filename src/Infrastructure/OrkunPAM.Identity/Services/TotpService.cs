using System.Security.Cryptography;

namespace OrkunPAM.Identity.Services;

public interface ITotpService
{
    /// <summary>Generate a new TOTP secret (base32 encoded) for QR code setup.</summary>
    (string Secret, string QrUri) GenerateSecret(string username, string issuer = "OrkunPAM");

    /// <summary>Validate a TOTP code against the secret. Allows ±1 time step drift.</summary>
    bool ValidateCode(byte[] secret, string code);

    /// <summary>Generate current TOTP code (for testing/SMS).</summary>
    string GenerateCode(byte[] secret);

    /// <summary>Rebuild the base32 secret string and QR URI from an existing secret byte array (idempotent re-display).</summary>
    (string Secret, string QrUri) RebuildSecretAndQr(string username, byte[] secretBytes, string issuer = "OrkunPAM");
}

/// <summary>
/// RFC 6238 TOTP implementation using built-in .NET crypto. No external dependencies.
/// Time step: 30 seconds, hash: HMAC-SHA1, code length: 6 digits.
/// </summary>
public sealed class TotpService : ITotpService
{
    private const int TimeStep = 30;
    private const int CodeLength = 6;
    private const int SecretLength = 20;
    private const int DriftSteps = 1; // Allow ±1 window (±30 seconds)

    public (string Secret, string QrUri) GenerateSecret(string username, string issuer = "OrkunPAM")
    {
        var secret = RandomNumberGenerator.GetBytes(SecretLength);
        var base32Secret = Base32Encode(secret);
        var uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(username)}?secret={base32Secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={CodeLength}&period={TimeStep}";

        return (base32Secret, uri);
    }

    public bool ValidateCode(byte[] secret, string code)
    {
        if (string.IsNullOrEmpty(code) || code.Length != CodeLength) return false;

        var currentStep = GetCurrentTimeStep();

        // Check current + drift window
        for (var i = -DriftSteps; i <= DriftSteps; i++)
        {
            var expectedCode = ComputeTotp(secret, currentStep + i);
            if (CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(expectedCode),
                System.Text.Encoding.UTF8.GetBytes(code)))
            {
                return true;
            }
        }

        return false;
    }

    public string GenerateCode(byte[] secret) =>
        ComputeTotp(secret, GetCurrentTimeStep());

    public (string Secret, string QrUri) RebuildSecretAndQr(string username, byte[] secretBytes, string issuer = "OrkunPAM")
    {
        var base32Secret = Base32Encode(secretBytes);
        var uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(username)}?secret={base32Secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={CodeLength}&period={TimeStep}";
        return (base32Secret, uri);
    }

    private static long GetCurrentTimeStep() =>
        DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TimeStep;

    private static string ComputeTotp(byte[] secret, long timeStep)
    {
        var timeBytes = BitConverter.GetBytes(timeStep);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timeBytes);

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(timeBytes);

        // Dynamic truncation (RFC 4226)
        var offset = hash[^1] & 0x0F;
        var code = ((hash[offset] & 0x7F) << 24) |
                   ((hash[offset + 1] & 0xFF) << 16) |
                   ((hash[offset + 2] & 0xFF) << 8) |
                   (hash[offset + 3] & 0xFF);

        var otp = code % (int)Math.Pow(10, CodeLength);
        return otp.ToString().PadLeft(CodeLength, '0');
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new char[(data.Length * 8 + 4) / 5];
        var idx = 0;
        int buffer = 0, bitsLeft = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                result[idx++] = alphabet[(buffer >> (bitsLeft - 5)) & 0x1F];
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
            result[idx++] = alphabet[(buffer << (5 - bitsLeft)) & 0x1F];

        return new string(result, 0, idx);
    }

    public static byte[] Base32Decode(string base32)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>();
        int buffer = 0, bitsLeft = 0;

        foreach (var c in base32.ToUpperInvariant())
        {
            var val = alphabet.IndexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                output.Add((byte)(buffer >> (bitsLeft - 8)));
                bitsLeft -= 8;
            }
        }

        return output.ToArray();
    }
}
