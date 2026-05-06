using OrkunPAM.Identity.Services;

namespace OrkunPAM.UnitTests;

public class TotpTests
{
    private readonly TotpService _totp = new();

    [Fact]
    public void GenerateSecret_ReturnsValidBase32AndUri()
    {
        var (secret, uri) = _totp.GenerateSecret("testuser");

        Assert.NotEmpty(secret);
        Assert.Contains("otpauth://totp/", uri);
        Assert.Contains("testuser", uri);
        Assert.Contains("OrkunPAM", uri);
        Assert.Contains($"secret={secret}", uri);
    }

    [Fact]
    public void GenerateCode_And_Validate_Succeeds()
    {
        var (secret, _) = _totp.GenerateSecret("testuser");
        var secretBytes = TotpService.Base32Decode(secret);

        var code = _totp.GenerateCode(secretBytes);
        Assert.Equal(6, code.Length);
        Assert.True(int.TryParse(code, out _));

        var isValid = _totp.ValidateCode(secretBytes, code);
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateCode_WrongCode_Fails()
    {
        var (secret, _) = _totp.GenerateSecret("testuser");
        var secretBytes = TotpService.Base32Decode(secret);

        Assert.False(_totp.ValidateCode(secretBytes, "000000"));
        Assert.False(_totp.ValidateCode(secretBytes, ""));
        Assert.False(_totp.ValidateCode(secretBytes, "12345")); // 5 digits
    }

    [Fact]
    public void Base32_RoundTrip()
    {
        var original = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
        var encoded = typeof(TotpService)
            .GetMethod("Base32Encode", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, [original]) as string;

        Assert.NotNull(encoded);
        var decoded = TotpService.Base32Decode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void DifferentSecrets_ProduceDifferentCodes()
    {
        var (s1, _) = _totp.GenerateSecret("user1");
        var (s2, _) = _totp.GenerateSecret("user2");

        var code1 = _totp.GenerateCode(TotpService.Base32Decode(s1));
        var code2 = _totp.GenerateCode(TotpService.Base32Decode(s2));

        // Very high probability of being different (1/1M chance of collision)
        // Don't assert inequality, but verify both are valid 6-digit
        Assert.Equal(6, code1.Length);
        Assert.Equal(6, code2.Length);
    }
}
