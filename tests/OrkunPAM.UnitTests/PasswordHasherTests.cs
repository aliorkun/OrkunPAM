using OrkunPAM.Identity.Services;

namespace OrkunPAM.UnitTests;

public class PasswordHasherTests
{
    private readonly Argon2PasswordHasher _hasher = new();

    [Fact]
    public void Hash_ProducesArgon2idFormat()
    {
        var hash = _hasher.Hash("TestPassword123!");
        Assert.StartsWith("$argon2id$v=19$", hash);
        Assert.Contains("m=65536", hash);
    }

    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        var hash = _hasher.Hash("MyP@ssw0rd!");
        Assert.True(_hasher.Verify("MyP@ssw0rd!", hash));
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFalse()
    {
        var hash = _hasher.Hash("CorrectPassword");
        Assert.False(_hasher.Verify("WrongPassword", hash));
    }

    [Fact]
    public void Verify_EmptyHash_ReturnsFalse()
    {
        Assert.False(_hasher.Verify("test", ""));
        Assert.False(_hasher.Verify("test", "invalid"));
    }

    [Fact]
    public void Hash_SamePassword_ProducesDifferentHashes()
    {
        var hash1 = _hasher.Hash("SamePassword");
        var hash2 = _hasher.Hash("SamePassword");
        Assert.NotEqual(hash1, hash2); // Different salts
    }

    [Fact]
    public void Hash_UnicodePassword_Works()
    {
        var hash = _hasher.Hash("Şifre_Güçlü_2026_Özel!");
        Assert.True(_hasher.Verify("Şifre_Güçlü_2026_Özel!", hash));
        Assert.False(_hasher.Verify("Sifre_Guclu_2026_Ozel!", hash));
    }
}
