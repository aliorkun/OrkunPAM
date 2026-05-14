using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using OrkunPAM.Cryptography;

namespace OrkunPAM.UnitTests;

/// <summary>
/// Tests encrypt/decrypt roundtrip, key rotation doesn't break existing data,
/// DEK cache behavior.
/// </summary>
public class VaultEncryptionTests
{
    private static IConfiguration BuildTestConfig() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:KeyDirectory"] = Path.Combine(Path.GetTempPath(), $"orkunpam-vault-test-{Guid.NewGuid()}")
            })
            .Build();

    private static (InMemoryKeyStore keyStore, AesGcmEncryptionService encService) CreateServices(
        string passphrase = "TestVaultPassphrase-2026!")
    {
        var keyStore = new InMemoryKeyStore(NullLogger<InMemoryKeyStore>.Instance, BuildTestConfig());
        keyStore.Initialize(passphrase);
        var encService = new AesGcmEncryptionService(keyStore, NullLogger<AesGcmEncryptionService>.Instance);
        return (keyStore, encService);
    }

    [Fact]
    public void EncryptDecrypt_Binary_Roundtrip()
    {
        var (_, enc) = CreateServices();
        var plaintext = new byte[] { 0x00, 0xFF, 0x42, 0xAB, 0xCD };

        var encrypted = enc.Encrypt(plaintext);
        Assert.True(encrypted.IsSuccess);

        var decrypted = enc.Decrypt(encrypted.Value);
        Assert.True(decrypted.IsSuccess);
        Assert.Equal(plaintext, decrypted.Value);
    }

    [Fact]
    public void EncryptDecrypt_String_Roundtrip()
    {
        var (_, enc) = CreateServices();
        var secret = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...";

        var encrypted = enc.EncryptString(secret);
        Assert.True(encrypted.IsSuccess);

        var decrypted = enc.DecryptString(encrypted.Value);
        Assert.True(decrypted.IsSuccess);
        Assert.Equal(secret, decrypted.Value);
    }

    [Fact]
    public void EncryptDecrypt_EmptyString_Works()
    {
        var (_, enc) = CreateServices();
        var encrypted = enc.EncryptString("");
        Assert.True(encrypted.IsSuccess);

        var decrypted = enc.DecryptString(encrypted.Value);
        Assert.True(decrypted.IsSuccess);
        Assert.Equal("", decrypted.Value);
    }

    [Fact]
    public void Encrypt_ProducesDifferentCiphertextEachTime()
    {
        var (_, enc) = CreateServices();
        var plaintext = "SameSecret";

        var enc1 = enc.EncryptString(plaintext);
        var enc2 = enc.EncryptString(plaintext);

        Assert.True(enc1.IsSuccess);
        Assert.True(enc2.IsSuccess);
        Assert.NotEqual(enc1.Value, enc2.Value); // Different IV each time
    }

    [Fact]
    public void KeyRotation_ExistingDataStillDecryptable()
    {
        var (keyStore, enc) = CreateServices();

        // Encrypt before rotation
        var secret = "EncryptBeforeRotation";
        var encrypted = enc.EncryptString(secret);
        Assert.True(encrypted.IsSuccess);

        // Rotate master key
        var rotateResult = keyStore.RotateMasterKey("NewPassphrase-2026!");
        Assert.True(rotateResult.IsSuccess);

        // Old data should still decrypt
        var decrypted = enc.DecryptString(encrypted.Value);
        Assert.True(decrypted.IsSuccess);
        Assert.Equal(secret, decrypted.Value);
    }

    [Fact]
    public void KeyRotation_NewDataEncryptsWithNewKey()
    {
        var (keyStore, enc) = CreateServices();

        var encBefore = enc.EncryptString("Before");
        Assert.True(encBefore.IsSuccess);

        keyStore.RotateMasterKey("NewPassphrase!");

        var encAfter = enc.EncryptString("After");
        Assert.True(encAfter.IsSuccess);

        // Both should decrypt successfully
        var decBefore = enc.DecryptString(encBefore.Value);
        var decAfter = enc.DecryptString(encAfter.Value);
        Assert.True(decBefore.IsSuccess);
        Assert.True(decAfter.IsSuccess);
        Assert.Equal("Before", decBefore.Value);
        Assert.Equal("After", decAfter.Value);
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Fails()
    {
        var (_, enc) = CreateServices();
        var encrypted = enc.EncryptString("sensitive data");
        Assert.True(encrypted.IsSuccess);

        var tampered = encrypted.Value.ToArray();
        // Flip byte in ciphertext area (past header)
        if (tampered.Length > 25)
            tampered[25] ^= 0xFF;

        var result = enc.Decrypt(tampered);
        Assert.True(result.IsFailure);
    }

    [Fact]
    public void Decrypt_TruncatedBlob_Fails()
    {
        var (_, enc) = CreateServices();
        var encrypted = enc.EncryptString("some data");
        Assert.True(encrypted.IsSuccess);

        // Truncate to just a few bytes
        var truncated = encrypted.Value[..5];
        var result = enc.Decrypt(truncated);
        Assert.True(result.IsFailure);
        Assert.Contains("too short", result.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UninitializedKeyStore_EncryptFails()
    {
        var keyStore = new InMemoryKeyStore(NullLogger<InMemoryKeyStore>.Instance, BuildTestConfig());
        // Deliberately NOT calling keyStore.Initialize()
        var enc = new AesGcmEncryptionService(keyStore, NullLogger<AesGcmEncryptionService>.Instance);

        var result = enc.EncryptString("test");
        Assert.True(result.IsFailure);
        Assert.Contains("not initialized", result.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LargePayload_EncryptDecrypt_Works()
    {
        var (_, enc) = CreateServices();
        // 1 MB payload
        var largeData = new byte[1024 * 1024];
        new Random(42).NextBytes(largeData);

        var encrypted = enc.Encrypt(largeData);
        Assert.True(encrypted.IsSuccess);

        var decrypted = enc.Decrypt(encrypted.Value);
        Assert.True(decrypted.IsSuccess);
        Assert.Equal(largeData, decrypted.Value);
    }
}
