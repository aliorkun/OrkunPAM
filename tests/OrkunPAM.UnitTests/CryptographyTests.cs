using Microsoft.Extensions.Logging.Abstractions;
using OrkunPAM.Cryptography;

namespace OrkunPAM.UnitTests;

public class CryptographyTests
{
    private readonly InMemoryKeyStore _keyStore;
    private readonly AesGcmEncryptionService _encService;

    public CryptographyTests()
    {
        _keyStore = new InMemoryKeyStore(NullLogger<InMemoryKeyStore>.Instance);
        _keyStore.Initialize("TestPassphrase-2026!");
        _encService = new AesGcmEncryptionService(_keyStore, NullLogger<AesGcmEncryptionService>.Instance);
    }

    [Fact]
    public void Encrypt_Decrypt_Roundtrip_ReturnsOriginal()
    {
        var plaintext = "SuperSecret-P@ssw0rd!"u8.ToArray();
        var encResult = _encService.Encrypt(plaintext);

        Assert.True(encResult.IsSuccess);
        Assert.NotEqual(plaintext, encResult.Value);
        Assert.True(encResult.Value.Length > plaintext.Length); // overhead from IV + tag + version

        var decResult = _encService.Decrypt(encResult.Value);
        Assert.True(decResult.IsSuccess);
        Assert.Equal(plaintext, decResult.Value);
    }

    [Fact]
    public void EncryptString_DecryptString_Roundtrip()
    {
        var password = "MyP@ssw0rd!2026_Ğüşöç";
        var encResult = _encService.EncryptString(password);
        Assert.True(encResult.IsSuccess);

        var decResult = _encService.DecryptString(encResult.Value);
        Assert.True(decResult.IsSuccess);
        Assert.Equal(password, decResult.Value);
    }

    [Fact]
    public void Decrypt_TamperedData_ReturnsFailure()
    {
        var encResult = _encService.EncryptString("test");
        Assert.True(encResult.IsSuccess);

        // Tamper with the ciphertext
        var tampered = encResult.Value.ToArray();
        tampered[20] ^= 0xFF; // flip a byte in the middle

        var decResult = _encService.Decrypt(tampered);
        Assert.True(decResult.IsFailure);
        Assert.Contains("tag mismatch", decResult.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Decrypt_TooShortBlob_ReturnsFailure()
    {
        var decResult = _encService.Decrypt(new byte[] { 1, 2, 3 });
        Assert.True(decResult.IsFailure);
        Assert.Contains("too short", decResult.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void KeyStore_NotInitialized_FailsGracefully()
    {
        var uninitStore = new InMemoryKeyStore(NullLogger<InMemoryKeyStore>.Instance);
        var enc = new AesGcmEncryptionService(uninitStore, NullLogger<AesGcmEncryptionService>.Instance);

        var result = enc.EncryptString("test");
        Assert.True(result.IsFailure);
        Assert.Contains("not initialized", result.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DifferentEncryptions_ProduceDifferentBlobs()
    {
        var plaintext = "SamePassword";
        var enc1 = _encService.EncryptString(plaintext);
        var enc2 = _encService.EncryptString(plaintext);

        Assert.True(enc1.IsSuccess);
        Assert.True(enc2.IsSuccess);
        Assert.NotEqual(enc1.Value, enc2.Value); // Different IVs each time
    }

    [Fact]
    public void MasterKeyRotation_ExistingData_StillDecryptable()
    {
        var plaintext = "EncryptedBeforeRotation";
        var encResult = _encService.EncryptString(plaintext);
        Assert.True(encResult.IsSuccess);

        // Rotate master key
        var rotateResult = _keyStore.RotateMasterKey();
        Assert.True(rotateResult.IsSuccess);

        // Old data should still decrypt
        var decResult = _encService.DecryptString(encResult.Value);
        Assert.True(decResult.IsSuccess);
        Assert.Equal(plaintext, decResult.Value);

        // New encryption should also work
        var enc2 = _encService.EncryptString("AfterRotation");
        Assert.True(enc2.IsSuccess);
        var dec2 = _encService.DecryptString(enc2.Value);
        Assert.True(dec2.IsSuccess);
        Assert.Equal("AfterRotation", dec2.Value);
    }
}
