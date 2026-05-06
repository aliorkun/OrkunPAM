using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Cryptography;

/// <summary>
/// AES-256-GCM encryption with 3-tier key hierarchy.
/// Blob format: [DEK_Version(4 bytes) | IV(12 bytes) | Ciphertext(variable) | GCM_Tag(16 bytes)]
/// </summary>
public sealed class AesGcmEncryptionService : IVaultEncryptionService
{
    private const int IvSize = 12;       // AES-GCM standard
    private const int TagSize = 16;      // 128-bit auth tag
    private const int VersionSize = 4;   // DEK version header
    private const int KeySize = 32;      // AES-256

    private readonly IKeyStore _keyStore;
    private readonly ILogger<AesGcmEncryptionService> _logger;

    public AesGcmEncryptionService(IKeyStore keyStore, ILogger<AesGcmEncryptionService> logger)
    {
        _keyStore = keyStore;
        _logger = logger;
    }

    public Result<byte[]> Encrypt(byte[] plaintext, string purpose = "VaultCredentials")
    {
        try
        {
            var dekResult = _keyStore.GetActiveDataEncryptionKey(purpose);
            if (dekResult.IsFailure)
                return Result<byte[]>.Failure(dekResult.Error);

            var (dekVersion, dekBytes) = dekResult.Value;

            // Generate random IV
            var iv = new byte[IvSize];
            RandomNumberGenerator.Fill(iv);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            using var aes = new AesGcm(dekBytes, TagSize);
            aes.Encrypt(iv, plaintext, ciphertext, tag);

            // Assemble blob: [Version(4) | IV(12) | Ciphertext | Tag(16)]
            var blob = new byte[VersionSize + IvSize + ciphertext.Length + TagSize];
            BitConverter.GetBytes(dekVersion).CopyTo(blob, 0);
            iv.CopyTo(blob, VersionSize);
            ciphertext.CopyTo(blob, VersionSize + IvSize);
            tag.CopyTo(blob, VersionSize + IvSize + ciphertext.Length);

            // Zero sensitive memory
            CryptographicOperations.ZeroMemory(dekBytes);

            return Result<byte[]>.Success(blob);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Encryption failed for purpose {Purpose}", purpose);
            return Result<byte[]>.Failure(Error.Encryption("encrypt", ex.Message));
        }
    }

    public Result<byte[]> Decrypt(byte[] encryptedBlob)
    {
        try
        {
            if (encryptedBlob.Length < VersionSize + IvSize + TagSize)
                return Result<byte[]>.Failure(Error.Encryption("decrypt", "Invalid blob: too short"));

            // Parse blob header
            var dekVersion = BitConverter.ToInt32(encryptedBlob, 0);
            var iv = encryptedBlob.AsSpan(VersionSize, IvSize);
            var ciphertextLength = encryptedBlob.Length - VersionSize - IvSize - TagSize;
            var ciphertext = encryptedBlob.AsSpan(VersionSize + IvSize, ciphertextLength);
            var tag = encryptedBlob.AsSpan(VersionSize + IvSize + ciphertextLength, TagSize);

            // Get DEK by version
            var dekResult = _keyStore.GetDataEncryptionKey(dekVersion);
            if (dekResult.IsFailure)
                return Result<byte[]>.Failure(dekResult.Error);

            var dekBytes = dekResult.Value;
            var plaintext = new byte[ciphertextLength];

            using var aes = new AesGcm(dekBytes, TagSize);
            aes.Decrypt(iv, ciphertext, tag, plaintext);

            CryptographicOperations.ZeroMemory(dekBytes);

            return Result<byte[]>.Success(plaintext);
        }
        catch (AuthenticationTagMismatchException)
        {
            _logger.LogWarning("Decryption failed: tampered data or wrong key");
            return Result<byte[]>.Failure(Error.Encryption("decrypt",
                "Authentication tag mismatch - data may be tampered or wrong key version"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Decryption failed");
            return Result<byte[]>.Failure(Error.Encryption("decrypt", ex.Message));
        }
    }

    public Result<byte[]> EncryptString(string plaintext, string purpose = "VaultCredentials")
        => Encrypt(Encoding.UTF8.GetBytes(plaintext), purpose);

    public Result<string> DecryptString(byte[] encryptedBlob)
    {
        var result = Decrypt(encryptedBlob);
        return result.IsSuccess
            ? Result<string>.Success(Encoding.UTF8.GetString(result.Value))
            : Result<string>.Failure(result.Error);
    }
}
