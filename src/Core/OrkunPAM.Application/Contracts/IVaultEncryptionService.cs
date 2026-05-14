using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Application-layer abstraction for vault encryption operations.
/// Implemented by Infrastructure.Cryptography.
/// </summary>
public interface IVaultEncryptionService
{
    Result<byte[]> Encrypt(byte[] plaintext, string purpose = "VaultCredentials");
    Result<byte[]> Decrypt(byte[] encryptedBlob);
    Result<byte[]> EncryptString(string plaintext, string purpose = "VaultCredentials");
    Result<string> DecryptString(byte[] encryptedBlob);
}
