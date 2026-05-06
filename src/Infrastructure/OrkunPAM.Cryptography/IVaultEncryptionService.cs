using OrkunPAM.SharedKernel;

namespace OrkunPAM.Cryptography;

/// <summary>
/// Vault encryption service interface. All credential data flows through this.
/// </summary>
public interface IVaultEncryptionService
{
    /// <summary>Encrypt plaintext using the active DEK for the given purpose.</summary>
    Result<byte[]> Encrypt(byte[] plaintext, string purpose = "VaultCredentials");

    /// <summary>Decrypt an encrypted blob. DEK version is embedded in the blob header.</summary>
    Result<byte[]> Decrypt(byte[] encryptedBlob);

    /// <summary>Encrypt a string value.</summary>
    Result<byte[]> EncryptString(string plaintext, string purpose = "VaultCredentials");

    /// <summary>Decrypt to string.</summary>
    Result<string> DecryptString(byte[] encryptedBlob);
}

/// <summary>
/// Master key provider - manages the KEK → MK relationship.
/// </summary>
public interface IMasterKeyProvider
{
    /// <summary>Initialize with passphrase (first-time setup or service start).</summary>
    Result Initialize(string passphrase);

    /// <summary>Check if the master key is loaded in memory.</summary>
    bool IsInitialized { get; }

    /// <summary>Get the decrypted master key (kept in memory only).</summary>
    Result<byte[]> GetMasterKey();

    /// <summary>Rotate the master key. Returns new key version.</summary>
    Result<int> RotateMasterKey(string passphrase);
}
