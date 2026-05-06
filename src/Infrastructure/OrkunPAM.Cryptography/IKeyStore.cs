using OrkunPAM.SharedKernel;

namespace OrkunPAM.Cryptography;

/// <summary>
/// Key store manages the 3-tier key hierarchy: KEK → Master Key → Data Encryption Keys.
/// All keys are decrypted only in memory and zeroed after use.
/// </summary>
public interface IKeyStore
{
    /// <summary>Get the active DEK for a given purpose. Returns (version, decrypted key bytes).</summary>
    Result<(int Version, byte[] Key)> GetActiveDataEncryptionKey(string purpose);

    /// <summary>Get a DEK by version (for decryption of existing data).</summary>
    Result<byte[]> GetDataEncryptionKey(int version);

    /// <summary>Initialize the key store with the master passphrase.</summary>
    Result Initialize(string passphrase);

    /// <summary>Whether the key store has been initialized with a passphrase.</summary>
    bool IsInitialized { get; }

    /// <summary>Create a new DEK for a given purpose.</summary>
    Result<int> CreateDataEncryptionKey(string purpose);

    /// <summary>Rotate the master key. All DEKs are re-encrypted with the new MK.</summary>
    Result RotateMasterKey();
}
