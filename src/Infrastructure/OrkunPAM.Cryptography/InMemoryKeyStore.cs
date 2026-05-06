using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Cryptography;

/// <summary>
/// In-memory key store for development. Production uses DB-backed key store with DPAPI.
/// Implements 3-tier hierarchy: Passphrase → Master Key → Data Encryption Keys.
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore, IDisposable
{
    private const int KeySize = 32; // AES-256
    private const int SaltSize = 16;
    private const int Pbkdf2Iterations = 600_000;

    private byte[]? _masterKey;
    private readonly Dictionary<int, byte[]> _dekCache = new();
    private readonly Dictionary<string, int> _activeDekVersions = new(); // purpose → active version
    private readonly Dictionary<int, (byte[] Encrypted, int MkVersion, string Purpose)> _storedDeks = new();
    private int _nextDekVersion = 1;
    private int _masterKeyVersion = 1;
    private readonly ILogger<InMemoryKeyStore> _logger;
    private readonly object _lock = new();

    public bool IsInitialized => _masterKey != null;

    public InMemoryKeyStore(ILogger<InMemoryKeyStore> logger)
    {
        _logger = logger;
    }

    public Result Initialize(string passphrase)
    {
        lock (_lock)
        {
            try
            {
                // Derive master key from passphrase using PBKDF2
                var salt = new byte[SaltSize];
                RandomNumberGenerator.Fill(salt);

                _masterKey = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(passphrase),
                    salt,
                    Pbkdf2Iterations,
                    HashAlgorithmName.SHA256,
                    KeySize);

                // Create default DEKs for each purpose
                CreateDataEncryptionKey("VaultCredentials");
                CreateDataEncryptionKey("SessionRecordings");
                CreateDataEncryptionKey("ConfigSecrets");

                _logger.LogInformation("Key store initialized with {DekCount} data encryption keys", _storedDeks.Count);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize key store");
                return Result.Failure(Error.Encryption("initialize", ex.Message));
            }
        }
    }

    public Result<(int Version, byte[] Key)> GetActiveDataEncryptionKey(string purpose)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<(int, byte[])>.Failure(Error.Encryption("getDek", "Key store not initialized. Call Initialize() first."));

            if (!_activeDekVersions.TryGetValue(purpose, out var version))
                return Result<(int, byte[])>.Failure(Error.Encryption("getDek", $"No active DEK for purpose '{purpose}'"));

            var dekResult = GetDataEncryptionKey(version);
            if (dekResult.IsFailure) return Result<(int, byte[])>.Failure(dekResult.Error);

            return Result<(int, byte[])>.Success((version, dekResult.Value));
        }
    }

    public Result<byte[]> GetDataEncryptionKey(int version)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<byte[]>.Failure(Error.Encryption("getDek", "Key store not initialized"));

            // Check cache first (performance: avoid repeated decryption)
            if (_dekCache.TryGetValue(version, out var cached))
            {
                var copy = new byte[cached.Length];
                cached.CopyTo(copy.AsSpan());
                return Result<byte[]>.Success(copy);
            }

            if (!_storedDeks.TryGetValue(version, out var stored))
                return Result<byte[]>.Failure(Error.Encryption("getDek", $"DEK version {version} not found"));

            // Decrypt DEK using master key
            var dek = DecryptWithMasterKey(stored.Encrypted);
            if (dek == null)
                return Result<byte[]>.Failure(Error.Encryption("getDek", $"Failed to decrypt DEK version {version}"));

            // Cache it
            _dekCache[version] = dek;

            var result = new byte[dek.Length];
            dek.CopyTo(result.AsSpan());
            return Result<byte[]>.Success(result);
        }
    }

    public Result<int> CreateDataEncryptionKey(string purpose)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<int>.Failure(Error.Encryption("createDek", "Key store not initialized"));

            var version = _nextDekVersion++;
            var dek = new byte[KeySize];
            RandomNumberGenerator.Fill(dek);

            var encrypted = EncryptWithMasterKey(dek);
            _storedDeks[version] = (encrypted, _masterKeyVersion, purpose);
            _activeDekVersions[purpose] = version;
            _dekCache[version] = dek;

            _logger.LogInformation("Created DEK version {Version} for purpose {Purpose}", version, purpose);
            return Result<int>.Success(version);
        }
    }

    public Result RotateMasterKey()
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result.Failure(Error.Encryption("rotateMk", "Key store not initialized"));

            // Generate new master key
            var newMk = new byte[KeySize];
            RandomNumberGenerator.Fill(newMk);

            // Re-encrypt all DEKs with new master key
            foreach (var (version, stored) in _storedDeks.ToList())
            {
                var dek = DecryptWithMasterKey(stored.Encrypted);
                if (dek == null) continue;

                var oldMk = _masterKey;
                _masterKey = newMk;
                var reEncrypted = EncryptWithMasterKey(dek);
                _masterKey = oldMk;

                _storedDeks[version] = (reEncrypted, _masterKeyVersion + 1, stored.Purpose);
                CryptographicOperations.ZeroMemory(dek);
            }

            // Swap master key
            CryptographicOperations.ZeroMemory(_masterKey!);
            _masterKey = newMk;
            _masterKeyVersion++;
            _dekCache.Clear();

            _logger.LogInformation("Master key rotated to version {Version}", _masterKeyVersion);
            return Result.Success();
        }
    }

    private byte[] EncryptWithMasterKey(byte[] plaintext)
    {
        var iv = new byte[12];
        RandomNumberGenerator.Fill(iv);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(_masterKey!, 16);
        aes.Encrypt(iv, plaintext, ciphertext, tag);

        var result = new byte[12 + plaintext.Length + 16];
        iv.CopyTo(result, 0);
        ciphertext.CopyTo(result, 12);
        tag.CopyTo(result, 12 + plaintext.Length);
        return result;
    }

    private byte[]? DecryptWithMasterKey(byte[] blob)
    {
        try
        {
            var iv = blob.AsSpan(0, 12);
            var ciphertextLen = blob.Length - 12 - 16;
            var ciphertext = blob.AsSpan(12, ciphertextLen);
            var tag = blob.AsSpan(12 + ciphertextLen, 16);
            var plaintext = new byte[ciphertextLen];

            using var aes = new AesGcm(_masterKey!, 16);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            return plaintext;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (_masterKey != null)
            CryptographicOperations.ZeroMemory(_masterKey);

        foreach (var dek in _dekCache.Values)
            CryptographicOperations.ZeroMemory(dek);

        _dekCache.Clear();
    }
}
