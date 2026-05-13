using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Cryptography;

/// <summary>
/// In-memory key store. Salt and metadata are persisted to disk so the same passphrase
/// re-derives the same master key across restarts. Production uses DPAPI-backed variant.
/// 3-tier hierarchy: Passphrase (PBKDF2) → Master Key → Data Encryption Keys.
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore, IDisposable
{
    private const int KeySize = 32; // AES-256
    private const int SaltSize = 16;
    private const int Pbkdf2Iterations = 600_000;
    private static readonly TimeSpan DekCacheTtl = TimeSpan.FromMinutes(15);

    private byte[]? _masterKey;
    private readonly Dictionary<int, (byte[] Key, DateTime Expires)> _dekCache = new();
    private readonly Dictionary<string, int> _activeDekVersions = new();
    private readonly Dictionary<int, (byte[] Encrypted, int MkVersion, string Purpose)> _storedDeks = new();
    private int _nextDekVersion = 1;
    private int _masterKeyVersion = 1;
    private int _rotationCount;
    private DateTime? _initializedAtUtc;
    private readonly ILogger<InMemoryKeyStore> _logger;
    private readonly string _metadataPath;
    private readonly object _lock = new();

    public bool IsInitialized => _masterKey != null;

    public InMemoryKeyStore(ILogger<InMemoryKeyStore> logger, IConfiguration config)
    {
        _logger = logger;
        var keyDir = config["Jwt:KeyDirectory"] ?? Path.Combine(AppContext.BaseDirectory, "keys");
        Directory.CreateDirectory(keyDir);
        _metadataPath = Path.Combine(keyDir, "encryption-keystore.json");
    }

    public Result Initialize(string passphrase)
    {
        lock (_lock)
        {
            try
            {
                KeystoreMetadata meta;
                if (File.Exists(_metadataPath))
                {
                    var json = File.ReadAllText(_metadataPath);
                    meta = JsonSerializer.Deserialize<KeystoreMetadata>(json) ?? CreateNewMetadata();
                    _logger.LogInformation("Key store metadata loaded from {Path}", _metadataPath);
                }
                else
                {
                    meta = CreateNewMetadata();
                    SaveMetadata(meta);
                    _logger.LogInformation("Key store metadata initialised at {Path}", _metadataPath);
                }

                var salt = Convert.FromBase64String(meta.Salt);
                _masterKey = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(passphrase),
                    salt,
                    Pbkdf2Iterations,
                    HashAlgorithmName.SHA256,
                    KeySize);

                _masterKeyVersion = meta.Version;
                _rotationCount = meta.RotationCount;
                _initializedAtUtc = meta.InitializedAtUtc;

                CreateDataEncryptionKey("VaultCredentials");
                CreateDataEncryptionKey("SessionRecordings");
                CreateDataEncryptionKey("ConfigSecrets");
                CreateDataEncryptionKey("SystemConfig");

                _logger.LogInformation("Key store ready: version {Version}, {DekCount} DEKs", _masterKeyVersion, _storedDeks.Count);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialise key store");
                return Result.Failure(Error.Encryption("initialize", ex.Message));
            }
        }
    }

    public Result<(int Version, byte[] Key)> GetActiveDataEncryptionKey(string purpose)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<(int, byte[])>.Failure(Error.Encryption("getDek", "Key store not initialized"));

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

            if (_dekCache.TryGetValue(version, out var cached))
            {
                if (cached.Expires > DateTime.UtcNow)
                {
                    var copy = new byte[cached.Key.Length];
                    cached.Key.CopyTo(copy.AsSpan());
                    return Result<byte[]>.Success(copy);
                }
                CryptographicOperations.ZeroMemory(cached.Key);
                _dekCache.Remove(version);
            }

            if (!_storedDeks.TryGetValue(version, out var stored))
                return Result<byte[]>.Failure(Error.Encryption("getDek", $"DEK version {version} not found"));

            var dek = DecryptWithMasterKey(stored.Encrypted);
            if (dek == null)
                return Result<byte[]>.Failure(Error.Encryption("getDek", $"Failed to decrypt DEK version {version}"));

            _dekCache[version] = (dek, DateTime.UtcNow.Add(DekCacheTtl));

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
            _dekCache[version] = (dek, DateTime.UtcNow.Add(DekCacheTtl));

            _logger.LogInformation("Created DEK version {Version} for purpose {Purpose}", version, purpose);
            return Result<int>.Success(version);
        }
    }

    public Result RotateMasterKey(string newPassphrase)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result.Failure(Error.Encryption("rotateMk", "Key store not initialized"));

            try
            {
                var newSalt = new byte[SaltSize];
                RandomNumberGenerator.Fill(newSalt);

                var newMk = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(newPassphrase),
                    newSalt,
                    Pbkdf2Iterations,
                    HashAlgorithmName.SHA256,
                    KeySize);

                // Re-encrypt all in-memory DEKs with the new master key
                foreach (var (version, stored) in _storedDeks.ToList())
                {
                    var dek = DecryptWithMasterKey(stored.Encrypted);
                    if (dek == null) continue;

                    var reEncrypted = EncryptWithKey(newMk, dek);
                    _storedDeks[version] = (reEncrypted, _masterKeyVersion + 1, stored.Purpose);
                    CryptographicOperations.ZeroMemory(dek);
                }

                CryptographicOperations.ZeroMemory(_masterKey!);
                _masterKey = newMk;
                _masterKeyVersion++;
                _rotationCount++;

                foreach (var (key, _) in _dekCache.Values)
                    CryptographicOperations.ZeroMemory(key);
                _dekCache.Clear();

                var meta = new KeystoreMetadata
                {
                    Salt = Convert.ToBase64String(newSalt),
                    Version = _masterKeyVersion,
                    RotationCount = _rotationCount,
                    InitializedAtUtc = _initializedAtUtc ?? DateTime.UtcNow,
                    LastRotatedAtUtc = DateTime.UtcNow
                };
                SaveMetadata(meta);

                _logger.LogWarning("Master key rotated to version {Version}", _masterKeyVersion);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to rotate master key");
                return Result.Failure(Error.Encryption("rotateMk", ex.Message));
            }
        }
    }

    public KeyStatus GetKeyStatus()
    {
        lock (_lock)
        {
            return new KeyStatus(_masterKeyVersion, _initializedAtUtc, _rotationCount, IsInitialized);
        }
    }

    public Result<byte[]> ExportEncryptedBackup(string backupPassphrase)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<byte[]>.Failure(Error.Encryption("backup", "Key store not initialized"));

            try
            {
                var backupSalt = new byte[SaltSize];
                RandomNumberGenerator.Fill(backupSalt);

                var backupKey = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(backupPassphrase),
                    backupSalt,
                    Pbkdf2Iterations,
                    HashAlgorithmName.SHA256,
                    KeySize);

                var encryptedMek = EncryptWithKey(backupKey, _masterKey!);
                CryptographicOperations.ZeroMemory(backupKey);

                var backup = new KeyBackupExport
                {
                    Format = "OrkunPAM-KeyBackup-v1",
                    MasterKeyVersion = _masterKeyVersion,
                    BackupSalt = Convert.ToBase64String(backupSalt),
                    EncryptedMek = Convert.ToBase64String(encryptedMek),
                    BackedUpAtUtc = DateTime.UtcNow,
                    RotationCount = _rotationCount
                };

                return Result<byte[]>.Success(
                    JsonSerializer.SerializeToUtf8Bytes(backup, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(Error.Encryption("backup", ex.Message));
            }
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private byte[] EncryptWithKey(byte[] key, byte[] plaintext)
    {
        var iv = new byte[12];
        RandomNumberGenerator.Fill(iv);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(iv, plaintext, ciphertext, tag);

        var result = new byte[12 + plaintext.Length + 16];
        iv.CopyTo(result, 0);
        ciphertext.CopyTo(result, 12);
        tag.CopyTo(result, 12 + plaintext.Length);
        return result;
    }

    private byte[] EncryptWithMasterKey(byte[] plaintext) => EncryptWithKey(_masterKey!, plaintext);

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

    private KeystoreMetadata CreateNewMetadata()
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);
        return new KeystoreMetadata
        {
            Salt = Convert.ToBase64String(salt),
            Version = 1,
            RotationCount = 0,
            InitializedAtUtc = DateTime.UtcNow,
            LastRotatedAtUtc = null
        };
    }

    private void SaveMetadata(KeystoreMetadata meta)
    {
        var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_metadataPath, json);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_metadataPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public void Dispose()
    {
        if (_masterKey != null)
            CryptographicOperations.ZeroMemory(_masterKey);

        foreach (var (key, _) in _dekCache.Values)
            CryptographicOperations.ZeroMemory(key);

        _dekCache.Clear();
    }

    // ── Nested persistence types ─────────────────────────────────────────────

    private sealed class KeystoreMetadata
    {
        public string Salt { get; set; } = string.Empty;
        public int Version { get; set; }
        public int RotationCount { get; set; }
        public DateTime InitializedAtUtc { get; set; }
        public DateTime? LastRotatedAtUtc { get; set; }
    }

    private sealed class KeyBackupExport
    {
        public string Format { get; set; } = string.Empty;
        public int MasterKeyVersion { get; set; }
        public string BackupSalt { get; set; } = string.Empty;
        public string EncryptedMek { get; set; } = string.Empty;
        public DateTime BackedUpAtUtc { get; set; }
        public int RotationCount { get; set; }
    }
}
