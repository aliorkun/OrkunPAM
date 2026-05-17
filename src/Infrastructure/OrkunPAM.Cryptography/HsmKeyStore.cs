using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Cryptography;

/// <summary>
/// HSM-backed key store. DEKs are wrapped by the HSM-resident MEK instead of a PBKDF2-derived
/// software key. The MEK never leaves the HSM — only wrapped DEK blobs are stored on disk.
/// 3-tier hierarchy: HSM MEK → wrapped DEKs → AES-256-GCM encrypted vault data.
/// </summary>
public sealed class HsmKeyStore : IKeyStore, IDisposable
{
    private const int KeySize = 32;
    private static readonly TimeSpan DekCacheTtl = TimeSpan.FromMinutes(15);

    private readonly IHsmProvider _hsm;
    private readonly ILogger<HsmKeyStore> _logger;
    private readonly string _metadataPath;
    private readonly string _mekLabel;
    private readonly object _lock = new();

    private readonly Dictionary<int, (byte[] Key, DateTime Expires)> _dekCache = new();
    private Dictionary<string, int> _activeDekVersions = new();
    private Dictionary<int, HsmDekEntry> _storedDeks = new();
    private int _nextDekVersion = 1;
    private int _keyVersion = 1;
    private int _rotationCount;
    private DateTime? _initializedAtUtc;

    public bool IsInitialized { get; private set; }

    public HsmKeyStore(IHsmProvider hsm, ILogger<HsmKeyStore> logger, IConfiguration config)
    {
        _hsm = hsm;
        _logger = logger;
        _mekLabel = config["Security:MekKeyLabel"] ?? "OrkunPAM-MEK";
        var keyDir = config["Jwt:KeyDirectory"] ?? Path.Combine(AppContext.BaseDirectory, "keys");
        Directory.CreateDirectory(keyDir);
        _metadataPath = Path.Combine(keyDir, "hsm-keystore.json");
    }

    public Result Initialize(string passphrase) // passphrase ignored — MEK lives in HSM
    {
        lock (_lock)
        {
            try
            {
                _hsm.EnsureMasterKeyExistsAsync(_mekLabel).GetAwaiter().GetResult();

                if (File.Exists(_metadataPath))
                {
                    var json = File.ReadAllText(_metadataPath);
                    var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var meta = JsonSerializer.Deserialize<HsmKeystoreMetadata>(json, opts);
                    if (meta != null)
                    {
                        _keyVersion        = meta.Version;
                        _rotationCount     = meta.RotationCount;
                        _initializedAtUtc  = meta.InitializedAtUtc;
                        _nextDekVersion    = meta.NextDekVersion;
                        _activeDekVersions = meta.ActiveDekVersions ?? new();
                        _storedDeks        = meta.StoredDeks        ?? new();
                    }
                    _logger.LogInformation("HSM key store loaded: {Count} DEKs, version {Version}", _storedDeks.Count, _keyVersion);
                }
                else
                {
                    _initializedAtUtc = DateTime.UtcNow;
                }

                IsInitialized = true;

                // Ensure default DEKs exist (call internal to avoid re-acquiring the lock)
                if (!_activeDekVersions.ContainsKey("VaultCredentials"))   CreateDekInternal("VaultCredentials");
                if (!_activeDekVersions.ContainsKey("SessionRecordings"))  CreateDekInternal("SessionRecordings");
                if (!_activeDekVersions.ContainsKey("ConfigSecrets"))      CreateDekInternal("ConfigSecrets");
                if (!_activeDekVersions.ContainsKey("SystemConfig"))       CreateDekInternal("SystemConfig");

                _logger.LogInformation("HSM key store ready via {Provider}: version {Version}, {Count} DEKs",
                    _hsm.ProviderName, _keyVersion, _storedDeks.Count);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize HSM key store via {Provider}", _hsm.ProviderName);
                return Result.Failure(Error.Encryption("initialize", ex.Message));
            }
        }
    }

    public Result<(int Version, byte[] Key)> GetActiveDataEncryptionKey(string purpose)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<(int, byte[])>.Failure(Error.Encryption("getDek", "HSM key store not initialized"));

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
                return Result<byte[]>.Failure(Error.Encryption("getDek", "HSM key store not initialized"));

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

            try
            {
                var wrappedBytes = Convert.FromBase64String(stored.WrappedBase64);
                var dek = _hsm.UnwrapKeyAsync(_mekLabel, wrappedBytes).GetAwaiter().GetResult();

                _dekCache[version] = (dek, DateTime.UtcNow.Add(DekCacheTtl));
                var result = new byte[dek.Length];
                dek.CopyTo(result.AsSpan());
                return Result<byte[]>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM UnwrapKey failed for DEK version {Version}", version);
                return Result<byte[]>.Failure(Error.Encryption("getDek", $"HSM unwrap failed: {ex.Message}"));
            }
        }
    }

    public Result<int> CreateDataEncryptionKey(string purpose)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<int>.Failure(Error.Encryption("createDek", "HSM key store not initialized"));
            return CreateDekInternal(purpose);
        }
    }

    // Lock-free DEK creation — caller must hold _lock.
    private Result<int> CreateDekInternal(string purpose)
    {
        try
        {
            var version = _nextDekVersion++;
            var dek = new byte[KeySize];
            RandomNumberGenerator.Fill(dek);

            var wrapped = _hsm.WrapKeyAsync(_mekLabel, dek).GetAwaiter().GetResult();
            _storedDeks[version] = new HsmDekEntry
            {
                WrappedBase64 = Convert.ToBase64String(wrapped),
                MkVersion = _keyVersion,
                Purpose = purpose
            };
            _activeDekVersions[purpose] = version;

            // Cache the plaintext DEK directly (already in memory)
            _dekCache[version] = (dek, DateTime.UtcNow.Add(DekCacheTtl));

            SaveMetadata();
            _logger.LogInformation("HSM: Created DEK version {Version} for purpose '{Purpose}'", version, purpose);
            return Result<int>.Success(version);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HSM WrapKey failed when creating DEK for purpose '{Purpose}'", purpose);
            return Result<int>.Failure(Error.Encryption("createDek", $"HSM wrap failed: {ex.Message}"));
        }
    }

    public Result RotateMasterKey(string newPassphrase)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result.Failure(Error.Encryption("rotateMek", "HSM key store not initialized"));

            try
            {
                // Step 1: Unwrap all current DEKs using the existing HSM key
                var dekPlaintexts = new Dictionary<int, byte[]>();
                foreach (var (version, entry) in _storedDeks)
                {
                    var wrappedBytes = Convert.FromBase64String(entry.WrappedBase64);
                    dekPlaintexts[version] = _hsm.UnwrapKeyAsync(_mekLabel, wrappedBytes).GetAwaiter().GetResult();
                }

                // Step 2: Rotate the HSM key (generates new MEK in HSM)
                _hsm.RegenerateMasterKeyAsync(_mekLabel).GetAwaiter().GetResult();

                // Step 3: Re-wrap all DEKs with the new HSM key
                foreach (var (version, dek) in dekPlaintexts)
                {
                    var newWrapped = _hsm.WrapKeyAsync(_mekLabel, dek).GetAwaiter().GetResult();
                    var existing = _storedDeks[version];
                    _storedDeks[version] = new HsmDekEntry
                    {
                        WrappedBase64 = Convert.ToBase64String(newWrapped),
                        MkVersion = _keyVersion + 1,
                        Purpose = existing.Purpose
                    };
                    CryptographicOperations.ZeroMemory(dek);
                }

                // Step 4: Clear cache and bump version
                foreach (var cached in _dekCache.Values)
                    CryptographicOperations.ZeroMemory(cached.Key);
                _dekCache.Clear();

                _keyVersion++;
                _rotationCount++;
                SaveMetadata();

                _logger.LogWarning("HSM MEK rotated via {Provider}, new version {Version}", _hsm.ProviderName, _keyVersion);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM MEK rotation failed");
                return Result.Failure(Error.Encryption("rotateMek", ex.Message));
            }
        }
    }

    public KeyStatus GetKeyStatus()
    {
        lock (_lock)
        {
            return new KeyStatus(_keyVersion, _initializedAtUtc, _rotationCount, IsInitialized);
        }
    }

    public Result<byte[]> ExportEncryptedBackup(string backupPassphrase)
    {
        lock (_lock)
        {
            if (!IsInitialized)
                return Result<byte[]>.Failure(Error.Encryption("backup", "HSM key store not initialized"));

            try
            {
                // In HSM mode, we export the wrapped DEK metadata.
                // The MEK stays in the HSM — restoration requires the same HSM device/key.
                var export = new
                {
                    Format = "OrkunPAM-HsmKeyBackup-v1",
                    HsmProvider = _hsm.ProviderName,
                    MekKeyLabel = _mekLabel,
                    KeyVersion = _keyVersion,
                    RotationCount = _rotationCount,
                    BackedUpAtUtc = DateTime.UtcNow,
                    Note = "DEKs are HSM-wrapped. Restore requires the same HSM device and key label.",
                    StoredDeks = _storedDeks
                };

                return Result<byte[]>.Success(
                    JsonSerializer.SerializeToUtf8Bytes(export, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(Error.Encryption("backup", ex.Message));
            }
        }
    }

    public void Dispose()
    {
        foreach (var cached in _dekCache.Values)
            CryptographicOperations.ZeroMemory(cached.Key);
        _dekCache.Clear();
    }

    // ── Private helpers ──────────────────────────────────────────

    private void SaveMetadata()
    {
        var meta = new HsmKeystoreMetadata
        {
            Version            = _keyVersion,
            RotationCount      = _rotationCount,
            InitializedAtUtc   = _initializedAtUtc ?? DateTime.UtcNow,
            LastRotatedAtUtc   = _rotationCount > 0 ? DateTime.UtcNow : null,
            NextDekVersion     = _nextDekVersion,
            ActiveDekVersions  = _activeDekVersions,
            StoredDeks         = _storedDeks
        };

        var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_metadataPath, json);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_metadataPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    // ── Nested types ─────────────────────────────────────────────

    private sealed class HsmDekEntry
    {
        public string WrappedBase64 { get; set; } = string.Empty;
        public int MkVersion { get; set; }
        public string Purpose { get; set; } = string.Empty;
    }

    private sealed class HsmKeystoreMetadata
    {
        public int Version { get; set; } = 1;
        public int RotationCount { get; set; }
        public DateTime InitializedAtUtc { get; set; }
        public DateTime? LastRotatedAtUtc { get; set; }
        public int NextDekVersion { get; set; } = 1;
        public Dictionary<string, int> ActiveDekVersions { get; set; } = new();
        public Dictionary<int, HsmDekEntry> StoredDeks { get; set; } = new();
    }
}
