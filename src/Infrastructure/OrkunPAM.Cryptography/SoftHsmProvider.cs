using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Cryptography;

/// <summary>
/// Software-only HSM simulation — for development and testing only.
/// Stores HSM root keys in a local file protected by OS file permissions.
/// NOT suitable for production — use Pkcs11HsmProvider, AzureKeyVaultHsmProvider, or AwsCloudHsmProvider.
/// </summary>
public sealed class SoftHsmProvider : IHsmProvider
{
    public string ProviderName => "SoftHSM (Development Only)";

    private readonly string _keyFilePath;
    private readonly ILogger<SoftHsmProvider> _logger;
    private readonly Dictionary<string, byte[]> _keys = new();
    private readonly object _lock = new();

    public SoftHsmProvider(ILogger<SoftHsmProvider> logger, IConfiguration config)
    {
        _logger = logger;
        var keyDir = config["Jwt:KeyDirectory"] ?? Path.Combine(AppContext.BaseDirectory, "keys");
        Directory.CreateDirectory(keyDir);
        _keyFilePath = Path.Combine(keyDir, "hsm-softhsm-keys.json");
        LoadKeys();
    }

    public Task<bool> IsAvailableAsync(CancellationToken ct = default) => Task.FromResult(true);

    public Task<HsmProviderStatus> GetStatusAsync(CancellationToken ct = default)
    {
        int keyCount;
        lock (_lock) keyCount = _keys.Count;
        return Task.FromResult(new HsmProviderStatus(
            ProviderName,
            "Software simulation — key file: " + _keyFilePath,
            true,
            $"SoftHSM slot 0 — {keyCount} key(s) stored",
            "1.0.0",
            DateTime.UtcNow));
    }

    public Task EnsureMasterKeyExistsAsync(string keyLabel, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (!_keys.ContainsKey(keyLabel))
            {
                var key = new byte[32];
                RandomNumberGenerator.Fill(key);
                _keys[keyLabel] = key;
                SaveKeys();
                _logger.LogInformation("SoftHSM: generated 256-bit key for label '{Label}'", keyLabel);
            }
        }
        return Task.CompletedTask;
    }

    public Task RegenerateMasterKeyAsync(string keyLabel, CancellationToken ct = default)
    {
        lock (_lock)
        {
            var newKey = new byte[32];
            RandomNumberGenerator.Fill(newKey);
            if (_keys.TryGetValue(keyLabel, out var oldKey))
                CryptographicOperations.ZeroMemory(oldKey);
            _keys[keyLabel] = newKey;
            SaveKeys();
            _logger.LogWarning("SoftHSM: regenerated key for label '{Label}'", keyLabel);
        }
        return Task.CompletedTask;
    }

    public Task<byte[]> WrapKeyAsync(string keyLabel, byte[] plaintext, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (!_keys.TryGetValue(keyLabel, out var rootKey))
                throw new InvalidOperationException($"SoftHSM: key label '{keyLabel}' not found. Call EnsureMasterKeyExistsAsync first.");

            var iv = new byte[12];
            RandomNumberGenerator.Fill(iv);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using var aes = new AesGcm(rootKey, 16);
            aes.Encrypt(iv, plaintext, ciphertext, tag);

            // blob: [IV(12) | Ciphertext | Tag(16)]
            var blob = new byte[12 + plaintext.Length + 16];
            iv.CopyTo(blob, 0);
            ciphertext.CopyTo(blob, 12);
            tag.CopyTo(blob, 12 + plaintext.Length);

            return Task.FromResult(blob);
        }
    }

    public Task<byte[]> UnwrapKeyAsync(string keyLabel, byte[] wrappedData, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (!_keys.TryGetValue(keyLabel, out var rootKey))
                throw new InvalidOperationException($"SoftHSM: key label '{keyLabel}' not found.");

            var iv = wrappedData.AsSpan(0, 12);
            var ciphertextLen = wrappedData.Length - 12 - 16;
            var ciphertext = wrappedData.AsSpan(12, ciphertextLen);
            var tag = wrappedData.AsSpan(12 + ciphertextLen, 16);
            var plaintext = new byte[ciphertextLen];

            using var aes = new AesGcm(rootKey, 16);
            aes.Decrypt(iv, ciphertext, tag, plaintext);

            return Task.FromResult(plaintext);
        }
    }

    // ── Private helpers ──────────────────────────────────────────

    private void LoadKeys()
    {
        if (!File.Exists(_keyFilePath)) return;
        try
        {
            var json = File.ReadAllText(_keyFilePath);
            var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (dict == null) return;
            lock (_lock)
            {
                foreach (var (label, b64) in dict)
                    _keys[label] = Convert.FromBase64String(b64);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SoftHSM: failed to load key file {Path}", _keyFilePath);
        }
    }

    private void SaveKeys()
    {
        var dict = new Dictionary<string, string>();
        foreach (var (label, key) in _keys)
            dict[label] = Convert.ToBase64String(key);

        var json = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_keyFilePath, json);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_keyFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
