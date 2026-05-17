using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Cryptography;

/// <summary>
/// PKCS#11 hardware HSM provider. Supports Thales Luna, nCipher nShield, SafeNet, AWS CloudHSM.
/// Requires native PKCS#11 library from the HSM vendor (e.g., libCryptoki2.so / CngProvider.dll).
///
/// To activate: set Security:HsmMode = "pkcs11" and Security:Pkcs11LibraryPath in appsettings.json.
/// Set ORKUN_HSM_PIN environment variable for slot authentication.
///
/// Requires Net.Pkcs11Interop NuGet package. Add to OrkunPAM.Cryptography.csproj:
///   &lt;PackageReference Include="Net.Pkcs11Interop" Version="5.*" /&gt;
/// </summary>
public sealed class Pkcs11HsmProvider : IHsmProvider
{
    public string ProviderName => "PKCS#11 Hardware HSM";

    private readonly string? _libraryPath;
    private readonly int _slotId;
    private readonly ILogger<Pkcs11HsmProvider> _logger;

    public Pkcs11HsmProvider(ILogger<Pkcs11HsmProvider> logger, IConfiguration config)
    {
        _logger = logger;
        _libraryPath = config["Security:Pkcs11LibraryPath"];
        _slotId = int.TryParse(config["Security:HsmSlot"], out var s) ? s : 0;
    }

    public Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_libraryPath) || !File.Exists(_libraryPath))
        {
            _logger.LogWarning("PKCS#11 library not found at: {Path}", _libraryPath);
            return Task.FromResult(false);
        }
        // Actual PKCS#11 library availability check requires Net.Pkcs11Interop
        return Task.FromResult(true);
    }

    public Task<HsmProviderStatus> GetStatusAsync(CancellationToken ct = default) =>
        Task.FromResult(new HsmProviderStatus(
            ProviderName,
            $"PKCS#11 slot {_slotId} — library: {_libraryPath ?? "(not configured)"}" ,
            !string.IsNullOrWhiteSpace(_libraryPath) && File.Exists(_libraryPath),
            $"Slot {_slotId}",
            null,
            DateTime.UtcNow));

    public Task EnsureMasterKeyExistsAsync(string keyLabel, CancellationToken ct = default) =>
        throw new NotSupportedException(
            "PKCS#11 HSM requires Net.Pkcs11Interop NuGet package. " +
            "Add it to OrkunPAM.Cryptography.csproj and implement PKCS#11 key generation via C_GenerateKey.");

    public Task RegenerateMasterKeyAsync(string keyLabel, CancellationToken ct = default) =>
        throw new NotSupportedException("PKCS#11 key rotation requires Net.Pkcs11Interop.");

    public Task<byte[]> WrapKeyAsync(string keyLabel, byte[] plaintext, CancellationToken ct = default) =>
        throw new NotSupportedException("PKCS#11 WrapKey requires Net.Pkcs11Interop — C_WrapKey with CKM_AES_KEY_WRAP.");

    public Task<byte[]> UnwrapKeyAsync(string keyLabel, byte[] wrappedData, CancellationToken ct = default) =>
        throw new NotSupportedException("PKCS#11 UnwrapKey requires Net.Pkcs11Interop — C_UnwrapKey with CKM_AES_KEY_WRAP.");
}
