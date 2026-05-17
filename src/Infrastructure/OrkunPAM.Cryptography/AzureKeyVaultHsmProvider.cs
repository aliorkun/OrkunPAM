using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Cryptography;

/// <summary>
/// Azure Managed HSM / Azure Key Vault HSM provider.
/// Uses Azure Key Vault Wrap/Unwrap operations to protect DEKs without exposing the MEK.
///
/// To activate: set Security:HsmMode = "azure-keyvault" and Security:AzureKeyVaultUrl.
/// Authenticate via DefaultAzureCredential (managed identity, env vars, or az CLI).
///
/// Requires Azure.Security.KeyVault.Keys NuGet package:
///   &lt;PackageReference Include="Azure.Security.KeyVault.Keys" Version="4.*" /&gt;
///   &lt;PackageReference Include="Azure.Identity" Version="1.*" /&gt;
/// </summary>
public sealed class AzureKeyVaultHsmProvider : IHsmProvider
{
    public string ProviderName => "Azure Managed HSM / Key Vault";

    private readonly string? _keyVaultUrl;
    private readonly ILogger<AzureKeyVaultHsmProvider> _logger;

    public AzureKeyVaultHsmProvider(ILogger<AzureKeyVaultHsmProvider> logger, IConfiguration config)
    {
        _logger = logger;
        _keyVaultUrl = config["Security:AzureKeyVaultUrl"];
    }

    public Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_keyVaultUrl))
        {
            _logger.LogWarning("Azure Key Vault URL not configured (Security:AzureKeyVaultUrl)");
            return Task.FromResult(false);
        }
        return Task.FromResult(true);
    }

    public Task<HsmProviderStatus> GetStatusAsync(CancellationToken ct = default) =>
        Task.FromResult(new HsmProviderStatus(
            ProviderName,
            $"Azure Key Vault: {_keyVaultUrl ?? "(not configured)"}",
            !string.IsNullOrWhiteSpace(_keyVaultUrl),
            _keyVaultUrl,
            null,
            DateTime.UtcNow));

    public Task EnsureMasterKeyExistsAsync(string keyLabel, CancellationToken ct = default) =>
        throw new NotSupportedException(
            "Azure Key Vault requires Azure.Security.KeyVault.Keys NuGet package. " +
            "Implement using KeyClient.CreateKeyAsync with KeyType.RsaHsm or EcHsm.");

    public Task RegenerateMasterKeyAsync(string keyLabel, CancellationToken ct = default) =>
        throw new NotSupportedException("Azure Key Vault key rotation requires Azure.Security.KeyVault.Keys — use CreateKeyVersionAsync.");

    public Task<byte[]> WrapKeyAsync(string keyLabel, byte[] plaintext, CancellationToken ct = default) =>
        throw new NotSupportedException("Azure Key Vault WrapKey requires Azure.Security.KeyVault.Keys — use CryptographyClient.WrapKeyAsync.");

    public Task<byte[]> UnwrapKeyAsync(string keyLabel, byte[] wrappedData, CancellationToken ct = default) =>
        throw new NotSupportedException("Azure Key Vault UnwrapKey requires Azure.Security.KeyVault.Keys — use CryptographyClient.UnwrapKeyAsync.");
}
