namespace OrkunPAM.Cryptography;

/// <summary>
/// Hardware Security Module abstraction. Implementations: SoftHSM (dev), PKCS#11, Azure Key Vault, AWS KMS.
/// The MEK (Master Encryption Key) lives inside the HSM and never leaves it in plaintext.
/// HsmKeyStore uses Wrap/Unwrap to protect DEKs without exposing the MEK.
/// </summary>
public interface IHsmProvider
{
    string ProviderName { get; }

    Task<bool> IsAvailableAsync(CancellationToken ct = default);
    Task<HsmProviderStatus> GetStatusAsync(CancellationToken ct = default);

    /// <summary>Create the MEK inside the HSM if it does not already exist.</summary>
    Task EnsureMasterKeyExistsAsync(string keyLabel, CancellationToken ct = default);

    /// <summary>
    /// Rotate the MEK: generate a new key for <paramref name="keyLabel"/> inside the HSM.
    /// Caller must re-wrap all DEKs BEFORE calling this (unwrap with old key, rewrap with new).
    /// </summary>
    Task RegenerateMasterKeyAsync(string keyLabel, CancellationToken ct = default);

    /// <summary>Use the HSM-resident key to wrap (encrypt) plaintext DEK bytes.</summary>
    Task<byte[]> WrapKeyAsync(string keyLabel, byte[] plaintext, CancellationToken ct = default);

    /// <summary>Use the HSM-resident key to unwrap (decrypt) a previously wrapped DEK blob.</summary>
    Task<byte[]> UnwrapKeyAsync(string keyLabel, byte[] wrappedData, CancellationToken ct = default);
}

public record HsmProviderStatus(
    string Provider,
    string Mode,
    bool Available,
    string? SlotInfo,
    string? FirmwareVersion,
    DateTime LastCheckedUtc);
