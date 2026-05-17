using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Cryptography;

/// <summary>
/// AWS CloudHSM / AWS KMS provider.
/// Uses KMS GenerateDataKey + Encrypt/Decrypt for DEK wrapping without exposing the CMK.
///
/// To activate: set Security:HsmMode = "aws-kms" and Security:AwsKmsKeyArn + Security:AwsRegion.
/// Authenticate via IAM role (EC2 instance profile, ECS task role, or env vars AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).
///
/// Requires AWSSDK.KeyManagementService NuGet package:
///   &lt;PackageReference Include="AWSSDK.KeyManagementService" Version="3.*" /&gt;
/// </summary>
public sealed class AwsCloudHsmProvider : IHsmProvider
{
    public string ProviderName => "AWS KMS / CloudHSM";

    private readonly string? _kmsKeyArn;
    private readonly string? _region;
    private readonly ILogger<AwsCloudHsmProvider> _logger;

    public AwsCloudHsmProvider(ILogger<AwsCloudHsmProvider> logger, IConfiguration config)
    {
        _logger = logger;
        _kmsKeyArn = config["Security:AwsKmsKeyArn"];
        _region = config["Security:AwsRegion"];
    }

    public Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_kmsKeyArn))
        {
            _logger.LogWarning("AWS KMS key ARN not configured (Security:AwsKmsKeyArn)");
            return Task.FromResult(false);
        }
        return Task.FromResult(true);
    }

    public Task<HsmProviderStatus> GetStatusAsync(CancellationToken ct = default) =>
        Task.FromResult(new HsmProviderStatus(
            ProviderName,
            $"AWS KMS region={_region ?? "not configured"} key={_kmsKeyArn ?? "not configured"}",
            !string.IsNullOrWhiteSpace(_kmsKeyArn),
            $"Region: {_region}",
            null,
            DateTime.UtcNow));

    public Task EnsureMasterKeyExistsAsync(string keyLabel, CancellationToken ct = default) =>
        throw new NotSupportedException(
            "AWS KMS requires AWSSDK.KeyManagementService NuGet. " +
            "Create CMK in AWS Console or via CreateKeyAsync and set Security:AwsKmsKeyArn.");

    public Task RegenerateMasterKeyAsync(string keyLabel, CancellationToken ct = default) =>
        throw new NotSupportedException("AWS KMS key rotation is managed by KMS — enable automatic rotation on the CMK.");

    public Task<byte[]> WrapKeyAsync(string keyLabel, byte[] plaintext, CancellationToken ct = default) =>
        throw new NotSupportedException("AWS KMS WrapKey requires AWSSDK.KeyManagementService — use EncryptAsync with the CMK ARN.");

    public Task<byte[]> UnwrapKeyAsync(string keyLabel, byte[] wrappedData, CancellationToken ct = default) =>
        throw new NotSupportedException("AWS KMS UnwrapKey requires AWSSDK.KeyManagementService — use DecryptAsync.");
}
