using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;
using OrkunPAM.Grpc.Vault;
using OrkunPAM.Persistence;

namespace OrkunPAM.Grpc.Services;

/// <summary>
/// gRPC service for vault credential operations.
/// Thin wrapper around IVaultEncryptionService — no business logic duplication.
/// </summary>
public sealed class VaultGrpcService : VaultService.VaultServiceBase
{
    private readonly OrkunPamDbContext _db;
    private readonly IVaultEncryptionService _vault;
    private readonly Persistence.Services.IAuditService _audit;
    private readonly ILogger<VaultGrpcService> _logger;

    public VaultGrpcService(
        OrkunPamDbContext db,
        IVaultEncryptionService vault,
        Persistence.Services.IAuditService audit,
        ILogger<VaultGrpcService> logger)
    {
        _db = db;
        _vault = vault;
        _audit = audit;
        _logger = logger;
    }

    public override async Task<CredentialResponse> DecryptCredential(
        CredentialRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.CredentialId, out var credId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid credential_id format"));

        var credential = await _db.Set<Domain.Entities.Vault.Credential>()
            .FirstOrDefaultAsync(c => c.Id == credId, context.CancellationToken);

        if (credential == null)
            throw new RpcException(new Status(StatusCode.NotFound, "Credential not found"));

        var response = new CredentialResponse
        {
            Username = credential.Username ?? "",
            Domain = ""
        };

        // Decrypt password
        if (credential.PasswordEnc != null && credential.PasswordEnc.Length > 0)
        {
            var decryptResult = _vault.DecryptString(credential.PasswordEnc);
            if (decryptResult.IsFailure)
                throw new RpcException(new Status(StatusCode.Internal,
                    $"Failed to decrypt credential: {decryptResult.Error.Message}"));

            response.Password = ByteString.CopyFromUtf8(decryptResult.Value);
        }

        // Decrypt private key if present
        if (credential.PrivateKeyEnc != null && credential.PrivateKeyEnc.Length > 0)
        {
            var keyResult = _vault.DecryptString(credential.PrivateKeyEnc);
            if (keyResult.IsFailure)
                throw new RpcException(new Status(StatusCode.Internal,
                    $"Failed to decrypt private key: {keyResult.Error.Message}"));

            response.PrivateKey = keyResult.Value;
        }

        await _audit.LogAsync("Vault", "CredentialDecrypt", null, null, null,
            "Credential", request.CredentialId,
            new { request.Purpose, request.RequesterSessionId, Via = "gRPC" },
            ct: context.CancellationToken);

        _logger.LogInformation("gRPC: Credential {CredentialId} decrypted for purpose={Purpose}, session={SessionId}",
            request.CredentialId, request.Purpose, request.RequesterSessionId);

        return response;
    }

    public override async Task<CheckOutResponse> CheckOutCredential(
        CheckOutRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.CredentialId, out var credId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid credential_id format"));

        var credential = await _db.Set<Domain.Entities.Vault.Credential>()
            .FirstOrDefaultAsync(c => c.Id == credId, context.CancellationToken);

        if (credential == null)
            throw new RpcException(new Status(StatusCode.NotFound, "Credential not found"));

        // Create checkout record
        var checkoutId = Guid.NewGuid().ToString();

        var response = new CheckOutResponse
        {
            CheckoutId = checkoutId,
            Username = credential.Username ?? "",
            Domain = ""
        };

        if (credential.PasswordEnc != null && credential.PasswordEnc.Length > 0)
        {
            var decryptResult = _vault.DecryptString(credential.PasswordEnc);
            if (decryptResult.IsFailure)
                throw new RpcException(new Status(StatusCode.Internal,
                    $"Failed to decrypt credential: {decryptResult.Error.Message}"));

            response.Password = ByteString.CopyFromUtf8(decryptResult.Value);
        }

        if (credential.PrivateKeyEnc != null && credential.PrivateKeyEnc.Length > 0)
        {
            var keyResult = _vault.DecryptString(credential.PrivateKeyEnc);
            if (keyResult.IsFailure)
                throw new RpcException(new Status(StatusCode.Internal,
                    $"Failed to decrypt private key: {keyResult.Error.Message}"));

            response.PrivateKey = keyResult.Value;
        }

        await _audit.LogAsync("Vault", "CredentialCheckOut", null, null, null,
            "Credential", request.CredentialId,
            new { checkoutId, request.SessionId, request.ProxyType, request.TtlMinutes, Via = "gRPC" },
            ct: context.CancellationToken);

        _logger.LogInformation("gRPC: Credential {CredentialId} checked out (checkout={CheckoutId}, proxy={ProxyType}, ttl={TTL}m)",
            request.CredentialId, checkoutId, request.ProxyType, request.TtlMinutes);

        return response;
    }

    public override async Task<Empty> CheckInCredential(
        CheckInRequest request, ServerCallContext context)
    {
        await _audit.LogAsync("Vault", "CredentialCheckIn", null, null, null,
            "Credential", request.CheckoutId,
            new { request.CheckoutId, request.SessionId, Via = "gRPC" },
            ct: context.CancellationToken);

        _logger.LogInformation("gRPC: Credential checked in (checkout={CheckoutId}, session={SessionId})",
            request.CheckoutId, request.SessionId);

        return new Empty();
    }
}
