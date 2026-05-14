using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Vault;

public sealed class RotatePasswordCommandHandler : IRequestHandler<RotatePasswordCommand, Result>
{
    private readonly ICredentialRepository _credentials;
    private readonly IPasswordRotationOrchestrator _rotator;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<RotatePasswordCommandHandler> _logger;

    public RotatePasswordCommandHandler(
        ICredentialRepository credentials,
        IPasswordRotationOrchestrator rotator,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<RotatePasswordCommandHandler> logger)
    {
        _credentials = credentials;
        _rotator = rotator;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result> Handle(RotatePasswordCommand request, CancellationToken cancellationToken)
    {
        var credential = await _credentials.GetByIdAsync(request.CredentialId, cancellationToken);
        if (credential is null)
            return Result.Failure(Error.NotFound("Credential", request.CredentialId));

        if (credential.Status == CredentialStatus.CheckedOut)
            return Result.Failure(Error.Conflict("Cannot rotate password while credential is checked out."));

        if (credential.Status == CredentialStatus.Rotating)
            return Result.Failure(Error.Conflict("Password rotation is already in progress."));

        var result = await _rotator.RotateAsync(request.CredentialId, cancellationToken);

        var outcome = result.IsSuccess ? AuditOutcome.Success : AuditOutcome.Failure;
        await _audit.LogAsync("Vault", "PasswordRotation", _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "Credential", credential.Id.ToString(),
            new { credential.Name, Success = result.IsSuccess, Error = result.IsFailure ? result.Error.Message : null },
            outcome, cancellationToken);

        if (result.IsFailure)
            _logger.LogWarning("Password rotation failed for '{Name}': {Error}", credential.Name, result.Error.Message);
        else
            _logger.LogInformation("Password rotated for '{Name}' by {User}", credential.Name, _currentUser.Username);

        return result;
    }
}
