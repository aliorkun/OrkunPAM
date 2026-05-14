using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Vault;

public sealed class CheckInCredentialCommandHandler : IRequestHandler<CheckInCredentialCommand, Result>
{
    private readonly ICredentialRepository _credentials;
    private readonly IUnitOfWork _uow;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<CheckInCredentialCommandHandler> _logger;

    public CheckInCredentialCommandHandler(
        ICredentialRepository credentials,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<CheckInCredentialCommandHandler> logger)
    {
        _credentials = credentials;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result> Handle(CheckInCredentialCommand request, CancellationToken cancellationToken)
    {
        var credential = await _credentials.GetByIdAsync(request.CredentialId, cancellationToken);
        if (credential is null)
            return Result.Failure(Error.NotFound("Credential", request.CredentialId));

        // Verify the current user is the one who checked it out (or is admin)
        if (credential.CheckedOutByUserId != _currentUser.UserId)
        {
            // Allow if user has Manage permission (admin override)
            if (!_currentUser.HasPermission("vault:manage"))
                return Result.Failure(Error.Forbidden("You can only check in credentials you checked out."));
        }

        var checkinResult = credential.CheckIn();
        if (checkinResult.IsFailure)
            return checkinResult;

        await _credentials.UpdateAsync(credential, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        await _audit.LogAsync("Vault", "CredentialCheckedIn", _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "Credential", credential.Id.ToString(),
            new { credential.Name },
            AuditOutcome.Success, cancellationToken);

        _logger.LogInformation("Credential '{Name}' checked in by {User}", credential.Name, _currentUser.Username);
        return Result.Success();
    }
}
