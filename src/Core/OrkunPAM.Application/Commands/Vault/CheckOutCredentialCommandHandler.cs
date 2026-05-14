using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Vault;

public sealed class CheckOutCredentialCommandHandler : IRequestHandler<CheckOutCredentialCommand, Result<CheckOutResult>>
{
    private readonly ICredentialRepository _credentials;
    private readonly IUnitOfWork _uow;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<CheckOutCredentialCommandHandler> _logger;

    public CheckOutCredentialCommandHandler(
        ICredentialRepository credentials,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<CheckOutCredentialCommandHandler> logger)
    {
        _credentials = credentials;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result<CheckOutResult>> Handle(CheckOutCredentialCommand request, CancellationToken cancellationToken)
    {
        var credential = await _credentials.GetByIdAsync(request.CredentialId, cancellationToken);
        if (credential is null)
            return Result<CheckOutResult>.Failure(Error.NotFound("Credential", request.CredentialId));

        if (credential.RequiresApproval)
        {
            // TODO: integrate with ApprovalWorkflow - for now, block
            return Result<CheckOutResult>.Failure(Error.Forbidden("This credential requires approval before checkout."));
        }

        var userId = _currentUser.UserId ?? Guid.Empty;
        var maxMinutes = request.MaxMinutes ?? credential.MaxCheckoutMinutes;

        var checkoutResult = credential.CheckOut(userId, maxMinutes);
        if (checkoutResult.IsFailure)
            return Result<CheckOutResult>.Failure(checkoutResult.Error);

        await _credentials.UpdateAsync(credential, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        await _audit.LogAsync("Vault", "CredentialCheckedOut", _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "Credential", credential.Id.ToString(),
            new { credential.Name, request.Reason, request.TicketNumber, maxMinutes },
            AuditOutcome.Success, cancellationToken);

        _logger.LogInformation("Credential '{Name}' checked out by {User} for {Minutes}min",
            credential.Name, _currentUser.Username, maxMinutes);

        return Result<CheckOutResult>.Success(new CheckOutResult(
            credential.Id,
            credential.CheckedOutAtUtc!.Value,
            credential.CheckOutExpiresUtc!.Value));
    }
}
