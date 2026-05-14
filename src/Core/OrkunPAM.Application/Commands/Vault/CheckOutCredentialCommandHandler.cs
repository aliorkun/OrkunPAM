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
    private readonly IPamAuthorizationService _authz;
    private readonly IAccessPolicyEngine? _accessPolicy;
    private readonly ILogger<CheckOutCredentialCommandHandler> _logger;

    public CheckOutCredentialCommandHandler(
        ICredentialRepository credentials,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        IPamAuthorizationService authz,
        ILogger<CheckOutCredentialCommandHandler> logger,
        IAccessPolicyEngine? accessPolicy = null)
    {
        _credentials = credentials;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _authz = authz;
        _accessPolicy = accessPolicy;
        _logger = logger;
    }

    public async Task<Result<CheckOutResult>> Handle(CheckOutCredentialCommand request, CancellationToken cancellationToken)
    {
        var userId = _currentUser.UserId;
        if (userId is null)
            return Result<CheckOutResult>.Failure(Error.Unauthorized("Authenticated user context is required."));

        var isAdmin = _currentUser.Roles.Contains("GlobalAdmin") || _currentUser.Roles.Contains("VaultAdmin");
        if (!await _authz.CanAccessCredentialAsync(userId.Value, isAdmin, request.CredentialId, cancellationToken))
            return Result<CheckOutResult>.Failure(Error.Forbidden("No access to the requested credential."));

        var credential = await _credentials.GetByIdAsync(request.CredentialId, cancellationToken);
        if (credential is null)
            return Result<CheckOutResult>.Failure(Error.NotFound("Credential", request.CredentialId));

        // Access policy check (time windows + IP restrictions)
        if (_accessPolicy != null)
        {
            var clientIp = _currentUser.IpAddress ?? "0.0.0.0";
            var decision = await _accessPolicy.EvaluateAsync(
                userId.Value, request.CredentialId, clientIp, DateTime.UtcNow, cancellationToken);

            if (decision.Verdict == AccessVerdict.Deny)
            {
                await _audit.LogAsync("Vault", "CredentialCheckoutDenied", _currentUser.UserId, _currentUser.Username,
                    _currentUser.IpAddress, "Credential", credential.Id.ToString(),
                    new { credential.Name, decision.Reason, decision.PolicyName },
                    AuditOutcome.Denied, cancellationToken);

                _logger.LogWarning("Credential checkout denied for '{Name}' by access policy: {Reason}",
                    credential.Name, decision.Reason);

                return Result<CheckOutResult>.Failure(Error.Forbidden($"Access denied: {decision.Reason}"));
            }
        }

        if (credential.RequiresApproval)
        {
            // TODO: integrate with ApprovalWorkflow - for now, block
            return Result<CheckOutResult>.Failure(Error.Forbidden("This credential requires approval before checkout."));
        }

        var maxMinutes = request.MaxMinutes ?? credential.MaxCheckoutMinutes;

        var checkoutResult = credential.CheckOut(userId.Value, maxMinutes);
        if (checkoutResult.IsFailure)
            return Result<CheckOutResult>.Failure(checkoutResult.Error);

        await _credentials.UpdateAsync(credential, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        await _audit.LogAsync("Vault", "CredentialCheckedOut", userId.Value, _currentUser.Username,
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
