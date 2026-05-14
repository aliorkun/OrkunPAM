using System.Security.Cryptography;
using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Sessions;

public sealed class StartSessionCommandHandler : IRequestHandler<StartSessionCommand, Result<StartSessionResult>>
{
    private readonly ISessionRepository _sessions;
    private readonly IUnitOfWork _uow;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly IPamAuthorizationService _authz;
    private readonly ILogger<StartSessionCommandHandler> _logger;

    public StartSessionCommandHandler(
        ISessionRepository sessions,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        IPamAuthorizationService authz,
        ILogger<StartSessionCommandHandler> logger)
    {
        _sessions = sessions;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _authz = authz;
        _logger = logger;
    }

    public async Task<Result<StartSessionResult>> Handle(StartSessionCommand request, CancellationToken cancellationToken)
    {
        var userId = _currentUser.UserId;
        if (userId is null)
            return Result<StartSessionResult>.Failure(Error.Unauthorized("Authenticated user context is required."));

        var isAdmin = _currentUser.Roles.Contains("GlobalAdmin") || _currentUser.Roles.Contains("SessionAdmin") || _currentUser.Roles.Contains("VaultAdmin");
        if (!await _authz.CanAccessCredentialAsync(userId.Value, isAdmin, request.CredentialId, cancellationToken))
            return Result<StartSessionResult>.Failure(Error.Forbidden("No access to the requested credential."));

        // CSRNG token — generate before persist so hash is stored with the session
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var sessionToken = Convert.ToBase64String(tokenBytes);
        var tokenHash = Convert.ToHexString(SHA256.HashData(tokenBytes));

        var session = new ProxySession
        {
            UserId = userId.Value,
            DeviceId = request.DeviceId,
            CredentialId = request.CredentialId,
            SessionType = request.SessionType,
            ClientIpAddress = request.ClientIpAddress ?? _currentUser.IpAddress,
            Reason = request.Reason,
            TicketNumber = request.TicketNumber,
            Status = SessionStatus.Active,
            StartedAtUtc = DateTime.UtcNow,
            SessionTokenHash = tokenHash
        };

        await _sessions.AddAsync(session, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        await _audit.LogAsync("Session", "SessionStarted", userId.Value, _currentUser.Username,
            _currentUser.IpAddress, "Session", session.Id.ToString(),
            new { request.DeviceId, request.CredentialId, request.SessionType, request.Reason },
            AuditOutcome.Success, cancellationToken);

        _logger.LogInformation("Session {SessionId} started: {Type} to device {DeviceId} by {User}",
            session.Id, request.SessionType, request.DeviceId, _currentUser.Username);

        return Result<StartSessionResult>.Success(new StartSessionResult(
            session.Id,
            sessionToken,
            session.TargetIpAddress ?? string.Empty,
            session.TargetPort ?? 0));
    }
}
