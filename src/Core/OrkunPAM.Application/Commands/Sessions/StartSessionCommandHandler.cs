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
    private readonly ILogger<StartSessionCommandHandler> _logger;

    public StartSessionCommandHandler(
        ISessionRepository sessions,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<StartSessionCommandHandler> logger)
    {
        _sessions = sessions;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result<StartSessionResult>> Handle(StartSessionCommand request, CancellationToken cancellationToken)
    {
        var userId = _currentUser.UserId ?? Guid.Empty;

        var session = new ProxySession
        {
            UserId = userId,
            DeviceId = request.DeviceId,
            CredentialId = request.CredentialId,
            SessionType = request.SessionType,
            ClientIpAddress = request.ClientIpAddress ?? _currentUser.IpAddress,
            Reason = request.Reason,
            TicketNumber = request.TicketNumber,
            Status = SessionStatus.Active,
            StartedAtUtc = DateTime.UtcNow
        };

        await _sessions.AddAsync(session, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        // Generate a session token (proxy services use this to authenticate the session)
        var sessionToken = Convert.ToBase64String(Guid.NewGuid().ToByteArray());

        await _audit.LogAsync("Session", "SessionStarted", userId, _currentUser.Username,
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
