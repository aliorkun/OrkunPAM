using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Sessions;

public sealed class EndSessionCommandHandler : IRequestHandler<EndSessionCommand, Result>
{
    private readonly ISessionRepository _sessions;
    private readonly IUnitOfWork _uow;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<EndSessionCommandHandler> _logger;

    public EndSessionCommandHandler(
        ISessionRepository sessions,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<EndSessionCommandHandler> logger)
    {
        _sessions = sessions;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result> Handle(EndSessionCommand request, CancellationToken cancellationToken)
    {
        var userId = _currentUser.UserId;
        if (userId is null)
            return Result.Failure(Error.Unauthorized("Authenticated user context is required."));

        var session = await _sessions.GetByIdAsync(request.SessionId, cancellationToken);
        if (session is null)
            return Result.Failure(Error.NotFound("Session", request.SessionId));

        if (session.Status != SessionStatus.Active)
            return Result.Failure(Error.Conflict($"Session is already {session.Status}."));

        var isAdmin = _currentUser.Roles.Contains("GlobalAdmin") || _currentUser.Roles.Contains("SessionAdmin");
        if (session.UserId != userId.Value && !isAdmin)
            return Result.Failure(Error.Forbidden("Cannot terminate another user's session."));

        var adminUserId = userId.Value;

        // If termination reason is provided, it's an admin-initiated termination
        if (!string.IsNullOrEmpty(request.TerminationReason))
            session.Terminate(adminUserId, request.TerminationReason);
        else
            session.End();

        await _sessions.UpdateAsync(session, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        var eventType = string.IsNullOrEmpty(request.TerminationReason) ? "SessionEnded" : "SessionTerminated";
        await _audit.LogAsync("Session", eventType, userId.Value, _currentUser.Username,
            _currentUser.IpAddress, "Session", session.Id.ToString(),
            new { session.DurationSeconds, request.TerminationReason },
            AuditOutcome.Success, cancellationToken);

        _logger.LogInformation("Session {SessionId} {Event} (duration: {Seconds}s)",
            session.Id, eventType, session.DurationSeconds);

        return Result.Success();
    }
}
