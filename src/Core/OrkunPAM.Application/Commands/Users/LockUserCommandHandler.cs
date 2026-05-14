using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Users;

public sealed class LockUserCommandHandler : IRequestHandler<LockUserCommand, Result>
{
    private readonly IUserRepository _users;
    private readonly IUnitOfWork _uow;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<LockUserCommandHandler> _logger;

    public LockUserCommandHandler(
        IUserRepository users,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<LockUserCommandHandler> logger)
    {
        _users = users;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result> Handle(LockUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _users.GetByIdAsync(request.UserId, cancellationToken);
        if (user is null)
            return Result.Failure(Error.NotFound("User", request.UserId));

        if (request.Lock)
        {
            user.Status = UserStatus.Locked;
            user.LockoutEndUtc = DateTime.UtcNow.AddYears(100); // permanent lock until admin unlocks
        }
        else
        {
            user.Status = UserStatus.Active;
            user.LockoutEndUtc = null;
            user.FailedLoginCount = 0;
        }

        user.UpdatedAtUtc = DateTime.UtcNow;
        user.UpdatedBy = _currentUser.UserId;

        await _users.UpdateAsync(user, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        var action = request.Lock ? "UserLocked" : "UserUnlocked";
        await _audit.LogAsync("UserMgmt", action, _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "User", user.Id.ToString(),
            new { user.Username, Action = action },
            AuditOutcome.Success, cancellationToken);

        _logger.LogInformation("User '{Username}' {Action} by {Admin}", user.Username, action, _currentUser.Username);
        return Result.Success();
    }
}
