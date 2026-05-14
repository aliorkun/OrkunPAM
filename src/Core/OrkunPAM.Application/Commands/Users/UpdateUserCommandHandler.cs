using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Users;

public sealed class UpdateUserCommandHandler : IRequestHandler<UpdateUserCommand, Result<UserDto>>
{
    private readonly IUserRepository _users;
    private readonly IUnitOfWork _uow;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<UpdateUserCommandHandler> _logger;

    public UpdateUserCommandHandler(
        IUserRepository users,
        IUnitOfWork uow,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<UpdateUserCommandHandler> logger)
    {
        _users = users;
        _uow = uow;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result<UserDto>> Handle(UpdateUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _users.GetByIdAsync(request.UserId, cancellationToken);
        if (user is null)
            return Result<UserDto>.Failure(Error.NotFound("User", request.UserId));

        if (request.DisplayName is not null) user.DisplayName = request.DisplayName;
        if (request.Email is not null) user.Email = request.Email;
        if (request.Phone is not null) user.Phone = request.Phone;
        if (request.Language is not null) user.Language = request.Language;
        if (request.Timezone is not null) user.Timezone = request.Timezone;

        user.UpdatedAtUtc = DateTime.UtcNow;
        user.UpdatedBy = _currentUser.UserId;

        await _users.UpdateAsync(user, cancellationToken);
        await _uow.SaveChangesAsync(cancellationToken);

        await _audit.LogAsync("UserMgmt", "UserUpdated", _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "User", user.Id.ToString(),
            new { request.DisplayName, request.Email, request.Phone },
            AuditOutcome.Success, cancellationToken);

        var dto = new UserDto(
            user.Id, user.Username, user.DisplayName, user.Email,
            user.AuthSource, user.Status, user.MfaEnabled, user.MfaType,
            user.LastLoginAtUtc, user.CreatedAtUtc);

        return Result<UserDto>.Success(dto);
    }
}
