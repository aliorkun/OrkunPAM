using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Users;

public sealed class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, Result<UserDto>>
{
    private readonly IAuthenticationService _auth;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<CreateUserCommandHandler> _logger;

    public CreateUserCommandHandler(
        IAuthenticationService auth,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<CreateUserCommandHandler> logger)
    {
        _auth = auth;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result<UserDto>> Handle(CreateUserCommand request, CancellationToken cancellationToken)
    {
        var result = await _auth.CreateLocalUserAsync(
            request.Username, request.Password, request.DisplayName, request.Email, cancellationToken);

        if (result.IsFailure)
            return Result<UserDto>.Failure(result.Error);

        var user = result.Value;

        await _audit.LogAsync("UserMgmt", "UserCreated", _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "User", user.Id.ToString(),
            new { user.Username, user.DisplayName, user.Email },
            AuditOutcome.Success, cancellationToken);

        var dto = new UserDto(
            user.Id, user.Username, user.DisplayName, user.Email,
            user.AuthSource, user.Status, user.MfaEnabled, user.MfaType,
            user.LastLoginAtUtc, user.CreatedAtUtc);

        return Result<UserDto>.Success(dto);
    }
}
