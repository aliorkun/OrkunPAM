using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Users;

public sealed class GetUserByIdQueryHandler : IRequestHandler<GetUserByIdQuery, Result<UserDto>>
{
    private readonly IUserRepository _users;

    public GetUserByIdQueryHandler(IUserRepository users) => _users = users;

    public async Task<Result<UserDto>> Handle(GetUserByIdQuery request, CancellationToken cancellationToken)
    {
        var user = await _users.GetByIdAsync(request.UserId, cancellationToken);
        if (user is null)
            return Result<UserDto>.Failure(Error.NotFound("User", request.UserId));

        var dto = new UserDto(
            user.Id, user.Username, user.DisplayName, user.Email,
            user.AuthSource, user.Status, user.MfaEnabled, user.MfaType,
            user.LastLoginAtUtc, user.CreatedAtUtc);

        return Result<UserDto>.Success(dto);
    }
}
