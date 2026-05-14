using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Users;

public sealed class GetUsersQueryHandler : IRequestHandler<GetUsersQuery, Result<PagedResultDto<UserDto>>>
{
    private readonly IUserRepository _users;

    public GetUsersQueryHandler(IUserRepository users) => _users = users;

    public async Task<Result<PagedResultDto<UserDto>>> Handle(GetUsersQuery request, CancellationToken cancellationToken)
    {
        var paged = await _users.GetPagedAsync(request.Page, request.PageSize, request.Search, cancellationToken);

        var dto = paged.ToDto(u => new UserDto(
            u.Id, u.Username, u.DisplayName, u.Email,
            u.AuthSource, u.Status, u.MfaEnabled, u.MfaType,
            u.LastLoginAtUtc, u.CreatedAtUtc));

        return Result<PagedResultDto<UserDto>>.Success(dto);
    }
}
