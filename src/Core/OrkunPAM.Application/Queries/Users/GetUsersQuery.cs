using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Users;

public record GetUsersQuery(
    int Page = 1,
    int PageSize = 20,
    string? Search = null) : IRequest<Result<PagedResultDto<UserDto>>>;
