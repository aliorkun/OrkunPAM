using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Users;

public record GetUserByIdQuery(Guid UserId) : IRequest<Result<UserDto>>;
