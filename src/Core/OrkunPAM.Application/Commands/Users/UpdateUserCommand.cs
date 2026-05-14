using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Users;

public record UpdateUserCommand(
    Guid UserId,
    string? DisplayName,
    string? Email,
    string? Phone,
    string? Language,
    string? Timezone) : IRequest<Result<UserDto>>;
