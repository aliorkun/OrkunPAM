using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Users;

public record CreateUserCommand(
    string Username,
    string Password,
    string? DisplayName,
    string? Email) : IRequest<Result<UserDto>>;
