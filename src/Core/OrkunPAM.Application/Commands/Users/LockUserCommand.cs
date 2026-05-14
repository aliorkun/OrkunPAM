using MediatR;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Users;

public record LockUserCommand(
    Guid UserId,
    bool Lock) : IRequest<Result>;
