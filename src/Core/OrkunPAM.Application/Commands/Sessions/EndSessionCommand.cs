using MediatR;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Sessions;

public record EndSessionCommand(
    Guid SessionId,
    string? TerminationReason) : IRequest<Result>;
