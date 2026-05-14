using MediatR;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Sessions;

public record StartSessionCommand(
    Guid DeviceId,
    Guid CredentialId,
    SessionType SessionType,
    string? Reason,
    string? TicketNumber,
    string? ClientIpAddress) : IRequest<Result<StartSessionResult>>;

public record StartSessionResult(
    Guid SessionId,
    string SessionToken,
    string TargetHost,
    int TargetPort);
