using MediatR;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Vault;

public record CheckInCredentialCommand(Guid CredentialId) : IRequest<Result>;
