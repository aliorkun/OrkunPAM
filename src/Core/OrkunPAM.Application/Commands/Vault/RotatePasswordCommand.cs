using MediatR;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Vault;

public record RotatePasswordCommand(Guid CredentialId) : IRequest<Result>;
