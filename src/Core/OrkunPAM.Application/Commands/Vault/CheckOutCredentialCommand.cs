using MediatR;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Vault;

public record CheckOutCredentialCommand(
    Guid CredentialId,
    string? Reason,
    string? TicketNumber,
    int? MaxMinutes) : IRequest<Result<CheckOutResult>>;

public record CheckOutResult(
    Guid CredentialId,
    DateTime CheckedOutAtUtc,
    DateTime ExpiresAtUtc);
