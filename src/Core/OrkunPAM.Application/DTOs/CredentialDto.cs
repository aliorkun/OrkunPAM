using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Application.DTOs;

public record CredentialDto(
    Guid Id,
    string Name,
    string? Description,
    CredentialType CredentialType,
    string? Username,
    Guid FolderId,
    Guid? DeviceId,
    CredentialStatus Status,
    bool RequiresApproval,
    Guid? CheckedOutByUserId,
    DateTime? CheckedOutAtUtc,
    DateTime? LastRotatedAtUtc,
    DateTime? NextRotationAtUtc,
    DateTime CreatedAtUtc);

public record CheckOutHistoryDto(
    long Id,
    Guid CredentialId,
    Guid UserId,
    DateTime CheckedOutAtUtc,
    DateTime? CheckedInAtUtc,
    string? Reason,
    string? TicketNumber,
    bool WasAutoCheckedIn);
