using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Application.DTOs;

public record UserDto(
    Guid Id,
    string Username,
    string? DisplayName,
    string? Email,
    AuthSource AuthSource,
    UserStatus Status,
    bool MfaEnabled,
    MfaType MfaType,
    DateTime? LastLoginAtUtc,
    DateTime CreatedAtUtc);
