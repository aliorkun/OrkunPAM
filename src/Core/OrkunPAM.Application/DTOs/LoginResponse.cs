namespace OrkunPAM.Application.DTOs;

public record LoginResponse(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpiry,
    DateTime RefreshTokenExpiry,
    Guid UserId,
    string Username,
    string? DisplayName,
    bool MfaRequired,
    bool MustChangePassword,
    bool PasswordExpired);
