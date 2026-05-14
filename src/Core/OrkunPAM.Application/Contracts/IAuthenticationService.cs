using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Application-layer abstraction for authentication operations.
/// Implemented by Infrastructure.Identity.
/// </summary>
public interface IAuthenticationService
{
    Task<Result<AuthResult>> LoginLocalAsync(string username, string password, string ipAddress, CancellationToken ct = default);
    Task<Result<User>> CreateLocalUserAsync(string username, string password, string? displayName, string? email, CancellationToken ct = default);
}

public record AuthResult(
    TokenPair Tokens,
    Guid UserId,
    string Username,
    string? DisplayName,
    bool MfaRequired,
    bool MustChangePassword,
    bool PasswordExpired);

public record TokenPair(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpiry,
    DateTime RefreshTokenExpiry);
