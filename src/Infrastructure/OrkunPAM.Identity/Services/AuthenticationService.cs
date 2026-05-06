using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Identity.Services;

public interface IAuthenticationService
{
    Task<Result<AuthResult>> LoginLocalAsync(string username, string password, string ipAddress, CancellationToken ct = default);
    Task<Result<User>> CreateLocalUserAsync(string username, string password, string? displayName, string? email, CancellationToken ct = default);
}

public record AuthResult(TokenPair Tokens, Guid UserId, string Username, string? DisplayName, bool MfaRequired);

public sealed class AuthenticationService : IAuthenticationService
{
    private readonly OrkunPamDbContext _db;
    private readonly IPasswordHasher _hasher;
    private readonly IJwtTokenService _jwt;
    private readonly ILogger<AuthenticationService> _logger;

    // Configurable lockout settings
    private const int MaxFailedAttempts = 5;
    private const int LockoutMinutes = 30;

    public AuthenticationService(OrkunPamDbContext db, IPasswordHasher hasher,
        IJwtTokenService jwt, ILogger<AuthenticationService> logger)
    {
        _db = db;
        _hasher = hasher;
        _jwt = jwt;
        _logger = logger;
    }

    public async Task<Result<AuthResult>> LoginLocalAsync(string username, string password, string ipAddress, CancellationToken ct = default)
    {
        var normalizedUsername = username.Trim().ToUpperInvariant();

        var user = await _db.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
            .Include(u => u.UserGroups).ThenInclude(ug => ug.Group).ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
            .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername, ct);

        if (user == null)
        {
            _logger.LogWarning("Login failed: user '{Username}' not found (IP: {Ip})", username, ipAddress);
            return Result<AuthResult>.Failure(Error.Unauthorized("Invalid username or password"));
        }

        if (user.AuthSource != AuthSource.Local)
        {
            _logger.LogWarning("Login failed: user '{Username}' is not a local user (source: {Source})", username, user.AuthSource);
            return Result<AuthResult>.Failure(Error.Unauthorized($"User '{username}' must authenticate via {user.AuthSource}"));
        }

        if (user.IsLocked)
        {
            _logger.LogWarning("Login failed: user '{Username}' is locked until {LockoutEnd}", username, user.LockoutEndUtc);
            return Result<AuthResult>.Failure(Error.Unauthorized(
                $"Account locked. Try again after {user.LockoutEndUtc:HH:mm:ss UTC}"));
        }

        if (user.Status != UserStatus.Active)
        {
            _logger.LogWarning("Login failed: user '{Username}' status is {Status}", username, user.Status);
            return Result<AuthResult>.Failure(Error.Unauthorized($"Account is {user.Status}"));
        }

        if (string.IsNullOrEmpty(user.PasswordHash) || !_hasher.Verify(password, user.PasswordHash))
        {
            user.RecordLoginFailure(MaxFailedAttempts, LockoutMinutes);
            await _db.SaveChangesAsync(ct);

            _logger.LogWarning("Login failed: wrong password for '{Username}' (attempt {Count}/{Max}, IP: {Ip})",
                username, user.FailedLoginCount, MaxFailedAttempts, ipAddress);

            return Result<AuthResult>.Failure(Error.Unauthorized("Invalid username or password"));
        }

        // Check if temporary user expired
        if (user.IsTemporary && user.TemporaryExpiresUtc.HasValue && user.TemporaryExpiresUtc < DateTime.UtcNow)
        {
            _logger.LogWarning("Login failed: temporary user '{Username}' expired at {Expiry}", username, user.TemporaryExpiresUtc);
            return Result<AuthResult>.Failure(Error.Unauthorized("Temporary account has expired"));
        }

        // Collect roles and permissions
        var roles = new HashSet<string>();
        var permissions = new HashSet<string>();

        // Direct user roles
        foreach (var ur in user.UserRoles)
        {
            roles.Add(ur.Role.Name);
            foreach (var rp in ur.Role.RolePermissions)
                permissions.Add(rp.PermissionCode);
        }

        // Group roles
        foreach (var ug in user.UserGroups)
        {
            foreach (var gr in ug.Group.GroupRoles)
            {
                roles.Add(gr.Role.Name);
                foreach (var rp in gr.Role.RolePermissions)
                    permissions.Add(rp.PermissionCode);
            }
        }

        // Check if MFA required
        bool mfaRequired = user.MfaEnabled;

        // Generate tokens (if MFA required, token will have mfa_verified=false)
        var tokenResult = _jwt.GenerateTokens(
            user.Id, user.Username, user.DisplayName ?? user.Username,
            user.AuthSource.ToString(), roles, permissions, mfaVerified: !mfaRequired);

        if (tokenResult.IsFailure)
            return Result<AuthResult>.Failure(tokenResult.Error);

        // Record success
        user.RecordLoginSuccess(ipAddress);
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("User '{Username}' logged in successfully (IP: {Ip}, Roles: {Roles})",
            username, ipAddress, string.Join(",", roles));

        return Result<AuthResult>.Success(new AuthResult(
            tokenResult.Value, user.Id, user.Username, user.DisplayName, mfaRequired));
    }

    public async Task<Result<User>> CreateLocalUserAsync(string username, string password,
        string? displayName, string? email, CancellationToken ct = default)
    {
        var normalizedUsername = username.Trim().ToUpperInvariant();

        if (await _db.Users.AnyAsync(u => u.NormalizedUsername == normalizedUsername, ct))
            return Result<User>.Failure(Error.Conflict($"Username '{username}' already exists"));

        var user = new User
        {
            Username = username.Trim(),
            NormalizedUsername = normalizedUsername,
            DisplayName = displayName,
            Email = email,
            PasswordHash = _hasher.Hash(password),
            AuthSource = AuthSource.Local,
            Status = UserStatus.Active,
            PasswordLastChanged = DateTime.UtcNow
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("Local user '{Username}' created (Id: {Id})", username, user.Id);
        return Result<User>.Success(user);
    }
}
