using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/auth").WithTags("Auth").AllowAnonymous();

        group.MapPost("/login", async (LoginRequest req, IAuthenticationService auth, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var result = await auth.LoginLocalAsync(req.Username, req.Password, ip);

            if (result.IsFailure)
                return Results.Json(new { success = false, errors = new[] { result.Error.Message } }, statusCode: 401);

            var data = result.Value;
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = data.Tokens.AccessToken,
                    refreshToken = data.Tokens.RefreshToken,
                    expiresAt = data.Tokens.AccessTokenExpiry,
                    userId = data.UserId,
                    username = data.Username,
                    displayName = data.DisplayName,
                    mfaRequired = data.MfaRequired,
                    mfaEnrollmentRequired = data.MfaEnrollmentRequired,
                    mustChangePassword = data.MustChangePassword,
                    passwordExpired = data.PasswordExpired
                }
            });
        }).RequireRateLimiting("auth");

        group.MapPost("/register", async (RegisterRequest req, IAuthenticationService auth) =>
        {
            var result = await auth.CreateLocalUserAsync(req.Username, req.Password, req.DisplayName, req.Email);
            if (result.IsFailure)
                return Results.Conflict(new { success = false, errors = new[] { result.Error.Message } });

            return Results.Created($"/api/v1/users/{result.Value.Id}", new
            {
                success = true,
                data = new { result.Value.Id, result.Value.Username, result.Value.DisplayName }
            });
        });

        // Change password — requires authentication; enforces policy + history
        app.MapPost("/api/v1/auth/change-password", async (ChangePasswordRequest req, OrkunPamDbContext db,
            IPasswordHasher hasher, IPasswordPolicyService policy, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
            if (user.AuthSource != AuthSource.Local)
                return Results.BadRequest(new { success = false, errors = new[] { $"Password change not supported for {user.AuthSource} accounts" } });

            if (string.IsNullOrEmpty(user.PasswordHash) || !hasher.Verify(req.CurrentPassword, user.PasswordHash))
                return Results.Json(new { success = false, errors = new[] { "Current password is incorrect" } }, statusCode: 401);

            var validation = await policy.ValidateAsync(req.NewPassword, userId, context.RequestAborted);
            if (validation.IsFailure)
                return Results.BadRequest(new { success = false, errors = new[] { validation.Error.Message } });

            var newHash = hasher.Hash(req.NewPassword);
            user.PasswordHash = newHash;
            user.PasswordLastChanged = DateTime.UtcNow;
            user.PasswordExpiresAt = policy.ComputeExpiry();
            user.MustChangePassword = false;
            await db.SaveChangesAsync(context.RequestAborted);

            await policy.RecordPasswordAsync(userId, newHash, context.RequestAborted);

            return Results.Ok(new { success = true, message = "Password changed successfully" });
        }).RequireAuthorization().WithTags("Auth").RequireRateLimiting("auth");

        // MFA Setup - requires authentication; userId taken from JWT to prevent IDOR
        app.MapPost("/api/v1/auth/mfa/setup", async (OrkunPamDbContext db, ITotpService totp,
            IVaultEncryptionService vault, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var (secret, qrUri) = totp.GenerateSecret(user.Username);
            var secretBytes = TotpService.Base32Decode(secret);
            try
            {
                var encResult = vault.Encrypt(secretBytes, "MfaSecret");
                if (encResult.IsFailure)
                    return Results.Problem("Failed to protect MFA secret");
                user.MfaSecret = encResult.Value;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secretBytes);
            }
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new { secret, qrUri, message = "Scan QR code with authenticator app, then call /mfa/verify to enable" }
            });
        }).RequireAuthorization().WithTags("Auth");

        // MFA Verify & Enable - requires authentication; userId taken from JWT to prevent IDOR
        app.MapPost("/api/v1/auth/mfa/verify", async (MfaVerifyRequest req, OrkunPamDbContext db,
            ITotpService totp, IVaultEncryptionService vault, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
            if (user.MfaSecret == null) return Results.BadRequest(new { success = false, errors = new[] { "MFA not set up. Call /mfa/setup first" } });

            var decResult = vault.Decrypt(user.MfaSecret);
            if (decResult.IsFailure)
                return Results.Problem("Failed to verify MFA secret");
            bool valid;
            try { valid = totp.ValidateCode(decResult.Value, req.Code); }
            finally { CryptographicOperations.ZeroMemory(decResult.Value); }

            if (!valid)
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid TOTP code. Check your authenticator app." } });

            // Generate 10 one-time recovery codes
            var recoveryCodes = RecoveryCodeHelper.GenerateCodes(10);
            user.RecoveryCodesHash = RecoveryCodeHelper.HashCodesToJson(recoveryCodes);
            user.MfaEnabled = true;
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                message = "MFA enabled successfully",
                data = new { recoveryCodes }
            });
        }).RequireAuthorization().WithTags("Auth").RequireRateLimiting("auth");

        // MFA Enrollment — anonymous, token-based (admin sends link to user)
        // GET /api/v1/auth/mfa/enrollment?token= — validate token, generate secret + QR URI
        app.MapGet("/api/v1/auth/mfa/enrollment", async (string token, OrkunPamDbContext db,
            ITotpService totp, IVaultEncryptionService vault) =>
        {
            if (!Guid.TryParse(token, out var tokenGuid))
                return Results.BadRequest(new { success = false, error = "Invalid token." });

            var user = await db.Users.FirstOrDefaultAsync(u => u.MfaEnrollmentToken == tokenGuid);
            if (user == null || user.MfaEnrollmentTokenExpiry == null || user.MfaEnrollmentTokenExpiry < DateTime.UtcNow)
                return Results.BadRequest(new { success = false, error = "Token expired or invalid." });

            var (secret, qrUri) = totp.GenerateSecret(user.Username);
            var secretBytes = TotpService.Base32Decode(secret);
            try
            {
                var encResult = vault.Encrypt(secretBytes, "MfaSecret");
                if (encResult.IsFailure) return Results.Problem("Failed to protect MFA secret");
                user.MfaSecret = encResult.Value;
            }
            finally { CryptographicOperations.ZeroMemory(secretBytes); }

            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, data = new { username = user.Username, secret, qrUri } });
        }).AllowAnonymous().WithTags("Auth");

        // POST /api/v1/auth/mfa/enrollment/confirm — validate token + TOTP code, enable MFA
        app.MapPost("/api/v1/auth/mfa/enrollment/confirm", async (MfaEnrollmentConfirmRequest req,
            OrkunPamDbContext db, ITotpService totp, IVaultEncryptionService vault) =>
        {
            if (!Guid.TryParse(req.Token, out var tokenGuid))
                return Results.BadRequest(new { success = false, error = "Invalid token." });

            var user = await db.Users.FirstOrDefaultAsync(u => u.MfaEnrollmentToken == tokenGuid);
            if (user == null || user.MfaEnrollmentTokenExpiry == null || user.MfaEnrollmentTokenExpiry < DateTime.UtcNow)
                return Results.BadRequest(new { success = false, error = "Token expired or invalid." });

            if (user.MfaSecret == null)
                return Results.BadRequest(new { success = false, error = "Open the setup link first to load the QR code." });

            var decResult = vault.Decrypt(user.MfaSecret);
            if (decResult.IsFailure) return Results.Problem("Failed to verify MFA secret");
            bool valid;
            try { valid = totp.ValidateCode(decResult.Value, req.Code); }
            finally { CryptographicOperations.ZeroMemory(decResult.Value); }

            if (!valid)
                return Results.BadRequest(new { success = false, error = "Invalid TOTP code. Check your authenticator app." });

            // Generate 10 one-time recovery codes
            var recoveryCodes = RecoveryCodeHelper.GenerateCodes(10);
            user.RecoveryCodesHash = RecoveryCodeHelper.HashCodesToJson(recoveryCodes);
            user.MfaEnabled = true;
            user.MfaEnrollmentToken = null;
            user.MfaEnrollmentTokenExpiry = null;
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                message = "MFA enrollment complete. You can now log in with your authenticator.",
                data = new { recoveryCodes }
            });
        }).AllowAnonymous().WithTags("Auth").RequireRateLimiting("auth");

        // MFA Disable
        app.MapPost("/api/v1/auth/mfa/disable", async (MfaDisableRequest req, OrkunPamDbContext db,
            IPasswordHasher hasher, ITotpService totp, IVaultEncryptionService vault, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            if (string.IsNullOrEmpty(user.PasswordHash) || !hasher.Verify(req.CurrentPassword, user.PasswordHash))
                return Results.Json(new { success = false, errors = new[] { "Invalid credentials" } }, statusCode: 401);

            if (user.MfaEnabled && user.MfaSecret != null)
            {
                var decResult = vault.Decrypt(user.MfaSecret);
                if (decResult.IsFailure)
                    return Results.Problem("Failed to verify MFA secret");
                bool valid;
                try { valid = totp.ValidateCode(decResult.Value, req.CurrentMfaCode); }
                finally { CryptographicOperations.ZeroMemory(decResult.Value); }
                if (!valid)
                    return Results.BadRequest(new { success = false, errors = new[] { "Invalid MFA code" } });
            }

            user.MfaEnabled = false;
            user.MfaSecret = null;
            user.RecoveryCodesHash = null;
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "MFA disabled" });
        }).RequireAuthorization().WithTags("Auth");

        // MFA Recovery Login — use a one-time recovery code instead of TOTP
        app.MapPost("/api/v1/auth/mfa/recovery", async (MfaRecoveryRequest req, OrkunPamDbContext db,
            IJwtTokenService jwt, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group).ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            if (!user.MfaEnabled || string.IsNullOrEmpty(user.RecoveryCodesHash))
                return Results.BadRequest(new { success = false, errors = new[] { "No recovery codes available" } });

            var (valid, remaining) = RecoveryCodeHelper.ValidateAndRemove(user.RecoveryCodesHash, req.Code);
            if (!valid)
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid recovery code" } });

            user.RecoveryCodesHash = remaining;
            await db.SaveChangesAsync();

            // Collect roles and permissions for new token with mfa_verified=true
            var roles = new HashSet<string>();
            var permissions = new HashSet<string>();
            foreach (var ur in user.UserRoles)
            {
                roles.Add(ur.Role.Name);
                foreach (var rp in ur.Role.RolePermissions) permissions.Add(rp.PermissionCode);
            }
            foreach (var ug in user.UserGroups)
                foreach (var gr in ug.Group.GroupRoles)
                {
                    roles.Add(gr.Role.Name);
                    foreach (var rp in gr.Role.RolePermissions) permissions.Add(rp.PermissionCode);
                }

            var tokenResult = jwt.GenerateTokens(
                user.Id, user.Username, user.DisplayName ?? user.Username,
                user.AuthSource.ToString(), roles, permissions, mfaVerified: true);

            if (tokenResult.IsFailure)
                return Results.Problem("Failed to generate tokens");

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = tokenResult.Value.AccessToken,
                    refreshToken = tokenResult.Value.RefreshToken,
                    expiresAt = tokenResult.Value.AccessTokenExpiry,
                    remainingRecoveryCodes = RecoveryCodeHelper.CountRemaining(user.RecoveryCodesHash)
                }
            });
        }).RequireAuthorization().WithTags("Auth").RequireRateLimiting("auth");

        // Self-Service Password Reset: Forgot Password
        group.MapPost("/forgot-password", async (ForgotPasswordRequest req, OrkunPamDbContext db,
            IEmailService email, ILogger<Program> logger) =>
        {
            // Always return OK to prevent user enumeration
            var normalizedUsername = req.Username.Trim().ToUpperInvariant();
            var user = await db.Users.FirstOrDefaultAsync(u =>
                u.NormalizedUsername == normalizedUsername &&
                u.Email != null && u.Email.ToLower() == req.Email.Trim().ToLower());

            if (user != null && user.AuthSource == AuthSource.Local)
            {
                var token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
                user.PasswordResetToken = RecoveryCodeHelper.Sha256Hash(token);
                user.PasswordResetExpiry = DateTime.UtcNow.AddMinutes(30);
                await db.SaveChangesAsync();

                var resetLink = $"/reset-password?token={token}";
                await email.SendAsync(user.Email!,
                    "OrkunPAM - Password Reset",
                    $"<h3>Password Reset Request</h3>" +
                    $"<p>A password reset was requested for your account <strong>{user.Username}</strong>.</p>" +
                    $"<p>Use this link to reset your password (valid for 30 minutes):</p>" +
                    $"<p><a href=\"{resetLink}\">{resetLink}</a></p>" +
                    $"<p>If you did not request this, ignore this email.</p>");

                logger.LogInformation("Password reset token generated for user '{Username}'", user.Username);
            }

            return Results.Ok(new { success = true, message = "If the account exists with that email, a reset link has been sent." });
        }).RequireRateLimiting("auth");

        // Self-Service Password Reset: Reset Password
        group.MapPost("/reset-password", async (ResetPasswordRequest req, OrkunPamDbContext db,
            IPasswordHasher hasher, IPasswordPolicyService policy, IAuditService audit, ILogger<Program> logger) =>
        {
            var tokenHash = RecoveryCodeHelper.Sha256Hash(req.Token);

            var user = await db.Users.FirstOrDefaultAsync(u =>
                u.PasswordResetToken == tokenHash &&
                u.PasswordResetExpiry != null && u.PasswordResetExpiry > DateTime.UtcNow);

            if (user == null)
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid or expired reset token" } });

            var validation = await policy.ValidateAsync(req.NewPassword, user.Id);
            if (validation.IsFailure)
                return Results.BadRequest(new { success = false, errors = new[] { validation.Error.Message } });

            var newHash = hasher.Hash(req.NewPassword);
            user.PasswordHash = newHash;
            user.PasswordLastChanged = DateTime.UtcNow;
            user.PasswordExpiresAt = policy.ComputeExpiry();
            user.MustChangePassword = false;
            user.PasswordResetToken = null;
            user.PasswordResetExpiry = null;
            user.FailedLoginCount = 0;
            user.LockoutEndUtc = null;
            if (user.Status == UserStatus.Locked)
                user.Status = UserStatus.Active;

            await db.SaveChangesAsync();
            await policy.RecordPasswordAsync(user.Id, newHash);

            await audit.LogAsync("Auth", "PASSWORD_RESET_SELF_SERVICE", user.Id, null, "self-service",
                "User", user.Id.ToString(), new { username = user.Username });

            logger.LogInformation("Password reset completed for user '{Username}' via self-service", user.Username);

            return Results.Ok(new { success = true, message = "Password has been reset successfully. You can now log in." });
        }).RequireRateLimiting("auth");

        // My Active Sessions — user can view and end their own sessions
        app.MapGet("/api/v1/auth/my-sessions", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var sessions = await db.ProxySessions
                .Where(s => s.UserId == userId)
                .OrderByDescending(s => s.StartedAtUtc)
                .Take(50)
                .Select(s => new
                {
                    s.Id,
                    Type = s.SessionType.ToString(),
                    s.TargetIpAddress,
                    s.TargetPort,
                    s.StartedAtUtc,
                    DurationMinutes = s.EndedAtUtc.HasValue
                        ? (int)(s.EndedAtUtc.Value - s.StartedAtUtc).TotalMinutes
                        : (int)(DateTime.UtcNow - s.StartedAtUtc).TotalMinutes,
                    Status = s.Status.ToString()
                }).ToListAsync();

            return Results.Ok(new { success = true, data = sessions });
        }).RequireAuthorization().WithTags("Auth");

        // End my own session
        app.MapPost("/api/v1/auth/my-sessions/{id:guid}/end", async (Guid id, OrkunPamDbContext db,
            ILogger<Program> logger, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var session = await db.ProxySessions.FindAsync(id);
            if (session == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (session.UserId != userId)
                return Results.Forbid();

            if (session.Status != SessionStatus.Active)
                return Results.Conflict(new { success = false, errors = new[] { $"Session is not active (status: {session.Status})" } });

            session.Terminate(userId, "Ended by user via self-service");
            await db.SaveChangesAsync();

            logger.LogInformation("Session {SessionId} ended by user {UserId} via self-service", id, userId);

            return Results.Ok(new { success = true, message = "Session ended" });
        }).RequireAuthorization().WithTags("Auth");
    }
}

public record LoginRequest(string Username, string Password);
public record RegisterRequest(string Username, string Password, string? DisplayName, string? Email);
public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public record MfaVerifyRequest(string Code);
public record MfaDisableRequest(string CurrentPassword, string CurrentMfaCode);
public record MfaEnrollmentConfirmRequest(string Token, string Code);
public record MfaRecoveryRequest(string Code);
public record ForgotPasswordRequest(string Username, string Email);
public record ResetPasswordRequest(string Token, string NewPassword);

/// <summary>
/// Helper for generating, hashing, and validating MFA recovery codes.
/// Codes are stored as a JSON array of SHA256 hashes.
/// </summary>
internal static class RecoveryCodeHelper
{
    private const int CodeLength = 8;
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/0/1 for readability

    public static string[] GenerateCodes(int count)
    {
        var codes = new string[count];
        for (int i = 0; i < count; i++)
        {
            var bytes = RandomNumberGenerator.GetBytes(CodeLength);
            var chars = new char[CodeLength];
            for (int j = 0; j < CodeLength; j++)
                chars[j] = Alphabet[bytes[j] % Alphabet.Length];
            codes[i] = new string(chars);
        }
        return codes;
    }

    public static string Sha256Hash(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input.ToUpperInvariant().Trim()));
        return Convert.ToHexString(hash);
    }

    public static string HashCodesToJson(string[] codes)
    {
        var hashed = codes.Select(Sha256Hash).ToArray();
        return JsonSerializer.Serialize(hashed);
    }

    public static (bool Valid, string RemainingJson) ValidateAndRemove(string hashesJson, string code)
    {
        var hashes = JsonSerializer.Deserialize<List<string>>(hashesJson) ?? [];
        var codeHash = Sha256Hash(code);

        var idx = hashes.FindIndex(h =>
            CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(h),
                Encoding.UTF8.GetBytes(codeHash)));

        if (idx < 0) return (false, hashesJson);

        hashes.RemoveAt(idx);
        return (true, JsonSerializer.Serialize(hashes));
    }

    public static int CountRemaining(string? hashesJson)
    {
        if (string.IsNullOrEmpty(hashesJson)) return 0;
        try { return (JsonSerializer.Deserialize<List<string>>(hashesJson) ?? []).Count; }
        catch { return 0; }
    }
}
