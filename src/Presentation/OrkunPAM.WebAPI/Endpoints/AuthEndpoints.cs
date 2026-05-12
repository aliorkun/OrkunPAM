using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Domain.Enums;

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

            user.MfaEnabled = true;
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "MFA enabled successfully" });
        }).RequireAuthorization().WithTags("Auth").RequireRateLimiting("auth");

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
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "MFA disabled" });
        }).RequireAuthorization().WithTags("Auth");
    }
}

public record LoginRequest(string Username, string Password);
public record RegisterRequest(string Username, string Password, string? DisplayName, string? Email);
public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public record MfaVerifyRequest(string Code);
public record MfaDisableRequest(string CurrentPassword, string CurrentMfaCode);
