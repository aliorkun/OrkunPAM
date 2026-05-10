using Microsoft.EntityFrameworkCore;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
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
                    mfaRequired = data.MfaRequired
                }
            });
        });

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

        // MFA Setup
        group.MapPost("/mfa/setup", async (MfaSetupRequest req, OrkunPamDbContext db, ITotpService totp) =>
        {
            var user = await db.Users.FindAsync(req.UserId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var (secret, qrUri) = totp.GenerateSecret(user.Username);
            var secretBytes = TotpService.Base32Decode(secret);

            // Store secret temporarily (user must verify before enabling)
            user.MfaSecret = secretBytes;
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new { secret, qrUri, message = "Scan QR code with authenticator app, then call /mfa/verify to enable" }
            });
        });

        // MFA Verify & Enable
        group.MapPost("/mfa/verify", async (MfaVerifyRequest req, OrkunPamDbContext db, ITotpService totp) =>
        {
            var user = await db.Users.FindAsync(req.UserId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
            if (user.MfaSecret == null) return Results.BadRequest(new { success = false, errors = new[] { "MFA not set up. Call /mfa/setup first" } });

            if (!totp.ValidateCode(user.MfaSecret, req.Code))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid TOTP code. Check your authenticator app." } });

            user.MfaEnabled = true;
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "MFA enabled successfully" });
        });

        // MFA Disable
        group.MapPost("/mfa/disable", async (MfaDisableRequest req, OrkunPamDbContext db) =>
        {
            var user = await db.Users.FindAsync(req.UserId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.MfaEnabled = false;
            user.MfaSecret = null;
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "MFA disabled" });
        });
    }
}

public record LoginRequest(string Username, string Password);
public record RegisterRequest(string Username, string Password, string? DisplayName, string? Email);
public record MfaSetupRequest(Guid UserId);
public record MfaVerifyRequest(Guid UserId, string Code);
public record MfaDisableRequest(Guid UserId);
