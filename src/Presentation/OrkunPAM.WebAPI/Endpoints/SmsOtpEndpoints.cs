using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SmsOtpEndpoints
{
    public static void MapSmsOtpEndpoints(this IEndpointRouteBuilder app)
    {
        // === SMS OTP MFA (#215) ===

        // POST /api/v1/auth/sms-otp/request
        app.MapPost("/api/v1/auth/sms-otp/request", async (SmsOtpRequestRequest req, OrkunPamDbContext db,
            IPasswordHasher hasher, ISmsGatewayService sms, ILogger<Program> logger, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var normalizedUsername = req.Username.Trim().ToUpperInvariant();

            var user = await db.Users
                .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername);

            if (user != null &&
                user.Status == UserStatus.Active && !user.IsLocked &&
                user.AuthSource == AuthSource.Local &&
                !string.IsNullOrEmpty(user.PasswordHash) && hasher.Verify(req.Password, user.PasswordHash) &&
                user.MfaType == MfaType.Sms && !string.IsNullOrEmpty(user.Phone))
            {
                var recentCount = await db.SmsOtpTokens
                    .CountAsync(t => t.UserId == user.Id &&
                                     t.CreatedAtUtc > DateTime.UtcNow.AddMinutes(-15) &&
                                     !t.IsUsed);

                if (recentCount < 3)
                {
                    await db.SmsOtpTokens
                        .Where(t => t.UserId == user.Id &&
                                    (t.ExpiresAtUtc < DateTime.UtcNow || t.IsUsed))
                        .ExecuteDeleteAsync();

                    var codeBytes = new byte[4];
                    System.Security.Cryptography.RandomNumberGenerator.Fill(codeBytes);
                    var code = (BitConverter.ToUInt32(codeBytes, 0) % 1_000_000u).ToString("D6");
                    var hashed = RecoveryCodeHelper.Sha256Hash(code);

                    db.SmsOtpTokens.Add(new SmsOtpToken
                    {
                        UserId          = user.Id,
                        HashedCode      = hashed,
                        ExpiresAtUtc    = DateTime.UtcNow.AddMinutes(10),
                        RequestedFromIp = ip
                    });
                    await db.SaveChangesAsync();

                    try
                    {
                        await sms.SendAsync(user.Phone,
                            "OrkunPAM login code: " + code + ". Valid 10 min. Do not share.");
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to send SMS OTP to user '{Username}'", user.Username);
                    }

                    logger.LogInformation("SMS OTP requested for user '{Username}' (IP: {Ip})", user.Username, ip);
                }
            }

            return Results.Ok(new { success = true, message = "If your credentials are valid, a code has been sent to your registered phone number." });
        }).AllowAnonymous().WithTags("Auth").RequireRateLimiting("auth");

        // POST /api/v1/auth/sms-otp/verify
        app.MapPost("/api/v1/auth/sms-otp/verify", async (SmsOtpVerifyRequest req, OrkunPamDbContext db,
            IJwtTokenService jwt, IAuditService audit, ILogger<Program> logger, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var normalizedUsername = req.Username.Trim().ToUpperInvariant();

            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group)
                    .ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername);

            if (user == null || user.IsLocked || user.Status != UserStatus.Active)
                return Results.Json(new { success = false, errors = new[] { "Invalid credentials or account locked" } }, statusCode: 401);

            var token = await db.SmsOtpTokens
                .Where(t => t.UserId == user.Id && !t.IsUsed && t.ExpiresAtUtc > DateTime.UtcNow)
                .OrderByDescending(t => t.CreatedAtUtc)
                .FirstOrDefaultAsync();

            if (token == null)
                return Results.BadRequest(new { success = false, errors = new[] { "No active OTP found. Request a new code." } });

            var inputHash = RecoveryCodeHelper.Sha256Hash(req.Code);
            var match = System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(token.HashedCode),
                System.Text.Encoding.UTF8.GetBytes(inputHash));

            if (!match)
            {
                token.FailedAttempts++;
                if (token.FailedAttempts >= 5)
                {
                    token.IsUsed = true;
                    user.RecordLoginFailure(5, 30);
                }
                await db.SaveChangesAsync();
                await audit.LogAsync("Auth", "SMS_OTP_VERIFY_FAILED", user.Id, null, ip,
                    "User", user.Id.ToString(), new { username = user.Username });
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid code. Please try again." } });
            }

            token.IsUsed = true;
            user.RecordLoginSuccess(ip);
            await db.SaveChangesAsync();

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

            await audit.LogAsync("Auth", "SMS_OTP_VERIFY_SUCCESS", user.Id, null, ip,
                "User", user.Id.ToString(), new { username = user.Username });
            logger.LogInformation("User '{Username}' authenticated via SMS OTP (IP: {Ip})", user.Username, ip);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken  = tokenResult.Value.AccessToken,
                    refreshToken = tokenResult.Value.RefreshToken,
                    expiresAt    = tokenResult.Value.AccessTokenExpiry,
                    userId       = user.Id,
                    username     = user.Username,
                    displayName  = user.DisplayName,
                    mfaRequired  = false,
                    mfaEnrollmentRequired = false,
                    mustChangePassword = user.MustChangePassword,
                    passwordExpired = user.PasswordExpiresAt.HasValue && user.PasswordExpiresAt < DateTime.UtcNow
                }
            });
        }).AllowAnonymous().WithTags("Auth").RequireRateLimiting("auth");

        // GET /api/v1/admin/sms-gateway/config
        app.MapGet("/api/v1/admin/sms-gateway/config", async (OrkunPamDbContext db) =>
        {
            var rows = await db.SystemConfigs
                .Where(c => c.Category == "sms")
                .ToListAsync();

            var dict = rows.ToDictionary(r => r.Key, r => r.Value ?? "");
            string Get(string key) => dict.TryGetValue(key, out var v) ? v : "";

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    provider         = Get("sms.provider"),
                    accountSid       = Get("sms.account_sid"),
                    fromNumber       = Get("sms.from_number"),
                    webhookUrl       = Get("sms.webhook_url"),
                    netgsmUser       = Get("sms.netgsm_user"),
                    netgsmOriginator = Get("sms.netgsm_originator"),
                    authTokenSet     = !string.IsNullOrEmpty(Get("sms.auth_token")),
                    webhookSecretSet = !string.IsNullOrEmpty(Get("sms.webhook_secret")),
                    netgsmPasswordSet = !string.IsNullOrEmpty(Get("sms.netgsm_password"))
                }
            });
        }).RequireAuthorization("GlobalAdmin").WithTags("Admin");

        // POST /api/v1/admin/sms-gateway/config
        app.MapPost("/api/v1/admin/sms-gateway/config", async (SmsGatewayConfigRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, IAuditService audit, ICurrentUserService currentUser) =>
        {
            async Task Upsert(string key, string value)
            {
                var row = await db.SystemConfigs.FirstOrDefaultAsync(c => c.Key == key);
                if (row == null) { row = new SystemConfig { Category = "sms", Key = key }; db.SystemConfigs.Add(row); }
                row.Value = value;
            }

            await Upsert("sms.provider", req.Provider ?? "");
            await Upsert("sms.account_sid", req.AccountSid ?? "");
            await Upsert("sms.from_number", req.FromNumber ?? "");
            await Upsert("sms.webhook_url", req.WebhookUrl ?? "");
            await Upsert("sms.netgsm_user", req.NetgsmUser ?? "");
            await Upsert("sms.netgsm_originator", req.NetgsmOriginator ?? "");

            if (!string.IsNullOrEmpty(req.AuthToken))
                await Upsert("sms.auth_token", "enc:" + vault.Encrypt(req.AuthToken));
            if (!string.IsNullOrEmpty(req.WebhookSecret))
                await Upsert("sms.webhook_secret", "enc:" + vault.Encrypt(req.WebhookSecret));
            if (!string.IsNullOrEmpty(req.NetgsmPassword))
                await Upsert("sms.netgsm_password", "enc:" + vault.Encrypt(req.NetgsmPassword));

            await db.SaveChangesAsync();

            if (currentUser.UserId.HasValue)
                await audit.LogAsync("Admin", "SMS_GATEWAY_CONFIG_SAVED", currentUser.UserId.Value, null,
                    currentUser.IpAddress ?? "", "SmsConfig", "sms", new { provider = req.Provider });

            return Results.Ok(new { success = true });
        }).RequireAuthorization("GlobalAdmin").WithTags("Admin");
    }
}

internal record SmsOtpRequestRequest(string Username, string Password);
internal record SmsOtpVerifyRequest(string Username, string Code);
internal record SmsGatewayConfigRequest(
    string? Provider,
    string? AccountSid,
    string? AuthToken,
    string? FromNumber,
    string? WebhookUrl,
    string? WebhookSecret,
    string? NetgsmUser,
    string? NetgsmPassword,
    string? NetgsmOriginator);
