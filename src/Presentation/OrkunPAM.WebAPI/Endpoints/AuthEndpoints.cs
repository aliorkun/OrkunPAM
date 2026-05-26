using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.SharedKernel;
using OrkunPAM.Domain.Entities.Analytics;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/auth").WithTags("Auth").AllowAnonymous();

        group.MapPost("/login", async (LoginRequest req, IAuthenticationService auth, OrkunPamDbContext db, IVaultEncryptionService? vault, IAuditService audit, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var result = await auth.LoginLocalAsync(req.Username, req.Password, ip);

            if (result.IsFailure)
                return Results.Json(new { success = false, errors = new[] { result.Error.Message } }, statusCode: 401);

            var data = result.Value;

            // Adaptive MFA risk evaluation (#205)
            decimal riskScore = 0;
            string riskLevel = "Low";
            var adaptivePolicy = await AdaptiveMfaHelper.LoadPolicyAsync(db);
            if (adaptivePolicy.Enabled)
            {
                riskScore = await AdaptiveMfaHelper.CalculateLoginRiskAsync(db, vault, data.UserId, ip);
                riskLevel = riskScore >= adaptivePolicy.BlockThreshold      ? "Critical"
                          : riskScore >= adaptivePolicy.HighRiskThreshold   ? "High"
                          : riskScore >= adaptivePolicy.MediumRiskThreshold ? "Medium"
                          : "Low";

                if (riskLevel == "Critical")
                    return Results.Json(new { success = false, errors = new[] { "Login blocked due to anomalous activity. Contact your administrator." } }, statusCode: 403);

                // Force MFA for High-risk logins that don't already require MFA
                if (riskLevel == "High" && !data.MfaRequired && !data.MfaEnrollmentRequired)
                {
                    var userCheck = await db.Users.FindAsync(data.UserId);
                    var forcedType = userCheck?.MfaEnabled == true ? (data.MfaType ?? "Totp") : "EmailOtp";
                    data = data with { MfaRequired = true, MfaType = forcedType };
                }
            }

            // Device Trust check (#207)
            var userAgent = ctx.Request.Headers.UserAgent.ToString();
            var deviceFingerprint = DeviceTrustHelper.ComputeFingerprint(userAgent, ctx);
            var trustedData = await DeviceTrustHelper.ApplyDeviceTrustAsync(db, data, data.UserId, deviceFingerprint, userAgent, ip);
            if (trustedData == null)
                return Results.Json(new { success = false, errors = new[] { "Login blocked: unrecognized device. Contact your administrator." } }, statusCode: 403);
            data = trustedData;

            // Geolocation check (#208)
            var geoData = await GeoLocationHelper.ApplyGeoAccessAsync(db, data, ip);
            if (geoData == null)
                return Results.Json(new { success = false, errors = new[] { "Login blocked: access from your location is not permitted." } }, statusCode: 403);
            data = geoData;

            // MFA Exception check (#259) — approved exceptions bypass MFA step
            if (data.MfaRequired)
            {
                var activeException = await db.MfaExceptions.FirstOrDefaultAsync(e =>
                    e.UserId == data.UserId &&
                    e.Status == MfaExceptionStatus.Approved &&
                    e.ExpiresAtUtc > DateTime.UtcNow &&
                    e.UsageCount < e.MaxUsageCount &&
                    !e.RevokedAtUtc.HasValue);

                if (activeException != null)
                {
                    var ipAllowed = true;
                    if (!string.IsNullOrEmpty(activeException.IpCidrRestriction))
                    {
                        var cidrs = activeException.IpCidrRestriction
                            .Split(',').Select(c => c.Trim())
                            .Where(c => !string.IsNullOrEmpty(c)).ToList();
                        if (cidrs.Count > 0)
                        {
                            if (IPAddress.TryParse(ip, out var clientAddr))
                                ipAllowed = MfaCidrHelper.IsIpAllowed(clientAddr, cidrs);
                            else
                                ipAllowed = false;
                        }
                    }

                    if (ipAllowed)
                    {
                        activeException.UsageCount++;
                        await db.SaveChangesAsync();
                        await audit.LogAsync("Auth", "MFA_EXCEPTION_USED", data.UserId, null, ip,
                            "MfaException", activeException.Id.ToString(), new { data.Username });
                        data = data with { MfaRequired = false };
                    }
                }
            }

            // Trusted Session check (#257) — skip MFA for recognized browsers
            if (data.MfaRequired)
            {
                var trustedSession = await db.MfaTrustedSessions.FirstOrDefaultAsync(s =>
                    s.UserId == data.UserId &&
                    s.BrowserFingerprint == deviceFingerprint &&
                    !s.IsRevoked &&
                    s.TrustExpiresAtUtc > DateTime.UtcNow);
                if (trustedSession != null)
                {
                    trustedSession.LastUsedAtUtc = DateTime.UtcNow;
                    await db.SaveChangesAsync();
                    await audit.LogAsync("Auth", "MFA_SESSION_TRUST_USED", data.UserId, null, ip,
                        "MfaTrustedSession", trustedSession.Id.ToString(), new { data.Username });
                    data = data with { MfaRequired = false };
                }
            }

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
                    mfaType = data.MfaType,
                    mfaEnrollmentRequired = data.MfaEnrollmentRequired,
                    mustChangePassword = data.MustChangePassword,
                    passwordExpired = data.PasswordExpired,
                    portalProfile = data.PortalProfile,
                    riskScore,
                    riskLevel
                }
            });
        }).RequireRateLimiting("auth");

        // GET /api/v1/auth/risk-score — real-time risk score for the authenticated user (#205)
        app.MapGet("/api/v1/auth/risk-score", async (OrkunPamDbContext db, IVaultEncryptionService? vault, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var score = await AdaptiveMfaHelper.CalculateLoginRiskAsync(db, vault, userId, ip);
            var policy = await AdaptiveMfaHelper.LoadPolicyAsync(db);
            var level = score >= policy.BlockThreshold      ? "Critical"
                      : score >= policy.HighRiskThreshold   ? "High"
                      : score >= policy.MediumRiskThreshold ? "Medium"
                      : "Low";

            return Results.Ok(new { success = true, data = new { riskScore = score, riskLevel = level } });
        }).RequireAuthorization().WithTags("Auth");

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
        }).RequireAuthorization("AdminOnly").RequireRateLimiting("auth");

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

            string secret;
            string qrUri;
            // Idempotent: only generate a new secret if one doesn't exist yet
            if (user.MfaSecret == null)
            {
                (secret, qrUri) = totp.GenerateSecret(user.Username);
                var secretBytes = TotpService.Base32Decode(secret);
                try
                {
                    var encResult = vault.Encrypt(secretBytes, "MfaSecret");
                    if (encResult.IsFailure) return Results.Problem("Failed to protect MFA secret");
                    user.MfaSecret = encResult.Value;
                }
                finally { CryptographicOperations.ZeroMemory(secretBytes); }
                await db.SaveChangesAsync();
            }
            else
            {
                var decResult = vault.Decrypt(user.MfaSecret);
                if (decResult.IsFailure) return Results.Problem("Failed to read MFA secret");
                try { (secret, qrUri) = totp.RebuildSecretAndQr(user.Username, decResult.Value); }
                finally { CryptographicOperations.ZeroMemory(decResult.Value); }
            }

            return Results.Ok(new { success = true, data = new { username = user.Username, secret, qrUri } });
        }).AllowAnonymous().WithTags("Auth").RequireRateLimiting("auth");

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
            IJwtTokenService jwt, IAuditService audit, IEmailService email, ILogger<Program> logger,
            HttpContext context) =>
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

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Auth", "MFA_BACKUP_CODE_USED", userId, null, ip,
                "User", userId.ToString(), new { });

            var codesLeft = RecoveryCodeHelper.CountRemaining(user.RecoveryCodesHash);
            if (codesLeft < 3 && !string.IsNullOrEmpty(user.Email))
            {
                try
                {
                    await email.SendAsync(user.Email,
                        "OrkunPAM — MFA Backup Codes Running Low",
                        $"<h3>Backup Codes Warning</h3>" +
                        $"<p>You have only <strong>{codesLeft}</strong> backup code(s) remaining.</p>" +
                        $"<p>Please log in and generate new backup codes from <strong>Self-Service &rarr; Security &rarr; Backup Codes</strong> to avoid being locked out.</p>" +
                        $"<p>If you did not use a backup code, contact your administrator immediately.</p>");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to send backup code low-count warning to user '{Username}'", user.Username);
                }
            }

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
                    remainingRecoveryCodes = codesLeft
                }
            });
        }).RequireAuthorization().WithTags("Auth").RequireRateLimiting("auth");

        // === Backup Codes Management (#289 — MFA #21) ===

        // POST /api/v1/auth/mfa/backup-codes/generate — regenerate 10 codes (invalidates old ones)
        app.MapPost("/api/v1/auth/mfa/backup-codes/generate", async (OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            if (!user.MfaEnabled)
                return Results.BadRequest(new { success = false, errors = new[] { "MFA is not enabled. Enable MFA first to use backup codes." } });

            var codes = RecoveryCodeHelper.GenerateCodes(10);
            user.RecoveryCodesHash = RecoveryCodeHelper.HashCodesToJson(codes);
            user.BackupCodesGeneratedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Auth", "MFA_BACKUP_CODES_GENERATED", userId, null, ip,
                "User", userId.ToString(), new { });

            return Results.Ok(new
            {
                success = true,
                message = "10 new backup codes generated. Store them securely — they will not be shown again.",
                data = new { codes }
            });
        }).RequireAuthorization().WithTags("Auth").RequireRateLimiting("auth");

        // GET /api/v1/auth/mfa/backup-codes/status — remaining count + generation date
        app.MapGet("/api/v1/auth/mfa/backup-codes/status", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    mfaEnabled = user.MfaEnabled,
                    remaining = RecoveryCodeHelper.CountRemaining(user.RecoveryCodesHash),
                    generatedAtUtc = user.BackupCodesGeneratedAtUtc
                }
            });
        }).RequireAuthorization().WithTags("Auth");

        // DELETE /api/v1/admin/users/{userId}/backup-codes — admin emergency revoke all
        app.MapDelete("/api/v1/admin/users/{userId:guid}/backup-codes", async (Guid userId, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);

            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.RecoveryCodesHash = null;
            user.BackupCodesGeneratedAtUtc = null;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Auth", "MFA_BACKUP_CODES_REVOKED_BY_ADMIN", adminId, null, ip,
                "User", userId.ToString(), new { });

            return Results.Ok(new { success = true, message = "All backup codes revoked" });
        }).RequireAuthorization("AdminPolicy").WithTags("Auth");

        // === Email OTP MFA (#178) ===

        // POST /api/v1/auth/email-otp/request — validate credentials, generate & email 6-digit OTP
        app.MapPost("/api/v1/auth/email-otp/request", async (EmailOtpRequestRequest req, OrkunPamDbContext db,
            IPasswordHasher hasher, IEmailService email, ILogger<Program> logger, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var normalizedUsername = req.Username.Trim().ToUpperInvariant();

            var user = await db.Users
                .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername);

            if (user != null &&
                user.Status == UserStatus.Active && !user.IsLocked &&
                user.AuthSource == AuthSource.Local &&
                !string.IsNullOrEmpty(user.PasswordHash) && hasher.Verify(req.Password, user.PasswordHash) &&
                user.MfaType == MfaType.EmailOtp && !string.IsNullOrEmpty(user.Email))
            {
                // Rate limit: max 3 OTP requests per 15 minutes per user
                var recentCount = await db.EmailOtpTokens
                    .CountAsync(t => t.UserId == user.Id &&
                                     t.CreatedAtUtc > DateTime.UtcNow.AddMinutes(-15) &&
                                     !t.IsUsed);

                if (recentCount < 3)
                {
                    // Purge expired/used tokens for this user
                    await db.EmailOtpTokens
                        .Where(t => t.UserId == user.Id &&
                                    (t.ExpiresAtUtc < DateTime.UtcNow || t.IsUsed))
                        .ExecuteDeleteAsync();

                    // CSPRNG 6-digit code (UInt32 avoids overflow with Math.Abs)
                    var codeBytes = new byte[4];
                    System.Security.Cryptography.RandomNumberGenerator.Fill(codeBytes);
                    var code = (BitConverter.ToUInt32(codeBytes, 0) % 1_000_000u).ToString("D6");
                    var hashed = RecoveryCodeHelper.Sha256Hash(code);

                    db.EmailOtpTokens.Add(new EmailOtpToken
                    {
                        UserId          = user.Id,
                        HashedCode      = hashed,
                        ExpiresAtUtc    = DateTime.UtcNow.AddMinutes(10),
                        RequestedFromIp = ip
                    });
                    await db.SaveChangesAsync();

                    try
                    {
                        await email.SendAsync(user.Email,
                            "OrkunPAM — One-Time Verification Code",
                            $"<h3>Your Verification Code</h3>" +
                            $"<p>Your one-time login code is:</p>" +
                            $"<p style=\"font-size:2em;font-weight:bold;letter-spacing:.3em\">{code}</p>" +
                            $"<p>This code expires in <strong>10 minutes</strong> and can only be used once.</p>" +
                            $"<p>If you did not request this, contact your administrator immediately.</p>");
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to send Email OTP to user '{Username}'", user.Username);
                    }

                    logger.LogInformation("Email OTP requested for user '{Username}' (IP: {Ip})", user.Username, ip);
                }
            }

            // Always return success to prevent user enumeration
            return Results.Ok(new { success = true, message = "If your credentials are valid, a code has been sent to your registered email." });
        }).AllowAnonymous().WithTags("Auth").RequireRateLimiting("auth");

        // POST /api/v1/auth/email-otp/verify — validate OTP, return full JWT
        app.MapPost("/api/v1/auth/email-otp/verify", async (EmailOtpVerifyRequest req, OrkunPamDbContext db,
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

            var token = await db.EmailOtpTokens
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
                await audit.LogAsync("Auth", "EMAIL_OTP_VERIFY_FAILED", user.Id, null, ip,
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

            // Device Trust check — #211: Email OTP flow must also enforce device trust policy
            var otpUserAgent = ctx.Request.Headers.UserAgent.ToString();
            var otpFingerprint = DeviceTrustHelper.ComputeFingerprint(otpUserAgent, ctx);
            var otpDtData = new AuthResult(tokenResult.Value, user.Id, user.Username, user.DisplayName,
                MfaRequired: false, MfaType: null, MfaEnrollmentRequired: false,
                MustChangePassword: user.MustChangePassword,
                PasswordExpired: user.PasswordExpiresAt.HasValue && user.PasswordExpiresAt < DateTime.UtcNow,
                PortalProfile: "StandardUser");
            if (await DeviceTrustHelper.ApplyDeviceTrustAsync(db, otpDtData, user.Id, otpFingerprint, otpUserAgent, ip) == null)
                return Results.Json(new { success = false, errors = new[] { "Login blocked: unrecognized device. Contact your administrator." } }, statusCode: 403);

            await audit.LogAsync("Auth", "EMAIL_OTP_VERIFY_SUCCESS", user.Id, null, ip,
                "User", user.Id.ToString(), new { username = user.Username });
            logger.LogInformation("User '{Username}' authenticated via Email OTP (IP: {Ip})", user.Username, ip);

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

        // === Windows/Kerberos SSO (#126) ===
        app.MapGet("/api/v1/auth/windows", async (OrkunPamDbContext db, IJwtTokenService jwt,
            IEventBus eventBus, HttpContext ctx) =>
        {
            var enabledStr = await db.SystemConfigs
                .Where(c => c.Key == "windows.auth.enabled")
                .Select(c => c.Value)
                .FirstOrDefaultAsync();
            if (enabledStr != "true")
                return Results.Json(new { success = false, error = "Windows authentication is not enabled" }, statusCode: 403);

            var windowsName = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(windowsName))
                return Results.Unauthorized();

            var samAccountName = windowsName.Contains('\\')
                ? windowsName.Split('\\')[1].Trim()
                : windowsName.Split('@')[0].Trim();
            var normalizedSam = samAccountName.ToUpperInvariant();

            if (windowsName.Contains('\\'))
            {
                var trustedDomains = await db.SystemConfigs
                    .Where(c => c.Key == "windows.auth.trusted_domains")
                    .Select(c => c.Value)
                    .FirstOrDefaultAsync();
                if (!string.IsNullOrEmpty(trustedDomains))
                {
                    var domain = windowsName.Split('\\')[0].ToUpperInvariant();
                    var allowed = trustedDomains.Split(',')
                        .Select(d => d.Trim().ToUpperInvariant())
                        .Where(d => !string.IsNullOrEmpty(d)).ToList();
                    if (allowed.Count > 0 && !allowed.Contains(domain))
                        return Results.Json(new { success = false, error = $"Domain '{domain}' is not trusted" }, statusCode: 401);
                }
            }

            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group).ThenInclude(g => g.GroupRoles)
                    .ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedSam &&
                    (u.AuthSource == AuthSource.Windows || u.AuthSource == AuthSource.ActiveDirectory));

            if (user == null)
            {
                var autoProvStr = await db.SystemConfigs
                    .Where(c => c.Key == "windows.auth.auto_provision")
                    .Select(c => c.Value)
                    .FirstOrDefaultAsync();
                if (autoProvStr != "true")
                    return Results.Json(new { success = false, error = "User not found; auto-provisioning disabled" }, statusCode: 401);

                var newUser = new User
                {
                    Id = Guid.NewGuid(),
                    Username = samAccountName,
                    NormalizedUsername = normalizedSam,
                    DisplayName = windowsName,
                    AuthSource = AuthSource.Windows,
                    Status = UserStatus.Active
                };
                db.Users.Add(newUser);
                await db.SaveChangesAsync();

                user = await db.Users
                    .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                    .Include(u => u.UserGroups).ThenInclude(ug => ug.Group).ThenInclude(g => g.GroupRoles)
                        .ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                    .FirstAsync(u => u.Id == newUser.Id);
            }

            if (user.Status != UserStatus.Active || user.IsLocked)
                return Results.Json(new { success = false, error = "Account is not active" }, statusCode: 401);

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

            var mfaBypassStr = await db.SystemConfigs
                .Where(c => c.Key == "windows.auth.mfa_bypass")
                .Select(c => c.Value)
                .FirstOrDefaultAsync();
            bool mfaVerified = mfaBypassStr == "true";

            var tokenResult = jwt.GenerateTokens(
                user.Id, user.Username, user.DisplayName ?? user.Username,
                "Windows", roles, permissions, mfaVerified: mfaVerified);
            if (tokenResult.IsFailure)
                return Results.Problem("Failed to generate tokens");

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var winUserAgent = ctx.Request.Headers.UserAgent.ToString();
            var winFingerprint = DeviceTrustHelper.ComputeFingerprint(winUserAgent, ctx);
            var winDtData = new AuthResult(tokenResult.Value, user.Id, user.Username, user.DisplayName,
                MfaRequired: false, MfaType: null, MfaEnrollmentRequired: false,
                MustChangePassword: false, PasswordExpired: false,
                PortalProfile: "StandardUser");
            if (await DeviceTrustHelper.ApplyDeviceTrustAsync(db, winDtData, user.Id, winFingerprint, winUserAgent, ip) == null)
                return Results.Json(new { success = false, errors = new[] { "Login blocked: unrecognized device. Contact your administrator." } }, statusCode: 403);

            await eventBus.PublishAsync(new UserLoggedInEvent
            {
                ActorUserId = user.Id,
                ActorUsername = user.Username,
                ActorIp = ip,
                AuthSource = "Windows"
            });

            user.RecordLoginSuccess(ip);
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = tokenResult.Value.AccessToken,
                    refreshToken = tokenResult.Value.RefreshToken,
                    expiresAt = tokenResult.Value.AccessTokenExpiry,
                    userId = user.Id,
                    username = user.Username,
                    displayName = user.DisplayName,
                    authMethod = "Windows/Kerberos",
                    mfaRequired = !mfaVerified && user.MfaEnabled
                }
            });
        }).RequireAuthorization("WindowsAuth").WithTags("Auth");

        // === My Profile ===
        app.MapGet("/api/v1/auth/me", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Id == userId, context.RequestAborted);
            if (user == null) return Results.NotFound();

            var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    id = user.Id,
                    username = user.Username,
                    displayName = user.DisplayName,
                    email = user.Email,
                    authSource = user.AuthSource.ToString(),
                    status = user.Status.ToString(),
                    mfaEnabled = user.MfaEnabled,
                    mfaType = user.MfaType.ToString(),
                    mustChangePassword = user.MustChangePassword,
                    passwordLastChanged = user.PasswordLastChanged,
                    passwordExpiresAt = user.PasswordExpiresAt,
                    lastLoginAtUtc = user.LastLoginAtUtc,
                    lastLoginIp = user.LastLoginIp,
                    language = user.Language,
                    timezone = user.Timezone,
                    roles
                }
            });
        }).RequireAuthorization().WithTags("Auth");

        // === MFA Trusted Sessions (#257) ===

        // GET /api/v1/auth/mfa-trust-policy — public: max trust hours (0 = disabled)
        app.MapGet("/api/v1/auth/mfa-trust-policy", async (OrkunPamDbContext db) =>
        {
            var maxHoursStr = await db.SystemConfigs
                .Where(c => c.Key == "mfa.trust.max_hours").Select(c => c.Value).FirstOrDefaultAsync();
            var maxHours = int.TryParse(maxHoursStr, out var h) ? h : 0;
            return Results.Ok(new { success = true, data = new { maxHours } });
        }).AllowAnonymous().WithTags("Auth");

        // POST /api/v1/auth/trusted-sessions — register current browser as trusted
        app.MapPost("/api/v1/auth/trusted-sessions", async (TrustSessionRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            // Require MFA to have been completed — pre-MFA tokens must not create trusted sessions (CWE-287 #267)
            var mfaVerified = ctx.User.FindFirstValue("mfa_verified");
            if (mfaVerified != "true")
                return Results.Forbid();

            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var maxHoursStr = await db.SystemConfigs
                .Where(c => c.Key == "mfa.trust.max_hours").Select(c => c.Value).FirstOrDefaultAsync();
            if (!int.TryParse(maxHoursStr, out var maxHours) || maxHours <= 0)
                return Results.BadRequest(new { success = false, errors = new[] { "MFA session trust is not enabled by policy" } });

            var userAgent = ctx.Request.Headers.UserAgent.ToString();
            var fingerprint = DeviceTrustHelper.ComputeFingerprint(userAgent, ctx);

            var existing = await db.MfaTrustedSessions
                .FirstOrDefaultAsync(s => s.UserId == userId && s.BrowserFingerprint == fingerprint && !s.IsRevoked);
            if (existing != null) existing.IsRevoked = true;

            var trustHours = Math.Min(maxHours, 168);
            var label = string.IsNullOrWhiteSpace(req.DeviceLabel) ? "Browser" : req.DeviceLabel[..Math.Min(req.DeviceLabel.Length, 256)];
            var session = new MfaTrustedSession
            {
                UserId = userId,
                BrowserFingerprint = fingerprint,
                DeviceLabel = label,
                TrustExpiresAtUtc = DateTime.UtcNow.AddHours(trustHours),
                GrantedFromIp = ip,
                GrantedAtUtc = DateTime.UtcNow
            };
            db.MfaTrustedSessions.Add(session);
            await db.SaveChangesAsync();

            await audit.LogAsync("Auth", "MFA_SESSION_TRUST_GRANTED", userId, null, ip,
                "MfaTrustedSession", session.Id.ToString(), new { session.DeviceLabel, TrustHours = trustHours });

            return Results.Ok(new { success = true, data = new { session.Id, session.TrustExpiresAtUtc, trustHours } });
        }).RequireAuthorization().WithTags("Auth");

        // GET /api/v1/auth/trusted-sessions — list user's active trusted sessions
        app.MapGet("/api/v1/auth/trusted-sessions", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            var sessions = await db.MfaTrustedSessions
                .Where(s => s.UserId == userId && !s.IsRevoked && s.TrustExpiresAtUtc > DateTime.UtcNow)
                .OrderByDescending(s => s.GrantedAtUtc)
                .Select(s => new { s.Id, s.DeviceLabel, s.TrustExpiresAtUtc, s.GrantedFromIp, s.GrantedAtUtc, s.LastUsedAtUtc })
                .ToListAsync();

            return Results.Ok(new { success = true, data = sessions });
        }).RequireAuthorization().WithTags("Auth");

        // DELETE /api/v1/auth/trusted-sessions/{id} — self-service revoke
        app.MapDelete("/api/v1/auth/trusted-sessions/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            var session = await db.MfaTrustedSessions.FindAsync(id);
            if (session == null || session.UserId != userId)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            session.IsRevoked = true;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Auth", "MFA_SESSION_TRUST_REVOKED", userId, null, ip,
                "MfaTrustedSession", id.ToString(), new { });

            return Results.Ok(new { success = true, message = "Trusted session revoked" });
        }).RequireAuthorization().WithTags("Auth");

        // GET /api/v1/admin/users/{userId}/trusted-sessions — admin view
        app.MapGet("/api/v1/admin/users/{userId:guid}/trusted-sessions", async (Guid userId, OrkunPamDbContext db) =>
        {
            var sessions = await db.MfaTrustedSessions
                .Where(s => s.UserId == userId)
                .OrderByDescending(s => s.GrantedAtUtc)
                .Select(s => new { s.Id, s.DeviceLabel, s.TrustExpiresAtUtc, s.GrantedFromIp, s.GrantedAtUtc, s.LastUsedAtUtc, s.IsRevoked })
                .ToListAsync();
            return Results.Ok(new { success = true, data = sessions });
        }).RequireAuthorization("AdminPolicy").WithTags("Auth");

        // DELETE /api/v1/admin/users/{userId}/trusted-sessions — admin bulk revoke all
        app.MapDelete("/api/v1/admin/users/{userId:guid}/trusted-sessions", async (Guid userId, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var count = await db.MfaTrustedSessions
                .Where(s => s.UserId == userId && !s.IsRevoked)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.IsRevoked, true));

            await audit.LogAsync("Auth", "MFA_SESSION_TRUST_ADMIN_REVOKED_ALL", adminId, null, ip,
                "User", userId.ToString(), new { Count = count });

            return Results.Ok(new { success = true, message = $"{count} trusted sessions revoked" });
        }).RequireAuthorization("AdminPolicy").WithTags("Auth");
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
public record EmailOtpRequestRequest(string Username, string Password);
public record EmailOtpVerifyRequest(string Username, string Code);
public record TrustSessionRequest(string? DeviceLabel);

/// <summary>
/// Adaptive MFA helper: loads policy from DB and calculates real-time login risk score.
/// </summary>
/// <summary>Device Trust helpers for login-time fingerprint evaluation (#207)</summary>
internal static class DeviceTrustHelper
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    internal static string ComputeFingerprint(string userAgent, HttpContext? ctx = null)
    {
        string raw;
        if (ctx != null)
        {
            var acceptLang = ctx.Request.Headers["Accept-Language"].ToString();
            var acceptEnc  = ctx.Request.Headers["Accept-Encoding"].ToString();
            var ip         = ctx.Connection.RemoteIpAddress?.ToString() ?? "";
            // Subnet-level (last octet stripped) to tolerate NAT/proxy IP variation
            var ipSubnet   = ip.Contains('.') ? string.Join('.', ip.Split('.')[..3]) : ip;

            // Server-issued HttpOnly token prevents header-spoofing MFA bypass (CWE-807, CWE-330 #268)
            var fpToken = ctx.Request.Cookies["__pam_fp_token"];
            if (string.IsNullOrEmpty(fpToken))
            {
                fpToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                ctx.Response.Cookies.Append("__pam_fp_token", fpToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(30)
                });
            }

            raw = $"{userAgent.ToLowerInvariant()}|{acceptLang}|{acceptEnc}|{ipSubnet}|{fpToken}";
        }
        else
        {
            raw = userAgent.ToLowerInvariant();
        }
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash)[..32].ToLowerInvariant();
    }

    internal static async Task<DeviceTrustPolicySettings> LoadPolicyAsync(OrkunPamDbContext db)
    {
        var p = await db.Policies.FirstOrDefaultAsync(
            x => x.PolicyType == "DeviceTrust" && x.Scope == PolicyScope.Global);
        if (p?.PolicyJson == null) return new();
        try { return JsonSerializer.Deserialize<DeviceTrustPolicySettings>(p.PolicyJson, JsonOpts) ?? new(); }
        catch { return new(); }
    }

    internal static async Task<AuthResult?> ApplyDeviceTrustAsync(
        OrkunPamDbContext db, AuthResult data, Guid userId, string fingerprint, string userAgent, string ip)
    {
        var policy = await LoadPolicyAsync(db);
        if (!policy.Enabled) return data;

        var device = await db.TrustedDevices
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceFingerprint == fingerprint && !d.IsRevoked);

        if (device != null)
        {
            device.LastSeenAtUtc = DateTime.UtcNow;

            if (policy.MaxTrustAgeDays > 0 &&
                (DateTime.UtcNow - device.RegisteredAtUtc).TotalDays > policy.MaxTrustAgeDays)
                device.TrustLevel = TrustLevel.Unknown;

            await db.SaveChangesAsync();

            if (device.TrustLevel == TrustLevel.Unknown && policy.RequireTrustedDevice)
                return ApplyUnknownDeviceAction(policy, data);

            return data;
        }

        // New device
        if (policy.AutoRegisterOnLogin)
        {
            db.TrustedDevices.Add(new TrustedDevice
            {
                DeviceFingerprint = fingerprint,
                UserId = userId,
                TrustLevel = TrustLevel.UserRegistered,
                UserAgent = userAgent
            });
            await db.SaveChangesAsync();
        }

        if (policy.RequireTrustedDevice)
            return ApplyUnknownDeviceAction(policy, data);

        return data;
    }

    private static AuthResult? ApplyUnknownDeviceAction(DeviceTrustPolicySettings policy, AuthResult data)
    {
        return policy.UnknownDeviceAction switch
        {
            "Block" => null,
            "StepUpAuth" => ForceStepUp(data),
            _ => data
        };
    }

    private static AuthResult ForceStepUp(AuthResult data)
    {
        if (data.MfaRequired || data.MfaEnrollmentRequired) return data;
        var forcedType = data.MfaType ?? "EmailOtp";
        return data with { MfaRequired = true, MfaType = forcedType };
    }
}

/// <summary>Geolocation-based access control helpers for login-time enforcement (#208)</summary>
internal static class GeoLocationHelper
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };
    private static readonly HttpClient GeoClient = new() { Timeout = TimeSpan.FromSeconds(3) };

    private record IpApiResult(string? Status, string? CountryCode);

    internal static async Task<string?> LookupCountryCodeAsync(string ip)
    {
        if (string.IsNullOrEmpty(ip) || ip == "unknown") return null;
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) return null;

        if (System.Net.IPAddress.IsLoopback(addr)) return null;
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            addr.IsIPv6LinkLocal) return null;

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            if (b[0] == 10 ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                (b[0] == 192 && b[1] == 168) ||
                (b[0] == 169 && b[1] == 254))
                return null;
        }

        try
        {
            var json = await GeoClient.GetStringAsync(
                $"https://ip-api.com/json/{Uri.EscapeDataString(ip)}?fields=status,countryCode");
            var r = JsonSerializer.Deserialize<IpApiResult>(json, JsonOpts);
            return r?.Status == "success" ? r.CountryCode : null;
        }
        catch { return null; }
    }

    internal static async Task<GeolocationPolicySettings> LoadPolicyAsync(OrkunPamDbContext db)
    {
        var p = await db.Policies.FirstOrDefaultAsync(
            x => x.PolicyType == "GeoAccess" && x.Scope == PolicyScope.Global);
        if (p?.PolicyJson == null) return new();
        try { return JsonSerializer.Deserialize<GeolocationPolicySettings>(p.PolicyJson, JsonOpts) ?? new(); }
        catch { return new(); }
    }

    internal static async Task<AuthResult?> ApplyGeoAccessAsync(
        OrkunPamDbContext db, AuthResult data, string ip)
    {
        var policy = await LoadPolicyAsync(db);
        if (!policy.Enabled) return data;

        var countryCode = await LookupCountryCodeAsync(ip);

        if (countryCode == null)
            return policy.AllowPrivateIps ? data : ApplyAction(policy.UnknownLocationAction, data);

        if (policy.BlockedCountryCodes.Length > 0 &&
            policy.BlockedCountryCodes.Contains(countryCode, StringComparer.OrdinalIgnoreCase))
            return ApplyAction(policy.ViolationAction, data);

        if (policy.AllowedCountryCodes.Length > 0 &&
            !policy.AllowedCountryCodes.Contains(countryCode, StringComparer.OrdinalIgnoreCase))
            return ApplyAction(policy.ViolationAction, data);

        return data;
    }

    private static AuthResult? ApplyAction(string action, AuthResult data) => action switch
    {
        "Block"      => null,
        "StepUpAuth" => ForceStepUp(data),
        _            => data
    };

    private static AuthResult ForceStepUp(AuthResult data)
    {
        if (data.MfaRequired || data.MfaEnrollmentRequired) return data;
        return data with { MfaRequired = true, MfaType = data.MfaType ?? "EmailOtp" };
    }
}

internal static class AdaptiveMfaHelper
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    internal static async Task<AdaptiveMfaPolicySettings> LoadPolicyAsync(OrkunPamDbContext db)
    {
        var p = await db.Policies.FirstOrDefaultAsync(
            x => x.PolicyType == "AdaptiveMFA" && x.Scope == PolicyScope.Global);
        if (p?.PolicyJson == null) return new();
        try { return JsonSerializer.Deserialize<AdaptiveMfaPolicySettings>(p.PolicyJson, JsonOpts) ?? new(); }
        catch { return new(); }
    }

    internal static async Task<decimal> CalculateLoginRiskAsync(
        OrkunPamDbContext db, IVaultEncryptionService? vault, Guid userId, string loginIp)
    {
        decimal risk = 0;

        var baseline = await db.UserBehaviorBaselines.FirstOrDefaultAsync(b => b.UserId == userId);
        if (baseline != null)
        {
            if (baseline.KnownIpsJson != null)
            {
                var raw = BehaviorBaselineService.DecryptOrDeserialize(vault, baseline.KnownIpsJson);
                var knownIps = raw != null ? JsonSerializer.Deserialize<List<string>>(raw) ?? [] : [];
                if (knownIps.Count > 0 && !knownIps.Contains(loginIp))
                    risk += 30;
            }

            if (baseline.TypicalHoursJson != null)
            {
                var hours = JsonSerializer.Deserialize<List<int>>(baseline.TypicalHoursJson) ?? [];
                if (hours.Count > 0 && !hours.Contains(DateTime.UtcNow.Hour))
                    risk += 20;
            }
        }

        var oneHourAgo = DateTime.UtcNow.AddHours(-1);
        var recentSessions = await db.ProxySessions
            .CountAsync(s => s.UserId == userId && s.StartedAtUtc > oneHourAgo);
        if (recentSessions > 5)
            risk += 25;

        return Math.Min(100, risk);
    }
}

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

internal static class MfaCidrHelper
{
    internal static bool IsIpAllowed(IPAddress clientIp, List<string> cidrs)
    {
        if (clientIp.IsIPv4MappedToIPv6)
            clientIp = clientIp.MapToIPv4();

        foreach (var cidr in cidrs)
        {
            var slash = cidr.IndexOf('/');
            if (slash < 0)
            {
                if (IPAddress.TryParse(cidr, out var single) && single.Equals(clientIp))
                    return true;
                continue;
            }
            if (!int.TryParse(cidr[(slash + 1)..], out var prefixLen) ||
                !IPAddress.TryParse(cidr[..slash], out var network))
                continue;
            if (IsInCidr(clientIp, network, prefixLen))
                return true;
        }
        return false;
    }

    private static bool IsInCidr(IPAddress address, IPAddress network, int prefixLen)
    {
        var addrBytes = address.GetAddressBytes();
        var netBytes  = network.GetAddressBytes();
        if (addrBytes.Length != netBytes.Length) return false;

        var fullBytes = prefixLen / 8;
        var remainder = prefixLen % 8;

        for (var i = 0; i < fullBytes; i++)
            if (addrBytes[i] != netBytes[i]) return false;

        if (remainder > 0)
        {
            var mask = (byte)(0xFF << (8 - remainder));
            if ((addrBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask)) return false;
        }
        return true;
    }
}
