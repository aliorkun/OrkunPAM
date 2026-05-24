using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class HardwareTokenEndpoints
{
    public static void MapHardwareTokenEndpoints(this IEndpointRouteBuilder app)
    {
        // POST /api/v1/auth/hardware-tokens — provision a hardware token (admin only)
        app.MapPost("/api/v1/auth/hardware-tokens", async (
            ProvisionHardwareTokenRequest req,
            OrkunPamDbContext db,
            IVaultEncryptionService vault,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (!Guid.TryParse(req.UserId, out var userId))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid userId" } });

            var user = await db.Users.FindAsync(userId);
            if (user == null)
                return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            if (string.IsNullOrWhiteSpace(req.SerialNumber))
                return Results.BadRequest(new { success = false, errors = new[] { "SerialNumber is required" } });

            if (string.IsNullOrWhiteSpace(req.SecretKeyBase32))
                return Results.BadRequest(new { success = false, errors = new[] { "SecretKeyBase32 is required" } });

            byte[] secretBytes;
            try { secretBytes = OathHelper.Base32Decode(req.SecretKeyBase32.Trim().ToUpperInvariant()); }
            catch { return Results.BadRequest(new { success = false, errors = new[] { "Invalid Base32 secret key" } }); }

            byte[] encryptedSecret;
            try
            {
                var encResult = vault.Encrypt(secretBytes, "HardwareToken");
                if (encResult.IsFailure)
                    return Results.Problem("Failed to protect hardware token secret");
                encryptedSecret = encResult.Value;
            }
            finally { CryptographicOperations.ZeroMemory(secretBytes); }

            if (!Enum.TryParse<HardwareTokenType>(req.TokenType ?? "Totp", true, out var tokenType))
                tokenType = HardwareTokenType.Totp;
            if (!Enum.TryParse<HardwareTokenAlgorithm>(req.Algorithm ?? "Sha1", true, out var algorithm))
                algorithm = HardwareTokenAlgorithm.Sha1;

            var token = new HardwareToken
            {
                UserId       = userId,
                SerialNumber = req.SerialNumber.Trim(),
                SecretKeyEnc = encryptedSecret,
                TokenType    = tokenType,
                Algorithm    = algorithm,
                Digits       = req.Digits is 6 or 8 ? req.Digits : 6,
                PeriodSeconds = req.PeriodSeconds > 0 ? req.PeriodSeconds : 30,
                Label        = req.Label,
                IsActive     = true
            };
            db.HardwareTokens.Add(token);
            await db.SaveChangesAsync();

            await audit.LogAsync("Auth", "HARDWARE_TOKEN_PROVISIONED", adminId, null, ip,
                "HardwareToken", token.Id.ToString(),
                new { token.SerialNumber, token.TokenType, UserId = userId, Username = user.Username });

            return Results.Created($"/api/v1/auth/hardware-tokens/{token.Id}", new
            {
                success = true,
                data    = new
                {
                    token.Id,
                    token.UserId,
                    token.SerialNumber,
                    tokenType  = token.TokenType.ToString(),
                    algorithm  = token.Algorithm.ToString(),
                    token.Digits,
                    token.PeriodSeconds,
                    token.Label,
                    token.IsActive,
                    token.ProvisionedAtUtc
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("HardwareToken");

        // GET /api/v1/auth/hardware-tokens?userId={guid}&all=true — list tokens (admin: all; user: own)
        app.MapGet("/api/v1/auth/hardware-tokens", async (
            string? userId,
            bool? all,
            OrkunPamDbContext db,
            HttpContext ctx) =>
        {
            var callerIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(callerIdStr, out var callerId);

            var isAdmin = ctx.User.HasClaim("role", "Admin") ||
                          ctx.User.IsInRole("Admin") ||
                          ctx.User.HasClaim(ClaimTypes.Role, "Admin");

            IQueryable<HardwareToken> query;
            if (all == true && isAdmin)
            {
                query = db.HardwareTokens;
            }
            else
            {
                Guid targetUserId;
                if (!string.IsNullOrEmpty(userId) && Guid.TryParse(userId, out var parsedUserId))
                    targetUserId = parsedUserId;
                else
                    targetUserId = callerId;

                if (targetUserId != callerId && !isAdmin)
                    return Results.Forbid();

                query = db.HardwareTokens.Where(t => t.UserId == targetUserId);
            }

            var tokens = await query
                .OrderByDescending(t => t.ProvisionedAtUtc)
                .Select(t => new
                {
                    t.Id,
                    t.UserId,
                    t.SerialNumber,
                    TokenType  = t.TokenType.ToString(),
                    Algorithm  = t.Algorithm.ToString(),
                    t.Digits,
                    t.PeriodSeconds,
                    t.Label,
                    t.IsActive,
                    t.ProvisionedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = tokens });
        }).RequireAuthorization().WithTags("HardwareToken");

        // DELETE /api/v1/auth/hardware-tokens/{id} — revoke a hardware token
        app.MapDelete("/api/v1/auth/hardware-tokens/{id:guid}", async (
            Guid id,
            OrkunPamDbContext db,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var callerIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(callerIdStr, out var callerId);
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var token = await db.HardwareTokens.FindAsync(id);
            if (token == null)
                return Results.NotFound(new { success = false, errors = new[] { "Token not found" } });

            var isAdmin = ctx.User.HasClaim("role", "Admin") ||
                          ctx.User.IsInRole("Admin") ||
                          ctx.User.HasClaim(ClaimTypes.Role, "Admin");

            if (token.UserId != callerId && !isAdmin)
                return Results.Forbid();

            token.IsActive = false;
            await db.SaveChangesAsync();

            await audit.LogAsync("Auth", "HARDWARE_TOKEN_REVOKED", callerId, null, ip,
                "HardwareToken", token.Id.ToString(),
                new { token.SerialNumber, token.UserId });

            return Results.Ok(new { success = true, message = "Hardware token revoked" });
        }).RequireAuthorization().WithTags("HardwareToken");

        // POST /api/v1/auth/verify-hardware-otp — verify OTP and return full JWT
        app.MapPost("/api/v1/auth/verify-hardware-otp", async (
            VerifyHardwareOtpRequest req,
            OrkunPamDbContext db,
            IVaultEncryptionService vault,
            IJwtTokenService jwt,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var normalizedUsername = req.Username.Trim().ToUpperInvariant();

            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group)
                    .ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername);

            if (user == null || user.IsLocked || user.Status != OrkunPAM.Domain.Enums.UserStatus.Active)
                return Results.Json(new { success = false, errors = new[] { "Invalid credentials or account locked" } }, statusCode: 401);

            var activeTokens = await db.HardwareTokens
                .Where(t => t.UserId == user.Id && t.IsActive)
                .ToListAsync();

            if (activeTokens.Count == 0)
                return Results.BadRequest(new { success = false, errors = new[] { "No active hardware token found for this account" } });

            bool verified = false;
            HardwareToken? matchedToken = null;
            long newCounter = 0;

            foreach (var hwToken in activeTokens)
            {
                var decResult = vault.Decrypt(hwToken.SecretKeyEnc);
                if (decResult.IsFailure) continue;

                var secret = decResult.Value;
                try
                {
                    if (hwToken.TokenType == HardwareTokenType.Totp)
                    {
                        if (OathHelper.VerifyTotp(secret, req.Otp, hwToken.PeriodSeconds,
                                hwToken.Digits, hwToken.Algorithm))
                        {
                            verified = true;
                            matchedToken = hwToken;
                        }
                    }
                    else
                    {
                        var (valid, updatedCounter) = OathHelper.VerifyHotp(
                            secret, req.Otp, hwToken.CounterValue,
                            hwToken.Digits, hwToken.Algorithm, window: 5);
                        if (valid)
                        {
                            verified = true;
                            matchedToken = hwToken;
                            newCounter = updatedCounter;
                        }
                    }
                }
                finally { CryptographicOperations.ZeroMemory(secret); }

                if (verified) break;
            }

            if (!verified || matchedToken == null)
            {
                await audit.LogAsync("Auth", "HARDWARE_TOKEN_VERIFY_FAILED", user.Id, null, ip,
                    "User", user.Id.ToString(), new { username = user.Username });
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid OTP code" } });
            }

            // Advance HOTP counter
            if (matchedToken.TokenType == HardwareTokenType.Hotp)
            {
                matchedToken.CounterValue = newCounter;
                await db.SaveChangesAsync();
            }

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

            await audit.LogAsync("Auth", "HARDWARE_TOKEN_VERIFIED", user.Id, null, ip,
                "HardwareToken", matchedToken.Id.ToString(),
                new { username = user.Username, matchedToken.SerialNumber });

            return Results.Ok(new
            {
                success = true,
                data    = new
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
        }).AllowAnonymous().WithTags("HardwareToken").RequireRateLimiting("auth");
    }
}

/// <summary>
/// RFC 4226 (HOTP) and RFC 6238 (TOTP) implementation.
/// Secret keys are always passed as byte arrays; callers zero memory after use.
/// </summary>
internal static class OathHelper
{
    internal static string ComputeHotp(byte[] secret, long counter, int digits, HardwareTokenAlgorithm algorithm)
    {
        Span<byte> counterBytes = stackalloc byte[8];
        BitConverter.TryWriteBytes(counterBytes, counter);
        if (BitConverter.IsLittleEndian) counterBytes.Reverse();

        byte[] hash = algorithm switch
        {
            HardwareTokenAlgorithm.Sha256 => HMACSHA256.HashData(secret, counterBytes),
            HardwareTokenAlgorithm.Sha512 => HMACSHA512.HashData(secret, counterBytes),
            _                             => HMACSHA1.HashData(secret, counterBytes)
        };

        var offset = hash[^1] & 0x0F;
        var code = ((hash[offset]     & 0x7F) << 24)
                 | ((hash[offset + 1] & 0xFF) << 16)
                 | ((hash[offset + 2] & 0xFF) << 8)
                 |  (hash[offset + 3] & 0xFF);

        var divisor = (int)Math.Pow(10, digits);
        return (code % divisor).ToString().PadLeft(digits, '0');
    }

    internal static bool VerifyTotp(byte[] secret, string code, int periodSeconds, int digits, HardwareTokenAlgorithm algorithm)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var t = now / periodSeconds;
        var codeBytes = Encoding.UTF8.GetBytes(code);

        for (long step = t - 1; step <= t + 1; step++)
        {
            var expected = Encoding.UTF8.GetBytes(ComputeHotp(secret, step, digits, algorithm));
            if (CryptographicOperations.FixedTimeEquals(expected, codeBytes))
                return true;
        }
        return false;
    }

    internal static (bool Valid, long NewCounter) VerifyHotp(
        byte[] secret, string code, long currentCounter, int digits, HardwareTokenAlgorithm algorithm, int window = 5)
    {
        var codeBytes = Encoding.UTF8.GetBytes(code);
        for (long c = currentCounter; c <= currentCounter + window; c++)
        {
            var expected = Encoding.UTF8.GetBytes(ComputeHotp(secret, c, digits, algorithm));
            if (CryptographicOperations.FixedTimeEquals(expected, codeBytes))
                return (true, c + 1);
        }
        return (false, currentCounter);
    }

    internal static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        input = input.TrimEnd('=');
        var output = new List<byte>();
        int buffer = 0, bitsLeft = 0;

        foreach (var c in input)
        {
            var idx = alphabet.IndexOf(c);
            if (idx < 0) throw new FormatException($"Invalid Base32 character: {c}");
            buffer = (buffer << 5) | idx;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }
        return [.. output];
    }
}

public record ProvisionHardwareTokenRequest(
    string  UserId,
    string  SerialNumber,
    string  SecretKeyBase32,
    string? TokenType,
    string? Algorithm,
    int     Digits,
    int     PeriodSeconds,
    string? Label);

public record VerifyHardwareOtpRequest(string Username, string Otp);
