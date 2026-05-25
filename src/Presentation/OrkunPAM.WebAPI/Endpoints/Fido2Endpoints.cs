using System.Buffers.Binary;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class Fido2Endpoints
{
    private const string ChallengePrefix = "fido2:";

    public static void MapFido2Endpoints(this IEndpointRouteBuilder app)
    {
        // ── Registration: begin ───────────────────────────────────────────────────────
        // type=cross-platform (hardware key, default) or type=platform (Windows Hello / Touch ID)
        app.MapPost("/api/v1/auth/fido2/register/begin",
            async (OrkunPamDbContext db, IMemoryCache cache, HttpContext ctx,
                   [FromQuery] string? type) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var authenticatorType = type?.ToLowerInvariant() == "platform" ? "platform" : "cross-platform";

            var user = await db.Users.FindAsync(userId.Value);
            if (user == null) return Results.NotFound();

            var existingCreds = await db.Set<Fido2Credential>()
                .Where(c => c.UserId == userId.Value && c.IsActive)
                .Select(c => c.CredentialIdB64)
                .ToListAsync();

            var challenge    = Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            cache.Set($"{ChallengePrefix}reg:{userId}:{authenticatorType}", challenge, TimeSpan.FromMinutes(2));

            var options = new
            {
                rp = new { name = "OrkunPAM", id = ctx.Request.Host.Host },
                user = new
                {
                    id          = Base64UrlEncode(userId.Value.ToByteArray()),
                    name        = user.Username,
                    displayName = user.DisplayName ?? user.Username
                },
                challenge            = challenge,
                pubKeyCredParams     = new[] { new { type = "public-key", alg = -7 } },
                timeout              = 60000,
                attestation          = "none",
                authenticatorSelection = new
                {
                    authenticatorAttachment = authenticatorType,
                    requireResidentKey      = false,
                    userVerification        = authenticatorType == "platform" ? "required" : "preferred"
                },
                excludeCredentials = existingCreds
                    .Select(id => new { type = "public-key", id })
                    .ToArray(),
                authenticatorType    = authenticatorType
            };

            return Results.Ok(new { success = true, data = options });
        }).WithTags("FIDO2").RequireAuthorization();

        // ── Registration: complete ────────────────────────────────────────────────────
        app.MapPost("/api/v1/auth/fido2/register/complete",
            async (OrkunPamDbContext db, IMemoryCache cache, HttpContext ctx,
                   IAuditService audit, [FromBody] Fido2RegisterRequest req) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var authenticatorType = req.AuthenticatorType?.ToLowerInvariant() == "platform" ? "platform" : "cross-platform";
            var cacheKey = $"{ChallengePrefix}reg:{userId}:{authenticatorType}";
            if (!cache.TryGetValue<string>(cacheKey, out var expectedChallenge))
            {
                // fallback: try legacy key without type suffix for backward compat
                var legacyKey = $"{ChallengePrefix}reg:{userId}";
                if (!cache.TryGetValue<string>(legacyKey, out expectedChallenge))
                    return Results.BadRequest(new { success = false, errors = new[] { "Challenge expired" } });
                cache.Remove(legacyKey);
            }
            else
            {
                cache.Remove(cacheKey);
            }

            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip = ctx.Connection.RemoteIpAddress?.ToString();

            try
            {
                var origin = ctx.Request.Scheme + "://" + ctx.Request.Host;
                var rpId   = ctx.Request.Host.Host;

                // Verify clientDataJSON
                var cdBytes   = Base64UrlDecode(req.ClientDataJSON);
                var cdJson    = JsonDocument.Parse(cdBytes);
                if (cdJson.RootElement.GetProperty("type").GetString() != "webauthn.create")
                    return Fail("Invalid type");
                if (cdJson.RootElement.GetProperty("challenge").GetString() != expectedChallenge)
                    return Fail("Challenge mismatch");
                if (!string.Equals(cdJson.RootElement.GetProperty("origin").GetString(), origin, StringComparison.OrdinalIgnoreCase))
                    return Fail("Origin mismatch");

                // Parse attestationObject (CBOR) → get authData bytes
                var attObjBytes = Base64UrlDecode(req.AttestationObject);
                var attObj      = CborHelper.ParseStringMap(attObjBytes);
                if (!attObj.TryGetValue("authData", out var authDataObj) || authDataObj is not byte[] authData)
                    return Fail("Missing authData");

                // Parse authData binary
                if (authData.Length < 37) return Fail("authData too short");

                var rpIdHash = authData.AsSpan(0, 32).ToArray();
                if (!rpIdHash.SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(rpId))))
                    return Fail("RP ID hash mismatch");

                var flags = authData[32];
                if ((flags & 0x01) == 0) return Fail("User Present flag not set");
                if ((flags & 0x40) == 0) return Fail("AT flag not set — no credential data");

                uint signCount = BinaryPrimitives.ReadUInt32BigEndian(authData.AsSpan(33, 4));

                int offset = 37 + 16; // skip AAGUID
                ushort credIdLen = BinaryPrimitives.ReadUInt16BigEndian(authData.AsSpan(offset, 2));
                offset += 2;
                var credId = authData.AsSpan(offset, credIdLen).ToArray();
                offset += credIdLen;

                // Parse COSE key (CBOR)
                var coseKey = CborHelper.ParseIntMap(authData.AsSpan(offset).ToArray());
                if (!coseKey.TryGetValue(1L, out var ktyObj) || ktyObj is not long kty || kty != 2)
                    return Fail("Only EC2 keys supported");
                if (!coseKey.TryGetValue(-2L, out var xObj) || xObj is not byte[] xBytes || xBytes.Length != 32)
                    return Fail("Invalid x coordinate");
                if (!coseKey.TryGetValue(-3L, out var yObj) || yObj is not byte[] yBytes || yBytes.Length != 32)
                    return Fail("Invalid y coordinate");

                var credIdB64 = Base64UrlEncode(credId);
                if (await db.Set<Fido2Credential>().AnyAsync(c => c.CredentialIdB64 == credIdB64))
                    return Results.Conflict(new { success = false, errors = new[] { "Already registered" } });

                var friendlyName = req.FriendlyName
                    ?? (authenticatorType == "platform" ? "Biometric Passkey" : "Security Key");

                var cred = new Fido2Credential
                {
                    UserId            = userId.Value,
                    CredentialIdBytes = credId,
                    CredentialIdB64   = credIdB64,
                    PublicKeyX        = xBytes,
                    PublicKeyY        = yBytes,
                    SignatureCounter  = signCount,
                    FriendlyName      = friendlyName,
                    AuthenticatorType = authenticatorType,
                    RegisteredAtUtc   = DateTime.UtcNow
                };

                db.Set<Fido2Credential>().Add(cred);
                await db.SaveChangesAsync();

                var auditEvent = authenticatorType == "platform"
                    ? "BIOMETRIC_PASSKEY_REGISTERED"
                    : "FIDO2_KEY_REGISTERED";
                _ = audit.LogAsync("MFA", auditEvent, userId.Value, actorName, ip,
                    "Fido2Credential", cred.Id.ToString(), new { friendlyName, authenticatorType });

                return Results.Ok(new { success = true, data = new { cred.Id, authenticatorType } });
            }
            catch (Exception ex)
            {
                return Fail("Verification failed: " + ex.Message);
            }
        }).WithTags("FIDO2").RequireAuthorization();

        // ── Authentication: begin ─────────────────────────────────────────────────────
        app.MapPost("/api/v1/auth/fido2/authenticate/begin",
            async (OrkunPamDbContext db, IMemoryCache cache, HttpContext ctx,
                   [FromBody] Fido2AuthBeginRequest req) =>
        {
            if (string.IsNullOrWhiteSpace(req.Username))
                return Results.BadRequest(new { success = false, errors = new[] { "Username required" } });

            var user = await db.Users
                .FirstOrDefaultAsync(u => u.NormalizedUsername == req.Username.ToUpperInvariant());

            if (user == null)
                return Results.Ok(new { success = true, data = (object?)null });

            var creds = await db.Set<Fido2Credential>()
                .Where(c => c.UserId == user.Id && c.IsActive)
                .Select(c => c.CredentialIdB64)
                .ToListAsync();

            if (creds.Count == 0)
                return Results.Ok(new { success = true, data = (object?)null });

            var challenge = Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            cache.Set($"{ChallengePrefix}auth:{user.Id}", challenge, TimeSpan.FromMinutes(2));

            var options = new
            {
                challenge        = challenge,
                timeout          = 60000,
                rpId             = ctx.Request.Host.Host,
                allowCredentials = creds.Select(id => new { type = "public-key", id }).ToArray(),
                userVerification = "preferred",
                userId           = user.Id.ToString()
            };

            return Results.Ok(new { success = true, data = options });
        }).WithTags("FIDO2").AllowAnonymous();

        // ── Authentication: complete ──────────────────────────────────────────────────
        app.MapPost("/api/v1/auth/fido2/authenticate/complete",
            async (OrkunPamDbContext db, IMemoryCache cache, HttpContext ctx,
                   [FromBody] Fido2AuthCompleteRequest req, IJwtTokenService jwt, IAuditService audit) =>
        {
            if (!Guid.TryParse(req.UserId, out var userId))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid userId" } });

            var cacheKey = $"{ChallengePrefix}auth:{userId}";
            if (!cache.TryGetValue<string>(cacheKey, out var expectedChallenge))
                return Results.BadRequest(new { success = false, errors = new[] { "Challenge expired" } });
            cache.Remove(cacheKey);

            var cred = await db.Set<Fido2Credential>()
                .FirstOrDefaultAsync(c => c.CredentialIdB64 == req.CredentialId
                                       && c.UserId == userId && c.IsActive);
            if (cred == null)
                return Results.BadRequest(new { success = false, errors = new[] { "Credential not found" } });

            try
            {
                var origin = ctx.Request.Scheme + "://" + ctx.Request.Host;
                var rpId   = ctx.Request.Host.Host;

                // Verify clientDataJSON
                var cdBytes = Base64UrlDecode(req.ClientDataJSON);
                var cdJson  = JsonDocument.Parse(cdBytes);
                if (cdJson.RootElement.GetProperty("type").GetString() != "webauthn.get")
                    return Fail("Invalid type");
                if (cdJson.RootElement.GetProperty("challenge").GetString() != expectedChallenge)
                    return Fail("Challenge mismatch");
                if (!string.Equals(cdJson.RootElement.GetProperty("origin").GetString(), origin, StringComparison.OrdinalIgnoreCase))
                    return Fail("Origin mismatch");

                // Verify authenticatorData
                var authData = Base64UrlDecode(req.AuthenticatorData);
                if (authData.Length < 37) return Fail("authData too short");

                var rpIdHash = authData.AsSpan(0, 32).ToArray();
                if (!rpIdHash.SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(rpId))))
                    return Fail("RP ID mismatch");

                if ((authData[32] & 0x01) == 0) return Fail("UP flag not set");

                uint signCount = BinaryPrimitives.ReadUInt32BigEndian(authData.AsSpan(33, 4));
                if (signCount != 0 && signCount <= cred.SignatureCounter)
                    return Fail("Signature counter too low (possible replay)");

                // Verify ECDSA P-256 signature over (authData || SHA-256(clientDataJSON))
                var cdHash     = SHA256.HashData(cdBytes);
                var verifyData = new byte[authData.Length + cdHash.Length];
                authData.CopyTo(verifyData, 0);
                cdHash.CopyTo(verifyData, authData.Length);

                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q     = new ECPoint { X = cred.PublicKeyX, Y = cred.PublicKeyY }
                });

                var sig = Base64UrlDecode(req.Signature);
                if (!ecdsa.VerifyData(verifyData, sig, HashAlgorithmName.SHA256,
                                      DSASignatureFormat.Rfc3279DerSequence))
                    return Fail("Signature verification failed");

                // Update credential state
                cred.SignatureCounter = signCount;
                cred.LastUsedAtUtc   = DateTime.UtcNow;
                var ip = ctx.Connection.RemoteIpAddress?.ToString();

                // Load user + roles + permissions for JWT
                var user = await db.Users
                    .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                    .Include(u => u.UserGroups).ThenInclude(ug => ug.Group).ThenInclude(g => g.GroupRoles)
                        .ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                    .FirstOrDefaultAsync(u => u.Id == userId);
                if (user == null) return Results.NotFound();

                var roles = new HashSet<string>();
                var perms = new HashSet<string>();
                foreach (var ur in user.UserRoles)
                {
                    roles.Add(ur.Role.Name);
                    foreach (var rp in ur.Role.RolePermissions) perms.Add(rp.PermissionCode);
                }
                foreach (var ug in user.UserGroups)
                    foreach (var gr in ug.Group.GroupRoles)
                    {
                        roles.Add(gr.Role.Name);
                        foreach (var rp in gr.Role.RolePermissions) perms.Add(rp.PermissionCode);
                    }

                var tokenResult = jwt.GenerateTokens(
                    user.Id, user.Username, user.DisplayName ?? user.Username,
                    user.AuthSource.ToString(), roles, perms, mfaVerified: true);

                if (tokenResult.IsFailure)
                    return Results.Problem("Failed to generate tokens");

                await db.SaveChangesAsync();

                var authEvent = cred.AuthenticatorType == "platform"
                    ? "BIOMETRIC_AUTH_SUCCESS"
                    : "FIDO2_AUTH_SUCCESS";
                _ = audit.LogAsync("Auth", authEvent, user.Id, user.Username, ip,
                    "Fido2Credential", cred.Id.ToString(), new { authenticatorType = cred.AuthenticatorType });

                return Results.Ok(new
                {
                    success = true,
                    data = new
                    {
                        accessToken    = tokenResult.Value.AccessToken,
                        refreshToken   = tokenResult.Value.RefreshToken,
                        expiresAt      = tokenResult.Value.AccessTokenExpiry,
                        userId         = user.Id,
                        username       = user.Username,
                        displayName    = user.DisplayName ?? user.Username,
                        mfaRequired    = false,
                        mfaEnrollmentRequired = false,
                        mustChangePassword = false,
                        passwordExpired    = false
                    }
                });
            }
            catch (Exception ex)
            {
                _ = audit.LogAsync("Auth", "BIOMETRIC_AUTH_FAILED", userId, null,
                    ctx.Connection.RemoteIpAddress?.ToString(), "Fido2", req.CredentialId, ex.Message);
                return Fail("Verification failed: " + ex.Message);
            }
        }).WithTags("FIDO2").AllowAnonymous();

        // ── List credentials ──────────────────────────────────────────────────────────
        app.MapGet("/api/v1/auth/fido2/credentials",
            async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var creds = await db.Set<Fido2Credential>()
                .Where(c => c.UserId == userId.Value && c.IsActive)
                .OrderByDescending(c => c.RegisteredAtUtc)
                .Select(c => new
                {
                    id                = c.Id,
                    friendlyName      = c.FriendlyName,
                    authenticatorType = c.AuthenticatorType,
                    registeredAt      = c.RegisteredAtUtc,
                    lastUsed          = c.LastUsedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = creds });
        }).WithTags("FIDO2").RequireAuthorization();

        // ── Remove credential ─────────────────────────────────────────────────────────
        app.MapDelete("/api/v1/auth/fido2/credentials/{id:guid}",
            async (OrkunPamDbContext db, HttpContext ctx, Guid id) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var cred = await db.Set<Fido2Credential>()
                .FirstOrDefaultAsync(c => c.Id == id && c.UserId == userId.Value);
            if (cred == null) return Results.NotFound();

            cred.IsActive = false;
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true });
        }).WithTags("FIDO2").RequireAuthorization();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────

    private static Guid? GetUserId(HttpContext ctx)
    {
        var s = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(s, out var id) ? id : null;
    }

    private static IResult Fail(string msg)
        => Results.BadRequest(new { success = false, errors = new[] { msg } });

    internal static string Base64UrlEncode(byte[] data)
        => Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    internal static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s += new string('=', (4 - s.Length % 4) % 4);
        return Convert.FromBase64String(s);
    }
}

// ── Request models ────────────────────────────────────────────────────────────────

public record Fido2RegisterRequest(
    string  ClientDataJSON,
    string  AttestationObject,
    string? FriendlyName,
    string? AuthenticatorType);

public record Fido2AuthBeginRequest(string Username);

public record Fido2AuthCompleteRequest(
    string UserId,
    string CredentialId,
    string ClientDataJSON,
    string AuthenticatorData,
    string Signature);

// ── Minimal CBOR parser (for attestationObject + COSE key) ───────────────────────

internal static class CborHelper
{
    // Parse CBOR map with string keys (e.g. attestationObject)
    public static Dictionary<string, object?> ParseStringMap(byte[] data)
    {
        int offset = 0;
        int count  = ReadMapHeader(data, ref offset);
        var result = new Dictionary<string, object?>(count);
        for (int i = 0; i < count; i++)
        {
            string key = ReadTextString(data, ref offset);
            result[key] = ReadValue(data, ref offset);
        }
        return result;
    }

    // Parse CBOR map with long integer keys (e.g. COSE key)
    public static Dictionary<long, object?> ParseIntMap(byte[] data)
    {
        int offset = 0;
        int count  = ReadMapHeader(data, ref offset);
        var result = new Dictionary<long, object?>(count);
        for (int i = 0; i < count; i++)
        {
            long key = ReadInteger(data, ref offset);
            result[key] = ReadValue(data, ref offset);
        }
        return result;
    }

    private static int ReadMapHeader(byte[] data, ref int offset)
    {
        byte head = data[offset++];
        if ((head >> 5) != 5) throw new InvalidDataException($"CBOR: expected map, got major type {head >> 5}");
        return (int)ReadAdditional(data, head & 0x1f, ref offset);
    }

    private static string ReadTextString(byte[] data, ref int offset)
    {
        byte head = data[offset++];
        if ((head >> 5) != 3) throw new InvalidDataException($"CBOR: expected text string, got major type {head >> 5}");
        long len = ReadAdditional(data, head & 0x1f, ref offset);
        var s = Encoding.UTF8.GetString(data, offset, (int)len);
        offset += (int)len;
        return s;
    }

    private static long ReadInteger(byte[] data, ref int offset)
    {
        byte head = data[offset++];
        int mt = head >> 5;
        if (mt != 0 && mt != 1) throw new InvalidDataException($"CBOR: expected integer, got major type {mt}");
        long v = ReadAdditional(data, head & 0x1f, ref offset);
        return mt == 1 ? -1 - v : v;
    }

    private static object? ReadValue(byte[] data, ref int offset)
    {
        byte head = data[offset++];
        int  mt   = head >> 5;
        int  ai   = head & 0x1f;
        long v    = ReadAdditional(data, ai, ref offset);

        switch (mt)
        {
            case 0: return v;
            case 1: return -1 - v;
            case 2:
            {
                var bytes = new byte[v];
                Buffer.BlockCopy(data, offset, bytes, 0, (int)v);
                offset += (int)v;
                return bytes;
            }
            case 3:
            {
                var s = Encoding.UTF8.GetString(data, offset, (int)v);
                offset += (int)v;
                return s;
            }
            case 4: // array — skip elements
            {
                for (long i = 0; i < v; i++) ReadValue(data, ref offset);
                return null;
            }
            case 5: // nested map — return as string-keyed dict
            {
                var m = new Dictionary<string, object?>((int)v);
                for (long i = 0; i < v; i++)
                {
                    var k   = ReadValue(data, ref offset);
                    var val = ReadValue(data, ref offset);
                    if (k is string ks) m[ks] = val;
                }
                return m;
            }
            default:
                throw new InvalidDataException($"CBOR: unsupported major type {mt}");
        }
    }

    private static long ReadAdditional(byte[] data, int ai, ref int offset)
    {
        if (ai <= 23) return ai;
        if (ai == 24) return data[offset++];
        if (ai == 25) { long v = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset)); offset += 2; return v; }
        if (ai == 26) { long v = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset)); offset += 4; return v; }
        if (ai == 27) { long v = (long)BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset)); offset += 8; return v; }
        throw new InvalidDataException($"CBOR: unsupported additional info {ai}");
    }
}
