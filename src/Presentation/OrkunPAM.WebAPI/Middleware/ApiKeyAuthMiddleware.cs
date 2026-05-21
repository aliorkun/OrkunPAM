using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Middleware;

public sealed class ApiKeyAuthMiddleware(RequestDelegate next)
{
    private const int TimestampToleranceSec = 300; // ±5 minutes

    public async Task InvokeAsync(HttpContext context, OrkunPamDbContext db,
        IVaultEncryptionService vault, RsaSecurityKey signingKey,
        IConfiguration config, IMemoryCache cache, IAuditService audit)
    {
        if (!context.Request.Headers.TryGetValue("X-Api-Key", out var apiKeyHeader) ||
            !context.Request.Headers.TryGetValue("X-Timestamp", out var tsHeader) ||
            !context.Request.Headers.TryGetValue("X-Signature", out var sigHeader))
        {
            await next(context);
            return;
        }

        var clientIp = context.Connection.RemoteIpAddress;
        var ipStr    = clientIp?.ToString() ?? "unknown";

        var keyValue = apiKeyHeader.ToString();
        var dotIdx   = keyValue.IndexOf('.');
        if (dotIdx < 1) { await WriteError(context, 401, "Invalid API key format"); return; }

        var prefix = keyValue[..dotIdx];
        var rawKey = keyValue[(dotIdx + 1)..];

        if (!long.TryParse(tsHeader.ToString(), out var timestamp))
        { await WriteError(context, 401, "Invalid timestamp"); return; }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - timestamp) > TimestampToleranceSec)
        { await WriteError(context, 401, "Request timestamp out of range"); return; }

        var signature = sigHeader.ToString();

        // Replay attack protection — nonce cached for 2× tolerance window
        var nonceKey = "apikey-nonce:" + signature;
        if (cache.TryGetValue(nonceKey, out _))
        {
            await audit.LogAsync("ApiKey", "API_KEY_REPLAY_DETECTED", null, null, ipStr,
                "ApiKeyPrefix", prefix, new { prefix }, AuditOutcome.Failure);
            await WriteError(context, 401, "Replay attack detected");
            return;
        }

        var apiKey = await db.ApiKeys
            .Include(k => k.ServiceAccountUser)
                .ThenInclude(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(k => k.Prefix == prefix && k.IsActive, context.RequestAborted);

        if (apiKey == null) { await WriteError(context, 401, "Invalid API key"); return; }

        if (apiKey.ExpiresAtUtc.HasValue && apiKey.ExpiresAtUtc.Value < DateTime.UtcNow)
        {
            await audit.LogAsync("ApiKey", "API_KEY_EXPIRED", apiKey.ServiceAccountUserId, null, ipStr,
                "ApiKey", apiKey.Id.ToString(), new { apiKey.Prefix }, AuditOutcome.Failure);
            await WriteError(context, 401, "API key expired");
            return;
        }

        // Verify key hash (constant-time)
        var rawKeyHash = SHA256.HashData(Encoding.UTF8.GetBytes(rawKey));
        if (!CryptographicOperations.FixedTimeEquals(rawKeyHash, apiKey.KeyHash))
        { await WriteError(context, 401, "Invalid API key"); return; }

        // Decrypt HMAC secret, verify signature, then zero secret bytes immediately (#255)
        var hmacResult = vault.Decrypt(apiKey.HmacSecretEnc);
        if (hmacResult.IsFailure) { await WriteError(context, 500, "Failed to process API key"); return; }

        var hmacSecret = hmacResult.Value;
        var sigOk      = false;
        try
        {
            var payload   = $"{context.Request.Method}\n{context.Request.Path}\n{timestamp}";
            var expectSig = ComputeHmac(hmacSecret, payload);
            try
            {
                var expectedBytes = Convert.FromBase64String(expectSig);
                var providedBytes = Convert.FromBase64String(signature);
                sigOk = CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
            }
            catch { /* bad base64 → sigOk stays false */ }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hmacSecret);
        }

        if (!sigOk)
        {
            await audit.LogAsync("ApiKey", "API_KEY_INVALID_SIGNATURE", apiKey.ServiceAccountUserId, null, ipStr,
                "ApiKey", apiKey.Id.ToString(), new { apiKey.Prefix }, AuditOutcome.Failure);
            await WriteError(context, 401, "Invalid signature");
            return;
        }

        // IP CIDR restriction (#256 audit)
        if (!string.IsNullOrEmpty(apiKey.AllowedIpCidrsJson))
        {
            var cidrs = JsonSerializer.Deserialize<List<string>>(apiKey.AllowedIpCidrsJson) ?? [];
            if (cidrs.Count > 0 && (clientIp == null || !IsIpAllowed(clientIp, cidrs)))
            {
                await audit.LogAsync("ApiKey", "API_KEY_IP_REJECTED", apiKey.ServiceAccountUserId, null, ipStr,
                    "ApiKey", apiKey.Id.ToString(), new { apiKey.Prefix, clientIp = ipStr }, AuditOutcome.Denied);
                await WriteError(context, 403, "IP address not allowed");
                return;
            }
        }

        // Mark nonce used
        cache.Set(nonceKey, true, TimeSpan.FromSeconds(TimestampToleranceSec * 2 + 10));

        // Update usage stats (best-effort, don't fail the request on error)
        try
        {
            apiKey.UsageCount++;
            apiKey.LastUsedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(context.RequestAborted);
        }
        catch { /* non-critical */ }

        // Build short-lived JWT for the service account user
        var user  = apiKey.ServiceAccountUser;
        var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new("apikey_id", apiKey.Id.ToString()),
            new("auth_method", "ApiKey")
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        // Enforce scope restrictions — add scope claim to JWT (#254)
        if (!string.IsNullOrEmpty(apiKey.AllowedScopesJson))
        {
            var scopes = JsonSerializer.Deserialize<List<string>>(apiKey.AllowedScopesJson) ?? [];
            if (scopes.Count > 0)
                claims.Add(new Claim("scope", string.Join(" ", scopes)));
        }

        var issuer   = config["Jwt:Issuer"]   ?? "OrkunPAM";
        var audience = config["Jwt:Audience"] ?? "OrkunPAM";

        var token = new JwtSecurityToken(
            issuer:             issuer,
            audience:           audience,
            claims:             claims,
            expires:            DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        context.Request.Headers.Authorization = "Bearer " + jwt;

        await next(context);
    }

    private static string ComputeHmac(byte[] secret, string payload)
    {
        using var hmac = new HMACSHA256(secret);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload)));
    }

    private static bool IsIpAllowed(IPAddress clientIp, List<string> cidrs)
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

    private static async Task WriteError(HttpContext context, int status, string message)
    {
        context.Response.StatusCode  = status;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(new { success = false, errors = new[] { message } }));
    }
}
