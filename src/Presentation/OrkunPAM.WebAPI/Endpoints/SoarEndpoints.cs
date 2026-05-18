using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

/// <summary>
/// SOAR Integration (#197) — bi-directional: PAM → SOAR event push + SOAR → PAM action API.
/// SOAR configs stored in SystemConfig (key = soar:config:{id}).
/// Inbound actions verified with HMAC-SHA256 (X-Soar-Signature + X-Soar-Timestamp).
/// </summary>
public static class SoarEndpoints
{
    private const string ConfigPrefix = "soar:config:";
    private const int MaxTimestampSkewSeconds = 300; // 5-minute replay window

    public static void MapSoarEndpoints(this IEndpointRouteBuilder app)
    {
        // === SOAR Config Management (AdminPolicy) ===
        var mgmt = app.MapGroup("/api/v1/integrations/soar").WithTags("Integrations").RequireAuthorization("AdminPolicy");

        mgmt.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var configs = await db.SystemConfigs
                .Where(c => c.Key.StartsWith(ConfigPrefix))
                .ToListAsync();

            var result = configs.Select(c => SafeDeserializeSoarConfig(c.Value)).Where(x => x != null).ToList();
            return Results.Ok(new { success = true, data = result });
        });

        mgmt.MapPost("/", async (CreateSoarConfigRequest req, OrkunPamDbContext db) =>
        {
            var id = Guid.NewGuid().ToString("N");
            var configKey = ConfigPrefix + id;
            var config = new
            {
                id,
                req.Name,
                req.Provider,
                req.WebhookUrl,
                req.HmacSecret,
                EventFilter = req.EventFilter ?? new[] { "SessionStarted", "CommandBlocked", "BruteForceDetected" },
                IsEnabled = true,
                CreatedAt = DateTime.UtcNow
            };
            db.SystemConfigs.Add(new SystemConfig
            {
                Key = configKey,
                Value = JsonSerializer.Serialize(config),
                Category = "SoarIntegration",
                UpdatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/soar/{id}",
                new { success = true, data = new { id, req.Name, req.Provider } });
        });

        mgmt.MapPut("/{id}/toggle", async (string id, OrkunPamDbContext db) =>
        {
            var key = ConfigPrefix + id;
            var sc = await db.SystemConfigs.FindAsync(key);
            if (sc == null) return Results.NotFound(new { success = false });

            var cfg = JsonSerializer.Deserialize<JsonElement>(sc.Value ?? "{}");
            var isEnabled = cfg.TryGetProperty("IsEnabled", out var p) && p.GetBoolean();
            var updated = JsonSerializer.Serialize(new
            {
                id,
                Name = cfg.TryGetProperty("Name", out var n) ? n.GetString() : "",
                Provider = cfg.TryGetProperty("Provider", out var pr) ? pr.GetString() : "",
                WebhookUrl = cfg.TryGetProperty("WebhookUrl", out var w) ? w.GetString() : "",
                HmacSecret = cfg.TryGetProperty("HmacSecret", out var h) ? h.GetString() : "",
                EventFilter = cfg.TryGetProperty("EventFilter", out var ef) ? ef : default,
                IsEnabled = !isEnabled,
                CreatedAt = cfg.TryGetProperty("CreatedAt", out var ca) ? ca.GetString() : DateTime.UtcNow.ToString("o")
            });
            sc.Value = updated;
            sc.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { id, isEnabled = !isEnabled } });
        });

        mgmt.MapDelete("/{id}", async (string id, OrkunPamDbContext db) =>
        {
            var key = ConfigPrefix + id;
            var sc = await db.SystemConfigs.FindAsync(key);
            if (sc == null) return Results.NotFound(new { success = false });
            db.SystemConfigs.Remove(sc);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        mgmt.MapPost("/{id}/test", async (string id, OrkunPamDbContext db) =>
        {
            var key = ConfigPrefix + id;
            var sc = await db.SystemConfigs.FindAsync(key);
            if (sc == null) return Results.NotFound(new { success = false, errors = new[] { "Config not found" } });

            var cfg = JsonSerializer.Deserialize<JsonElement>(sc.Value ?? "{}");
            var url = cfg.TryGetProperty("WebhookUrl", out var w) ? w.GetString() : null;

            if (string.IsNullOrEmpty(url))
                return Results.BadRequest(new { success = false, errors = new[] { "No webhook URL configured" } });

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                var payload = JsonSerializer.Serialize(new { eventType = "PAM_SOAR_TEST", timestamp = DateTime.UtcNow });
                var resp = await http.PostAsync(url, new StringContent(payload, Encoding.UTF8, "application/json"));
                return Results.Ok(new { success = resp.IsSuccessStatusCode, data = new { statusCode = (int)resp.StatusCode } });
            }
            catch (Exception ex)
            {
                return Results.Ok(new { success = false, data = new { error = ex.Message } });
            }
        });

        // === Inbound SOAR → PAM Action API (HMAC verified, open endpoint) ===
        var actions = app.MapGroup("/api/v1/integrations/soar").WithTags("Integrations").AllowAnonymous();

        actions.MapPost("/terminate-session", async (SoarTerminateSessionRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            if (!await VerifyHmac(ctx, db)) return Results.Forbid();

            var session = await db.ProxySessions.FindAsync(req.SessionId);
            if (session == null || session.EndedAtUtc.HasValue)
                return Results.NotFound(new { success = false, errors = new[] { "Active session not found" } });

            session.Terminate(Guid.Empty, req.Reason ?? "Terminated by SOAR");
            await db.SaveChangesAsync();
            _ = audit.LogAsync("Integration", "SoarTerminateSession", null, "SOAR", ctx.Connection.RemoteIpAddress?.ToString(),
                "ProxySession", req.SessionId.ToString(), new { req.Reason });

            return Results.Ok(new { success = true, data = new { sessionId = req.SessionId, terminatedAt = DateTime.UtcNow } });
        });

        actions.MapPost("/lock-account", async (SoarLockAccountRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            if (!await VerifyHmac(ctx, db)) return Results.Forbid();

            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username || u.Id == req.UserId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.Status = UserStatus.Locked;
            user.LockoutEndUtc = req.LockoutMinutes.HasValue ? DateTime.UtcNow.AddMinutes(req.LockoutMinutes.Value) : null;
            await db.SaveChangesAsync();
            _ = audit.LogAsync("Integration", "SoarLockAccount", null, "SOAR", ctx.Connection.RemoteIpAddress?.ToString(),
                "User", user.Id.ToString(), new { user.Username, req.LockoutMinutes, req.Reason });

            return Results.Ok(new { success = true, data = new { userId = user.Id, username = user.Username, lockedAt = DateTime.UtcNow } });
        });

        actions.MapPost("/revoke-jit", async (SoarRevokeJitRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            if (!await VerifyHmac(ctx, db)) return Results.Forbid();

            var jit = await db.JitAccessRequests.FindAsync(req.JitRequestId);
            if (jit == null || jit.Status == JitAccessStatus.Revoked)
                return Results.NotFound(new { success = false, errors = new[] { "Active JIT request not found" } });

            jit.Status = JitAccessStatus.Revoked;
            jit.RevokeReason = req.Reason ?? "Revoked by SOAR";
            jit.RevokedByUsername = "SOAR";
            await db.SaveChangesAsync();
            _ = audit.LogAsync("Integration", "SoarRevokeJit", null, "SOAR", ctx.Connection.RemoteIpAddress?.ToString(),
                "JitAccessRequest", req.JitRequestId.ToString(), new { req.Reason });

            return Results.Ok(new { success = true, data = new { jitRequestId = req.JitRequestId, revokedAt = DateTime.UtcNow } });
        });

        actions.MapPost("/rotate-credential", async (SoarRotateCredentialRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            if (!await VerifyHmac(ctx, db)) return Results.Forbid();

            var cred = await db.Credentials.FindAsync(req.CredentialId);
            if (cred == null) return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            // Mark for rotation (actual rotation executed by rotation service scheduled job)
            cred.NextRotationAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
            _ = audit.LogAsync("Integration", "SoarRotateCredential", null, "SOAR", ctx.Connection.RemoteIpAddress?.ToString(),
                "Credential", req.CredentialId.ToString(), new { credentialName = cred.Name, req.Reason });

            return Results.Ok(new { success = true, data = new { credentialId = req.CredentialId, rotationScheduledAt = DateTime.UtcNow } });
        });

        actions.MapGet("/session-details/{sessionId:guid}", async (Guid sessionId,
            OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (!await VerifyHmac(ctx, db)) return Results.Forbid();

            var session = await db.ProxySessions
                .Select(s => new
                {
                    s.Id, Protocol = s.SessionType.ToString(), s.UserId, s.DeviceId,
                    s.StartedAtUtc, s.EndedAtUtc,
                    Status = s.Status.ToString(),
                    s.DurationSeconds, ClientIp = s.ClientIpAddress
                })
                .FirstOrDefaultAsync(s => s.Id == sessionId);

            if (session == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });
            return Results.Ok(new { success = true, data = session });
        });
    }

    private static async Task<bool> VerifyHmac(HttpContext ctx, OrkunPamDbContext db)
    {
        var signature = ctx.Request.Headers["X-Soar-Signature"].FirstOrDefault();
        var timestampStr = ctx.Request.Headers["X-Soar-Timestamp"].FirstOrDefault();
        var configId = ctx.Request.Headers["X-Soar-Config-Id"].FirstOrDefault();

        if (string.IsNullOrEmpty(signature) || string.IsNullOrEmpty(timestampStr) || string.IsNullOrEmpty(configId))
            return false;

        if (!long.TryParse(timestampStr, out var tsUnix)) return false;
        var tsAge = Math.Abs((DateTimeOffset.UtcNow.ToUnixTimeSeconds() - tsUnix));
        if (tsAge > MaxTimestampSkewSeconds) return false;

        var sc = await db.SystemConfigs.FindAsync(ConfigPrefix + configId);
        if (sc?.Value == null) return false;

        var cfg = JsonSerializer.Deserialize<JsonElement>(sc.Value);
        if (!cfg.TryGetProperty("HmacSecret", out var secretEl) || !cfg.TryGetProperty("IsEnabled", out var en) || !en.GetBoolean())
            return false;

        var secret = secretEl.GetString();
        if (string.IsNullOrEmpty(secret)) return false;

        ctx.Request.EnableBuffering();
        using var reader = new System.IO.StreamReader(ctx.Request.Body, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        ctx.Request.Body.Position = 0;

        var expected = "sha256=" + ComputeHmac(secret, timestampStr + "." + body);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(signature));
    }

    private static string ComputeHmac(string secret, string data)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        return Convert.ToHexString(HMACSHA256.HashData(keyBytes, dataBytes)).ToLowerInvariant();
    }

    private static object? SafeDeserializeSoarConfig(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            var doc = JsonSerializer.Deserialize<JsonElement>(json);
            return new
            {
                Id = doc.TryGetProperty("id", out var i) ? i.GetString() : null,
                Name = doc.TryGetProperty("Name", out var n) ? n.GetString() : null,
                Provider = doc.TryGetProperty("Provider", out var p) ? p.GetString() : null,
                WebhookUrl = doc.TryGetProperty("WebhookUrl", out var w) ? w.GetString() : null,
                IsEnabled = doc.TryGetProperty("IsEnabled", out var e) && e.GetBoolean(),
                CreatedAt = doc.TryGetProperty("CreatedAt", out var ca) ? ca.GetString() : null
            };
        }
        catch { return null; }
    }
}

public record CreateSoarConfigRequest(string Name, string Provider, string WebhookUrl, string HmacSecret, string[]? EventFilter);
public record SoarTerminateSessionRequest(Guid SessionId, string? Reason);
public record SoarLockAccountRequest(string? Username, Guid? UserId, int? LockoutMinutes, string? Reason);
public record SoarRevokeJitRequest(Guid JitRequestId, string? Reason);
public record SoarRotateCredentialRequest(Guid CredentialId, string? Reason);
