using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class RotationScriptEndpoints
{
    public static void MapRotationScriptEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/vault/rotation-scripts")
            .WithTags("Vault")
            .RequireAuthorization("AdminPolicy");

        // GET / — list all rotation scripts
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var scripts = await db.RotationScripts
                .OrderBy(s => s.Name)
                .Select(s => new
                {
                    s.Id, s.Name, s.Description, s.DeviceType,
                    ScriptType   = s.ScriptType.ToString(),
                    s.IsEnabled,
                    s.CredentialId,
                    s.DeviceGroupId,
                    s.CreatedAtUtc, s.UpdatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = scripts });
        });

        // GET /{id} — single script with content
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var s = await db.RotationScripts.FirstOrDefaultAsync(x => x.Id == id);
            if (s == null) return Results.NotFound(new { success = false, errors = new[] { "Script not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    s.Id, s.Name, s.Description, s.DeviceType,
                    ScriptType        = s.ScriptType.ToString(),
                    s.ScriptContent,
                    s.TestScriptContent,
                    s.IsEnabled,
                    s.CredentialId,
                    s.DeviceGroupId,
                    s.CreatedAtUtc, s.UpdatedAtUtc
                }
            });
        });

        // POST / — create script
        group.MapPost("/", async (CreateRotationScriptRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            if (string.IsNullOrWhiteSpace(req.ScriptContent))
                return Results.BadRequest(new { success = false, errors = new[] { "ScriptContent is required" } });

            if (!Enum.TryParse<RotationScriptType>(req.ScriptType, true, out var scriptType))
                return Results.BadRequest(new { success = false, errors = new[] { "ScriptType must be PowerShell, Bash, or Python" } });

            var script = new RotationScript
            {
                Name              = req.Name.Trim(),
                Description       = req.Description?.Trim(),
                DeviceType        = (req.DeviceType ?? "Custom").Trim(),
                ScriptType        = scriptType,
                ScriptContent     = req.ScriptContent,
                TestScriptContent = req.TestScriptContent,
                IsEnabled         = req.IsEnabled ?? true,
                CredentialId      = req.CredentialId,
                DeviceGroupId     = req.DeviceGroupId
            };

            db.RotationScripts.Add(script);
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "ROTATION_SCRIPT_CREATED", null, actor, "127.0.0.1",
                "RotationScript", script.Id.ToString(),
                new { script.Name, script.DeviceType, script.ScriptType },
                AuditOutcome.Success);

            return Results.Created($"/api/v1/vault/rotation-scripts/{script.Id}", new { success = true, data = new { script.Id } });
        });

        // PUT /{id} — update script
        group.MapPut("/{id:guid}", async (Guid id, UpdateRotationScriptRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var script = await db.RotationScripts.FirstOrDefaultAsync(x => x.Id == id);
            if (script == null) return Results.NotFound(new { success = false, errors = new[] { "Script not found" } });

            if (!string.IsNullOrWhiteSpace(req.Name))           script.Name           = req.Name.Trim();
            if (!string.IsNullOrWhiteSpace(req.DeviceType))     script.DeviceType     = req.DeviceType.Trim();
            if (!string.IsNullOrWhiteSpace(req.ScriptContent))  script.ScriptContent  = req.ScriptContent;
            if (req.Description       != null) script.Description       = req.Description.Trim();
            if (req.TestScriptContent != null) script.TestScriptContent = req.TestScriptContent;
            if (req.IsEnabled         != null) script.IsEnabled         = req.IsEnabled.Value;
            if (req.CredentialId      != null) script.CredentialId      = req.CredentialId;
            if (req.DeviceGroupId     != null) script.DeviceGroupId     = req.DeviceGroupId;

            if (!string.IsNullOrWhiteSpace(req.ScriptType) &&
                Enum.TryParse<RotationScriptType>(req.ScriptType, true, out var st))
                script.ScriptType = st;

            script.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "ROTATION_SCRIPT_UPDATED", null, actor, "127.0.0.1",
                "RotationScript", id.ToString(), new { script.Name }, AuditOutcome.Success);

            return Results.Ok(new { success = true });
        });

        // DELETE /{id}
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var script = await db.RotationScripts.FirstOrDefaultAsync(x => x.Id == id);
            if (script == null) return Results.NotFound(new { success = false, errors = new[] { "Script not found" } });

            await db.Credentials
                .Where(c => c.RotationScriptId == id)
                .ExecuteUpdateAsync(s => s.SetProperty(c => c.RotationScriptId, (Guid?)null));

            db.RotationScripts.Remove(script);
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "ROTATION_SCRIPT_DELETED", null, actor, "127.0.0.1",
                "RotationScript", id.ToString(), new { script.Name }, AuditOutcome.Success);

            return Results.Ok(new { success = true });
        });

        // POST /{id}/test — sandbox test run
        group.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var script = await db.RotationScripts.FirstOrDefaultAsync(x => x.Id == id);
            if (script == null) return Results.NotFound(new { success = false, errors = new[] { "Script not found" } });

            var testContent = string.IsNullOrWhiteSpace(script.TestScriptContent)
                ? script.ScriptContent
                : script.TestScriptContent;

            var result = await RotationScriptRunner.RunAsync(script.ScriptType, testContent, isTest: true);

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault",
                result.Success ? "ROTATION_SCRIPT_TEST_SUCCESS" : "ROTATION_SCRIPT_TEST_FAILED",
                null, actor, "127.0.0.1", "RotationScript", id.ToString(),
                new { script.Name, result.ExitCode },
                result.Success ? AuditOutcome.Success : AuditOutcome.Failure);

            // Redact any credential-like values from test output before returning
            var safeOutput = RedactSensitivePatterns(result.Output);
            var safeError  = RedactSensitivePatterns(result.Error);

            return Results.Ok(new { success = true, data = new { result.Success, result.ExitCode, Output = safeOutput, Error = safeError } });
        });

        // POST /credentials/{credentialId}/rotate-with-script/{scriptId} — manual trigger
        app.MapPost("/api/v1/vault/credentials/{credentialId:guid}/rotate-with-script/{scriptId:guid}",
            async (Guid credentialId, Guid scriptId, OrkunPamDbContext db, IAuditService audit, HttpContext ctx, IVaultEncryptionService vault) =>
        {
            var credential = await db.Credentials
                .Include(c => c.RotationPolicy)
                .FirstOrDefaultAsync(c => c.Id == credentialId);
            if (credential == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var script = await db.RotationScripts.FirstOrDefaultAsync(s => s.Id == scriptId);
            if (script == null)
                return Results.NotFound(new { success = false, errors = new[] { "Script not found" } });

            if (!script.IsEnabled)
                return Results.BadRequest(new { success = false, errors = new[] { "Script is disabled" } });

            var deviceCredential = await db.DeviceCredentials
                .Include(dc => dc.Device)
                .FirstOrDefaultAsync(dc => dc.CredentialId == credentialId);

            var targetIp    = deviceCredential?.Device?.IpAddress ?? deviceCredential?.Device?.Hostname ?? "";
            var newPassword = GeneratePassword();

            var result = await RotationScriptRunner.RunAsync(
                script.ScriptType, script.ScriptContent, isTest: false,
                env: new Dictionary<string, string>
                {
                    ["PAM_TARGET_IP"]        = targetIp,
                    ["PAM_CURRENT_PASSWORD"] = "[REDACTED]",
                    ["PAM_NEW_PASSWORD"]     = newPassword,
                    ["PAM_USERNAME"]         = credential.Username ?? ""
                });

            var actor = ctx.User.Identity?.Name ?? "unknown";

            if (result.Success)
            {
                // Encrypt and persist the new password so the vault stays in sync (#245)
                var encResult = vault.EncryptString(newPassword);
                if (!encResult.IsFailure)
                    credential.PasswordEnc = encResult.Value;

                credential.LastRotatedAtUtc = DateTime.UtcNow;
                credential.RotationScriptId = scriptId;
                await db.SaveChangesAsync();

                await audit.LogAsync("Vault", "ROTATION_SCRIPT_EXECUTED", null, actor, "127.0.0.1",
                    "Credential", credentialId.ToString(),
                    new { credential.Name, ScriptName = script.Name, result.ExitCode },
                    AuditOutcome.Success);

                // Do NOT include script output — it may contain the new password (#246)
                return Results.Ok(new { success = true });
            }
            else
            {
                await audit.LogAsync("Vault", "ROTATION_SCRIPT_FAILED", null, actor, "127.0.0.1",
                    "Credential", credentialId.ToString(),
                    new { credential.Name, ScriptName = script.Name, result.ExitCode, Error = RedactSensitivePatterns(result.Error) },
                    AuditOutcome.Failure);

                return Results.Ok(new { success = false, data = new { Error = RedactSensitivePatterns(result.Error) } });
            }
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");
    }

    // Bias-free password generation using rejection sampling (NIST SP 800-132, CWE-331)
    private static string GeneratePassword()
    {
        const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";
        int limit = 256 - (256 % chars.Length); // 248 — rejects the biased tail
        var result = new char[24];
        int filled = 0;
        while (filled < 24)
        {
            var buf = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(buf);
            foreach (var b in buf)
            {
                if (b >= limit) continue;
                if (filled == 24) break;
                result[filled++] = chars[b % chars.Length];
            }
        }
        return new string(result);
    }

    // Redacts credential-like patterns from script output before returning to caller
    private static string? RedactSensitivePatterns(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        var redacted = System.Text.RegularExpressions.Regex.Replace(
            text,
            @"(?i)(password|pass|pwd|secret|token|key|PAM_NEW_PASSWORD|PAM_CURRENT_PASSWORD)\s*[:=\s']+\s*\S+",
            "$1=[REDACTED]");
        return redacted.Length > 2048 ? redacted[..2048] + "…[truncated]" : redacted;
    }
}

internal record CreateRotationScriptRequest(
    string   Name,
    string?  Description,
    string?  DeviceType,
    string   ScriptType,
    string   ScriptContent,
    string?  TestScriptContent,
    bool?    IsEnabled,
    Guid?    CredentialId,
    Guid?    DeviceGroupId);

internal record UpdateRotationScriptRequest(
    string?  Name,
    string?  Description,
    string?  DeviceType,
    string?  ScriptType,
    string?  ScriptContent,
    string?  TestScriptContent,
    bool?    IsEnabled,
    Guid?    CredentialId,
    Guid?    DeviceGroupId);
