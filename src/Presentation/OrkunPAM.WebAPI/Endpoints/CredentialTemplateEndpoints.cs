using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CredentialTemplateEndpoints
{
    public static void MapCredentialTemplateEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/vault/credential-templates")
            .WithTags("Vault")
            .RequireAuthorization();

        // GET / — list all templates (all authenticated users)
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var templates = await db.CredentialTemplates
                .OrderBy(t => t.IsBuiltIn ? 0 : 1)
                .ThenBy(t => t.Name)
                .Select(t => new
                {
                    t.Id, t.Name, t.Description, t.DeviceType, t.DefaultUsername,
                    t.CredentialKind, t.RotationPeriodDays, t.PasswordMinLength,
                    t.PasswordRequireSpecial, t.SshKeyRotation, t.Notes, t.IsBuiltIn,
                    t.CreatedAtUtc, t.UpdatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = templates });
        });

        // GET /{id}
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var t = await db.CredentialTemplates.FirstOrDefaultAsync(x => x.Id == id);
            if (t == null) return Results.NotFound(new { success = false, errors = new[] { "Template not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    t.Id, t.Name, t.Description, t.DeviceType, t.DefaultUsername,
                    t.CredentialKind, t.RotationPeriodDays, t.PasswordMinLength,
                    t.PasswordRequireSpecial, t.SshKeyRotation, t.Notes, t.IsBuiltIn,
                    t.CreatedAtUtc, t.UpdatedAtUtc
                }
            });
        });

        // POST / — create custom template (AdminPolicy)
        group.MapPost("/", async (CreateCredentialTemplateRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            if (string.IsNullOrWhiteSpace(req.DeviceType))
                return Results.BadRequest(new { success = false, errors = new[] { "DeviceType is required" } });

            if (await db.CredentialTemplates.AnyAsync(t => t.Name == req.Name.Trim()))
                return Results.Conflict(new { success = false, errors = new[] { "A template with this name already exists" } });

            var template = new CredentialTemplate
            {
                Name                  = req.Name.Trim(),
                Description           = req.Description?.Trim(),
                DeviceType            = req.DeviceType.Trim(),
                DefaultUsername       = req.DefaultUsername?.Trim(),
                CredentialKind        = req.CredentialKind?.Trim() ?? "Linux",
                RotationPeriodDays    = req.RotationPeriodDays ?? 90,
                PasswordMinLength     = req.PasswordMinLength ?? 16,
                PasswordRequireSpecial = req.PasswordRequireSpecial ?? true,
                SshKeyRotation        = req.SshKeyRotation ?? false,
                Notes                 = req.Notes?.Trim(),
                IsBuiltIn             = false
            };

            db.CredentialTemplates.Add(template);
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "CREDENTIAL_TEMPLATE_CREATED", null, actor, "127.0.0.1",
                "CredentialTemplate", template.Id.ToString(),
                new { template.Name, template.DeviceType }, AuditOutcome.Success);

            return Results.Created($"/api/v1/vault/credential-templates/{template.Id}",
                new { success = true, data = new { template.Id } });
        }).RequireAuthorization("AdminPolicy");

        // PUT /{id} — update (AdminPolicy, built-in templates protected)
        group.MapPut("/{id:guid}", async (Guid id, UpdateCredentialTemplateRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var template = await db.CredentialTemplates.FirstOrDefaultAsync(x => x.Id == id);
            if (template == null) return Results.NotFound(new { success = false, errors = new[] { "Template not found" } });

            if (template.IsBuiltIn)
                return Results.BadRequest(new { success = false, errors = new[] { "Built-in templates cannot be modified" } });

            if (!string.IsNullOrWhiteSpace(req.Name))           template.Name            = req.Name.Trim();
            if (!string.IsNullOrWhiteSpace(req.DeviceType))     template.DeviceType      = req.DeviceType.Trim();
            if (!string.IsNullOrWhiteSpace(req.CredentialKind)) template.CredentialKind  = req.CredentialKind.Trim();
            if (req.Description       != null) template.Description           = req.Description.Trim();
            if (req.DefaultUsername   != null) template.DefaultUsername        = req.DefaultUsername.Trim();
            if (req.RotationPeriodDays.HasValue) template.RotationPeriodDays  = req.RotationPeriodDays.Value;
            if (req.PasswordMinLength.HasValue)  template.PasswordMinLength   = req.PasswordMinLength.Value;
            if (req.PasswordRequireSpecial.HasValue) template.PasswordRequireSpecial = req.PasswordRequireSpecial.Value;
            if (req.SshKeyRotation.HasValue)    template.SshKeyRotation       = req.SshKeyRotation.Value;
            if (req.Notes             != null) template.Notes                 = req.Notes.Trim();

            template.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "CREDENTIAL_TEMPLATE_UPDATED", null, actor, "127.0.0.1",
                "CredentialTemplate", id.ToString(), new { template.Name }, AuditOutcome.Success);

            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminPolicy");

        // DELETE /{id} — delete (AdminPolicy, built-in templates protected)
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var template = await db.CredentialTemplates.FirstOrDefaultAsync(x => x.Id == id);
            if (template == null) return Results.NotFound(new { success = false, errors = new[] { "Template not found" } });

            if (template.IsBuiltIn)
                return Results.BadRequest(new { success = false, errors = new[] { "Built-in templates cannot be deleted" } });

            db.CredentialTemplates.Remove(template);
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "CREDENTIAL_TEMPLATE_DELETED", null, actor, "127.0.0.1",
                "CredentialTemplate", id.ToString(), new { template.Name }, AuditOutcome.Success);

            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminPolicy");

        // POST /{id}/apply — create credential from template
        group.MapPost("/{id:guid}/apply", async (
            Guid id,
            ApplyCredentialTemplateRequest req,
            OrkunPamDbContext db,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var template = await db.CredentialTemplates.FirstOrDefaultAsync(x => x.Id == id);
            if (template == null) return Results.NotFound(new { success = false, errors = new[] { "Template not found" } });

            if (req.FolderId == Guid.Empty)
                return Results.BadRequest(new { success = false, errors = new[] { "FolderId is required" } });

            if (!await db.VaultFolders.AnyAsync(f => f.Id == req.FolderId))
                return Results.NotFound(new { success = false, errors = new[] { "Vault folder not found" } });

            var credential = new Credential
            {
                FolderId       = req.FolderId,
                Name           = req.Name?.Trim() ?? $"{template.Name}-{DateTime.UtcNow:yyyyMMddHHmm}",
                Description    = req.Description?.Trim() ?? template.Description,
                CredentialType = MapCredentialKind(template.CredentialKind),
                Username       = req.Username?.Trim() ?? template.DefaultUsername,
            };

            if (template.RotationPeriodDays > 0)
                credential.NextRotationAtUtc = DateTime.UtcNow.AddDays(template.RotationPeriodDays);

            db.Credentials.Add(credential);
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "unknown";
            await audit.LogAsync("Vault", "CREDENTIAL_TEMPLATE_APPLIED", null, actor, "127.0.0.1",
                "Credential", credential.Id.ToString(),
                new { credential.Name, TemplateName = template.Name, TemplateId = id },
                AuditOutcome.Success);

            return Results.Created($"/api/v1/vault/credentials/{credential.Id}",
                new { success = true, data = new { credential.Id, credential.Name } });
        }).RequireAuthorization("AdminPolicy");
    }

    private static CredentialType MapCredentialKind(string kind) => kind switch
    {
        "DB"  => CredentialType.ConnectionString,
        "API" => CredentialType.ApiKey,
        _     => CredentialType.UserPassword
    };
}

internal record CreateCredentialTemplateRequest(
    string  Name,
    string? Description,
    string  DeviceType,
    string? DefaultUsername,
    string? CredentialKind,
    int?    RotationPeriodDays,
    int?    PasswordMinLength,
    bool?   PasswordRequireSpecial,
    bool?   SshKeyRotation,
    string? Notes);

internal record UpdateCredentialTemplateRequest(
    string? Name,
    string? Description,
    string? DeviceType,
    string? DefaultUsername,
    string? CredentialKind,
    int?    RotationPeriodDays,
    int?    PasswordMinLength,
    bool?   PasswordRequireSpecial,
    bool?   SshKeyRotation,
    string? Notes);

internal record ApplyCredentialTemplateRequest(
    Guid    FolderId,
    string? Name,
    string? Description,
    string? Username);
