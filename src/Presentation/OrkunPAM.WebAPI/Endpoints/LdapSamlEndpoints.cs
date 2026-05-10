using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class LdapSamlEndpoints
{
    public static void MapLdapSamlEndpoints(this WebApplication app)
    {
        // === LDAP Configurations ===
        var ldap = app.MapGroup("/api/v1/ldap-configs").WithTags("LDAP");

        ldap.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.LdapConfigurations
                .Select(l => new
                {
                    l.Id, l.Name, l.Host, l.Port, l.UseSsl, l.BaseDn,
                    l.SyncIntervalMinutes, l.LastSyncAtUtc, l.IsEnabled
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        ldap.MapPost("/", async (CreateLdapConfigRequest req, OrkunPamDbContext db) =>
        {
            var config = new LdapConfiguration
            {
                Name = req.Name,
                Host = req.Host,
                Port = req.Port ?? 389,
                UseSsl = req.UseSsl ?? true,
                BaseDn = req.BaseDn,
                BindDn = req.BindDn,
                UserSearchFilter = req.UserSearchFilter ?? "(&(objectClass=user)(sAMAccountName={0}))",
                GroupSearchFilter = req.GroupSearchFilter ?? "(objectClass=group)",
                SyncIntervalMinutes = req.SyncIntervalMinutes ?? 60,
                UserAttributeMapping = req.UserAttributeMapping,
                GroupMapping = req.GroupMapping
            };
            db.LdapConfigurations.Add(config);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/ldap-configs/{config.Id}",
                new { success = true, data = new { config.Id, config.Name, config.Host } });
        });

        ldap.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var l = await db.LdapConfigurations.FindAsync(id);
            if (l == null) return Results.NotFound(new { success = false, errors = new[] { "LDAP config not found" } });
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    l.Id, l.Name, l.Host, l.Port, l.UseSsl, l.BaseDn, l.BindDn,
                    l.UserSearchFilter, l.GroupSearchFilter,
                    l.UserAttributeMapping, l.GroupMapping,
                    l.SyncIntervalMinutes, l.LastSyncAtUtc, l.IsEnabled, l.CreatedAtUtc
                }
            });
        });

        ldap.MapPut("/{id:guid}", async (Guid id, UpdateLdapConfigRequest req, OrkunPamDbContext db) =>
        {
            var l = await db.LdapConfigurations.FindAsync(id);
            if (l == null) return Results.NotFound(new { success = false, errors = new[] { "LDAP config not found" } });

            if (req.Name != null) l.Name = req.Name;
            if (req.Host != null) l.Host = req.Host;
            if (req.Port.HasValue) l.Port = req.Port.Value;
            if (req.BaseDn != null) l.BaseDn = req.BaseDn;
            if (req.BindDn != null) l.BindDn = req.BindDn;
            if (req.UserSearchFilter != null) l.UserSearchFilter = req.UserSearchFilter;
            if (req.GroupMapping != null) l.GroupMapping = req.GroupMapping;
            if (req.SyncIntervalMinutes.HasValue) l.SyncIntervalMinutes = req.SyncIntervalMinutes.Value;
            if (req.IsEnabled.HasValue) l.IsEnabled = req.IsEnabled.Value;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        ldap.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db,
            OrkunPAM.Identity.Services.ILdapService ldapService, ILogger<Program> logger) =>
        {
            var l = await db.LdapConfigurations.FindAsync(id);
            if (l == null) return Results.NotFound(new { success = false, errors = new[] { "LDAP config not found" } });

            logger.LogInformation("Testing LDAP connection to {Host}:{Port}", l.Host, l.Port);

            // Decrypt bind password if stored
            string? bindPassword = null; // Will be decrypted from l.BindPasswordEnc when vault is available

            var result = await ldapService.TestConnectionAsync(l.Host, l.Port, l.UseSsl, l.BindDn, bindPassword, l.BaseDn);

            return Results.Ok(new
            {
                success = result.Success,
                data = new
                {
                    host = l.Host,
                    port = l.Port,
                    status = result.Success ? "connected" : "failed",
                    message = result.Message,
                    responseTimeMs = result.ResponseTimeMs,
                    serverType = result.ServerType
                }
            });
        });

        ldap.MapPost("/{id:guid}/sync", async (Guid id, OrkunPamDbContext db,
            OrkunPAM.Identity.Services.ILdapService ldapService, ILogger<Program> logger) =>
        {
            var l = await db.LdapConfigurations.FindAsync(id);
            if (l == null) return Results.NotFound(new { success = false, errors = new[] { "LDAP config not found" } });

            string? bindPassword = null; // Will be decrypted from l.BindPasswordEnc

            var result = await ldapService.SyncUsersAndGroupsAsync(
                l.Host, l.Port, l.UseSsl, l.BindDn, bindPassword,
                l.BaseDn, l.UserSearchFilter, l.GroupSearchFilter, l.UserAttributeMapping);

            l.LastSyncAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            logger.LogInformation("LDAP sync completed for '{Name}'. Users: {Users}, Groups: {Groups}",
                l.Name, result.UsersFound, result.GroupsFound);

            return Results.Ok(new
            {
                success = result.Success,
                data = new
                {
                    message = result.Message,
                    usersFound = result.UsersFound,
                    groupsFound = result.GroupsFound,
                    lastSync = l.LastSyncAtUtc,
                    users = result.Users.Take(100),
                    groups = result.Groups.Take(100)
                }
            });
        });

        // === SAML Providers ===
        var saml = app.MapGroup("/api/v1/saml-providers").WithTags("SAML");

        saml.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.SamlProviders
                .Select(s => new { s.Id, s.Name, s.EntityId, s.IsEnabled, s.CreatedAtUtc })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        saml.MapPost("/", async (CreateSamlProviderRequest req, OrkunPamDbContext db) =>
        {
            var provider = new SamlProvider
            {
                Name = req.Name,
                EntityId = req.EntityId,
                MetadataUrl = req.MetadataUrl,
                MetadataXml = req.MetadataXml,
                SigningCertThumbprint = req.SigningCertThumbprint,
                AssertionConsumerUrl = req.AssertionConsumerUrl,
                SingleLogoutUrl = req.SingleLogoutUrl,
                AttributeMapping = req.AttributeMapping,
                GroupAttributeName = req.GroupAttributeName,
                GroupMapping = req.GroupMapping
            };
            db.SamlProviders.Add(provider);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/saml-providers/{provider.Id}",
                new { success = true, data = new { provider.Id, provider.Name, provider.EntityId } });
        });

        saml.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var s = await db.SamlProviders.FindAsync(id);
            if (s == null) return Results.NotFound(new { success = false, errors = new[] { "SAML provider not found" } });
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    s.Id, s.Name, s.EntityId, s.MetadataUrl, s.MetadataXml,
                    s.SigningCertThumbprint, s.AssertionConsumerUrl, s.SingleLogoutUrl,
                    s.AttributeMapping, s.GroupAttributeName, s.GroupMapping,
                    s.IsEnabled, s.CreatedAtUtc
                }
            });
        });

        saml.MapPut("/{id:guid}", async (Guid id, UpdateSamlProviderRequest req, OrkunPamDbContext db) =>
        {
            var s = await db.SamlProviders.FindAsync(id);
            if (s == null) return Results.NotFound(new { success = false, errors = new[] { "SAML provider not found" } });

            if (req.Name != null) s.Name = req.Name;
            if (req.MetadataUrl != null) s.MetadataUrl = req.MetadataUrl;
            if (req.MetadataXml != null) s.MetadataXml = req.MetadataXml;
            if (req.AttributeMapping != null) s.AttributeMapping = req.AttributeMapping;
            if (req.GroupMapping != null) s.GroupMapping = req.GroupMapping;
            if (req.IsEnabled.HasValue) s.IsEnabled = req.IsEnabled.Value;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // SAML metadata endpoint (SP metadata for IdP configuration)
        app.MapGet("/saml/metadata", () =>
        {
            var metadata = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
    entityID=""OrkunPAM"">
    <SPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol""
        AuthnRequestsSigned=""true"" WantAssertionsSigned=""true"">
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService index=""0"" isDefault=""true""
            Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
            Location=""/api/v1/auth/saml/acs""/>
    </SPSSODescriptor>
</EntityDescriptor>";

            return Results.Content(metadata, "application/xml");
        }).WithTags("SAML");
    }
}

public record CreateLdapConfigRequest(string Name, string Host, int? Port, bool? UseSsl, string BaseDn,
    string? BindDn, string? UserSearchFilter, string? GroupSearchFilter,
    string? UserAttributeMapping, string? GroupMapping, int? SyncIntervalMinutes);
public record UpdateLdapConfigRequest(string? Name, string? Host, int? Port, string? BaseDn,
    string? BindDn, string? UserSearchFilter, string? GroupMapping, int? SyncIntervalMinutes, bool? IsEnabled);
public record CreateSamlProviderRequest(string Name, string EntityId, string? MetadataUrl, string? MetadataXml,
    string? SigningCertThumbprint, string? AssertionConsumerUrl, string? SingleLogoutUrl,
    string? AttributeMapping, string? GroupAttributeName, string? GroupMapping);
public record UpdateSamlProviderRequest(string? Name, string? MetadataUrl, string? MetadataXml,
    string? AttributeMapping, string? GroupMapping, bool? IsEnabled);
