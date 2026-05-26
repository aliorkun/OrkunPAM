using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

// SCIM 2.0 RFC 7643/7644 — User Provisioning (Azure AD / Okta / Ping Identity)
public static class ScimEndpoints
{
    private const string UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User";
    private const string GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private const string ListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    private const string PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";
    private const string ContentType = "application/scim+json";

    public static void MapScimEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Admin: SCIM Token Management (JWT auth, AdminPolicy) ──────────────────
        var mgmt = app.MapGroup("/api/v1/system/scim-tokens").WithTags("SCIM")
            .RequireAuthorization("AdminPolicy");

        mgmt.MapGet("/", ListTokensAsync);
        mgmt.MapPost("/", CreateTokenAsync);
        mgmt.MapDelete("/{id:guid}", RevokeTokenAsync);
        mgmt.MapGet("/log", GetProvisioningLogAsync);

        // ── SCIM Discovery (no auth per RFC 7644 §11.3) ──────────────────────────
        app.MapGet("/scim/v2/ServiceProviderConfig", ServiceProviderConfigAsync)
            .WithTags("SCIM").AllowAnonymous();

        app.MapGet("/scim/v2/Schemas", SchemasAsync)
            .WithTags("SCIM").AllowAnonymous();

        app.MapGet("/scim/v2/ResourceTypes", ResourceTypesAsync)
            .WithTags("SCIM").AllowAnonymous();

        // ── SCIM Users ────────────────────────────────────────────────────────────
        app.MapGet("/scim/v2/Users",             ScimListUsersAsync).WithTags("SCIM").AllowAnonymous();
        app.MapGet("/scim/v2/Users/{id}",        ScimGetUserAsync).WithTags("SCIM").AllowAnonymous();
        app.MapPost("/scim/v2/Users",            ScimCreateUserAsync).WithTags("SCIM").AllowAnonymous();
        app.MapPut("/scim/v2/Users/{id}",        ScimReplaceUserAsync).WithTags("SCIM").AllowAnonymous();
        app.MapMethods("/scim/v2/Users/{id}", ["PATCH"], ScimPatchUserAsync).WithTags("SCIM").AllowAnonymous();
        app.MapDelete("/scim/v2/Users/{id}",     ScimDeleteUserAsync).WithTags("SCIM").AllowAnonymous();

        // ── SCIM Groups ───────────────────────────────────────────────────────────
        app.MapGet("/scim/v2/Groups",            ScimListGroupsAsync).WithTags("SCIM").AllowAnonymous();
        app.MapGet("/scim/v2/Groups/{id}",       ScimGetGroupAsync).WithTags("SCIM").AllowAnonymous();
        app.MapPost("/scim/v2/Groups",           ScimCreateGroupAsync).WithTags("SCIM").AllowAnonymous();
        app.MapMethods("/scim/v2/Groups/{id}", ["PATCH"], ScimPatchGroupAsync).WithTags("SCIM").AllowAnonymous();
        app.MapDelete("/scim/v2/Groups/{id}",    ScimDeleteGroupAsync).WithTags("SCIM").AllowAnonymous();
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Admin: Token Management
    // ════════════════════════════════════════════════════════════════════════════

    static async Task<IResult> ListTokensAsync(OrkunPamDbContext db, ClaimsPrincipal user)
    {
        var tokens = await db.ScimTokens
            .OrderByDescending(t => t.CreatedAtUtc)
            .Select(t => new
            {
                t.Id,
                t.Name,
                t.TokenPrefix,
                t.IsActive,
                t.CreatedAtUtc,
                t.ExpiresAtUtc,
                t.LastUsedAtUtc
            }).ToListAsync();

        return Results.Ok(new { success = true, data = tokens });
    }

    static async Task<IResult> CreateTokenAsync(
        HttpContext ctx, OrkunPamDbContext db,
        IAuditService audit, ClaimsPrincipal user)
    {
        using var body = await JsonDocument.ParseAsync(ctx.Request.Body);
        var name     = body.RootElement.TryGetProperty("name",     out var nProp) ? nProp.GetString() ?? "SCIM Token" : "SCIM Token";
        DateTime? exp = null;
        if (body.RootElement.TryGetProperty("expiresInDays", out var expProp) && expProp.TryGetInt32(out var days) && days > 0)
            exp = DateTime.UtcNow.AddDays(days);

        var raw    = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var hash   = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        var prefix = raw[..Math.Min(8, raw.Length)];

        var actorId = user.FindFirstValue(ClaimTypes.NameIdentifier);
        Guid? actorGuid = Guid.TryParse(actorId, out var g) ? g : null;

        var token = new ScimToken
        {
            Name            = name,
            TokenHash       = hash,
            TokenPrefix     = prefix,
            IsActive        = true,
            ExpiresAtUtc    = exp,
            CreatedByUserId = actorGuid
        };
        db.ScimTokens.Add(token);
        await db.SaveChangesAsync();

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("ScimToken", "SCIM_TOKEN_CREATED", actorGuid, null, ip,
            "ScimToken", token.Id.ToString(), new { token.Name, token.TokenPrefix });

        return Results.Ok(new
        {
            success = true,
            data    = new { token.Id, token.Name, token.TokenPrefix, token.ExpiresAtUtc, rawToken = raw }
        });
    }

    static async Task<IResult> RevokeTokenAsync(
        Guid id, OrkunPamDbContext db,
        IAuditService audit, ClaimsPrincipal user, HttpContext ctx)
    {
        var token = await db.ScimTokens.FindAsync(id);
        if (token == null) return Results.NotFound(new { success = false, errors = new[] { "Token not found" } });

        token.IsActive = false;
        await db.SaveChangesAsync();

        var actorId = user.FindFirstValue(ClaimTypes.NameIdentifier);
        Guid? actorGuid = Guid.TryParse(actorId, out var g) ? g : null;
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("ScimToken", "SCIM_TOKEN_REVOKED", actorGuid, null, ip,
            "ScimToken", id.ToString(), new { token.Name });

        return Results.Ok(new { success = true });
    }

    static async Task<IResult> GetProvisioningLogAsync(OrkunPamDbContext db)
    {
        var logs = await db.AuditLogs
            .Where(a => a.EventType.StartsWith("SCIM_"))
            .OrderByDescending(a => a.Timestamp)
            .Take(100)
            .Select(a => new
            {
                a.Id,
                a.EventType,
                ActorId        = a.ActorUserId,
                a.ActorUsername,
                a.TargetId,
                OccurredAtUtc  = a.Timestamp,
                IpAddress      = a.ActorIpAddress
            }).ToListAsync();

        return Results.Ok(new { success = true, data = logs });
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SCIM Discovery
    // ════════════════════════════════════════════════════════════════════════════

    static IResult ServiceProviderConfigAsync()
    {
        var config = new
        {
            schemas = new[] { "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig" },
            documentationUri = "https://tools.ietf.org/html/rfc7644",
            patch         = new { supported = true },
            bulk          = new { supported = false, maxOperations = 0, maxPayloadSize = 0 },
            filter        = new { supported = true, maxResults = 200 },
            changePassword = new { supported = false },
            sort          = new { supported = false },
            etag          = new { supported = false },
            authenticationSchemes = new[]
            {
                new
                {
                    type        = "oauthbearertoken",
                    name        = "OAuth Bearer Token",
                    description = "Authentication using Bearer token generated in Integrations → SCIM"
                }
            },
            meta = new
            {
                resourceType  = "ServiceProviderConfig",
                created       = "2026-05-26T00:00:00Z",
                lastModified  = "2026-05-26T00:00:00Z",
                location      = "/scim/v2/ServiceProviderConfig"
            }
        };
        return ScimOk(config);
    }

    static IResult SchemasAsync()
    {
        var userSchema = new
        {
            id       = UserSchema,
            name     = "User",
            description = "User Account",
            attributes = new object[]
            {
                new { name = "userName",    type = "string",  required = true,  multiValued = false },
                new { name = "displayName", type = "string",  required = false, multiValued = false },
                new { name = "active",      type = "boolean", required = false, multiValued = false },
                new { name = "emails",      type = "complex", required = false, multiValued = true  },
                new { name = "name",        type = "complex", required = false, multiValued = false },
                new { name = "externalId",  type = "string",  required = false, multiValued = false }
            },
            meta = new { resourceType = "Schema", location = "/scim/v2/Schemas/" + UserSchema }
        };
        var groupSchema = new
        {
            id       = GroupSchema,
            name     = "Group",
            description = "Group",
            attributes = new object[]
            {
                new { name = "displayName", type = "string",  required = true,  multiValued = false },
                new { name = "members",     type = "complex", required = false, multiValued = true  }
            },
            meta = new { resourceType = "Schema", location = "/scim/v2/Schemas/" + GroupSchema }
        };
        return ScimOk(new
        {
            schemas      = new[] { ListSchema },
            totalResults = 2,
            startIndex   = 1,
            itemsPerPage = 2,
            Resources    = new object[] { userSchema, groupSchema }
        });
    }

    static IResult ResourceTypesAsync()
    {
        var resources = new object[]
        {
            new
            {
                schemas      = new[] { "urn:ietf:params:scim:schemas:core:2.0:ResourceType" },
                id           = "User",
                name         = "User",
                endpoint     = "/Users",
                description  = "User Account",
                schema       = UserSchema,
                schemaExtensions = Array.Empty<object>(),
                meta = new { resourceType = "ResourceType", location = "/scim/v2/ResourceTypes/User" }
            },
            new
            {
                schemas      = new[] { "urn:ietf:params:scim:schemas:core:2.0:ResourceType" },
                id           = "Group",
                name         = "Group",
                endpoint     = "/Groups",
                description  = "Group",
                schema       = GroupSchema,
                schemaExtensions = Array.Empty<object>(),
                meta = new { resourceType = "ResourceType", location = "/scim/v2/ResourceTypes/Group" }
            }
        };
        return ScimOk(new
        {
            schemas      = new[] { ListSchema },
            totalResults = 2,
            startIndex   = 1,
            itemsPerPage = 2,
            Resources    = resources
        });
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SCIM Users
    // ════════════════════════════════════════════════════════════════════════════

    static async Task<IResult> ScimListUsersAsync(
        HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        var filter     = ctx.Request.Query["filter"].ToString();
        var startIndex = int.TryParse(ctx.Request.Query["startIndex"], out var si) ? Math.Max(1, si) : 1;
        var count      = int.TryParse(ctx.Request.Query["count"], out var c) ? Math.Clamp(c, 1, 200) : 20;

        var query = db.Users.AsQueryable();

        if (!string.IsNullOrEmpty(filter))
            query = ApplyUserFilter(query, filter);

        var total   = await query.CountAsync();
        var users   = await query
            .OrderBy(u => u.Username)
            .Skip(startIndex - 1).Take(count)
            .ToListAsync();

        return ScimOk(new
        {
            schemas      = new[] { ListSchema },
            totalResults = total,
            startIndex   = startIndex,
            itemsPerPage = users.Count,
            Resources    = users.Select(MapUserToScim).ToArray()
        });
    }

    static async Task<IResult> ScimGetUserAsync(
        string id, HttpContext ctx, OrkunPamDbContext db)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        User? user = null;
        if (Guid.TryParse(id, out var guid))
            user = await db.Users.FirstOrDefaultAsync(u => u.Id == guid);

        if (user == null) return ScimNotFound("User");
        return ScimOk(MapUserToScim(user));
    }

    static async Task<IResult> ScimCreateUserAsync(
        HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        using var body = await JsonDocument.ParseAsync(ctx.Request.Body);
        var root       = body.RootElement;

        var userName = root.TryGetProperty("userName", out var un) ? un.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(userName))
            return ScimError(400, "userName is required");

        var externalId = root.TryGetProperty("externalId", out var extId) ? extId.GetString() : null;

        // Duplicate check by externalId first, then by userName
        if (!string.IsNullOrEmpty(externalId))
        {
            var existing = await db.Users.FirstOrDefaultAsync(u => u.ScimExternalId == externalId);
            if (existing != null)
                return ScimError(409, $"User with externalId '{externalId}' already exists");
        }

        var normalizedUser = userName.ToUpperInvariant();
        if (await db.Users.AnyAsync(u => u.NormalizedUsername == normalizedUser))
            return ScimError(409, $"User '{userName}' already exists");

        var active      = !root.TryGetProperty("active", out var act) || act.GetBoolean();
        var displayName = root.TryGetProperty("displayName", out var dn) ? dn.GetString() : null;
        var email       = ExtractPrimaryEmail(root);
        string? givenName  = null;
        string? familyName = null;
        if (root.TryGetProperty("name", out var nameObj) && nameObj.ValueKind == JsonValueKind.Object)
        {
            if (nameObj.TryGetProperty("givenName",  out var gn)) givenName  = gn.GetString();
            if (nameObj.TryGetProperty("familyName", out var fn)) familyName = fn.GetString();
        }

        if (string.IsNullOrEmpty(displayName) && (givenName != null || familyName != null))
            displayName = $"{givenName} {familyName}".Trim();

        var user = new User
        {
            Username            = userName,
            NormalizedUsername  = normalizedUser,
            DisplayName         = displayName,
            Email               = email,
            AuthSource          = AuthSource.SCIM,
            Status              = active ? UserStatus.Active : UserStatus.Disabled,
            ScimExternalId      = externalId,
            ScimProvisioned     = true,
            ScimLastSyncedAt    = DateTime.UtcNow,
            PasswordHash        = null // SCIM provisioned users have no local password
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("User", "SCIM_USER_PROVISIONED", null, "scim", ip,
            "User", user.Id.ToString(), new { user.Username, user.Email, externalId });

        ctx.Response.StatusCode = 201;
        return ScimCreated(MapUserToScim(user));
    }

    static async Task<IResult> ScimReplaceUserAsync(
        string id, HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        User? user = Guid.TryParse(id, out var guid)
            ? await db.Users.FirstOrDefaultAsync(u => u.Id == guid)
            : null;
        if (user == null) return ScimNotFound("User");

        using var body = await JsonDocument.ParseAsync(ctx.Request.Body);
        var root       = body.RootElement;

        if (root.TryGetProperty("active", out var act))
            user.Status = act.GetBoolean() ? UserStatus.Active : UserStatus.Disabled;

        if (root.TryGetProperty("displayName", out var dn))
            user.DisplayName = dn.GetString();

        if (root.TryGetProperty("emails", out _))
            user.Email = ExtractPrimaryEmail(root);

        if (root.TryGetProperty("externalId", out var extId))
            user.ScimExternalId = extId.GetString();

        user.ScimLastSyncedAt = DateTime.UtcNow;

        // Terminate active sessions if deactivated
        if (user.Status == UserStatus.Disabled)
            await TerminateUserSessionsAsync(user.Id, db);

        await db.SaveChangesAsync();

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("User", "SCIM_USER_UPDATED", null, "scim", ip,
            "User", user.Id.ToString(), new { user.Username, user.Status });

        return ScimOk(MapUserToScim(user));
    }

    static async Task<IResult> ScimPatchUserAsync(
        string id, HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        User? user = Guid.TryParse(id, out var guid)
            ? await db.Users.FirstOrDefaultAsync(u => u.Id == guid)
            : null;
        if (user == null) return ScimNotFound("User");

        using var body = await JsonDocument.ParseAsync(ctx.Request.Body);
        if (!body.RootElement.TryGetProperty("Operations", out var ops))
            return ScimError(400, "Missing Operations array");

        foreach (var op in ops.EnumerateArray())
        {
            var opType = op.TryGetProperty("op", out var opTypeProp) ? opTypeProp.GetString()?.ToLower() : null;
            var path   = op.TryGetProperty("path", out var pathProp) ? pathProp.GetString()?.ToLower() : null;
            var value  = op.TryGetProperty("value", out var valProp) ? valProp : (JsonElement?)null;

            if (opType == "replace")
            {
                if (path == "active" && value.HasValue)
                {
                    var active = value.Value.ValueKind == JsonValueKind.True ||
                                 (value.Value.ValueKind == JsonValueKind.String && value.Value.GetString() == "true");
                    user.Status = active ? UserStatus.Active : UserStatus.Disabled;
                    if (!active) await TerminateUserSessionsAsync(user.Id, db);
                }
                else if (path == "displayname" && value.HasValue)
                    user.DisplayName = value.Value.GetString();
                else if (path == "emails" && value.HasValue)
                    user.Email = ExtractPrimaryEmailFromValue(value.Value);
                else if ((path == null || path == "") && value.HasValue && value.Value.ValueKind == JsonValueKind.Object)
                {
                    // Azure AD sometimes sends: { "op": "Replace", "value": { "active": false, ... } }
                    if (value.Value.TryGetProperty("active", out var activeInline))
                    {
                        var active = activeInline.GetBoolean();
                        user.Status = active ? UserStatus.Active : UserStatus.Disabled;
                        if (!active) await TerminateUserSessionsAsync(user.Id, db);
                    }
                    if (value.Value.TryGetProperty("displayName", out var dnInline))
                        user.DisplayName = dnInline.GetString();
                }
            }
            else if (opType == "add" && path == "emails" && value.HasValue)
                user.Email = ExtractPrimaryEmailFromValue(value.Value);
        }

        user.ScimLastSyncedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("User", "SCIM_USER_UPDATED", null, "scim", ip,
            "User", user.Id.ToString(), new { user.Username, user.Status });

        return ScimOk(MapUserToScim(user));
    }

    static async Task<IResult> ScimDeleteUserAsync(
        string id, HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        User? user = Guid.TryParse(id, out var guid)
            ? await db.Users.FirstOrDefaultAsync(u => u.Id == guid)
            : null;
        if (user == null) return ScimNotFound("User");

        user.IsDeleted   = true;
        user.DeletedAtUtc = DateTime.UtcNow;
        user.Status      = UserStatus.Disabled;
        await TerminateUserSessionsAsync(user.Id, db);
        await db.SaveChangesAsync();

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("User", "SCIM_USER_DEPROVISIONED", null, "scim", ip,
            "User", user.Id.ToString(), new { user.Username });

        return Results.NoContent();
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SCIM Groups
    // ════════════════════════════════════════════════════════════════════════════

    static async Task<IResult> ScimListGroupsAsync(
        HttpContext ctx, OrkunPamDbContext db)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        var filter     = ctx.Request.Query["filter"].ToString();
        var startIndex = int.TryParse(ctx.Request.Query["startIndex"], out var si) ? Math.Max(1, si) : 1;
        var count      = int.TryParse(ctx.Request.Query["count"], out var c) ? Math.Clamp(c, 1, 200) : 20;

        var query = db.Groups.Include(g => g.UserGroups).ThenInclude(ug => ug.User).AsQueryable();

        if (!string.IsNullOrEmpty(filter))
        {
            var eq = ParseEqFilter(filter);
            if (eq != null)
            {
                var (attr, val) = eq.Value;
                if (attr == "displayname") query = query.Where(g => g.Name.ToUpper() == val.ToUpper());
                else if (attr == "externalid") query = query.Where(g => g.ExternalGroupId == val);
            }
        }

        var total  = await query.CountAsync();
        var groups = await query
            .OrderBy(g => g.Name)
            .Skip(startIndex - 1).Take(count)
            .ToListAsync();

        return ScimOk(new
        {
            schemas      = new[] { ListSchema },
            totalResults = total,
            startIndex   = startIndex,
            itemsPerPage = groups.Count,
            Resources    = groups.Select(MapGroupToScim).ToArray()
        });
    }

    static async Task<IResult> ScimGetGroupAsync(
        string id, HttpContext ctx, OrkunPamDbContext db)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        Group? group = null;
        if (Guid.TryParse(id, out var guid))
            group = await db.Groups.Include(g => g.UserGroups).ThenInclude(ug => ug.User)
                .FirstOrDefaultAsync(g => g.Id == guid);

        if (group == null) return ScimNotFound("Group");
        return ScimOk(MapGroupToScim(group));
    }

    static async Task<IResult> ScimCreateGroupAsync(
        HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        using var body = await JsonDocument.ParseAsync(ctx.Request.Body);
        var root       = body.RootElement;

        var displayName = root.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(displayName))
            return ScimError(400, "displayName is required");

        var externalId = root.TryGetProperty("externalId", out var ext) ? ext.GetString() : null;

        if (await db.Groups.AnyAsync(g => g.Name == displayName))
            return ScimError(409, $"Group '{displayName}' already exists");

        var group = new Group
        {
            Name            = displayName,
            ExternalGroupId = externalId,
            GroupSource     = GroupSource.SCIM
        };
        db.Groups.Add(group);
        await db.SaveChangesAsync();

        // Process initial members
        if (root.TryGetProperty("members", out var members))
            await AddGroupMembersAsync(group.Id, members, db);

        await db.SaveChangesAsync();

        // Reload with navigation
        group = await db.Groups.Include(g => g.UserGroups).ThenInclude(ug => ug.User)
            .FirstAsync(g => g.Id == group.Id);

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("Group", "SCIM_GROUP_PROVISIONED", null, "scim", ip,
            "Group", group.Id.ToString(), new { group.Name });

        ctx.Response.StatusCode = 201;
        return ScimCreated(MapGroupToScim(group));
    }

    static async Task<IResult> ScimPatchGroupAsync(
        string id, HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        Group? group = Guid.TryParse(id, out var guid)
            ? await db.Groups.Include(g => g.UserGroups).ThenInclude(ug => ug.User)
                .FirstOrDefaultAsync(g => g.Id == guid)
            : null;
        if (group == null) return ScimNotFound("Group");

        using var body = await JsonDocument.ParseAsync(ctx.Request.Body);
        if (!body.RootElement.TryGetProperty("Operations", out var ops))
            return ScimError(400, "Missing Operations array");

        foreach (var op in ops.EnumerateArray())
        {
            var opType = op.TryGetProperty("op", out var opTypeProp) ? opTypeProp.GetString()?.ToLower() : null;
            var path   = op.TryGetProperty("path", out var pathProp) ? pathProp.GetString()?.ToLower() : null;
            var value  = op.TryGetProperty("value", out var valProp) ? valProp : (JsonElement?)null;

            if (opType == "replace" && (path == "displayname" || path == null) && value.HasValue)
            {
                if (value.Value.ValueKind == JsonValueKind.String)
                    group.Name = value.Value.GetString() ?? group.Name;
                else if (value.Value.ValueKind == JsonValueKind.Object &&
                         value.Value.TryGetProperty("displayName", out var dnProp))
                    group.Name = dnProp.GetString() ?? group.Name;
            }
            else if (opType == "add" && (path == "members" || path == null) && value.HasValue)
            {
                await AddGroupMembersAsync(group.Id, value.Value, db);
            }
            else if ((opType == "remove") && path != null && path.StartsWith("members["))
            {
                // path format: members[value eq "userId"]
                var memberIdStr = ExtractMemberIdFromPath(path);
                if (Guid.TryParse(memberIdStr, out var memberId))
                {
                    var ug = await db.UserGroups.FindAsync(memberId, group.Id);
                    if (ug != null) db.UserGroups.Remove(ug);
                }
            }
            else if (opType == "remove" && path == "members" && value.HasValue)
            {
                // Remove specific members listed in value
                foreach (var m in value.Value.EnumerateArray())
                {
                    var memberIdStr = m.TryGetProperty("value", out var mv) ? mv.GetString() : null;
                    if (Guid.TryParse(memberIdStr, out var memberId))
                    {
                        var ug = await db.UserGroups.FindAsync(memberId, group.Id);
                        if (ug != null) db.UserGroups.Remove(ug);
                    }
                }
            }
        }

        await db.SaveChangesAsync();

        // Reload
        group = await db.Groups.Include(g => g.UserGroups).ThenInclude(ug => ug.User)
            .FirstAsync(g => g.Id == group.Id);

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("Group", "SCIM_GROUP_UPDATED", null, "scim", ip,
            "Group", group.Id.ToString(), new { group.Name });

        return ScimOk(MapGroupToScim(group));
    }

    static async Task<IResult> ScimDeleteGroupAsync(
        string id, HttpContext ctx, OrkunPamDbContext db, IAuditService audit)
    {
        if (!await AuthenticateScimAsync(ctx, db)) return ScimUnauthorized();

        Group? group = Guid.TryParse(id, out var guid)
            ? await db.Groups.FirstOrDefaultAsync(g => g.Id == guid)
            : null;
        if (group == null) return ScimNotFound("Group");

        db.Groups.Remove(group);
        await db.SaveChangesAsync();

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await audit.LogAsync("Group", "SCIM_GROUP_DELETED", null, "scim", ip,
            "Group", group.Id.ToString(), new { group.Name });

        return Results.NoContent();
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════════

    static async Task<bool> AuthenticateScimAsync(HttpContext ctx, OrkunPamDbContext db)
    {
        if (!ctx.Request.Headers.TryGetValue("Authorization", out var authHeader)) return false;
        var bearer = authHeader.ToString();
        if (!bearer.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        var raw  = bearer["Bearer ".Length..].Trim();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));

        var token = await db.ScimTokens.FirstOrDefaultAsync(
            t => t.TokenHash == hash && t.IsActive);
        if (token == null) return false;
        if (token.ExpiresAtUtc.HasValue && token.ExpiresAtUtc.Value < DateTime.UtcNow) return false;

        token.LastUsedAtUtc = DateTime.UtcNow;
        try { await db.SaveChangesAsync(); } catch { /* best-effort */ }
        return true;
    }

    static IQueryable<User> ApplyUserFilter(IQueryable<User> query, string filter)
    {
        var eq = ParseEqFilter(filter);
        if (eq == null) return query;
        var (attr, val) = eq.Value;

        return attr switch
        {
            "username"   => query.Where(u => u.Username == val),
            "externalid" => query.Where(u => u.ScimExternalId == val),
            "active"     => bool.TryParse(val, out var b)
                ? query.Where(u => (u.Status == UserStatus.Active) == b)
                : query,
            "emails"     => query.Where(u => u.Email != null && u.Email == val),
            "id"         => Guid.TryParse(val, out var g)
                ? query.Where(u => u.Id == g)
                : query,
            _ => query
        };
    }

    static (string attr, string val)? ParseEqFilter(string filter)
    {
        // Simple: attr eq "value" or attr eq value
        var parts = filter.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3 || !parts[1].Equals("eq", StringComparison.OrdinalIgnoreCase))
            return null;
        var attr = parts[0].ToLowerInvariant();
        var val  = parts[2].Trim('"');
        return (attr, val);
    }

    static string? ExtractPrimaryEmail(JsonElement root)
    {
        if (!root.TryGetProperty("emails", out var emails)) return null;
        foreach (var email in emails.EnumerateArray())
        {
            var isPrimary = email.TryGetProperty("primary", out var p) && p.GetBoolean();
            if (isPrimary && email.TryGetProperty("value", out var v))
                return v.GetString();
        }
        // Fallback: first email
        if (emails.GetArrayLength() > 0 && emails[0].TryGetProperty("value", out var fv))
            return fv.GetString();
        return null;
    }

    static string? ExtractPrimaryEmailFromValue(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Array) return ExtractPrimaryEmail(value);
        if (value.ValueKind == JsonValueKind.String) return value.GetString();
        return null;
    }

    static string? ExtractMemberIdFromPath(string path)
    {
        // e.g. members[value eq "some-guid"]
        var start = path.IndexOf('"');
        var end   = path.LastIndexOf('"');
        if (start >= 0 && end > start) return path[(start + 1)..end];
        return null;
    }

    static async Task AddGroupMembersAsync(Guid groupId, JsonElement members, OrkunPamDbContext db)
    {
        foreach (var m in members.EnumerateArray())
        {
            var memberIdStr = m.TryGetProperty("value", out var mv) ? mv.GetString() : null;
            if (!Guid.TryParse(memberIdStr, out var memberId)) continue;
            if (!await db.Users.AnyAsync(u => u.Id == memberId)) continue;
            if (await db.UserGroups.AnyAsync(ug => ug.UserId == memberId && ug.GroupId == groupId)) continue;
            db.UserGroups.Add(new UserGroup { UserId = memberId, GroupId = groupId });
        }
    }

    static async Task TerminateUserSessionsAsync(Guid userId, OrkunPamDbContext db)
    {
        var activeSessions = await db.ProxySessions
            .Where(s => s.UserId == userId && s.Status == SessionStatus.Active)
            .ToListAsync();
        foreach (var s in activeSessions)
        {
            s.Status            = SessionStatus.Terminated;
            s.EndedAtUtc        = DateTime.UtcNow;
            s.TerminationReason = "SCIM deprovisioning";
        }
    }

    static object MapUserToScim(User u) => new
    {
        schemas    = new[] { UserSchema },
        id         = u.Id.ToString(),
        externalId = u.ScimExternalId,
        userName   = u.Username,
        displayName = u.DisplayName,
        name       = new
        {
            formatted  = u.DisplayName,
            givenName  = (string?)null,
            familyName = (string?)null
        },
        emails = u.Email != null ? new object[]
        {
            new { value = u.Email, type = "work", primary = true }
        } : Array.Empty<object>(),
        active = u.Status == UserStatus.Active,
        meta   = new
        {
            resourceType = "User",
            created      = u.CreatedAtUtc.ToString("O"),
            lastModified = u.UpdatedAtUtc?.ToString("O") ?? u.CreatedAtUtc.ToString("O"),
            location     = $"/scim/v2/Users/{u.Id}"
        }
    };

    static object MapGroupToScim(Group g) => new
    {
        schemas     = new[] { GroupSchema },
        id          = g.Id.ToString(),
        externalId  = g.ExternalGroupId,
        displayName = g.Name,
        members     = g.UserGroups?.Select(ug => new
        {
            value   = ug.UserId.ToString(),
            display = ug.User?.DisplayName ?? ug.User?.Username,
            type    = "User"
        }).ToArray() ?? Array.Empty<object>(),
        meta = new
        {
            resourceType = "Group",
            created      = g.CreatedAtUtc.ToString("O"),
            lastModified = g.UpdatedAtUtc?.ToString("O") ?? g.CreatedAtUtc.ToString("O"),
            location     = $"/scim/v2/Groups/{g.Id}"
        }
    };

    // SCIM response helpers
    static IResult ScimOk(object body) =>
        Results.Content(JsonSerializer.Serialize(body), ContentType, statusCode: 200);

    static IResult ScimCreated(object body) =>
        Results.Content(JsonSerializer.Serialize(body), ContentType, statusCode: 201);

    static IResult ScimUnauthorized() =>
        Results.Content(
            JsonSerializer.Serialize(new
            {
                schemas  = new[] { ErrorSchema },
                status   = 401,
                detail   = "Bearer token missing or invalid"
            }),
            ContentType, statusCode: 401);

    static IResult ScimNotFound(string resourceType) =>
        Results.Content(
            JsonSerializer.Serialize(new
            {
                schemas  = new[] { ErrorSchema },
                status   = 404,
                detail   = $"{resourceType} not found"
            }),
            ContentType, statusCode: 404);

    static IResult ScimError(int status, string detail) =>
        Results.Content(
            JsonSerializer.Serialize(new
            {
                schemas = new[] { ErrorSchema },
                status,
                detail
            }),
            ContentType, statusCode: status);
}
