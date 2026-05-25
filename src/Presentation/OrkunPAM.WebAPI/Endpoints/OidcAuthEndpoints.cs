using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class OidcAuthEndpoints
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public static void MapOidcAuthEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Public auth flow ──────────────────────────────────────────────────
        var auth = app.MapGroup("/api/v1/auth/oidc").WithTags("OIDC Auth").AllowAnonymous();

        // List enabled providers for login page
        auth.MapGet("/providers", async (OrkunPamDbContext db) =>
        {
            var providers = await db.OidcProviders
                .Where(p => p.IsEnabled)
                .Select(p => new { p.Id, p.Name, p.DisplayName })
                .ToListAsync();
            return Results.Ok(new { success = true, data = providers });
        });

        // SP-initiated login: build PKCE+state+nonce authorization URL → redirect to IdP
        auth.MapGet("/{name}/login", async (
            string name, HttpContext ctx, OrkunPamDbContext db,
            IMemoryCache cache, ILogger<Program> log) =>
        {
            var provider = await db.OidcProviders.FirstOrDefaultAsync(p =>
                p.Name == name && p.IsEnabled);
            if (provider == null)
                return Results.NotFound(new { success = false, errors = new[] { "OIDC provider not found" } });

            var discovery = await FetchDiscoveryAsync(provider.Authority, log);
            if (discovery == null)
                return Results.BadRequest(new { success = false, errors = new[] { "Cannot reach OIDC discovery endpoint" } });

            // PKCE
            var verifier  = Base64UrlEncode(RandomBytes(32));
            var challenge = Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

            // state + nonce
            var state = Base64UrlEncode(RandomBytes(32));
            var nonce = Base64UrlEncode(RandomBytes(32));

            var stateKey = $"oidc:state:{state}";
            cache.Set(stateKey, new OidcStateEntry(provider.Id, verifier, nonce),
                TimeSpan.FromMinutes(10));

            var callbackUri = BuildCallbackUri(ctx, name);

            var scopes   = provider.Scopes.Trim();
            var authUrl  = discovery.AuthorizationEndpoint
                         + "?response_type=code"
                         + "&client_id=" + Uri.EscapeDataString(provider.ClientId)
                         + "&redirect_uri=" + Uri.EscapeDataString(callbackUri)
                         + "&scope=" + Uri.EscapeDataString(scopes)
                         + "&state=" + Uri.EscapeDataString(state)
                         + "&nonce=" + Uri.EscapeDataString(nonce)
                         + "&code_challenge=" + challenge
                         + "&code_challenge_method=S256";

            return Results.Redirect(authUrl);
        });

        // Callback: exchange code, validate ID token, provision user, issue PAM JWT
        auth.MapGet("/{name}/callback", async (
            string name, string? code, string? state, string? error,
            HttpContext ctx, OrkunPamDbContext db,
            IJwtTokenService jwt, IAuditService audit,
            IMemoryCache cache, IVaultEncryptionService? vault,
            ILogger<Program> log) =>
        {
            var clientIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (!string.IsNullOrEmpty(error))
            {
                log.LogWarning("OIDC callback error from IdP: {Error} (provider={Name})", error, name);
                return Results.Redirect("/login?error=oidc_error");
            }

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                return Results.Redirect("/login?error=oidc_invalid");

            // Validate state
            var stateKey = $"oidc:state:{state}";
            if (!cache.TryGetValue(stateKey, out OidcStateEntry? stateEntry) || stateEntry == null)
                return Results.Redirect("/login?error=oidc_state_invalid");
            cache.Remove(stateKey);

            var provider = await db.OidcProviders.FindAsync(stateEntry.ProviderId);
            if (provider == null || !provider.IsEnabled || provider.Name != name)
                return Results.Redirect("/login?error=oidc_provider_not_found");

            var discovery = await FetchDiscoveryAsync(provider.Authority, log);
            if (discovery == null)
                return Results.Redirect("/login?error=oidc_discovery_failed");

            // Decrypt client secret
            string? clientSecret = null;
            if (provider.ClientSecretEnc != null && vault != null)
            {
                var dec = vault.DecryptString(provider.ClientSecretEnc);
                if (dec.IsSuccess)
                    clientSecret = dec.Value;
            }

            // Exchange code for tokens
            var callbackUri = BuildCallbackUri(ctx, name);
            var tokenResponse = await ExchangeCodeAsync(
                discovery.TokenEndpoint,
                code, callbackUri,
                provider.ClientId, clientSecret,
                stateEntry.CodeVerifier, log);

            if (tokenResponse == null)
            {
                await audit.LogAsync("Auth", "OIDC_LOGIN_FAILED", null, null, clientIp,
                    "OidcProvider", provider.Id.ToString(),
                    new { provider = provider.Name, reason = "token_exchange_failed" },
                    AuditOutcome.Failure);
                return Results.Redirect("/login?error=oidc_token_error");
            }

            // Decode and validate ID token
            OidcClaims claims;
            try
            {
                claims = DecodeIdToken(tokenResponse.IdToken, provider.ClientId,
                    provider.Authority, stateEntry.Nonce);
            }
            catch (Exception ex)
            {
                log.LogWarning("OIDC ID token validation failed (provider={Name}): {Msg}", name, ex.Message);
                await audit.LogAsync("Auth", "OIDC_LOGIN_FAILED", null, null, clientIp,
                    "OidcProvider", provider.Id.ToString(),
                    new { provider = provider.Name, reason = "id_token_invalid" },
                    AuditOutcome.Failure);
                return Results.Redirect("/login?error=oidc_token_invalid");
            }

            // Find or auto-provision user
            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group)
                    .ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role)
                    .ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.AuthSource == AuthSource.Oidc
                    && u.ExternalId == claims.Sub);

            var provisioned = false;
            if (user == null)
            {
                if (!provider.AutoProvisionUsers)
                {
                    await audit.LogAsync("Auth", "OIDC_LOGIN_FAILED", null, null, clientIp,
                        "OidcProvider", provider.Id.ToString(),
                        new { provider = provider.Name, reason = "user_not_found_auto_provision_disabled" },
                        AuditOutcome.Failure);
                    return Results.Redirect("/login?error=oidc_user_not_found");
                }

                var username = claims.PreferredUsername ?? claims.Email ?? claims.Sub;
                if (username.Length > 100) username = username[..100];

                user = new User
                {
                    Username            = username,
                    NormalizedUsername  = username.ToUpperInvariant(),
                    Email               = claims.Email,
                    DisplayName         = claims.Name ?? username,
                    AuthSource          = AuthSource.Oidc,
                    ExternalId          = claims.Sub,
                    Status              = UserStatus.Active
                };
                db.Users.Add(user);
                await db.SaveChangesAsync();

                // Assign default role
                await AssignDefaultRoleAsync(db, user, provider.DefaultRole);

                // Reload with roles
                user = await db.Users
                    .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                    .Include(u => u.UserGroups).ThenInclude(ug => ug.Group)
                        .ThenInclude(g => g.GroupRoles).ThenInclude(gr => gr.Role)
                        .ThenInclude(r => r.RolePermissions)
                    .FirstAsync(u => u.Id == user.Id);

                provisioned = true;
                log.LogInformation("Auto-provisioned OIDC user '{User}' from provider '{Provider}'",
                    user.Username, provider.Name);
            }

            // Collect roles/permissions
            var roles       = new HashSet<string>();
            var permissions = new HashSet<string>();
            foreach (var ur in user.UserRoles)
            {
                roles.Add(ur.Role.Name);
                foreach (var rp in ur.Role.RolePermissions)
                    permissions.Add(rp.PermissionCode);
            }
            foreach (var ug in user.UserGroups)
                foreach (var gr in ug.Group.GroupRoles)
                {
                    roles.Add(gr.Role.Name);
                    foreach (var rp in gr.Role.RolePermissions)
                        permissions.Add(rp.PermissionCode);
                }

            var tokenResult = jwt.GenerateTokens(
                user.Id, user.Username, user.DisplayName ?? user.Username,
                AuthSource.Oidc.ToString(), roles, permissions, mfaVerified: true);

            if (tokenResult.IsFailure)
            {
                log.LogError("JWT generation failed for OIDC user '{User}'", user.Username);
                return Results.Redirect("/login?error=oidc_jwt_failed");
            }

            user.RecordLoginSuccess(clientIp);
            await db.SaveChangesAsync();

            await audit.LogAsync("Auth", "OIDC_LOGIN_SUCCESS", user.Id, user.Username, clientIp,
                "OidcProvider", provider.Id.ToString(),
                new { provider = provider.Name, provisioned });

            if (provisioned)
                await audit.LogAsync("Auth", "OIDC_USER_PROVISIONED", user.Id, user.Username, clientIp,
                    "OidcProvider", provider.Id.ToString(), new { provider = provider.Name });

            // Redirect to callback page with JWT in URL (same pattern as SAML)
            var redirectUrl = "/oidc-callback?token=" + Uri.EscapeDataString(tokenResult.Value.AccessToken);
            return Results.Redirect(redirectUrl);
        });

        // ── Admin CRUD ────────────────────────────────────────────────────────
        var admin = app.MapGroup("/api/v1/system/oidc-providers").WithTags("OIDC Admin")
            .RequireAuthorization("AdminPolicy");

        admin.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.OidcProviders
                .Select(p => new OidcProviderDto(
                    p.Id, p.Name, p.DisplayName, p.Authority, p.ClientId,
                    p.ClientSecretEnc != null,
                    p.Scopes, p.GroupClaimType, p.GroupRoleMapping,
                    p.AutoProvisionUsers, p.DefaultRole, p.IsEnabled,
                    p.CreatedAtUtc, p.UpdatedAtUtc))
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        admin.MapPost("/", async (
            CreateOidcProviderRequest req, HttpContext ctx,
            OrkunPamDbContext db, IVaultEncryptionService? vault, IAuditService audit) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name) || string.IsNullOrWhiteSpace(req.Authority)
                || string.IsNullOrWhiteSpace(req.ClientId))
                return Results.BadRequest(new { success = false, errors = new[] { "Name, Authority, and ClientId are required" } });

            if (await db.OidcProviders.AnyAsync(p => p.Name == req.Name))
                return Results.Conflict(new { success = false, errors = new[] { "A provider with this name already exists" } });

            byte[]? secretEnc = null;
            if (!string.IsNullOrEmpty(req.ClientSecret) && vault != null)
            {
                var enc = vault.EncryptString(req.ClientSecret, "OidcClientSecret");
                if (enc.IsSuccess) secretEnc = enc.Value;
                Array.Clear(System.Text.Encoding.UTF8.GetBytes(req.ClientSecret));
            }

            var provider = new OidcProvider
            {
                Name               = req.Name.Trim(),
                DisplayName        = req.DisplayName?.Trim() ?? req.Name.Trim(),
                Authority          = req.Authority.TrimEnd('/'),
                ClientId           = req.ClientId.Trim(),
                ClientSecretEnc    = secretEnc,
                Scopes             = string.IsNullOrWhiteSpace(req.Scopes) ? "openid profile email" : req.Scopes.Trim(),
                GroupClaimType     = req.GroupClaimType?.Trim(),
                GroupRoleMapping   = req.GroupRoleMapping?.Trim(),
                AutoProvisionUsers = req.AutoProvisionUsers ?? true,
                DefaultRole        = req.DefaultRole?.Trim() ?? "Viewer",
                IsEnabled          = req.IsEnabled ?? true
            };
            db.OidcProviders.Add(provider);
            await db.SaveChangesAsync();

            var user = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            await audit.LogAsync("System", "OIDC_PROVIDER_CREATED", null, user, null,
                "OidcProvider", provider.Id.ToString(), new { provider.Name });

            return Results.Created($"/api/v1/system/oidc-providers/{provider.Id}",
                new { success = true, data = new { provider.Id } });
        });

        admin.MapPut("/{id:guid}", async (
            Guid id, UpdateOidcProviderRequest req, HttpContext ctx,
            OrkunPamDbContext db, IVaultEncryptionService? vault, IAuditService audit) =>
        {
            var provider = await db.OidcProviders.FindAsync(id);
            if (provider == null)
                return Results.NotFound(new { success = false, errors = new[] { "Provider not found" } });

            if (!string.IsNullOrWhiteSpace(req.DisplayName)) provider.DisplayName = req.DisplayName.Trim();
            if (!string.IsNullOrWhiteSpace(req.Authority))   provider.Authority   = req.Authority.TrimEnd('/');
            if (!string.IsNullOrWhiteSpace(req.ClientId))    provider.ClientId    = req.ClientId.Trim();
            if (!string.IsNullOrWhiteSpace(req.Scopes))      provider.Scopes      = req.Scopes.Trim();
            if (req.GroupClaimType   != null) provider.GroupClaimType   = req.GroupClaimType.Trim();
            if (req.GroupRoleMapping != null) provider.GroupRoleMapping = req.GroupRoleMapping.Trim();
            if (req.AutoProvisionUsers.HasValue) provider.AutoProvisionUsers = req.AutoProvisionUsers.Value;
            if (!string.IsNullOrWhiteSpace(req.DefaultRole)) provider.DefaultRole = req.DefaultRole.Trim();
            if (req.IsEnabled.HasValue) provider.IsEnabled = req.IsEnabled.Value;

            if (!string.IsNullOrEmpty(req.ClientSecret) && vault != null)
            {
                var enc = vault.EncryptString(req.ClientSecret, "OidcClientSecret");
                if (enc.IsSuccess) provider.ClientSecretEnc = enc.Value;
            }

            await db.SaveChangesAsync();
            var user = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            await audit.LogAsync("System", "OIDC_PROVIDER_UPDATED", null, user, null,
                "OidcProvider", id.ToString(), new { provider.Name });
            return Results.Ok(new { success = true });
        });

        admin.MapDelete("/{id:guid}", async (
            Guid id, HttpContext ctx, OrkunPamDbContext db, IAuditService audit) =>
        {
            var provider = await db.OidcProviders.FindAsync(id);
            if (provider == null)
                return Results.NotFound(new { success = false, errors = new[] { "Provider not found" } });

            db.OidcProviders.Remove(provider);
            await db.SaveChangesAsync();
            var user = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            await audit.LogAsync("System", "OIDC_PROVIDER_DELETED", null, user, null,
                "OidcProvider", id.ToString(), new { provider.Name });
            return Results.Ok(new { success = true });
        });

        admin.MapPost("/{id:guid}/test", async (
            Guid id, OrkunPamDbContext db, ILogger<Program> log) =>
        {
            var provider = await db.OidcProviders.FindAsync(id);
            if (provider == null)
                return Results.NotFound(new { success = false, errors = new[] { "Provider not found" } });

            var discovery = await FetchDiscoveryAsync(provider.Authority, log);
            if (discovery == null)
                return Results.Ok(new { success = false, reachable = false,
                    error = "Cannot reach OIDC discovery endpoint: " + provider.Authority + "/.well-known/openid-configuration" });

            return Results.Ok(new
            {
                success = true, reachable = true,
                authorizationEndpoint = discovery.AuthorizationEndpoint,
                tokenEndpoint         = discovery.TokenEndpoint,
                issuer                = discovery.Issuer
            });
        });
    }

    // ── OIDC discovery ────────────────────────────────────────────────────────

    private static readonly HttpClient DiscoveryClient = new(new HttpClientHandler
    {
        CheckCertificateRevocationList = true
    })
    { Timeout = TimeSpan.FromSeconds(10) };

    private static async Task<OidcDiscovery?> FetchDiscoveryAsync(string authority, ILogger log)
    {
        try
        {
            var url  = authority.TrimEnd('/') + "/.well-known/openid-configuration";
            var resp = await DiscoveryClient.GetStringAsync(url);
            using var doc = JsonDocument.Parse(resp);
            var root = doc.RootElement;
            var authEp  = root.GetProperty("authorization_endpoint").GetString();
            var tokenEp = root.GetProperty("token_endpoint").GetString();
            var issuer  = root.TryGetProperty("issuer", out var iss) ? iss.GetString() : null;
            if (string.IsNullOrEmpty(authEp) || string.IsNullOrEmpty(tokenEp)) return null;
            return new OidcDiscovery(authEp, tokenEp, issuer ?? authority);
        }
        catch (Exception ex)
        {
            log.LogWarning("OIDC discovery fetch failed ({Authority}): {Msg}", authority, ex.Message);
            return null;
        }
    }

    // ── Code exchange ─────────────────────────────────────────────────────────

    private static async Task<OidcTokenResponse?> ExchangeCodeAsync(
        string tokenEndpoint, string code, string redirectUri,
        string clientId, string? clientSecret, string codeVerifier, ILogger log)
    {
        try
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"]    = "authorization_code",
                ["code"]          = code,
                ["redirect_uri"]  = redirectUri,
                ["client_id"]     = clientId,
                ["code_verifier"] = codeVerifier
            };
            if (!string.IsNullOrEmpty(clientSecret))
                form["client_secret"] = clientSecret;

            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(form)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var resp = await DiscoveryClient.SendAsync(request);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                log.LogWarning("OIDC token exchange failed (HTTP {Code}): {Body}", (int)resp.StatusCode, body);
                return null;
            }

            using var doc   = JsonDocument.Parse(body);
            var root        = doc.RootElement;
            var idToken     = root.TryGetProperty("id_token",     out var it) ? it.GetString() : null;
            var accessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null;
            if (string.IsNullOrEmpty(idToken)) return null;
            return new OidcTokenResponse(idToken, accessToken);
        }
        catch (Exception ex)
        {
            log.LogWarning("OIDC token exchange exception: {Msg}", ex.Message);
            return null;
        }
    }

    // ── ID token validation ───────────────────────────────────────────────────

    private static OidcClaims DecodeIdToken(
        string idToken, string clientId, string authority, string expectedNonce)
    {
        var parts = idToken.Split('.');
        if (parts.Length != 3) throw new FormatException("Malformed ID token");

        var payload = parts[1];
        var padded  = payload.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(padded)));
        var root = doc.RootElement;

        // Validate expiry
        if (root.TryGetProperty("exp", out var expEl))
        {
            var exp = DateTimeOffset.FromUnixTimeSeconds(expEl.GetInt64());
            if (exp < DateTimeOffset.UtcNow.AddMinutes(-5))
                throw new SecurityTokenExpiredException("ID token is expired");
        }

        // Validate issuer (flexible: authority may or may not have trailing slash)
        if (root.TryGetProperty("iss", out var issEl))
        {
            var iss = issEl.GetString()?.TrimEnd('/') ?? "";
            var exp = authority.TrimEnd('/');
            if (!iss.Equals(exp, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"ID token issuer mismatch: {iss} != {exp}");
        }

        // Validate audience
        if (root.TryGetProperty("aud", out var audEl))
        {
            var audiences = new List<string>();
            if (audEl.ValueKind == JsonValueKind.Array)
                foreach (var a in audEl.EnumerateArray())
                { if (a.GetString() is string s) audiences.Add(s); }
            else if (audEl.GetString() is string single)
                audiences.Add(single);

            if (!audiences.Contains(clientId))
                throw new InvalidOperationException("ID token audience does not include clientId");
        }

        // Validate nonce
        if (root.TryGetProperty("nonce", out var nonceEl))
        {
            var tokenNonce = nonceEl.GetString();
            if (!string.Equals(tokenNonce, expectedNonce, StringComparison.Ordinal))
                throw new InvalidOperationException("ID token nonce mismatch (possible replay)");
        }

        string GetClaim(string key)
            => root.TryGetProperty(key, out var p) ? p.GetString() ?? "" : "";

        var sub   = GetClaim("sub");
        if (string.IsNullOrEmpty(sub))
            throw new InvalidOperationException("ID token missing 'sub' claim");

        return new OidcClaims(
            Sub:                sub,
            Email:              GetClaim("email") is { Length: > 0 } e ? e : null,
            Name:               GetClaim("name") is { Length: > 0 } n ? n : null,
            PreferredUsername:  GetClaim("preferred_username") is { Length: > 0 } u ? u : null);
    }

    // ── Role assignment helper ────────────────────────────────────────────────

    private static async Task AssignDefaultRoleAsync(OrkunPamDbContext db, User user, string roleName)
    {
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == roleName);
        role ??= await db.Roles.FirstOrDefaultAsync(r => r.Name == "Viewer");
        if (role == null) return;

        if (!await db.UserRoles.AnyAsync(ur => ur.UserId == user.Id && ur.RoleId == role.Id))
        {
            db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
            await db.SaveChangesAsync();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string BuildCallbackUri(HttpContext ctx, string name)
        => $"{ctx.Request.Scheme}://{ctx.Request.Host}/api/v1/auth/oidc/{name}/callback";

    private static byte[] RandomBytes(int count)
    {
        var b = new byte[count];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ── Records ───────────────────────────────────────────────────────────────

    private sealed record OidcStateEntry(Guid ProviderId, string CodeVerifier, string Nonce);
    private sealed record OidcDiscovery(string AuthorizationEndpoint, string TokenEndpoint, string Issuer);
    private sealed record OidcTokenResponse(string IdToken, string? AccessToken);
    private sealed record OidcClaims(string Sub, string? Email, string? Name, string? PreferredUsername);

    private sealed class SecurityTokenExpiredException(string message) : Exception(message) { }
}

// ── Request/Response DTOs ─────────────────────────────────────────────────────

public sealed record OidcProviderDto(
    Guid     Id,
    string   Name,
    string   DisplayName,
    string   Authority,
    string   ClientId,
    bool     ClientSecretSet,
    string   Scopes,
    string?  GroupClaimType,
    string?  GroupRoleMapping,
    bool     AutoProvisionUsers,
    string   DefaultRole,
    bool     IsEnabled,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public sealed record CreateOidcProviderRequest(
    string  Name,
    string? DisplayName,
    string  Authority,
    string  ClientId,
    string? ClientSecret,
    string? Scopes,
    string? GroupClaimType,
    string? GroupRoleMapping,
    bool?   AutoProvisionUsers,
    string? DefaultRole,
    bool?   IsEnabled);

public sealed record UpdateOidcProviderRequest(
    string? DisplayName,
    string? Authority,
    string? ClientId,
    string? ClientSecret,
    string? Scopes,
    string? GroupClaimType,
    string? GroupRoleMapping,
    bool?   AutoProvisionUsers,
    string? DefaultRole,
    bool?   IsEnabled);
