using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class PkiEndpoints
{
    public static void MapPkiEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Trusted CA management (admin only) ──────────────────────────────
        var cas = app.MapGroup("/api/v1/auth/pki/trusted-cas")
            .WithTags("PKI")
            .RequireAuthorization("AdminPolicy");

        cas.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.TrustedCaCertificates
                .OrderBy(c => c.Name)
                .Select(c => new
                {
                    c.Id, c.Name, c.Subject, c.Issuer, c.Thumbprint,
                    c.NotBefore, c.NotAfter, c.IsEnabled, c.CheckRevocation,
                    c.OcspUrl, c.CrlUrl
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        cas.MapPost("/", async (AddTrustedCaRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            X509Certificate2 cert;
            try
            {
                cert = X509Certificate2.CreateFromPem(req.PemCertificate);
            }
            catch
            {
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid PEM certificate" } });
            }

            var thumbprint = cert.Thumbprint;
            if (await db.TrustedCaCertificates.AnyAsync(c => c.Thumbprint == thumbprint))
                return Results.Conflict(new { success = false, errors = new[] { "Certificate already registered" } });

            var entity = new TrustedCaCertificate
            {
                Name = req.Name,
                PemCertificate = req.PemCertificate,
                Thumbprint = thumbprint,
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                OcspUrl = req.OcspUrl,
                CrlUrl = req.CrlUrl,
                CheckRevocation = req.CheckRevocation ?? true,
                IsEnabled = true
            };
            db.TrustedCaCertificates.Add(entity);
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "PKI",
                EventType = "TrustedCaAdded",
                ActorUsername = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "TrustedCaCertificate",
                Details = $"name='{req.Name}' thumbprint={thumbprint}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/auth/pki/trusted-cas/{entity.Id}",
                new { success = true, data = new { entity.Id, entity.Name, entity.Thumbprint } });
        });

        cas.MapPut("/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var ca = await db.TrustedCaCertificates.FindAsync(id);
            if (ca == null) return Results.NotFound(new { success = false });
            ca.IsEnabled = !ca.IsEnabled;
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "PKI",
                EventType = "TrustedCaToggled",
                ActorUsername = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "TrustedCaCertificate",
                TargetId = id.ToString(),
                Details = $"isEnabled={ca.IsEnabled}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { id, ca.IsEnabled } });
        });

        cas.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var ca = await db.TrustedCaCertificates.FindAsync(id);
            if (ca == null) return Results.NotFound(new { success = false });
            db.TrustedCaCertificates.Remove(ca);
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "PKI",
                EventType = "TrustedCaRemoved",
                ActorUsername = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "TrustedCaCertificate",
                TargetId = id.ToString(),
                Details = $"name='{ca.Name}' thumbprint={ca.Thumbprint}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // ── User certificate mapping (admin only) ────────────────────────────
        var userCerts = app.MapGroup("/api/v1/auth/pki/user-certs")
            .WithTags("PKI")
            .RequireAuthorization("AdminPolicy");

        userCerts.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.PkiUserCertificates
                .Join(db.Users, p => p.UserId, u => u.Id, (p, u) => new
                {
                    p.Id, p.UserId, p.CertThumbprint, p.SubjectDn, p.IssuingCaThumbprint,
                    p.ExpiresAtUtc, p.RequirePkiOnly, p.IsEnabled, p.LastUsedAtUtc,
                    Username = u.Username
                })
                .OrderBy(p => p.Username)
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        userCerts.MapPost("/", async (MapUserCertRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            X509Certificate2 cert;
            try { cert = X509Certificate2.CreateFromPem(req.PemCertificate); }
            catch { return Results.BadRequest(new { success = false, errors = new[] { "Invalid PEM certificate" } }); }

            var user = await db.Users.FindAsync(req.UserId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var thumbprint = cert.Thumbprint;
            if (await db.PkiUserCertificates.AnyAsync(p => p.CertThumbprint == thumbprint))
                return Results.Conflict(new { success = false, errors = new[] { "Certificate already mapped to a user" } });

            var issuingCa = await db.TrustedCaCertificates
                .Where(c => c.IsEnabled)
                .ToListAsync();
            var caThumbprint = FindIssuingCaThumbprint(cert, issuingCa);

            var entity = new PkiUserCertificate
            {
                UserId = req.UserId,
                CertThumbprint = thumbprint,
                SubjectDn = cert.Subject,
                IssuingCaThumbprint = caThumbprint ?? "",
                ExpiresAtUtc = cert.NotAfter.ToUniversalTime(),
                RequirePkiOnly = req.RequirePkiOnly,
                IsEnabled = true
            };
            db.PkiUserCertificates.Add(entity);

            if (req.RequirePkiOnly)
                user.RequirePkiAuth = true;

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "PKI",
                EventType = "UserCertMapped",
                ActorUsername = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "User",
                TargetId = req.UserId.ToString(),
                Details = $"username={user.Username} thumbprint={thumbprint}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/auth/pki/user-certs/{entity.Id}",
                new { success = true, data = new { entity.Id, entity.CertThumbprint, username = user.Username } });
        });

        userCerts.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var mapping = await db.PkiUserCertificates.FindAsync(id);
            if (mapping == null) return Results.NotFound(new { success = false });
            db.PkiUserCertificates.Remove(mapping);

            // If no other PKI certs remain, clear RequirePkiAuth flag
            var remaining = await db.PkiUserCertificates.CountAsync(p => p.UserId == mapping.UserId && p.Id != id && p.IsEnabled);
            if (remaining == 0)
            {
                var user = await db.Users.FindAsync(mapping.UserId);
                if (user != null) user.RequirePkiAuth = false;
            }

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "PKI",
                EventType = "UserCertUnmapped",
                ActorUsername = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "PkiUserCertificate",
                TargetId = id.ToString(),
                Details = $"thumbprint={mapping.CertThumbprint}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // ── PKI / Smart Card Login ────────────────────────────────────────────
        // Accepts a PEM certificate in the request body. Validates it against
        // trusted CAs and issues a PAM JWT if a user mapping exists.
        // For browser smart card SSO, the TLS reverse proxy forwards the
        // client certificate as X-Client-Cert PEM header.
        var auth = app.MapGroup("/api/v1/auth/pki").WithTags("PKI");

        auth.MapPost("/login", async (PkiLoginRequest req, OrkunPamDbContext db,
            IJwtTokenService jwt, HttpContext ctx, ILogger<Program> logger) =>
        {
            // Accept cert from body, or from X-Client-Cert header (reverse-proxy forwarded)
            var pemCert = !string.IsNullOrWhiteSpace(req.PemCertificate)
                ? req.PemCertificate
                : ctx.Request.Headers["X-Client-Cert"].ToString();

            if (string.IsNullOrWhiteSpace(pemCert))
                return Results.BadRequest(new { success = false, errors = new[] { "No certificate provided" } });

            X509Certificate2 cert;
            try { cert = X509Certificate2.CreateFromPem(pemCert); }
            catch
            {
                logger.LogWarning("PKI login: invalid certificate from {IP}", ctx.Connection.RemoteIpAddress);
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid certificate" } });
            }

            if (cert.NotAfter < DateTime.UtcNow)
            {
                db.AuditLogs.Add(AuditEntry("PKILoginFailed", null, ctx, $"expired cert thumbprint={cert.Thumbprint}"));
                await db.SaveChangesAsync();
                return Results.Unauthorized();
            }

            var thumbprint = cert.Thumbprint;

            // Validate against trusted CAs
            var trustedCAs = await db.TrustedCaCertificates
                .Where(c => c.IsEnabled)
                .ToListAsync();

            if (!ValidateCertificateChain(cert, trustedCAs))
            {
                logger.LogWarning("PKI login: untrusted certificate {Thumbprint}", thumbprint);
                db.AuditLogs.Add(AuditEntry("PKILoginFailed", null, ctx, $"untrusted cert thumbprint={thumbprint}"));
                await db.SaveChangesAsync();
                return Results.Unauthorized();
            }

            // Look up user mapping
            var mapping = await db.PkiUserCertificates
                .FirstOrDefaultAsync(p => p.CertThumbprint == thumbprint && p.IsEnabled);

            if (mapping == null)
            {
                logger.LogWarning("PKI login: no user mapped to certificate {Thumbprint}", thumbprint);
                db.AuditLogs.Add(AuditEntry("PKILoginFailed", null, ctx, $"no mapping for thumbprint={thumbprint}"));
                await db.SaveChangesAsync();
                return Results.Unauthorized();
            }

            var user = await db.Users
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group).ThenInclude(g => g.GroupRoles)
                    .ThenInclude(gr => gr.Role).ThenInclude(r => r.RolePermissions)
                .FirstOrDefaultAsync(u => u.Id == mapping.UserId);

            if (user == null || user.IsLocked || user.Status == UserStatus.Disabled)
            {
                db.AuditLogs.Add(AuditEntry("PKILoginFailed", user?.Username, ctx, "account disabled/locked"));
                await db.SaveChangesAsync();
                return Results.Unauthorized();
            }

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
                "PKI", roles, permissions, mfaVerified: true);

            if (tokenResult.IsFailure)
                return Results.Problem("Token generation failed");

            // Update tracking
            mapping.LastUsedAtUtc = DateTime.UtcNow;
            user.RecordLoginSuccess(ctx.Connection.RemoteIpAddress?.ToString() ?? "");
            db.AuditLogs.Add(AuditEntry("PKILoginSuccess", user.Username, ctx,
                $"thumbprint={thumbprint} subject='{cert.Subject}'"));
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = tokenResult.Value.AccessToken,
                    refreshToken = tokenResult.Value.RefreshToken,
                    expiresAt = tokenResult.Value.AccessTokenExpiry,
                    authMethod = "PKI"
                }
            });
        }).RequireRateLimiting("auth");
    }

    private static bool ValidateCertificateChain(X509Certificate2 cert, List<TrustedCaCertificate> trustedCAs)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        foreach (var ca in trustedCAs)
        {
            try
            {
                var caCert = X509Certificate2.CreateFromPem(ca.PemCertificate);
                chain.ChainPolicy.ExtraStore.Add(caCert);
            }
            catch { /* skip invalid stored CA */ }
        }

        var built = chain.Build(cert);
        if (built) return true;

        // Check if chain ends at one of our trusted CAs
        foreach (var element in chain.ChainElements)
        {
            var tp = element.Certificate.Thumbprint;
            if (trustedCAs.Any(ca => string.Equals(ca.Thumbprint, tp, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    private static string? FindIssuingCaThumbprint(X509Certificate2 cert, List<TrustedCaCertificate> trustedCAs)
    {
        // Try to match by Issuer DN against trusted CA subjects
        foreach (var ca in trustedCAs)
        {
            try
            {
                var caCert = X509Certificate2.CreateFromPem(ca.PemCertificate);
                if (string.Equals(cert.Issuer, caCert.Subject, StringComparison.OrdinalIgnoreCase))
                    return ca.Thumbprint;
            }
            catch { }
        }
        return null;
    }

    private static AuditLogEntry AuditEntry(
        string eventType, string? username, HttpContext ctx, string details)
        => new()
        {
            EventCategory = "PKI",
            EventType = eventType,
            ActorUsername = username ?? ctx.User.FindFirstValue(ClaimTypes.Name),
            ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
            TargetType = "Auth",
            Details = details,
            Outcome = eventType.EndsWith("Failed")
                ? AuditOutcome.Failure
                : AuditOutcome.Success
        };
}

public record AddTrustedCaRequest(
    string Name,
    string PemCertificate,
    string? OcspUrl,
    string? CrlUrl,
    bool? CheckRevocation);

public record MapUserCertRequest(
    Guid UserId,
    string PemCertificate,
    bool RequirePkiOnly);

public record PkiLoginRequest(string? PemCertificate);
