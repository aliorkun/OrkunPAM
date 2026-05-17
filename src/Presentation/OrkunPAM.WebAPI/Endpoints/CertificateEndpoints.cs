using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CertificateEndpoints
{
    public static void MapCertificateEndpoints(this IEndpointRouteBuilder app)
    {
        var certs = app.MapGroup("/api/v1/certificates").WithTags("Certificates").RequireAuthorization("AdminPolicy");

        certs.MapGet("/", async (OrkunPamDbContext db, string? source) =>
        {
            var query = db.ManagedCertificates.AsQueryable();
            if (!string.IsNullOrEmpty(source))
                query = query.Where(c => c.Source == source);

            var now = DateTime.UtcNow;
            var list = await query
                .OrderBy(c => c.NotAfter)
                .Select(c => new
                {
                    c.Id, c.SubjectCN, c.Issuer, c.Thumbprint, c.SerialNumber,
                    c.NotBefore, c.NotAfter, c.KeyUsage, c.KeyAlgorithm, c.KeySizeBits,
                    c.DeviceId, c.FolderId, c.Notes, c.Source, c.CreatedAtUtc,
                    DaysUntilExpiry = (int)(c.NotAfter - now).TotalDays,
                    IsExpired = c.NotAfter < now
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = list });
        });

        certs.MapGet("/expiring", async (OrkunPamDbContext db, int? days) =>
        {
            var threshold = DateTime.UtcNow.AddDays(days ?? 90);
            var now = DateTime.UtcNow;
            var list = await db.ManagedCertificates
                .Where(c => c.NotAfter <= threshold)
                .OrderBy(c => c.NotAfter)
                .Select(c => new
                {
                    c.Id, c.SubjectCN, c.Issuer, c.Thumbprint,
                    c.NotAfter, c.Source, c.DeviceId,
                    DaysUntilExpiry = (int)(c.NotAfter - now).TotalDays,
                    IsExpired = c.NotAfter < now
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = list, count = list.Count });
        });

        certs.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var now = DateTime.UtcNow;
            var c = await db.ManagedCertificates.FindAsync(id);
            if (c == null) return Results.NotFound(new { success = false, errors = new[] { "Certificate not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    c.Id, c.SubjectCN, c.SubjectAltNames, c.Issuer, c.Thumbprint, c.SerialNumber,
                    c.NotBefore, c.NotAfter, c.KeyUsage, c.KeyAlgorithm, c.KeySizeBits,
                    c.DeviceId, c.FolderId, c.Notes, c.Source, c.CreatedAtUtc,
                    DaysUntilExpiry = (int)(c.NotAfter - now).TotalDays,
                    IsExpired = c.NotAfter < now
                }
            });
        });

        certs.MapPost("/", async (ImportCertificateRequest req, OrkunPamDbContext db,
            IAuditService audit, IVaultEncryptionService vault,
            ILogger<Program> logger, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(req.PemCertificate))
                return Results.BadRequest(new { success = false, errors = new[] { "PEM certificate is required" } });

            X509Certificate2 cert;
            try
            {
                cert = X509Certificate2.CreateFromPem(req.PemCertificate);
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { success = false, errors = new[] { $"Invalid PEM: {ex.Message}" } });
            }

            var thumbprint = cert.Thumbprint;
            if (await db.ManagedCertificates.AnyAsync(c => c.Thumbprint == thumbprint))
                return Results.Conflict(new { success = false, errors = new[] { "Certificate with this thumbprint already exists" } });

            var actorId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var actorGuid = actorId != null ? Guid.Parse(actorId) : (Guid?)null;

            string? pemEnc = null;
            if (!string.IsNullOrEmpty(req.PemCertificate))
            {
                var encResult = vault.EncryptString(req.PemCertificate);
                if (encResult.IsSuccess) pemEnc = encResult.Value;
            }

            var subjectCn = cert.GetNameInfo(X509NameType.SimpleName, false);
            var keyUsage = string.Join(", ", cert.Extensions
                .OfType<X509KeyUsageExtension>()
                .Select(k => k.KeyUsages.ToString()));

            var san = cert.Extensions["2.5.29.17"]?.Format(false);
            var keyAlg = cert.GetKeyAlgorithm() switch
            {
                "1.2.840.113549.1.1.1" => "RSA",
                "1.2.840.10040.4.1" => "DSA",
                "1.2.840.10045.2.1" => "EC",
                _ => cert.GetKeyAlgorithm()
            };

            var managed = new ManagedCertificate
            {
                SubjectCN = subjectCn,
                SubjectAltNames = san,
                Issuer = cert.Issuer,
                Thumbprint = thumbprint,
                SerialNumber = cert.SerialNumber,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                KeyUsage = string.IsNullOrEmpty(keyUsage) ? null : keyUsage,
                KeyAlgorithm = keyAlg,
                KeySizeBits = cert.GetRSAPublicKey()?.KeySize
                              ?? cert.GetECDsaPublicKey()?.KeySize
                              ?? 0,
                PemCertificateEnc = pemEnc,
                DeviceId = req.DeviceId,
                FolderId = req.FolderId,
                Notes = req.Notes,
                Source = req.Source ?? "Manual",
                CreatedBy = actorGuid
            };

            db.ManagedCertificates.Add(managed);
            await db.SaveChangesAsync();

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Certificate", "CERT_IMPORTED", actorGuid, null, ip,
                "ManagedCertificate", managed.Id.ToString(),
                new { managed.SubjectCN, managed.Thumbprint, managed.NotAfter });

            logger.LogInformation("Certificate '{SubjectCN}' imported. Expires: {NotAfter}", managed.SubjectCN, managed.NotAfter);

            return Results.Created($"/api/v1/certificates/{managed.Id}",
                new { success = true, data = new { managed.Id, managed.SubjectCN, managed.Thumbprint, managed.NotAfter } });
        });

        certs.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, ILogger<Program> logger, HttpContext context) =>
        {
            var cert = await db.ManagedCertificates.FindAsync(id);
            if (cert == null) return Results.NotFound(new { success = false, errors = new[] { "Certificate not found" } });

            db.ManagedCertificates.Remove(cert);
            await db.SaveChangesAsync();

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var actorId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            await audit.LogAsync("Certificate", "CERT_DELETED", actorId != null ? Guid.Parse(actorId) : (Guid?)null, null, ip,
                "ManagedCertificate", id.ToString(), new { cert.SubjectCN, cert.Thumbprint });

            logger.LogInformation("Certificate '{SubjectCN}' deleted", cert.SubjectCN);

            return Results.Ok(new { success = true });
        });
    }
}

public record ImportCertificateRequest(
    string PemCertificate,
    Guid? DeviceId,
    Guid? FolderId,
    string? Notes,
    string? Source);
