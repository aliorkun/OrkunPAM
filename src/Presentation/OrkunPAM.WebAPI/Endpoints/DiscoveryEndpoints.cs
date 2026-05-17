using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class DiscoveryEndpoints
{
    public static void MapDiscoveryEndpoints(this IEndpointRouteBuilder app)
    {
        var jobs = app.MapGroup("/api/v1/vault/discovery-jobs").WithTags("Discovery");

        jobs.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.DiscoveryJobs
                .Select(j => new
                {
                    j.Id, j.Name,
                    Type = j.DiscoveryType.ToString(),
                    j.Schedule, j.LastRunAtUtc, j.IsEnabled
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        jobs.MapPost("/", async (CreateDiscoveryJobRequest req, OrkunPamDbContext db) =>
        {
            var job = new DiscoveryJob
            {
                Name = req.Name,
                DiscoveryType = req.DiscoveryType,
                TargetScopeJson = req.TargetScope,
                Schedule = req.Schedule,
                CreatedBy = req.CreatedBy
            };
            db.DiscoveryJobs.Add(job);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/vault/discovery-jobs/{job.Id}",
                new { success = true, data = new { job.Id, job.Name } });
        });

        jobs.MapPost("/{id:guid}/run", async (Guid id, OrkunPamDbContext db,
            IDiscoveryService discoveryService, IAuditService audit,
            ILogger<Program> logger, HttpContext context) =>
        {
            var job = await db.DiscoveryJobs.FindAsync(id);
            if (job == null) return Results.NotFound(new { success = false, errors = new[] { "Job not found" } });

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Discovery", "DISCOVERY_SCAN_STARTED", null, null, ip,
                "DiscoveryJob", id.ToString(), new { job.Name, Type = job.DiscoveryType.ToString() });

            var scanResult = await discoveryService.RunScanAsync(job.DiscoveryType, job.TargetScopeJson);

            job.LastRunAtUtc = DateTime.UtcNow;
            job.LastRunResult = scanResult.Message;

            var newAccounts = scanResult.Accounts
                .Where(a => a.AccountType != "Error")
                .Select(a => new DiscoveredAccount
                {
                    DiscoveryJobId = id,
                    AccountName = a.AccountName,
                    AccountType = a.AccountType
                }).ToList();

            if (newAccounts.Count > 0)
                db.DiscoveredAccounts.AddRange(newAccounts);

            await db.SaveChangesAsync();

            await audit.LogAsync("Discovery", "DISCOVERY_SCAN_COMPLETED", null, null, ip,
                "DiscoveryJob", id.ToString(), new { job.Name, AccountsFound = newAccounts.Count, scanResult.Message });

            logger.LogInformation("Discovery job '{Name}' completed. Found {Count} accounts", job.Name, newAccounts.Count);

            return Results.Ok(new
            {
                success = scanResult.Success,
                data = new
                {
                    job.LastRunAtUtc,
                    accountsFound = newAccounts.Count,
                    result = scanResult.Message,
                    accounts = scanResult.Accounts.Take(50)
                }
            });
        });

        var accounts = app.MapGroup("/api/v1/vault/discovered-accounts").WithTags("Discovery");

        accounts.MapGet("/", async (OrkunPamDbContext db, string? status) =>
        {
            var query = db.DiscoveredAccounts.AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<TakeoverStatus>(status, true, out var ts))
                query = query.Where(a => a.TakeoverStatus == ts);

            var discovered = await query
                .OrderByDescending(a => a.DiscoveredAtUtc)
                .ToListAsync();

            // Vault deduplication: check which account names already exist in Credentials
            var accountNames = discovered.Select(a => a.AccountName).Distinct().ToList();
            var inVaultNames = await db.Credentials
                .Where(c => c.Username != null && accountNames.Contains(c.Username))
                .Select(c => c.Username!)
                .ToHashSetAsync();

            var list = discovered.Select(a => new
            {
                a.Id, a.DiscoveryJobId, a.DeviceId, a.AccountName, a.AccountType,
                a.DiscoveredAtUtc, Status = a.TakeoverStatus.ToString(), a.LinkedCredentialId,
                InVault = inVaultNames.Contains(a.AccountName)
            });

            return Results.Ok(new { success = true, data = list });
        });

        // Bulk import: onboard multiple discovered accounts to vault in one call
        accounts.MapPost("/bulk-import", async (BulkImportRequest req, OrkunPamDbContext db,
            IAuditService audit, ILogger<Program> logger, HttpContext context) =>
        {
            if (req.AccountIds == null || req.AccountIds.Count == 0)
                return Results.BadRequest(new { success = false, errors = new[] { "No accounts selected" } });

            var folder = await db.VaultFolders.FindAsync(req.FolderId);
            if (folder == null)
                return Results.NotFound(new { success = false, errors = new[] { "Folder not found" } });

            var toImport = await db.DiscoveredAccounts
                .Where(a => req.AccountIds.Contains(a.Id) && a.TakeoverStatus == TakeoverStatus.Pending)
                .ToListAsync();

            var imported = 0;
            var skipped = 0;
            foreach (var account in toImport)
            {
                var alreadyExists = await db.Credentials.AnyAsync(
                    c => c.Username == account.AccountName && c.FolderId == req.FolderId);
                if (alreadyExists) { skipped++; continue; }

                var credential = new Credential
                {
                    FolderId = req.FolderId,
                    Name = account.AccountName,
                    CredentialType = CredentialType.UserPassword,
                    Username = account.AccountName,
                    DeviceId = account.DeviceId,
                    IsDiscovered = true,
                    IsTakenOver = true,
                    Status = CredentialStatus.Active,
                    KeyVersion = 1
                };
                db.Credentials.Add(credential);
                account.TakeoverStatus = TakeoverStatus.TakenOver;
                account.LinkedCredentialId = credential.Id;
                imported++;
            }

            await db.SaveChangesAsync();

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var actorId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            await audit.LogAsync("Discovery", "DISCOVERY_BULK_IMPORTED", actorId != null ? Guid.Parse(actorId) : (Guid?)null, null, ip,
                "Vault", req.FolderId.ToString(), new { Imported = imported, Skipped = skipped, FolderId = req.FolderId });

            logger.LogInformation("Bulk import: {Imported} accounts imported to folder {FolderId}, {Skipped} skipped (duplicates)",
                imported, req.FolderId, skipped);

            return Results.Ok(new { success = true, data = new { imported, skipped, message = $"{imported} accounts imported to vault. {skipped} skipped (already exist)." } });
        });

        accounts.MapPost("/{id:guid}/takeover", async (Guid id, TakeoverRequest req,
            OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var account = await db.DiscoveredAccounts.FindAsync(id);
            if (account == null) return Results.NotFound(new { success = false, errors = new[] { "Account not found" } });

            if (account.TakeoverStatus != TakeoverStatus.Pending)
                return Results.Conflict(new { success = false, errors = new[] { $"Account already {account.TakeoverStatus}" } });

            var credential = new Credential
            {
                FolderId = req.FolderId,
                Name = $"{account.AccountName}@{account.DeviceId}",
                CredentialType = CredentialType.UserPassword,
                Username = account.AccountName,
                DeviceId = account.DeviceId,
                IsDiscovered = true,
                IsTakenOver = true,
                Status = CredentialStatus.Active,
                KeyVersion = 1
            };

            db.Credentials.Add(credential);
            account.TakeoverStatus = TakeoverStatus.TakenOver;
            account.LinkedCredentialId = credential.Id;
            await db.SaveChangesAsync();

            logger.LogInformation("Account '{AccountName}' taken over -> credential {CredId}",
                account.AccountName, credential.Id);

            return Results.Ok(new
            {
                success = true,
                data = new { credentialId = credential.Id, account.AccountName, message = "Account taken over. Set password via rotation." }
            });
        });

        accounts.MapPost("/{id:guid}/ignore", async (Guid id, OrkunPamDbContext db) =>
        {
            var account = await db.DiscoveredAccounts.FindAsync(id);
            if (account == null) return Results.NotFound(new { success = false, errors = new[] { "Account not found" } });

            account.TakeoverStatus = TakeoverStatus.Ignored;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        var rotation = app.MapGroup("/api/v1/vault/rotation-policies").WithTags("Vault");

        rotation.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.RotationPolicies
                .Select(r => new
                {
                    r.Id, r.Name, r.IntervalDays,
                    Connector = r.ConnectorType.ToString(),
                    r.RotateOnCheckIn, r.NotifyBeforeDays,
                    r.RetryCount, r.RetryIntervalMinutes
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        rotation.MapPost("/", async (CreateRotationPolicyRequest req, OrkunPamDbContext db) =>
        {
            var policy = new RotationPolicy
            {
                Name = req.Name,
                IntervalDays = req.IntervalDays ?? 30,
                PasswordComplexityJson = req.PasswordComplexityJson,
                ConnectorType = req.ConnectorType,
                RotateOnCheckIn = req.RotateOnCheckIn,
                NotifyBeforeDays = req.NotifyBeforeDays ?? 3,
                RetryCount = req.RetryCount ?? 3,
                RetryIntervalMinutes = req.RetryIntervalMinutes ?? 15
            };
            db.RotationPolicies.Add(policy);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/vault/rotation-policies/{policy.Id}",
                new { success = true, data = new { policy.Id, policy.Name } });
        });

        app.MapPost("/api/v1/vault/credentials/{id:guid}/rotate", async (Guid id,
            OrkunPamDbContext db, OrkunPAM.Persistence.Services.IRotationService rotationService,
            IVaultEncryptionService vault, ILogger<Program> logger) =>
        {
            var cred = await db.Credentials.FirstOrDefaultAsync(c => c.Id == id);
            if (cred == null) return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var connector = RotationConnector.Ldap;
            if (cred.RotationPolicyId.HasValue)
            {
                var policy = await db.RotationPolicies.FindAsync(cred.RotationPolicyId.Value);
                if (policy != null) connector = policy.ConnectorType;
            }

            string? currentPassword = null;
            if (cred.PasswordEnc != null)
            {
                var decResult = vault.DecryptString(cred.PasswordEnc);
                if (decResult.IsSuccess) currentPassword = decResult.Value;
            }

            var newPassword = rotationService.GeneratePassword();

            var device = cred.DeviceId.HasValue ? await db.Devices.FindAsync(cred.DeviceId.Value) : null;
            var host = device?.IpAddress ?? device?.Hostname ?? "localhost";
            var port = connector switch
            {
                RotationConnector.Ldap => 636,
                RotationConnector.SqlServer => 1433,
                RotationConnector.MySql => 3306,
                RotationConnector.PostgreSql => 5432,
                RotationConnector.Ssh => 22,
                RotationConnector.WinRm => 5985,
                _ => 0
            };

            var target = new OrkunPAM.Application.Contracts.RotationTarget(
                host, port, cred.Username ?? "", currentPassword, newPassword);

            var result = await rotationService.RotatePasswordAsync(connector, target);

            if (result.Success)
            {
                var encResult = vault.EncryptString(newPassword);
                if (encResult.IsSuccess)
                    cred.PasswordEnc = encResult.Value;

                cred.LastRotatedAtUtc = DateTime.UtcNow;
                cred.NextRotationAtUtc = cred.RotationPolicyId != null
                    ? DateTime.UtcNow.AddDays(30)
                    : null;
                cred.Version++;
                await db.SaveChangesAsync();
            }

            logger.LogInformation("Credential '{Name}' rotation {Status} via {Connector}. Version: {Version}",
                cred.Name, result.Success ? "succeeded" : "failed", connector, cred.Version);

            return Results.Ok(new
            {
                success = result.Success,
                data = new
                {
                    cred.Id, cred.Name, cred.Version,
                    connector = connector.ToString(),
                    cred.LastRotatedAtUtc, cred.NextRotationAtUtc,
                    responseTimeMs = result.ResponseTimeMs,
                    message = result.Message
                }
            });
        }).WithTags("Vault");
    }
}

public record CreateDiscoveryJobRequest(string Name, DiscoveryType DiscoveryType, string? TargetScope, string? Schedule, Guid? CreatedBy);
public record TakeoverRequest(Guid FolderId);
public record BulkImportRequest(List<Guid> AccountIds, Guid FolderId);
public record CreateRotationPolicyRequest(string Name, int? IntervalDays, string? PasswordComplexityJson,
    RotationConnector ConnectorType, bool RotateOnCheckIn, int? NotifyBeforeDays, int? RetryCount, int? RetryIntervalMinutes);
