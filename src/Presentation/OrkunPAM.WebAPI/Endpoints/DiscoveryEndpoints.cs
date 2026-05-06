using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class DiscoveryEndpoints
{
    public static void MapDiscoveryEndpoints(this WebApplication app)
    {
        // === Discovery Jobs ===
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

        jobs.MapPost("/{id:guid}/run", async (Guid id, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var job = await db.DiscoveryJobs.FindAsync(id);
            if (job == null) return Results.NotFound(new { success = false, errors = new[] { "Job not found" } });

            // TODO: Actual discovery scan based on type (AD, WMI, SSH, etc.)
            job.LastRunAtUtc = DateTime.UtcNow;
            job.LastRunResult = "Scan completed (placeholder - will connect to targets in full implementation)";

            // Simulate finding some accounts
            var simulatedAccounts = new[]
            {
                new DiscoveredAccount { DiscoveryJobId = id, AccountName = "Administrator", AccountType = "LocalAdmin" },
                new DiscoveredAccount { DiscoveryJobId = id, AccountName = "svc_backup", AccountType = "ServiceAccount" }
            };

            db.DiscoveredAccounts.AddRange(simulatedAccounts);
            await db.SaveChangesAsync();

            logger.LogInformation("Discovery job '{Name}' completed. Found {Count} accounts", job.Name, simulatedAccounts.Length);

            return Results.Ok(new
            {
                success = true,
                data = new { job.LastRunAtUtc, accountsFound = simulatedAccounts.Length, job.LastRunResult }
            });
        });

        // === Discovered Accounts ===
        var accounts = app.MapGroup("/api/v1/vault/discovered-accounts").WithTags("Discovery");

        accounts.MapGet("/", async (OrkunPamDbContext db, string? status) =>
        {
            var query = db.DiscoveredAccounts.AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<TakeoverStatus>(status, true, out var ts))
                query = query.Where(a => a.TakeoverStatus == ts);

            var list = await query
                .OrderByDescending(a => a.DiscoveredAtUtc)
                .Select(a => new
                {
                    a.Id, a.DiscoveryJobId, a.DeviceId, a.AccountName, a.AccountType,
                    a.DiscoveredAtUtc, Status = a.TakeoverStatus.ToString(), a.LinkedCredentialId
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list });
        });

        accounts.MapPost("/{id:guid}/takeover", async (Guid id, TakeoverRequest req,
            OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var account = await db.DiscoveredAccounts.FindAsync(id);
            if (account == null) return Results.NotFound(new { success = false, errors = new[] { "Account not found" } });

            if (account.TakeoverStatus != TakeoverStatus.Pending)
                return Results.Conflict(new { success = false, errors = new[] { $"Account already {account.TakeoverStatus}" } });

            // Create managed credential from discovered account
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

            logger.LogInformation("Account '{AccountName}' taken over → credential {CredId}",
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

        // === Rotation Policies ===
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

        // Manual rotation trigger
        app.MapPost("/api/v1/vault/credentials/{id:guid}/rotate", async (Guid id,
            OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var cred = await db.Credentials.FindAsync(id);
            if (cred == null) return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            // TODO: Actually connect to target and change password via rotation connector
            cred.LastRotatedAtUtc = DateTime.UtcNow;
            cred.NextRotationAtUtc = cred.RotationPolicyId != null
                ? DateTime.UtcNow.AddDays(30) // Use policy interval
                : null;
            cred.Version++;

            await db.SaveChangesAsync();

            logger.LogInformation("Credential '{Name}' rotated (version {Version}). " +
                "TODO: connect to target via {Connector} and change password",
                cred.Name, cred.Version, "WinRM/SSH/LDAP");

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    cred.Id, cred.Name, cred.Version,
                    cred.LastRotatedAtUtc, cred.NextRotationAtUtc,
                    message = "Rotation triggered (placeholder - actual target connection in full implementation)"
                }
            });
        }).WithTags("Vault");
    }
}

public record CreateDiscoveryJobRequest(string Name, DiscoveryType DiscoveryType, string? TargetScope, string? Schedule, Guid? CreatedBy);
public record TakeoverRequest(Guid FolderId);
public record CreateRotationPolicyRequest(string Name, int? IntervalDays, string? PasswordComplexityJson,
    RotationConnector ConnectorType, bool RotateOnCheckIn, int? NotifyBeforeDays, int? RetryCount, int? RetryIntervalMinutes);
