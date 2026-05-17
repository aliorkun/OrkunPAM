using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CloudPamEndpoints
{
    public static void MapCloudPamEndpoints(this IEndpointRouteBuilder app)
    {
        var cloud = app.MapGroup("/api/v1/cloud").WithTags("CloudPAM").RequireAuthorization("AdminPolicy");

        // === Dashboard ===
        cloud.MapGet("/dashboard", async (OrkunPamDbContext db) =>
        {
            var accounts = await db.CloudAccounts.Where(a => a.IsEnabled).ToListAsync();
            var resources = await db.CloudResources.ToListAsync();
            var jit = await db.CloudJitRequests.ToListAsync();

            var byProvider = accounts.GroupBy(a => a.Provider).Select(g => new
            {
                provider = g.Key,
                accounts = g.Count(),
                resources = resources.Count(r => r.Provider == g.Key),
                activeJit = jit.Count(j => j.Status == "Active" && resources.Any(r => r.Id.ToString() == j.CloudResourceId.ToString() && r.Provider == g.Key))
            }).ToList();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    totalAccounts = accounts.Count,
                    totalResources = resources.Count,
                    activeJitRequests = jit.Count(j => j.Status == "Active"),
                    pendingJitRequests = jit.Count(j => j.Status == "Pending"),
                    byProvider,
                    recentJit = jit.OrderByDescending(j => j.RequestedAtUtc).Take(5).Select(j => new
                    {
                        j.Id, j.RequestedByUsername, j.Permission, j.Status, j.RequestedAtUtc, j.ExpiresAtUtc,
                        resourceId = j.CloudResourceId
                    })
                }
            });
        });

        // === Cloud Accounts ===
        cloud.MapGet("/accounts", async (OrkunPamDbContext db) =>
        {
            var list = await db.CloudAccounts
                .OrderBy(a => a.Provider).ThenBy(a => a.Name)
                .Select(a => new
                {
                    a.Id, a.Name, a.Provider, a.AccountIdentifier, a.Region,
                    a.IsEnabled, a.ResourceCount, a.LastSyncAtUtc, a.LastSyncError, a.CreatedAtUtc
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        cloud.MapPost("/accounts", async (CreateCloudAccountRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, HttpContext ctx, ILogger<Program> logger) =>
        {
            string? accessKeyEnc = null;
            string? secretKeyEnc = null;

            if (!string.IsNullOrEmpty(req.AccessKeyId))
            {
                var enc = vault.EncryptString(req.AccessKeyId, "CloudAccessKey");
                if (enc.IsFailure) return Results.Problem("Failed to protect access key");
                accessKeyEnc = Convert.ToBase64String(enc.Value);
            }
            if (!string.IsNullOrEmpty(req.SecretKey))
            {
                var enc = vault.EncryptString(req.SecretKey, "CloudSecretKey");
                if (enc.IsFailure) return Results.Problem("Failed to protect secret key");
                secretKeyEnc = Convert.ToBase64String(enc.Value);
            }

            var account = new CloudAccount
            {
                Name = req.Name,
                Provider = req.Provider,
                AccountIdentifier = req.AccountIdentifier,
                Region = req.Region,
                AccessKeyIdEnc = accessKeyEnc,
                SecretKeyEnc = secretKeyEnc,
                AdditionalConfigJson = req.AdditionalConfigJson
            };
            db.CloudAccounts.Add(account);

            var actor = ctx.User.Identity?.Name ?? "system";
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudAccountCreated",
                ActorUsername = actor,
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "CloudAccount",
                TargetId = account.Id.ToString(),
                Details = $"provider={req.Provider} account={req.AccountIdentifier}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();

            logger.LogInformation("Cloud account created: {Provider} {Account}", req.Provider, req.AccountIdentifier);
            return Results.Created($"/api/v1/cloud/accounts/{account.Id}",
                new { success = true, data = new { account.Id, account.Name, account.Provider } });
        });

        cloud.MapPut("/accounts/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var account = await db.CloudAccounts.FindAsync(id);
            if (account == null) return Results.NotFound(new { success = false });
            account.IsEnabled = !account.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { id, account.IsEnabled } });
        });

        cloud.MapDelete("/accounts/{id:guid}", async (Guid id, OrkunPamDbContext db,
            HttpContext ctx) =>
        {
            var account = await db.CloudAccounts.FindAsync(id);
            if (account == null) return Results.NotFound(new { success = false });

            var actor = ctx.User.Identity?.Name ?? "system";
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudAccountDeleted",
                ActorUsername = actor,
                TargetType = "CloudAccount",
                TargetId = id.ToString(),
                Details = $"provider={account.Provider} account={account.AccountIdentifier}",
                Outcome = AuditOutcome.Success
            });
            db.CloudAccounts.Remove(account);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Simulate cloud resource discovery sync
        cloud.MapPost("/accounts/{id:guid}/sync", async (Guid id, OrkunPamDbContext db,
            HttpContext ctx, ILogger<Program> logger) =>
        {
            var account = await db.CloudAccounts.FindAsync(id);
            if (account == null) return Results.NotFound(new { success = false });

            // Simulate discovery: generate sample resources based on provider
            var existing = await db.CloudResources.Where(r => r.CloudAccountId == id).ToListAsync();
            var discovered = GenerateSampleResources(account);

            int added = 0;
            foreach (var res in discovered)
            {
                if (!existing.Any(e => e.NativeId == res.NativeId))
                {
                    db.CloudResources.Add(res);
                    added++;
                }
            }

            account.LastSyncAtUtc = DateTime.UtcNow;
            account.ResourceCount = existing.Count + added;
            account.LastSyncError = null;
            await db.SaveChangesAsync();

            var actor = ctx.User.Identity?.Name ?? "system";
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudAccountSynced",
                ActorUsername = actor,
                TargetType = "CloudAccount",
                TargetId = id.ToString(),
                Details = $"provider={account.Provider} discovered={added} total={account.ResourceCount}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();

            logger.LogInformation("Cloud sync: {Provider} account {Id}, {Added} new resources", account.Provider, id, added);
            return Results.Ok(new
            {
                success = true,
                data = new { accountId = id, newResources = added, totalResources = account.ResourceCount, syncedAt = account.LastSyncAtUtc }
            });
        });

        // === Cloud Resources ===
        cloud.MapGet("/resources", async (OrkunPamDbContext db,
            string? provider, string? type, string? accountId) =>
        {
            var q = db.CloudResources.AsQueryable();
            if (!string.IsNullOrEmpty(provider)) q = q.Where(r => r.Provider == provider);
            if (!string.IsNullOrEmpty(type)) q = q.Where(r => r.ResourceType == type);
            if (Guid.TryParse(accountId, out var aid)) q = q.Where(r => r.CloudAccountId == aid);

            var list = await q.OrderBy(r => r.Provider).ThenBy(r => r.ResourceType).ThenBy(r => r.Name)
                .Select(r => new
                {
                    r.Id, r.Provider, r.NativeId, r.Name, r.ResourceType, r.Region,
                    r.Status, r.IpAddress, r.IsEnabled, r.LastSeenAtUtc, r.CloudAccountId
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        cloud.MapPut("/resources/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var res = await db.CloudResources.FindAsync(id);
            if (res == null) return Results.NotFound(new { success = false });
            res.IsEnabled = !res.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { id, res.IsEnabled } });
        });

        // === JIT Access Requests ===
        cloud.MapGet("/jit", async (OrkunPamDbContext db, string? status) =>
        {
            var q = db.CloudJitRequests
                .Include(j => j.CloudResource)
                .AsQueryable();
            if (!string.IsNullOrEmpty(status)) q = q.Where(j => j.Status == status);

            var list = await q.OrderByDescending(j => j.RequestedAtUtc)
                .Select(j => new
                {
                    j.Id, j.RequestedByUsername, j.Permission, j.Justification, j.Status,
                    j.RequestedAtUtc, j.DurationMinutes, j.ExpiresAtUtc, j.GrantedAtUtc,
                    j.ApprovedByUsername, j.RevokedAtUtc, j.RevokeReason, j.TicketNumber,
                    resource = j.CloudResource == null ? null : new
                    {
                        j.CloudResource.Id, j.CloudResource.Name, j.CloudResource.Provider,
                        j.CloudResource.ResourceType, j.CloudResource.Region, j.CloudResource.NativeId
                    }
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        cloud.MapPost("/jit", async (CreateCloudJitRequest req, OrkunPamDbContext db,
            HttpContext ctx, ILogger<Program> logger) =>
        {
            var resource = await db.CloudResources.FindAsync(req.CloudResourceId);
            if (resource == null || !resource.IsEnabled)
                return Results.BadRequest(new { success = false, errors = new[] { "Cloud resource not found or disabled" } });

            var actor = ctx.User.Identity?.Name ?? "unknown";
            var jit = new CloudJitRequest
            {
                RequestedByUserId = Guid.Empty,
                RequestedByUsername = actor,
                CloudResourceId = req.CloudResourceId,
                Permission = req.Permission,
                Justification = req.Justification,
                DurationMinutes = req.DurationMinutes <= 0 ? 60 : req.DurationMinutes,
                Status = "Pending",
                TicketNumber = req.TicketNumber
            };
            db.CloudJitRequests.Add(jit);

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudJitRequested",
                ActorUsername = actor,
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "CloudResource",
                TargetId = req.CloudResourceId.ToString(),
                Details = $"permission={req.Permission} duration={req.DurationMinutes}m resource={resource.Name}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();

            logger.LogInformation("Cloud JIT requested by {User} for {Resource}", actor, resource.Name);
            return Results.Created($"/api/v1/cloud/jit/{jit.Id}",
                new { success = true, data = new { jit.Id, jit.Status, jit.RequestedAtUtc } });
        });

        cloud.MapPut("/jit/{id:guid}/approve", async (Guid id, ApproveCloudJitRequest req,
            OrkunPamDbContext db, HttpContext ctx, ILogger<Program> logger) =>
        {
            var jit = await db.CloudJitRequests.Include(j => j.CloudResource).FirstOrDefaultAsync(j => j.Id == id);
            if (jit == null) return Results.NotFound(new { success = false });
            if (jit.Status != "Pending")
                return Results.BadRequest(new { success = false, errors = new[] { "Request is not in Pending state" } });

            var actor = ctx.User.Identity?.Name ?? "system";
            jit.Status = "Active";
            jit.ApprovedByUsername = actor;
            jit.GrantedAtUtc = DateTime.UtcNow;
            jit.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(jit.DurationMinutes);
            jit.CloudGrantReference = $"grant-{Guid.NewGuid():N}";

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudJitApproved",
                ActorUsername = actor,
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "CloudJitRequest",
                TargetId = id.ToString(),
                Details = $"user={jit.RequestedByUsername} resource={jit.CloudResource?.Name} expires={jit.ExpiresAtUtc:u}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();

            logger.LogInformation("Cloud JIT approved: {Id} by {Actor}", id, actor);
            return Results.Ok(new
            {
                success = true,
                data = new { jit.Id, jit.Status, jit.ExpiresAtUtc, jit.CloudGrantReference }
            });
        });

        cloud.MapPut("/jit/{id:guid}/deny", async (Guid id, DenyCloudJitRequest req,
            OrkunPamDbContext db, HttpContext ctx) =>
        {
            var jit = await db.CloudJitRequests.FindAsync(id);
            if (jit == null) return Results.NotFound(new { success = false });
            if (jit.Status != "Pending")
                return Results.BadRequest(new { success = false, errors = new[] { "Request is not in Pending state" } });

            var actor = ctx.User.Identity?.Name ?? "system";
            jit.Status = "Denied";
            jit.RevokeReason = req.Reason ?? "Denied by admin";
            jit.RevokedAtUtc = DateTime.UtcNow;

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudJitDenied",
                ActorUsername = actor,
                TargetType = "CloudJitRequest",
                TargetId = id.ToString(),
                Details = $"user={jit.RequestedByUsername} reason={jit.RevokeReason}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { jit.Id, jit.Status } });
        });

        cloud.MapPut("/jit/{id:guid}/revoke", async (Guid id, RevokeCloudJitRequest req,
            OrkunPamDbContext db, HttpContext ctx, ILogger<Program> logger) =>
        {
            var jit = await db.CloudJitRequests.Include(j => j.CloudResource).FirstOrDefaultAsync(j => j.Id == id);
            if (jit == null) return Results.NotFound(new { success = false });
            if (jit.Status != "Active")
                return Results.BadRequest(new { success = false, errors = new[] { "Request is not Active" } });

            var actor = ctx.User.Identity?.Name ?? "system";
            jit.Status = "Revoked";
            jit.RevokedAtUtc = DateTime.UtcNow;
            jit.RevokeReason = req.Reason ?? "Revoked by admin";

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "CloudPAM",
                EventType = "CloudJitRevoked",
                ActorUsername = actor,
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType = "CloudJitRequest",
                TargetId = id.ToString(),
                Details = $"user={jit.RequestedByUsername} resource={jit.CloudResource?.Name} reason={jit.RevokeReason}",
                Outcome = AuditOutcome.Success
            });
            await db.SaveChangesAsync();

            logger.LogInformation("Cloud JIT revoked: {Id} by {Actor}", id, actor);
            return Results.Ok(new { success = true, data = new { jit.Id, jit.Status, jit.RevokedAtUtc } });
        });
    }

    private static List<CloudResource> GenerateSampleResources(CloudAccount account)
    {
        var now = DateTime.UtcNow;
        return account.Provider switch
        {
            "AWS" => new List<CloudResource>
            {
                new() { CloudAccountId = account.Id, Provider = "AWS", NativeId = $"arn:aws:ec2:{account.Region ?? "us-east-1"}:{account.AccountIdentifier}:instance/i-0a1b2c3d4e5f60001", Name = "prod-web-01", ResourceType = "EC2Instance", Region = account.Region ?? "us-east-1", Status = "Running", IpAddress = "10.0.1.10", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "AWS", NativeId = $"arn:aws:ec2:{account.Region ?? "us-east-1"}:{account.AccountIdentifier}:instance/i-0a1b2c3d4e5f60002", Name = "prod-db-01", ResourceType = "EC2Instance", Region = account.Region ?? "us-east-1", Status = "Running", IpAddress = "10.0.1.20", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "AWS", NativeId = $"arn:aws:iam::{account.AccountIdentifier}:user/svc-deploy", Name = "svc-deploy", ResourceType = "IAMUser", Region = "global", Status = "Active", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "AWS", NativeId = $"arn:aws:iam::{account.AccountIdentifier}:role/AdminRole", Name = "AdminRole", ResourceType = "IAMRole", Region = "global", Status = "Active", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "AWS", NativeId = $"arn:aws:s3:::{account.AccountIdentifier}-data-bucket", Name = $"{account.AccountIdentifier}-data-bucket", ResourceType = "S3Bucket", Region = "global", Status = "Available", LastSeenAtUtc = now },
            },
            "Azure" => new List<CloudResource>
            {
                new() { CloudAccountId = account.Id, Provider = "Azure", NativeId = $"/subscriptions/{account.AccountIdentifier}/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/prod-vm-01", Name = "prod-vm-01", ResourceType = "VirtualMachine", Region = account.Region ?? "eastus", Status = "Running", IpAddress = "10.1.0.10", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "Azure", NativeId = $"/subscriptions/{account.AccountIdentifier}/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/prod-vm-02", Name = "prod-vm-02", ResourceType = "VirtualMachine", Region = account.Region ?? "eastus", Status = "Stopped", IpAddress = "10.1.0.11", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "Azure", NativeId = $"/subscriptions/{account.AccountIdentifier}/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/prod-kv", Name = "prod-kv", ResourceType = "KeyVault", Region = account.Region ?? "eastus", Status = "Available", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "Azure", NativeId = $"spn-{account.AccountIdentifier}-deploy", Name = "svc-principal-deploy", ResourceType = "ServicePrincipal", Region = "global", Status = "Active", LastSeenAtUtc = now },
            },
            "GCP" => new List<CloudResource>
            {
                new() { CloudAccountId = account.Id, Provider = "GCP", NativeId = $"projects/{account.AccountIdentifier}/zones/us-central1-a/instances/prod-instance-01", Name = "prod-instance-01", ResourceType = "GCEInstance", Region = account.Region ?? "us-central1", Status = "RUNNING", IpAddress = "10.2.0.10", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "GCP", NativeId = $"projects/{account.AccountIdentifier}/zones/us-central1-a/instances/prod-instance-02", Name = "prod-instance-02", ResourceType = "GCEInstance", Region = account.Region ?? "us-central1", Status = "TERMINATED", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "GCP", NativeId = $"projects/{account.AccountIdentifier}/serviceAccounts/svc-deploy@{account.AccountIdentifier}.iam.gserviceaccount.com", Name = "svc-deploy", ResourceType = "ServiceAccount", Region = "global", Status = "Active", LastSeenAtUtc = now },
                new() { CloudAccountId = account.Id, Provider = "GCP", NativeId = $"projects/{account.AccountIdentifier}/buckets/{account.AccountIdentifier}-storage", Name = $"{account.AccountIdentifier}-storage", ResourceType = "GCSBucket", Region = account.Region ?? "us-central1", Status = "Available", LastSeenAtUtc = now },
            },
            _ => new List<CloudResource>()
        };
    }
}

public record CreateCloudAccountRequest(
    string Name,
    string Provider,
    string AccountIdentifier,
    string? Region,
    string? AccessKeyId,
    string? SecretKey,
    string? AdditionalConfigJson);

public record CreateCloudJitRequest(
    Guid CloudResourceId,
    string Permission,
    string Justification,
    int DurationMinutes,
    string? TicketNumber);

public record ApproveCloudJitRequest(string? Comment);
public record DenyCloudJitRequest(string? Reason);
public record RevokeCloudJitRequest(string? Reason);
