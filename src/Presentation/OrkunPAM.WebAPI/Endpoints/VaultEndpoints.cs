using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class VaultEndpoints
{
    public static void MapVaultEndpoints(this WebApplication app)
    {
        // === Folders ===
        var folders = app.MapGroup("/api/v1/vault/folders").WithTags("Vault");

        folders.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.VaultFolders
                .Where(f => !f.IsPersonalVault)
                .Select(f => new
                {
                    f.Id, f.Name, f.Description, f.ParentFolderId,
                    CredentialCount = f.Credentials.Count,
                    ChildCount = f.ChildFolders.Count
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        folders.MapPost("/", async (CreateFolderRequest req, OrkunPamDbContext db) =>
        {
            var folder = new VaultFolder
            {
                Name = req.Name,
                Description = req.Description,
                ParentFolderId = req.ParentFolderId
            };
            db.VaultFolders.Add(folder);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/vault/folders/{folder.Id}", new { success = true, data = new { folder.Id, folder.Name } });
        });

        folders.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var f = await db.VaultFolders
                .Include(f => f.ChildFolders)
                .Include(f => f.Permissions)
                .FirstOrDefaultAsync(f => f.Id == id);
            if (f == null) return Results.NotFound(new { success = false, errors = new[] { "Folder not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    f.Id, f.Name, f.Description, f.ParentFolderId, f.IsPersonalVault,
                    Children = f.ChildFolders.Select(c => new { c.Id, c.Name }),
                    Permissions = f.Permissions.Select(p => new
                    {
                        p.PrincipalType, p.PrincipalId,
                        Level = p.PermissionLevel.ToString(),
                        p.CanShare
                    })
                }
            });
        });

        folders.MapGet("/{id:guid}/credentials", async (Guid id, OrkunPamDbContext db) =>
        {
            var creds = await db.Credentials
                .Where(c => c.FolderId == id)
                .Select(c => new
                {
                    c.Id, c.Name, c.Description, c.Username,
                    Type = c.CredentialType.ToString(),
                    Status = c.Status.ToString(),
                    c.DeviceId, c.Tags,
                    c.LastRotatedAtUtc, c.NextRotationAtUtc,
                    c.CheckedOutByUserId, c.CheckOutExpiresUtc,
                    c.RequiresApproval
                }).ToListAsync();
            return Results.Ok(new { success = true, data = creds });
        });

        // === Credentials ===
        var creds = app.MapGroup("/api/v1/vault/credentials").WithTags("Vault");

        creds.MapGet("/", async (OrkunPamDbContext db, string? search, string? type, int page = 1, int pageSize = 50) =>
        {
            var query = db.Credentials.AsQueryable();

            if (!string.IsNullOrEmpty(search))
                query = query.Where(c => c.Name.Contains(search) || c.Username!.Contains(search) || c.Tags!.Contains(search));

            if (!string.IsNullOrEmpty(type) && Enum.TryParse<CredentialType>(type, true, out var ct))
                query = query.Where(c => c.CredentialType == ct);

            var total = await query.CountAsync();
            var list = await query
                .OrderBy(c => c.Name)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(c => new
                {
                    c.Id, c.Name, c.Description, c.Username, c.FolderId,
                    Type = c.CredentialType.ToString(),
                    Status = c.Status.ToString(),
                    c.DeviceId, c.Tags, c.IsDiscovered, c.IsTakenOver,
                    c.LastRotatedAtUtc, c.NextRotationAtUtc,
                    IsCheckedOut = c.CheckedOutByUserId != null,
                    c.CheckedOutByUserId, c.CheckOutExpiresUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        creds.MapPost("/", async (CreateCredentialRequest req, OrkunPamDbContext db, IVaultEncryptionService vault) =>
        {
            byte[]? encPassword = null;
            if (!string.IsNullOrEmpty(req.Password))
            {
                var encResult = vault.EncryptString(req.Password);
                if (encResult.IsFailure)
                    return Results.BadRequest(new { success = false, errors = new[] { $"Encryption failed: {encResult.Error.Message}" } });
                encPassword = encResult.Value;
            }

            var cred = new Credential
            {
                FolderId = req.FolderId,
                Name = req.Name,
                Description = req.Description,
                CredentialType = req.Type,
                Username = req.Username,
                PasswordEnc = encPassword,
                DeviceId = req.DeviceId,
                Tags = req.Tags,
                MaxCheckoutMinutes = req.MaxCheckoutMinutes ?? 60,
                RequiresApproval = req.RequiresApproval,
                KeyVersion = 1
            };

            db.Credentials.Add(cred);
            await db.SaveChangesAsync();

            return Results.Created($"/api/v1/vault/credentials/{cred.Id}",
                new { success = true, data = new { cred.Id, cred.Name, cred.Username } });
        });

        creds.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var c = await db.Credentials.FindAsync(id);
            if (c == null) return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    c.Id, c.Name, c.Description, c.Username, c.FolderId,
                    Type = c.CredentialType.ToString(),
                    Status = c.Status.ToString(),
                    c.DeviceId, c.Tags,
                    c.IsDiscovered, c.IsTakenOver,
                    c.LastRotatedAtUtc, c.NextRotationAtUtc,
                    c.MaxCheckoutMinutes, c.RequiresApproval,
                    IsCheckedOut = c.CheckedOutByUserId != null,
                    c.CheckedOutByUserId, c.CheckedOutAtUtc, c.CheckOutExpiresUtc,
                    c.Version, c.CreatedAtUtc, c.UpdatedAtUtc
                    // NOTE: Password is NEVER returned here. Use /checkout to get it.
                }
            });
        });

        // === Check-Out (retrieve password) ===
        creds.MapPost("/{id:guid}/checkout", async (Guid id, CheckoutRequest req,
            OrkunPamDbContext db, IVaultEncryptionService vault, ILogger<Program> logger, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var cred = await db.Credentials.FindAsync(id);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var checkoutResult = cred.CheckOut(userId, req.DurationMinutes ?? cred.MaxCheckoutMinutes);
            if (checkoutResult.IsFailure)
                return Results.Conflict(new { success = false, errors = new[] { checkoutResult.Error.Message } });

            // Decrypt password
            string? password = null;
            if (cred.PasswordEnc != null)
            {
                var decResult = vault.DecryptString(cred.PasswordEnc);
                if (decResult.IsFailure)
                {
                    logger.LogError("Failed to decrypt credential {CredId}", id);
                    return Results.Problem("Decryption failed. Check server logs for details.");
                }
                password = decResult.Value;
            }

            // Record checkout history
            db.CheckOutHistories.Add(new CheckOutHistory
            {
                CredentialId = id,
                UserId = userId,
                CheckedOutAtUtc = DateTime.UtcNow,
                Reason = req.Reason,
                TicketNumber = req.TicketNumber
            });

            await db.SaveChangesAsync();

            logger.LogInformation("Credential '{Name}' checked out by user {UserId} (reason: {Reason})",
                cred.Name, userId, req.Reason);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    cred.Id, cred.Name, cred.Username,
                    password,
                    expiresAt = cred.CheckOutExpiresUtc
                }
            });
        }).RequireAuthorization();

        // === Check-In ===
        creds.MapPost("/{id:guid}/checkin", async (Guid id, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var cred = await db.Credentials.FindAsync(id);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var checkinResult = cred.CheckIn();
            if (checkinResult.IsFailure)
                return Results.Conflict(new { success = false, errors = new[] { checkinResult.Error.Message } });

            // Update history
            var history = await db.CheckOutHistories
                .Where(h => h.CredentialId == id && h.CheckedInAtUtc == null)
                .OrderByDescending(h => h.CheckedOutAtUtc)
                .FirstOrDefaultAsync();
            if (history != null)
                history.CheckedInAtUtc = DateTime.UtcNow;

            await db.SaveChangesAsync();
            logger.LogInformation("Credential '{Name}' checked in", cred.Name);

            return Results.Ok(new { success = true, message = $"Credential '{cred.Name}' checked in" });
        });

        // === Share Credential ===
        creds.MapPost("/{id:guid}/share", async (Guid id, ShareCredentialRequest req, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var cred = await db.Credentials.FindAsync(id);
            if (cred == null) return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var share = new CredentialShare
            {
                CredentialId = id,
                SharedByUserId = req.SharedByUserId,
                SharedToUserId = req.SharedToUserId,
                PermissionLevel = req.PermissionLevel,
                ExpiresAtUtc = req.ExpiresInHours.HasValue ? DateTime.UtcNow.AddHours(req.ExpiresInHours.Value) : null,
                MaxUseCount = req.MaxUseCount
            };

            db.CredentialShares.Add(share);
            await db.SaveChangesAsync();

            logger.LogInformation("Credential '{Name}' shared from user {From} to user {To} (expires: {Expires})",
                cred.Name, req.SharedByUserId, req.SharedToUserId, share.ExpiresAtUtc);

            return Results.Ok(new { success = true, data = new { share.Id, share.ExpiresAtUtc, share.MaxUseCount } });
        });

        creds.MapGet("/{id:guid}/shares", async (Guid id, OrkunPamDbContext db) =>
        {
            var shares = await db.CredentialShares
                .Where(s => s.CredentialId == id)
                .Select(s => new
                {
                    s.Id, s.SharedByUserId, s.SharedToUserId,
                    Level = s.PermissionLevel.ToString(),
                    s.ExpiresAtUtc, s.MaxUseCount, s.UseCount,
                    IsExpired = s.ExpiresAtUtc.HasValue && s.ExpiresAtUtc < DateTime.UtcNow,
                    IsExhausted = s.MaxUseCount.HasValue && s.UseCount >= s.MaxUseCount
                }).ToListAsync();
            return Results.Ok(new { success = true, data = shares });
        });

        // === Personal Vault ===
        creds.MapGet("/personal/{userId:guid}", async (Guid userId, OrkunPamDbContext db) =>
        {
            var folder = await db.VaultFolders
                .FirstOrDefaultAsync(f => f.IsPersonalVault && f.OwnerUserId == userId);

            if (folder == null)
            {
                // Auto-create personal vault
                folder = new VaultFolder
                {
                    Name = $"Personal Vault",
                    IsPersonalVault = true,
                    OwnerUserId = userId
                };
                db.VaultFolders.Add(folder);
                await db.SaveChangesAsync();
            }

            var creds2 = await db.Credentials
                .Where(c => c.FolderId == folder.Id)
                .Select(c => new { c.Id, c.Name, c.Username, Type = c.CredentialType.ToString(), c.Tags })
                .ToListAsync();

            return Results.Ok(new { success = true, data = new { folder.Id, folder.Name, credentials = creds2 } });
        });

        // === Password History ===
        creds.MapGet("/{id:guid}/history", async (Guid id, OrkunPamDbContext db) =>
        {
            var history = await db.CheckOutHistories
                .Where(h => h.CredentialId == id)
                .OrderByDescending(h => h.CheckedOutAtUtc)
                .Select(h => new
                {
                    h.Id, h.UserId, h.CheckedOutAtUtc, h.CheckedInAtUtc,
                    h.Reason, h.TicketNumber, h.WasAutoCheckedIn
                }).Take(100).ToListAsync();

            return Results.Ok(new { success = true, data = history });
        });

        // === Vault Permissions ===
        var perms = app.MapGroup("/api/v1/vault/permissions").WithTags("Vault");

        perms.MapGet("/{folderId:guid}", async (Guid folderId, OrkunPamDbContext db) =>
        {
            var list = await db.CredentialPermissions
                .Where(p => p.FolderId == folderId)
                .Select(p => new
                {
                    p.Id, p.PrincipalType, p.PrincipalId,
                    Level = p.PermissionLevel.ToString(),
                    p.CanShare
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        perms.MapPost("/{folderId:guid}", async (Guid folderId, SetPermissionRequest req, OrkunPamDbContext db) =>
        {
            var perm = new CredentialPermission
            {
                FolderId = folderId,
                PrincipalType = req.PrincipalType,
                PrincipalId = req.PrincipalId,
                PermissionLevel = req.Level,
                CanShare = req.CanShare
            };
            db.CredentialPermissions.Add(perm);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { perm.Id } });
        });
    }
}

public record CreateFolderRequest(string Name, string? Description, Guid? ParentFolderId);
public record CreateCredentialRequest(
    Guid FolderId, string Name, string? Description, CredentialType Type,
    string? Username, string? Password, Guid? DeviceId, string? Tags,
    int? MaxCheckoutMinutes, bool RequiresApproval);
public record CheckoutRequest(string? Reason, string? TicketNumber, int? DurationMinutes);
public record SetPermissionRequest(PrincipalType PrincipalType, Guid PrincipalId, PermissionLevel Level, bool CanShare);
public record ShareCredentialRequest(Guid SharedByUserId, Guid SharedToUserId, PermissionLevel PermissionLevel, int? ExpiresInHours, int? MaxUseCount);
