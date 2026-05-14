using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class VaultEndpoints
{
    public static void MapVaultEndpoints(this IEndpointRouteBuilder app)
    {
        // === Folders ===
        var folders = app.MapGroup("/api/v1/vault/folders").WithTags("Vault").RequireAuthorization();

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
        var creds = app.MapGroup("/api/v1/vault/credentials").WithTags("Vault").RequireAuthorization();

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

            byte[]? encPrivateKey = null;
            if (!string.IsNullOrEmpty(req.PrivateKey))
            {
                var encPk = vault.EncryptString(req.PrivateKey);
                if (encPk.IsFailure)
                    return Results.BadRequest(new { success = false, errors = new[] { $"Encryption failed: {encPk.Error.Message}" } });
                encPrivateKey = encPk.Value;
            }

            var cred = new Credential
            {
                FolderId = req.FolderId,
                Name = req.Name,
                Description = req.Description,
                CredentialType = req.Type,
                Username = req.Username,
                PasswordEnc = encPassword,
                PrivateKeyEnc = encPrivateKey,
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

            if (cred.RequiresApproval)
            {
                var hasApproval = await db.ApprovalRequests
                    .AnyAsync(ar => ar.ResourceId == id
                                 && ar.RequesterId == userId
                                 && ar.Status == ApprovalStatus.Approved
                                 && (ar.ExpiresAtUtc == null || ar.ExpiresAtUtc > DateTime.UtcNow));
                if (!hasApproval)
                    return Results.Forbid();
            }

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

            // Decrypt private key (for SSH key credentials)
            string? privateKey = null;
            if (cred.PrivateKeyEnc != null)
            {
                var pkDec = vault.DecryptString(cred.PrivateKeyEnc);
                if (pkDec.IsFailure)
                {
                    logger.LogError("Failed to decrypt private key for credential {CredId}", id);
                    return Results.Problem("Decryption failed. Check server logs for details.");
                }
                privateKey = pkDec.Value;
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
                    privateKey,
                    expiresAt = cred.CheckOutExpiresUtc
                }
            });
        }).RequireAuthorization();

        // === Check-In ===
        creds.MapPost("/{id:guid}/checkin", async (Guid id, OrkunPamDbContext db, ILogger<Program> logger, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var cred = await db.Credentials.FindAsync(id);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            if (cred.CheckedOutByUserId != userId)
                return Results.Forbid();

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
            logger.LogInformation("Credential '{Name}' checked in by user {UserId}", cred.Name, userId);

            return Results.Ok(new { success = true, message = $"Credential '{cred.Name}' checked in" });
        }).RequireAuthorization();

        // === Share Credential ===
        creds.MapPost("/{id:guid}/share", async (Guid id, ShareCredentialRequest req, OrkunPamDbContext db, ILogger<Program> logger, HttpContext context) =>
        {
            var sharedByIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (sharedByIdStr == null || !Guid.TryParse(sharedByIdStr, out var sharedByUserId))
                return Results.Unauthorized();

            var cred = await db.Credentials.FindAsync(id);
            if (cred == null) return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var share = new CredentialShare
            {
                CredentialId = id,
                SharedByUserId = sharedByUserId,
                SharedToUserId = req.SharedToUserId,
                PermissionLevel = req.PermissionLevel,
                ExpiresAtUtc = req.ExpiresInHours.HasValue ? DateTime.UtcNow.AddHours(req.ExpiresInHours.Value) : null,
                MaxUseCount = req.MaxUseCount
            };

            db.CredentialShares.Add(share);
            await db.SaveChangesAsync();

            logger.LogInformation("Credential '{Name}' shared by user {From} to user {To} (expires: {Expires})",
                cred.Name, sharedByUserId, req.SharedToUserId, share.ExpiresAtUtc);

            return Results.Ok(new { success = true, data = new { share.Id, share.ExpiresAtUtc, share.MaxUseCount } });
        }).RequireAuthorization();

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

        // === Personal Vault - userId from JWT to prevent IDOR ===
        creds.MapGet("/personal", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var folder = await db.VaultFolders
                .FirstOrDefaultAsync(f => f.IsPersonalVault && f.OwnerUserId == userId);

            if (folder == null)
            {
                folder = new VaultFolder
                {
                    Name = "Personal Vault",
                    IsPersonalVault = true,
                    OwnerUserId = userId
                };
                db.VaultFolders.Add(folder);
                await db.SaveChangesAsync();
            }

            var personalCreds = await db.Credentials
                .Where(c => c.FolderId == folder.Id)
                .Select(c => new { c.Id, c.Name, c.Username, Type = c.CredentialType.ToString(), c.Tags })
                .ToListAsync();

            return Results.Ok(new { success = true, data = new { folder.Id, folder.Name, credentials = personalCreds } });
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

        // === Proxy Service Decrypt (called by SSH/RDP proxy daemons) ===
        // Requires X-Proxy-Secret header in addition to JWT — defense-in-depth.
        creds.MapPost("/proxy-decrypt", async (ProxyDecryptRequest req,
            OrkunPamDbContext db, IVaultEncryptionService vault, IConfiguration config,
            ILogger<Program> logger, HttpContext context) =>
        {
            var expectedSecret = config["ProxyService:Secret"];
            var providedSecret = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault();
            if (string.IsNullOrEmpty(expectedSecret) || providedSecret != expectedSecret)
            {
                logger.LogWarning("proxy-decrypt: invalid proxy secret from {IP}",
                    context.Connection.RemoteIpAddress);
                return Results.Forbid();
            }

            if (req.CredentialId == Guid.Empty)
                return Results.BadRequest(new { success = false, errors = new[] { "credentialId required" } });

            var cred = await db.Credentials.FindAsync(req.CredentialId);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            string? password = null;
            if (cred.PasswordEnc != null)
            {
                var decResult = vault.DecryptString(cred.PasswordEnc);
                if (decResult.IsFailure)
                {
                    logger.LogError("proxy-decrypt: decryption failed for credential {CredId}", req.CredentialId);
                    return Results.Problem("Decryption failed");
                }
                password = decResult.Value;
            }

            string? privateKey = null;
            if (cred.PrivateKeyEnc != null)
            {
                var pkDec = vault.DecryptString(cred.PrivateKeyEnc);
                if (pkDec.IsFailure)
                {
                    logger.LogError("proxy-decrypt: private key decryption failed for credential {CredId}", req.CredentialId);
                    return Results.Problem("Decryption failed");
                }
                privateKey = pkDec.Value;
            }

            logger.LogInformation("proxy-decrypt: '{Name}' decrypted for purpose '{Purpose}'",
                cred.Name, req.Purpose);

            return Results.Ok(new { success = true, data = new { password, privateKey } });
        });

        // === Generate SSH Key Pair ===
        creds.MapPost("/generate-ssh-key", (HttpContext _) =>
        {
            using var rsa = RSA.Create(4096);
            var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
            var pubKeyLine    = BuildSshRsaPublicKeyLine(rsa);
            return Results.Ok(new { success = true, data = new { privateKey = privateKeyPem, publicKey = pubKeyLine } });
        }).RequireAuthorization();

        // === Password Rotation ===
        creds.MapPost("/{id:guid}/rotate", async (Guid id, RotateCredentialRequest req,
            OrkunPamDbContext db, IVaultEncryptionService vault, IRotationService rotation,
            ILogger<Program> logger, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var cred = await db.Credentials
                .Include(c => c.RotationPolicy)
                .FirstOrDefaultAsync(c => c.Id == id);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            if (cred.CredentialType != CredentialType.UserPassword)
                return Results.BadRequest(new { success = false, errors = new[] { "Only UserPassword credentials support rotation" } });

            // Resolve connection details: explicit request params override device lookup
            string? host = req.Host;
            int port = req.Port ?? 0;
            RotationConnector connector;

            if (!Enum.TryParse<RotationConnector>(req.Connector, true, out connector))
                return Results.BadRequest(new { success = false, errors = new[] { $"Unknown connector '{req.Connector}'. Valid: WinRm, Ssh, Ldap, SqlServer, MySql, PostgreSql" } });

            if (string.IsNullOrEmpty(host) && cred.DeviceId.HasValue)
            {
                var device = await db.Devices.FindAsync(cred.DeviceId.Value);
                if (device != null)
                {
                    host = device.Fqdn ?? device.IpAddress ?? device.Hostname;
                    port = port == 0 ? (device.ConnectionPort ?? 0) : port;
                }
            }

            if (string.IsNullOrEmpty(host))
                return Results.BadRequest(new { success = false, errors = new[] { "Host is required when credential has no associated device" } });

            // Decrypt current password
            string? currentPassword = null;
            if (cred.PasswordEnc != null)
            {
                var decResult = vault.DecryptString(cred.PasswordEnc);
                if (decResult.IsFailure)
                    return Results.Problem("Failed to decrypt current password");
                currentPassword = decResult.Value;
            }

            // Generate new password
            var newPassword = rotation.GeneratePassword(length: 24);

            var target = new RotationTarget(
                Host: host,
                Port: port,
                Username: cred.Username ?? "",
                CurrentPassword: currentPassword,
                NewPassword: newPassword,
                Domain: req.Domain);

            // Mark as rotating
            cred.Status = CredentialStatus.Rotating;
            await db.SaveChangesAsync();

            var rotResult = await rotation.RotatePasswordAsync(connector, target);

            if (rotResult.Success)
            {
                // Encrypt and save new password
                var encResult = vault.EncryptString(newPassword);
                if (encResult.IsFailure)
                {
                    cred.Status = CredentialStatus.Active;
                    await db.SaveChangesAsync();
                    return Results.Problem("Rotation succeeded on target but failed to encrypt new password");
                }

                // Archive old password in history
                if (cred.PasswordEnc != null)
                {
                    db.PasswordHistories.Add(new PasswordHistory
                    {
                        CredentialId = id,
                        PasswordEnc = cred.PasswordEnc,
                        ChangedBy = userId,
                        ChangeReason = PasswordChangeReason.OnDemand
                    });
                }

                cred.PasswordEnc = encResult.Value;
                cred.LastRotatedAtUtc = DateTime.UtcNow;
                cred.Version++;
                cred.Status = CredentialStatus.Active;

                if (cred.RotationPolicy != null)
                    cred.NextRotationAtUtc = DateTime.UtcNow.AddDays(cred.RotationPolicy.IntervalDays);

                await db.SaveChangesAsync();

                logger.LogInformation("Password rotated for credential '{Name}' via {Connector} by user {UserId}",
                    cred.Name, connector, userId);

                return Results.Ok(new
                {
                    success = true,
                    data = new
                    {
                        cred.Id, cred.Name,
                        connector = connector.ToString(),
                        responseTimeMs = rotResult.ResponseTimeMs,
                        lastRotatedAt = cred.LastRotatedAtUtc
                    }
                });
            }
            else
            {
                cred.Status = CredentialStatus.Active;
                await db.SaveChangesAsync();

                logger.LogWarning("Password rotation failed for credential '{Name}': {Error}", cred.Name, rotResult.Message);

                return Results.UnprocessableEntity(new
                {
                    success = false,
                    errors = new[] { $"Rotation failed: {rotResult.Message}" },
                    data = new { connector = connector.ToString(), rotResult.ResponseTimeMs }
                });
            }
        }).RequireAuthorization();

        // === Vault Permissions ===
        var perms = app.MapGroup("/api/v1/vault/permissions").WithTags("Vault").RequireAuthorization();

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

    // -------------------------------------------------------------------------
    // SSH public key serialization helpers (authorized_keys format)
    // -------------------------------------------------------------------------

    internal static string BuildSshRsaPublicKeyLine(RSA rsa, string comment = "orkunpam-generated")
    {
        var p = rsa.ExportParameters(false);
        using var ms = new MemoryStream();
        WriteKeyStr(ms, "ssh-rsa"u8.ToArray());
        WriteKeyMpInt(ms, p.Exponent!);
        WriteKeyMpInt(ms, p.Modulus!);
        return "ssh-rsa " + Convert.ToBase64String(ms.ToArray()) + " " + comment;
    }

    private static void WriteKeyStr(Stream s, byte[] data)
    {
        uint l = (uint)data.Length;
        s.WriteByte((byte)(l >> 24)); s.WriteByte((byte)(l >> 16));
        s.WriteByte((byte)(l >> 8));  s.WriteByte((byte)l);
        s.Write(data);
    }

    private static void WriteKeyMpInt(Stream s, byte[] bytes)
    {
        bool pad = bytes[0] >= 0x80;
        uint l = (uint)(bytes.Length + (pad ? 1 : 0));
        s.WriteByte((byte)(l >> 24)); s.WriteByte((byte)(l >> 16));
        s.WriteByte((byte)(l >> 8));  s.WriteByte((byte)l);
        if (pad) s.WriteByte(0);
        s.Write(bytes);
    }
}

public record CreateFolderRequest(string Name, string? Description, Guid? ParentFolderId);
public record CreateCredentialRequest(
    Guid FolderId, string Name, string? Description, CredentialType Type,
    string? Username, string? Password, string? PrivateKey, Guid? DeviceId, string? Tags,
    int? MaxCheckoutMinutes, bool RequiresApproval);
public record CheckoutRequest(string? Reason, string? TicketNumber, int? DurationMinutes);
public record ProxyDecryptRequest(Guid CredentialId, string Purpose);
public record SetPermissionRequest(PrincipalType PrincipalType, Guid PrincipalId, PermissionLevel Level, bool CanShare);
public record ShareCredentialRequest(Guid SharedToUserId, PermissionLevel PermissionLevel, int? ExpiresInHours, int? MaxUseCount);
public record RotateCredentialRequest(string? Host, int? Port, string Connector, string? Domain);
