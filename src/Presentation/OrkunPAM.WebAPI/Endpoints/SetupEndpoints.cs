using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Access;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SetupEndpoints
{
    public static void MapSetupEndpoints(this IEndpointRouteBuilder app)
    {
        // One-time bootstrap: creates admin user + initial data if DB is empty
        app.MapPost("/api/v1/setup/bootstrap", async (BootstrapRequest req,
            OrkunPamDbContext db, IPasswordHasher hasher, IVaultEncryptionService vault,
            ILogger<Program> logger) =>
        {
            // Only allow if no users exist yet
            if (await db.Users.AnyAsync())
                return Results.Conflict(new { success = false, errors = new[] { "System already initialized. Users exist." } });

            // 1. Create admin user
            var adminUser = new User
            {
                Username = req.AdminUsername,
                NormalizedUsername = req.AdminUsername.Trim().ToUpperInvariant(),
                DisplayName = req.AdminDisplayName ?? "System Admin",
                Email = req.AdminEmail,
                PasswordHash = hasher.Hash(req.AdminPassword),
                AuthSource = AuthSource.Local,
                Status = UserStatus.Active,
                PortalProfile = PortalProfile.FullAdmin,
                PasswordLastChanged = DateTime.UtcNow
            };
            db.Users.Add(adminUser);
            await db.SaveChangesAsync();

            // Assign GlobalAdmin role
            db.UserRoles.Add(new UserRole { UserId = adminUser.Id, RoleId = SeedData.AdminRoleId });
            await db.SaveChangesAsync();

            logger.LogInformation("Bootstrap: admin user '{Username}' created with Id {Id}", adminUser.Username, adminUser.Id);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    adminUserId = adminUser.Id,
                    adminUsername = adminUser.Username,
                    message = "System bootstrapped. Admin user created. Log in and add devices/credentials via API."
                }
            });
        }).WithTags("Setup").AllowAnonymous();

        // Quick-setup: create a device + credential + access assignment in one call
        app.MapPost("/api/v1/setup/quick-access", async (QuickAccessRequest req,
            OrkunPamDbContext db, IVaultEncryptionService vault, ILogger<Program> logger) =>
        {
            // 1. Create or find device
            var device = await db.Devices.FirstOrDefaultAsync(d => d.IpAddress == req.DeviceIp);
            if (device == null)
            {
                device = new Device
                {
                    Hostname = req.DeviceHostname ?? req.DeviceIp,
                    IpAddress = req.DeviceIp,
                    DeviceType = req.DeviceType ?? DeviceType.LinuxServer,
                    ConnectionProtocol = req.Protocol ?? ConnectionProtocol.Ssh,
                    ConnectionPort = req.Port ?? 22,
                    Status = DeviceStatus.Active,
                    IsManaged = true,
                    ImportSource = ImportSource.Manual
                };
                db.Devices.Add(device);
                await db.SaveChangesAsync();
                logger.LogInformation("Quick-setup: device '{Hostname}' ({Ip}) created", device.Hostname, device.IpAddress);
            }

            // 2. Create vault folder if needed
            var folder = await db.VaultFolders.FirstOrDefaultAsync(f => f.Name == "Default");
            if (folder == null)
            {
                folder = new VaultFolder { Name = "Default", Description = "Default credential folder" };
                db.VaultFolders.Add(folder);
                await db.SaveChangesAsync();
            }

            // 3. Create credential
            var encResult = vault.EncryptString(req.Password);
            if (encResult.IsFailure)
                return Results.Problem($"Password encryption failed: {encResult.Error.Message}");

            var credential = new Credential
            {
                FolderId = folder.Id,
                Name = $"{req.Username}@{req.DeviceIp}",
                CredentialType = CredentialType.UserPassword,
                Username = req.Username,
                PasswordEnc = encResult.Value,
                DeviceId = device.Id,
                Status = CredentialStatus.Active
            };
            db.Credentials.Add(credential);
            await db.SaveChangesAsync();

            // Link credential to device
            var existing = await db.DeviceCredentials.FindAsync(device.Id, credential.Id);
            if (existing == null)
            {
                db.DeviceCredentials.Add(new DeviceCredential
                {
                    DeviceId = device.Id,
                    CredentialId = credential.Id,
                    Purpose = CredentialPurpose.Administrative,
                    IsPrimary = true
                });
                await db.SaveChangesAsync();
            }

            // 4. Create access assignment for the specified user
            var assignment = new AccessAssignment
            {
                PrincipalType = PrincipalType.User,
                PrincipalId = req.AssignToUserId,
                TargetType = AccessTargetType.Device,
                TargetId = device.Id,
                CredentialId = credential.Id,
                Protocol = req.Protocol ?? ConnectionProtocol.Ssh,
                IsEnabled = true,
                Description = $"Quick-setup: {req.Username}@{req.DeviceIp}"
            };
            db.AccessAssignments.Add(assignment);

            // 5. Grant credential permission to the user
            db.CredentialPermissions.Add(new CredentialPermission
            {
                CredentialId = credential.Id,
                PrincipalType = PrincipalType.User,
                PrincipalId = req.AssignToUserId,
                PermissionLevel = PermissionLevel.Use
            });

            await db.SaveChangesAsync();

            logger.LogInformation("Quick-setup: access assignment created for user {UserId} → {Ip} via credential {CredId}",
                req.AssignToUserId, req.DeviceIp, credential.Id);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    deviceId = device.Id,
                    credentialId = credential.Id,
                    accessAssignmentId = assignment.Id,
                    message = $"Access configured: user can connect to {req.DeviceIp} via {(req.Protocol ?? ConnectionProtocol.Ssh)}"
                }
            });
        }).WithTags("Setup").RequireAuthorization();
    }
}

public record BootstrapRequest(string AdminUsername, string AdminPassword, string? AdminDisplayName, string? AdminEmail);
public record QuickAccessRequest(
    string DeviceIp,
    string? DeviceHostname,
    string Username,
    string Password,
    Guid AssignToUserId,
    DeviceType? DeviceType,
    ConnectionProtocol? Protocol,
    int? Port);
