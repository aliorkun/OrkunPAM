using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public sealed class LdapPamSyncService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<LdapPamSyncService> _logger;

    public LdapPamSyncService(IServiceScopeFactory scopeFactory, ILogger<LdapPamSyncService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SyncAllDueAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "LDAP sync loop error");
            }
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task SyncAllDueAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var ldap = scope.ServiceProvider.GetRequiredService<ILdapService>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var vault = scope.ServiceProvider.GetRequiredService<IVaultEncryptionService>();

        var configs = await db.LdapConfigurations.Where(c => c.IsEnabled).ToListAsync(ct);
        foreach (var config in configs)
        {
            if (config.LastSyncAtUtc.HasValue)
            {
                var next = config.LastSyncAtUtc.Value.AddMinutes(config.SyncIntervalMinutes);
                if (DateTime.UtcNow < next) continue;
            }
            await ApplySyncAsync(config, db, ldap, audit, vault, ct);
        }
    }

    public static async Task<LdapSyncApplyResult> ApplySyncAsync(
        LdapConfiguration config, OrkunPamDbContext db,
        ILdapService ldap, IAuditService audit, IVaultEncryptionService vault, CancellationToken ct)
    {
        string? bindPassword = null;
        if (config.BindPasswordEnc != null)
        {
            var decrypted = vault.DecryptString(config.BindPasswordEnc);
            if (decrypted.IsSuccess)
                bindPassword = decrypted.Value;
        }

        var result = await ldap.SyncUsersAndGroupsAsync(
            config.Host, config.Port, config.UseSsl, config.BindDn, bindPassword,
            config.BaseDn, config.UserSearchFilter, config.GroupSearchFilter, config.UserAttributeMapping);

        if (!result.Success)
        {
            config.LastSyncAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            await audit.LogAsync("LDAP", "LDAP_SYNC_FAILED", null, "System", null,
                "LdapConfig", config.Id.ToString(),
                new { config.Name, result.Message }, AuditOutcome.Failure, ct);
            return new LdapSyncApplyResult(false, result.Message, 0, 0, 0);
        }

        int created = 0, updated = 0, locked = 0;
        foreach (var ldapUser in result.Users)
        {
            var normalized = ldapUser.SamAccountName.ToUpperInvariant();
            var existing = await db.Users.FirstOrDefaultAsync(
                u => u.NormalizedUsername == normalized && u.AuthSource == AuthSource.ActiveDirectory, ct);

            if (existing == null)
            {
                db.Users.Add(new User
                {
                    Username = ldapUser.SamAccountName,
                    NormalizedUsername = normalized,
                    DisplayName = ldapUser.DisplayName,
                    Email = ldapUser.Email,
                    AuthSource = AuthSource.ActiveDirectory,
                    Status = ldapUser.IsEnabled ? UserStatus.Active : UserStatus.Locked
                });
                created++;
            }
            else
            {
                if (ldapUser.DisplayName != null) existing.DisplayName = ldapUser.DisplayName;
                if (ldapUser.Email != null) existing.Email = ldapUser.Email;
                if (!ldapUser.IsEnabled && existing.Status == UserStatus.Active)
                {
                    existing.Status = UserStatus.Locked;
                    locked++;
                }
                else if (ldapUser.IsEnabled && existing.Status == UserStatus.Locked
                         && existing.AuthSource == AuthSource.ActiveDirectory)
                {
                    existing.Status = UserStatus.Active;
                }
                updated++;
            }
        }

        // Orphaned account detection: AD users no longer present in LDAP results
        var syncedNorms = result.Users.Select(u => u.SamAccountName.ToUpperInvariant()).ToHashSet();
        var adUsersInPam = await db.Users
            .Where(u => u.AuthSource == AuthSource.ActiveDirectory && !u.IsDeleted)
            .ToListAsync(ct);

        foreach (var adUser in adUsersInPam)
        {
            var presentInAd = syncedNorms.Contains(adUser.NormalizedUsername);
            if (!presentInAd && !adUser.IsOrphaned)
            {
                adUser.IsOrphaned = true;
                adUser.OrphanedDetectedAtUtc = DateTime.UtcNow;
                await audit.LogAsync("User", "User.MarkedOrphaned", null, "System", null,
                    "User", adUser.Id.ToString(),
                    new { username = adUser.Username, ldapConfig = config.Name },
                    AuditOutcome.Failure, ct);
            }
            else if (presentInAd && adUser.IsOrphaned)
            {
                adUser.IsOrphaned = false;
                adUser.OrphanedDetectedAtUtc = null;
            }
        }

        // Group membership sync: create/update PAM groups and sync memberships
        int groupsCreated = 0, membershipsAdded = 0, membershipsRemoved = 0;
        if (result.Groups.Count > 0)
        {
            // Build DN → NormalizedUsername lookup from synced users
            var dnToNorm = result.Users
                .Where(u => u.Dn != null)
                .ToDictionary(u => u.Dn!, u => u.SamAccountName.ToUpperInvariant(),
                    StringComparer.OrdinalIgnoreCase);

            foreach (var adGroup in result.Groups)
            {
                var pamGroup = await db.Groups.FirstOrDefaultAsync(
                    g => g.GroupSource == GroupSource.ActiveDirectory && g.Name == adGroup.Name, ct);

                if (pamGroup == null)
                {
                    pamGroup = new Group
                    {
                        Name = adGroup.Name,
                        Description = $"Synced from AD: {adGroup.Dn}",
                        GroupSource = GroupSource.ActiveDirectory,
                        ExternalGroupId = adGroup.Dn
                    };
                    db.Groups.Add(pamGroup);
                    await db.SaveChangesAsync(ct);
                    groupsCreated++;
                }

                // Resolve expected PAM user IDs from member DNs (single bulk query per group)
                var memberNorms = adGroup.MemberDns
                    .Where(dn => dnToNorm.ContainsKey(dn))
                    .Select(dn => dnToNorm[dn])
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                var expectedIds = await db.Users
                    .Where(u => memberNorms.Contains(u.NormalizedUsername)
                             && u.AuthSource == AuthSource.ActiveDirectory)
                    .Select(u => u.Id)
                    .ToListAsync(ct);

                var existing = await db.UserGroups
                    .Where(ug => ug.GroupId == pamGroup.Id)
                    .ToListAsync(ct);

                var existingIds = existing.Select(ug => ug.UserId).ToHashSet();
                var expectedSet = expectedIds.ToHashSet();

                // Remove stale memberships
                foreach (var ug in existing.Where(ug => !expectedSet.Contains(ug.UserId)))
                {
                    db.UserGroups.Remove(ug);
                    membershipsRemoved++;
                }

                // Add new memberships
                foreach (var uid in expectedSet.Where(id => !existingIds.Contains(id)))
                {
                    db.UserGroups.Add(new UserGroup { UserId = uid, GroupId = pamGroup.Id });
                    membershipsAdded++;
                }
            }

            await db.SaveChangesAsync(ct);
        }

        config.LastSyncAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        await audit.LogAsync("LDAP", "LDAP_SYNC_COMPLETED", null, "System", null,
            "LdapConfig", config.Id.ToString(),
            new { config.Name, created, updated, locked, usersFound = result.UsersFound,
                  groupsCreated, membershipsAdded, membershipsRemoved }, ct: ct);

        return new LdapSyncApplyResult(true, "Sync completed", created, updated, locked);
    }
}

public record LdapSyncApplyResult(bool Success, string Message, int Created, int Updated, int Locked);
