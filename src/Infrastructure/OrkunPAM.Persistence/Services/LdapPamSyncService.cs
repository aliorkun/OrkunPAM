using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Application.Contracts;

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

        var configs = await db.LdapConfigurations.Where(c => c.IsEnabled).ToListAsync(ct);
        foreach (var config in configs)
        {
            if (config.LastSyncAtUtc.HasValue)
            {
                var next = config.LastSyncAtUtc.Value.AddMinutes(config.SyncIntervalMinutes);
                if (DateTime.UtcNow < next) continue;
            }
            await ApplySyncAsync(config, db, ldap, audit, ct);
        }
    }

    public static async Task<LdapSyncApplyResult> ApplySyncAsync(
        LdapConfiguration config, OrkunPamDbContext db,
        ILdapService ldap, IAuditService audit, CancellationToken ct)
    {
        string? bindPassword = null; // TODO: decrypt config.BindPasswordEnc via vault when implemented

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

        config.LastSyncAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        await audit.LogAsync("LDAP", "LDAP_SYNC_COMPLETED", null, "System", null,
            "LdapConfig", config.Id.ToString(),
            new { config.Name, created, updated, locked, usersFound = result.UsersFound }, ct: ct);

        return new LdapSyncApplyResult(true, "Sync completed", created, updated, locked);
    }
}

public record LdapSyncApplyResult(bool Success, string Message, int Created, int Updated, int Locked);
