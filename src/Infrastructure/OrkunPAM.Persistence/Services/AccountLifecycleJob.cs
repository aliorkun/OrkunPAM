using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Daily background job that enforces account lifecycle policies:
///   - Temporary account expiry (IsTemporary + TemporaryExpiresUtc)
///   - Inactivity lockout (MaxInactivityDays)
///   - Password age lockout (MaxPasswordAgeDays)
/// Sends warning emails 7 days before lockout. Config keys (category "account"):
///   account.maxPasswordAgeDays   — 0 = disabled
///   account.maxInactivityDays    — 0 = disabled
///   account.warnDaysBefore       — default 7
/// </summary>
public sealed class AccountLifecycleJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AccountLifecycleJob> _logger;
    private static readonly TimeSpan RunInterval = TimeSpan.FromHours(24);

    public AccountLifecycleJob(IServiceScopeFactory scopeFactory, ILogger<AccountLifecycleJob> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AccountLifecycleJob started");
        // Stagger startup so DB migrations complete first
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(RunInterval);
        do
        {
            try { await RunAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            { _logger.LogError(ex, "AccountLifecycleJob sweep failed"); }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task RunAsync(CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db    = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var email = scope.ServiceProvider.GetRequiredService<IEmailService>();

        var policy = await LoadPolicyAsync(db, ct);
        var now    = DateTime.UtcNow;
        int locked = 0, warned = 0;

        var users = await db.Users
            .Where(u => !u.IsDeleted && u.Status == UserStatus.Active)
            .ToListAsync(ct);

        foreach (var user in users)
        {
            // --- Temporary account expiry ---
            if (user.IsTemporary && user.TemporaryExpiresUtc.HasValue)
            {
                var exp = user.TemporaryExpiresUtc.Value;
                if (exp <= now)
                {
                    LockUser(user, "Auto-expired: temporary account expiry date reached");
                    await audit.LogAsync("User", "User.AutoExpired", null, "System", null,
                        "User", user.Id.ToString(),
                        new { username = user.Username, expiresAt = exp }, ct: ct);
                    await SendEmailAsync(email, user.Email,
                        "OrkunPAM — Account Expired",
                        $"<p>Your PAM account <strong>{user.Username}</strong> has expired as of {exp:yyyy-MM-dd} UTC and has been automatically deactivated.</p>" +
                        "<p>Please contact your administrator to renew access.</p>", _logger, ct);
                    locked++;
                    continue;
                }

                // Warn 7 days before expiry
                if (exp <= now.AddDays(policy.WarnDaysBefore) && exp > now)
                {
                    await SendEmailAsync(email, user.Email,
                        "OrkunPAM — Account Expiry Warning",
                        $"<p>Your PAM account <strong>{user.Username}</strong> will expire on <strong>{exp:yyyy-MM-dd}</strong> UTC.</p>" +
                        "<p>Please contact your administrator to renew access before expiry.</p>", _logger, ct);
                    warned++;
                }
            }

            // --- Password age lockout ---
            if (policy.MaxPasswordAgeDays > 0 && user.PasswordLastChanged.HasValue)
            {
                var lockDate = user.PasswordLastChanged.Value.AddDays(policy.MaxPasswordAgeDays);
                if (lockDate <= now)
                {
                    LockUser(user, $"Auto-locked: password not changed in {policy.MaxPasswordAgeDays} days");
                    await audit.LogAsync("User", "User.AutoLockedPasswordAge", null, "System", null,
                        "User", user.Id.ToString(),
                        new { username = user.Username, passwordLastChanged = user.PasswordLastChanged, maxDays = policy.MaxPasswordAgeDays }, ct: ct);
                    await SendEmailAsync(email, user.Email,
                        "OrkunPAM — Account Locked: Password Expired",
                        $"<p>Your PAM account <strong>{user.Username}</strong> has been locked because your password has not been changed in {policy.MaxPasswordAgeDays} days.</p>" +
                        "<p>Contact your administrator to reset your password and unlock your account.</p>", _logger, ct);
                    locked++;
                    continue;
                }

                // Warn before lockout
                if (lockDate <= now.AddDays(policy.WarnDaysBefore))
                {
                    await SendEmailAsync(email, user.Email,
                        "OrkunPAM — Password Expiry Warning",
                        $"<p>Your PAM account <strong>{user.Username}</strong> will be locked on <strong>{lockDate:yyyy-MM-dd}</strong> UTC because your password has not been changed recently.</p>" +
                        "<p>Please change your password to prevent account lockout.</p>", _logger, ct);
                    warned++;
                }
            }

            // --- Inactivity lockout ---
            if (policy.MaxInactivityDays > 0)
            {
                var lastActivity = user.LastLoginAtUtc ?? user.CreatedAtUtc;
                var lockDate     = lastActivity.AddDays(policy.MaxInactivityDays);
                if (lockDate <= now)
                {
                    LockUser(user, $"Auto-locked: no login in {policy.MaxInactivityDays} days");
                    await audit.LogAsync("User", "User.AutoLockedInactive", null, "System", null,
                        "User", user.Id.ToString(),
                        new { username = user.Username, lastLogin = user.LastLoginAtUtc, maxDays = policy.MaxInactivityDays }, ct: ct);
                    await SendEmailAsync(email, user.Email,
                        "OrkunPAM — Account Locked: Inactivity",
                        $"<p>Your PAM account <strong>{user.Username}</strong> has been locked due to {policy.MaxInactivityDays} days of inactivity.</p>" +
                        "<p>Contact your administrator to unlock your account.</p>", _logger, ct);
                    locked++;
                }
                else if (lockDate <= now.AddDays(policy.WarnDaysBefore))
                {
                    await SendEmailAsync(email, user.Email,
                        "OrkunPAM — Inactivity Warning",
                        $"<p>Your PAM account <strong>{user.Username}</strong> will be locked on <strong>{lockDate:yyyy-MM-dd}</strong> UTC due to inactivity.</p>" +
                        "<p>Please log in to keep your account active.</p>", _logger, ct);
                    warned++;
                }
            }
        }

        if (locked > 0 || warned > 0)
            await db.SaveChangesAsync(ct);

        _logger.LogInformation("AccountLifecycleJob: locked={Locked} warned={Warned}", locked, warned);
    }

    private static void LockUser(OrkunPAM.Domain.Entities.Identity.User user, string reason)
    {
        user.Status        = UserStatus.Locked;
        user.LockoutEndUtc = DateTime.UtcNow.AddYears(100);
    }

    private static async Task SendEmailAsync(IEmailService email, string? to, string subject,
        string body, ILogger logger, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(to)) return;
        try { await email.SendAsync(to, subject, body, ct); }
        catch (Exception ex) { logger.LogWarning(ex, "AccountLifecycleJob: email failed to {To}", to); }
    }

    private static async Task<AccountPolicy> LoadPolicyAsync(OrkunPamDbContext db, CancellationToken ct)
    {
        var configs = await db.SystemConfigs
            .Where(c => c.Category == "account")
            .ToDictionaryAsync(c => c.Key, c => c.Value, ct);

        static int GetInt(Dictionary<string, string?> d, string key, int def)
            => d.TryGetValue(key, out var v) && int.TryParse(v, out var n) ? n : def;

        return new AccountPolicy(
            MaxPasswordAgeDays: GetInt(configs, "account.maxPasswordAgeDays", 0),
            MaxInactivityDays:  GetInt(configs, "account.maxInactivityDays",  0),
            WarnDaysBefore:     GetInt(configs, "account.warnDaysBefore",     7));
    }

    private record AccountPolicy(int MaxPasswordAgeDays, int MaxInactivityDays, int WarnDaysBefore);
}
