using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Background service that automatically rotates credentials whose NextRotationAtUtc has passed.
/// Runs every 5 minutes, processes up to 10 concurrent rotations per cycle.
/// </summary>
public sealed class AutoRotationService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AutoRotationService> _logger;
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    private const int MaxConcurrentRotations = 10;

    public AutoRotationService(
        IServiceScopeFactory scopeFactory,
        ILogger<AutoRotationService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AutoRotationService started - checking every {Interval} minutes", Interval.TotalMinutes);

        // Initial delay to let the application fully start
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessDueRotationsAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AutoRotationService cycle failed - will retry next interval");
            }

            await Task.Delay(Interval, stoppingToken);
        }

        _logger.LogInformation("AutoRotationService stopped");
    }

    private async Task ProcessDueRotationsAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();

        var now = DateTime.UtcNow;

        var dueCredentials = await db.Credentials
            .Include(c => c.RotationPolicy)
            .Where(c => c.RotationPolicyId != null
                && c.NextRotationAtUtc != null
                && c.NextRotationAtUtc <= now
                && c.Status == CredentialStatus.Active)
            .OrderBy(c => c.NextRotationAtUtc)
            .Take(MaxConcurrentRotations * 2)
            .ToListAsync(ct);

        if (dueCredentials.Count == 0)
        {
            _logger.LogDebug("AutoRotation: no credentials due for rotation");
            return;
        }

        _logger.LogInformation("AutoRotation: found {Count} credentials due for rotation", dueCredentials.Count);

        using var semaphore = new SemaphoreSlim(MaxConcurrentRotations);
        var tasks = new List<Task>();

        foreach (var credential in dueCredentials)
        {
            if (ct.IsCancellationRequested) break;

            await semaphore.WaitAsync(ct);

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    await RotateCredentialAsync(credential.Id, credential.RotationPolicy!, ct);
                }
                finally
                {
                    semaphore.Release();
                }
            }, ct));
        }

        await Task.WhenAll(tasks);
        _logger.LogInformation("AutoRotation cycle complete - processed {Count} credentials", dueCredentials.Count);
    }

    private async Task RotateCredentialAsync(Guid credentialId, Domain.Entities.Vault.RotationPolicy policy, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var rotationService = scope.ServiceProvider.GetRequiredService<IRotationService>();
        var orchestrator = scope.ServiceProvider.GetRequiredService<PasswordRotationOrchestrator>();
        var emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();

        var credential = await db.Credentials
            .Include(c => c.RotationPolicy)
            .Include(c => c.RotationScript)
            .FirstOrDefaultAsync(c => c.Id == credentialId, ct);

        if (credential == null)
        {
            _logger.LogWarning("AutoRotation: credential {Id} not found (may have been deleted)", credentialId);
            return;
        }

        if (credential.Status != CredentialStatus.Active)
        {
            _logger.LogDebug("AutoRotation: skipping credential {Id} - status is {Status}", credentialId, credential.Status);
            return;
        }

        credential.Status = CredentialStatus.Rotating;
        await db.SaveChangesAsync(ct);

        try
        {
            var deviceCredential = await db.DeviceCredentials
                .Include(dc => dc.Device)
                .FirstOrDefaultAsync(dc => dc.CredentialId == credentialId, ct);

            if (deviceCredential?.Device == null)
            {
                _logger.LogWarning("AutoRotation: no device found for credential {Id} - skipping", credentialId);
                credential.Status = CredentialStatus.Active;
                await db.SaveChangesAsync(ct);
                return;
            }

            var device = deviceCredential.Device;

            // If credential has a custom rotation script, use it instead of the standard connector
            if (credential.RotationScript != null && credential.RotationScript.IsEnabled)
            {
                var scriptResult = await RotationScriptRunner.RunAsync(
                    credential.RotationScript.ScriptType,
                    credential.RotationScript.ScriptContent,
                    isTest: false,
                    env: new Dictionary<string, string>
                    {
                        ["PAM_TARGET_IP"]        = device.IpAddress ?? device.Hostname ?? "",
                        ["PAM_CURRENT_PASSWORD"] = "[REDACTED]",
                        ["PAM_NEW_PASSWORD"]     = orchestrator.GeneratePassword(),
                        ["PAM_USERNAME"]         = credential.Username ?? ""
                    },
                    ct: ct);

                if (scriptResult.Success)
                {
                    credential.LastRotatedAtUtc  = DateTime.UtcNow;
                    credential.NextRotationAtUtc = DateTime.UtcNow.AddDays(
                        credential.RotationPolicy?.IntervalDays ?? policy.IntervalDays);
                    credential.Status = CredentialStatus.Active;
                    await db.SaveChangesAsync(ct);

                    await audit.LogAsync("AutoRotation", "ROTATION_SCRIPT_EXECUTED", null, "auto-rotation", "127.0.0.1",
                        "Credential", credentialId.ToString(),
                        new { credential.Name, DeviceHostname = device.Hostname, ScriptName = credential.RotationScript.Name },
                        AuditOutcome.Success, ct);

                    _logger.LogInformation("AutoRotation (custom script) succeeded for '{Name}' on {Host}",
                        credential.Name, device.Hostname);
                }
                else
                {
                    credential.Status = CredentialStatus.Active;
                    credential.LastRotationError     = scriptResult.Error?[..Math.Min(scriptResult.Error.Length, 512)];
                    credential.RotationFailureCount++;
                    credential.LastRotationFailedAtUtc = DateTime.UtcNow;
                    await db.SaveChangesAsync(ct);

                    await audit.LogAsync("AutoRotation", "ROTATION_SCRIPT_FAILED", null, "auto-rotation", "127.0.0.1",
                        "Credential", credentialId.ToString(),
                        new { credential.Name, DeviceHostname = device.Hostname, ScriptName = credential.RotationScript.Name, Error = scriptResult.Error },
                        AuditOutcome.Failure, ct);

                    _logger.LogWarning("AutoRotation (custom script) failed for '{Name}': {Error}",
                        credential.Name, scriptResult.Error);

                    await NotifyRotationFailureAsync(emailService, db, credential, device.Hostname, scriptResult.Error ?? "Script failed", ct);
                }
                return;
            }

            var connector = credential.RotationPolicy?.ConnectorType
                ?? PasswordRotationOrchestrator.ResolveConnector(device.DeviceType, device.ConnectionProtocol);

            var newPassword = orchestrator.GeneratePassword();

            var target = new RotationTarget(
                Host: device.IpAddress ?? device.Hostname,
                Port: device.ConnectionPort ?? 22,
                Username: credential.Username ?? "",
                CurrentPassword: null,
                NewPassword: newPassword);

            var result = await orchestrator.RotateAsync(
                connector, target,
                credentialId: credentialId,
                actorUsername: "auto-rotation",
                ct: ct);

            if (result.Success)
            {
                credential.LastRotatedAtUtc = DateTime.UtcNow;
                credential.NextRotationAtUtc = DateTime.UtcNow.AddDays(
                    credential.RotationPolicy?.IntervalDays ?? policy.IntervalDays);
                credential.Status = CredentialStatus.Active;

                await db.SaveChangesAsync(ct);

                await audit.LogAsync(
                    category: "AutoRotation",
                    eventType: "AutoRotationSuccess",
                    actorUserId: null,
                    actorUsername: "auto-rotation",
                    actorIp: "127.0.0.1",
                    targetType: "Credential",
                    targetId: credentialId.ToString(),
                    details: new
                    {
                        CredentialName = credential.Name,
                        DeviceHostname = device.Hostname,
                        Connector = connector.ToString(),
                        NextRotation = credential.NextRotationAtUtc,
                        result.ResponseTimeMs
                    },
                    outcome: AuditOutcome.Success,
                    ct: ct);

                _logger.LogInformation(
                    "AutoRotation succeeded for '{Name}' on {Host}. Next rotation: {Next}",
                    credential.Name, device.Hostname, credential.NextRotationAtUtc);
            }
            else
            {
                credential.Status = CredentialStatus.Active;
                credential.LastRotationError = SanitizeErrorMessage(result.Message);
                credential.RotationFailureCount++;
                credential.LastRotationFailedAtUtc = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);

                await audit.LogAsync(
                    category: "AutoRotation",
                    eventType: "CREDENTIAL_ROTATION_FAILED",
                    actorUserId: null,
                    actorUsername: "auto-rotation",
                    actorIp: "127.0.0.1",
                    targetType: "Credential",
                    targetId: credentialId.ToString(),
                    details: new
                    {
                        CredentialName = credential.Name,
                        DeviceHostname = device.Hostname,
                        Connector = connector.ToString(),
                        Error = SanitizeErrorMessage(result.Message),
                        result.ResponseTimeMs,
                        FailureCount = credential.RotationFailureCount
                    },
                    outcome: AuditOutcome.Failure,
                    ct: ct);

                _logger.LogWarning(
                    "AutoRotation failed for '{Name}' on {Host}: {Error}",
                    credential.Name, device.Hostname, result.Message);

                await NotifyRotationFailureAsync(emailService, db, credential, device.Hostname, result.Message ?? "Unknown error", ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AutoRotation error for credential {Id}", credentialId);

            try
            {
                credential.Status = CredentialStatus.Active;
                credential.LastRotationError = SanitizeErrorMessage(ex.Message);
                credential.RotationFailureCount++;
                credential.LastRotationFailedAtUtc = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
            }
            catch (Exception saveEx)
            {
                _logger.LogError(saveEx, "Failed to reset credential {Id} status after rotation error", credentialId);
            }

            await audit.LogAsync(
                category: "AutoRotation",
                eventType: "CREDENTIAL_ROTATION_FAILED",
                actorUserId: null,
                actorUsername: "auto-rotation",
                actorIp: "127.0.0.1",
                targetType: "Credential",
                targetId: credentialId.ToString(),
                details: new { Error = SanitizeErrorMessage(ex.Message), FailureCount = credential.RotationFailureCount },
                outcome: AuditOutcome.Failure,
                ct: ct);

            try
            {
                await NotifyRotationFailureAsync(emailService, db, credential, null, ex.Message, ct);
            }
            catch (Exception emailEx)
            {
                _logger.LogError(emailEx, "Failed to send rotation failure email for credential {Id}", credentialId);
            }
        }
    }

    // Strips potential credential values from error messages before writing to DB or audit log.
    // Matches patterns like: password=secret, pwd: hunter2, token 'abc123'
    private static string SanitizeErrorMessage(string? message)
    {
        if (string.IsNullOrEmpty(message)) return "Rotation failed";
        // Use non-verbatim string so double-quote in character class can be escaped safely
        var sanitized = System.Text.RegularExpressions.Regex.Replace(
            message, "(?i)(password|pass|pwd|secret|token|key)\\s*[:=\\s']+\\s*\\S+", "$1=[REDACTED]");
        return sanitized[..Math.Min(sanitized.Length, 512)];
    }

    private async Task NotifyRotationFailureAsync(
        IEmailService emailService,
        OrkunPamDbContext db,
        Domain.Entities.Vault.Credential credential,
        string? deviceHostname,
        string errorMessage,
        CancellationToken ct)
    {
        try
        {
            var adminEmails = await db.Users
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                .Where(u => u.Email != null
                    && u.Status == UserStatus.Active
                    && u.UserRoles.Any(ur => ur.Role.Name == "GlobalAdmin" || ur.Role.Name == "VaultAdmin"))
                .Select(u => u.Email!)
                .Distinct()
                .ToListAsync(ct);

            if (adminEmails.Count == 0)
                return;

            var subject = $"[OrkunPAM] Credential Rotation Failed: {credential.Name}";
            var body = $"""
                <h2 style="color:#dc2626">Credential Rotation Failed</h2>
                <table style="border-collapse:collapse;font-family:sans-serif">
                  <tr><td style="padding:4px 12px 4px 0"><strong>Credential</strong></td><td>{System.Net.WebUtility.HtmlEncode(credential.Name)}</td></tr>
                  <tr><td style="padding:4px 12px 4px 0"><strong>Username</strong></td><td>{System.Net.WebUtility.HtmlEncode(credential.Username ?? "?")}</td></tr>
                  <tr><td style="padding:4px 12px 4px 0"><strong>Device</strong></td><td>{System.Net.WebUtility.HtmlEncode(deviceHostname ?? "?")}</td></tr>
                  <tr><td style="padding:4px 12px 4px 0"><strong>Error</strong></td><td style="color:#dc2626">{System.Net.WebUtility.HtmlEncode(errorMessage)}</td></tr>
                  <tr><td style="padding:4px 12px 4px 0"><strong>Failure Count</strong></td><td>{credential.RotationFailureCount}</td></tr>
                  <tr><td style="padding:4px 12px 4px 0"><strong>Time (UTC)</strong></td><td>{credential.LastRotationFailedAtUtc:yyyy-MM-dd HH:mm:ss}</td></tr>
                </table>
                <p>Log in to <strong>OrkunPAM</strong> to investigate and resolve this issue.</p>
                """;

            foreach (var email in adminEmails)
                await emailService.SendAsync(email, subject, body, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "NotifyRotationFailureAsync failed for credential {Id}", credential.Id);
        }
    }
}
