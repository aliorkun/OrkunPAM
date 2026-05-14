using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Orchestrates password rotation by selecting the correct IPasswordRotator
/// based on device type/protocol, executing the rotation, updating the vault,
/// and logging audit events. Central coordination point for all rotation workflows.
/// </summary>
public sealed class PasswordRotationOrchestrator
{
    private readonly IReadOnlyDictionary<RotationConnector, IPasswordRotator> _rotators;
    private readonly IRotationService _legacyRotationService;
    private readonly IAuditService _auditService;
    private readonly ILogger<PasswordRotationOrchestrator> _logger;

    public PasswordRotationOrchestrator(
        IEnumerable<IPasswordRotator> rotators,
        IRotationService legacyRotationService,
        IAuditService auditService,
        ILogger<PasswordRotationOrchestrator> logger)
    {
        _rotators = rotators.ToDictionary(r => r.ConnectorType, r => r);
        _legacyRotationService = legacyRotationService;
        _auditService = auditService;
        _logger = logger;

        _logger.LogInformation("PasswordRotationOrchestrator initialized with {Count} rotators: {Types}",
            _rotators.Count, string.Join(", ", _rotators.Keys));
    }

    /// <summary>
    /// Execute password rotation for a target using the specified connector.
    /// Selects the appropriate IPasswordRotator, performs rotation, logs audit.
    /// Falls back to legacy RotationService for connectors without dedicated rotators.
    /// </summary>
    public async Task<RotationResult> RotateAsync(
        RotationConnector connector,
        RotationTarget target,
        Guid? credentialId = null,
        Guid? actorUserId = null,
        string? actorUsername = null,
        string? actorIp = null,
        CancellationToken ct = default)
    {
        _logger.LogInformation(
            "Rotation orchestration started. Connector={Connector}, Host={Host}, User={User}, CredentialId={CredentialId}",
            connector, target.Host, target.Username, credentialId);

        var sw = Stopwatch.StartNew();
        RotationResult result;

        try
        {
            if (_rotators.TryGetValue(connector, out var rotator))
            {
                _logger.LogDebug("Using dedicated rotator for {Connector}", connector);
                result = await rotator.RotatePasswordAsync(target, ct);
            }
            else
            {
                // Fall back to legacy rotation service (LDAP, SqlServer, etc.)
                _logger.LogDebug("No dedicated rotator for {Connector}, using legacy RotationService", connector);
                result = await _legacyRotationService.RotatePasswordAsync(connector, target, ct);
            }

            sw.Stop();
            result = result with { ResponseTimeMs = (int)sw.ElapsedMilliseconds };
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            result = new RotationResult(false, "Rotation cancelled", connector.ToString(), (int)sw.ElapsedMilliseconds);
            _logger.LogWarning("Rotation cancelled for {User}@{Host} via {Connector}",
                target.Username, target.Host, connector);
        }
        catch (Exception ex)
        {
            sw.Stop();
            result = new RotationResult(false, $"Rotation error: {ex.Message}", connector.ToString(), (int)sw.ElapsedMilliseconds);
            _logger.LogError(ex, "Rotation orchestration error for {User}@{Host} via {Connector}",
                target.Username, target.Host, connector);
        }

        // Audit log (never log passwords)
        await _auditService.LogAsync(
            category: "PasswordRotation",
            eventType: result.Success ? "RotationSuccess" : "RotationFailed",
            actorUserId: actorUserId,
            actorUsername: actorUsername ?? "system",
            actorIp: actorIp,
            targetType: "Credential",
            targetId: credentialId?.ToString(),
            details: new
            {
                Connector = connector.ToString(),
                Host = target.Host,
                Port = target.Port,
                Username = target.Username,
                result.Success,
                result.Message,
                result.ResponseTimeMs
            },
            outcome: result.Success ? AuditOutcome.Success : AuditOutcome.Failure,
            ct: ct);

        if (result.Success)
        {
            _logger.LogInformation(
                "Rotation succeeded for {User}@{Host} via {Connector} in {Ms}ms",
                target.Username, target.Host, connector, result.ResponseTimeMs);
        }
        else
        {
            _logger.LogWarning(
                "Rotation failed for {User}@{Host} via {Connector} in {Ms}ms: {Error}",
                target.Username, target.Host, connector, result.ResponseTimeMs, result.Message);
        }

        return result;
    }

    /// <summary>
    /// Determines the appropriate RotationConnector based on device type and connection protocol.
    /// </summary>
    public static RotationConnector ResolveConnector(DeviceType deviceType, ConnectionProtocol protocol)
    {
        return protocol switch
        {
            ConnectionProtocol.Ssh => RotationConnector.Ssh,
            ConnectionProtocol.MySql => RotationConnector.MySql,
            ConnectionProtocol.PostgreSql => RotationConnector.PostgreSql,
            ConnectionProtocol.SqlServer => RotationConnector.SqlServer,
            ConnectionProtocol.Oracle => RotationConnector.Oracle,
            ConnectionProtocol.Rdp => deviceType switch
            {
                // Windows devices via RDP: prefer WMI for local accounts, LDAP for domain
                DeviceType.WindowsServer or DeviceType.WindowsWorkstation => RotationConnector.Wmi,
                _ => RotationConnector.WinRm
            },
            _ => deviceType switch
            {
                DeviceType.WindowsServer or DeviceType.WindowsWorkstation => RotationConnector.Wmi,
                DeviceType.LinuxServer => RotationConnector.Ssh,
                DeviceType.DatabaseServer => RotationConnector.SqlServer,
                _ => RotationConnector.Ssh // default
            }
        };
    }

    /// <summary>
    /// Generates a cryptographically secure password using the legacy rotation service.
    /// </summary>
    public string GeneratePassword(int length = 24) =>
        _legacyRotationService.GeneratePassword(length);

    /// <summary>
    /// Returns which connectors have dedicated (non-legacy) rotator implementations.
    /// </summary>
    public IReadOnlyCollection<RotationConnector> GetAvailableRotators() =>
        _rotators.Keys.ToList().AsReadOnly();
}
