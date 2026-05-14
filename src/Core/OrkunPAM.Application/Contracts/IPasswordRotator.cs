using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Target information for password rotation.
/// </summary>
public record RotationTarget(
    string Host,
    int Port,
    string Username,
    string? CurrentPassword,
    string NewPassword,
    string? Domain = null,
    string? DatabaseName = null);

/// <summary>
/// Result of a password rotation attempt.
/// </summary>
public record RotationResult(
    bool Success,
    string Message,
    string Connector,
    int? ResponseTimeMs = null);

/// <summary>
/// Contract for protocol-specific password rotators.
/// Each implementation handles one connector type (MySQL, PostgreSQL, SSH, WMI, etc.).
/// </summary>
public interface IPasswordRotator
{
    /// <summary>
    /// The connector type this rotator handles.
    /// </summary>
    RotationConnector ConnectorType { get; }

    /// <summary>
    /// Rotate (change) the password on the target system.
    /// Implementations must zero all sensitive memory after use.
    /// </summary>
    Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct);
}
