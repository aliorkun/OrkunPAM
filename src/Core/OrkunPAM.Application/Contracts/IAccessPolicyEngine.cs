namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Access decision verdict.
/// </summary>
public enum AccessVerdict
{
    Allow,
    Deny
}

/// <summary>
/// Result of access policy evaluation.
/// </summary>
public sealed record AccessDecision(
    AccessVerdict Verdict,
    string Reason,
    string? PolicyName = null,
    Guid? PolicyId = null);

/// <summary>
/// Evaluates time-based and IP-based access policies for users.
/// </summary>
public interface IAccessPolicyEngine
{
    Task<AccessDecision> EvaluateAsync(Guid userId, Guid? credentialId, string clientIp, DateTime requestTime, CancellationToken ct = default);
}
