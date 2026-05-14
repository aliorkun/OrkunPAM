using System.Text;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Formats domain events into ArcSight Common Event Format (CEF).
/// Format: CEF:0|DeviceVendor|DeviceProduct|DeviceVersion|SignatureId|Name|Severity|Extensions
/// </summary>
public static class CefFormatter
{
    private const string Vendor = "OrkunPAM";
    private const string Product = "PAM";
    private const string Version = "1.0";

    public static string Format(IDomainEvent domainEvent)
    {
        var (signatureId, name, severity, extensions) = MapEvent(domainEvent);
        var extensionStr = FormatExtensions(extensions);

        // CEF header fields: pipe-delimited, pipes in values must be escaped
        return $"CEF:0|{EscapeHeader(Vendor)}|{EscapeHeader(Product)}|{EscapeHeader(Version)}|{EscapeHeader(signatureId)}|{EscapeHeader(name)}|{severity}|{extensionStr}";
    }

    private static (string SignatureId, string Name, int Severity, Dictionary<string, string> Extensions) MapEvent(IDomainEvent domainEvent)
    {
        var extensions = new Dictionary<string, string>();

        // Common fields from PamEvent base
        if (domainEvent is PamEvent pamEvent)
        {
            extensions["rt"] = pamEvent.OccurredAtUtc.ToString("o");
            if (pamEvent.ActorUserId.HasValue)
                extensions["suid"] = pamEvent.ActorUserId.Value.ToString();
            if (!string.IsNullOrEmpty(pamEvent.ActorUsername))
                extensions["suser"] = pamEvent.ActorUsername;
            if (!string.IsNullOrEmpty(pamEvent.ActorIp))
                extensions["src"] = pamEvent.ActorIp;
        }

        return domainEvent switch
        {
            UserLoggedInEvent e => (
                "100", "User Login Success", 3,
                AddTo(extensions, new()
                {
                    ["act"] = "Login",
                    ["outcome"] = "Success",
                    ["cs1"] = e.AuthSource,
                    ["cs1Label"] = "AuthSource"
                })),

            UserLoginFailedEvent e => (
                "101", "User Login Failed", 6,
                AddTo(extensions, new()
                {
                    ["act"] = "Login",
                    ["outcome"] = "Failure",
                    ["reason"] = e.Reason
                })),

            CredentialCheckedOutEvent e => (
                "200", "Credential Checked Out", 5,
                AddTo(extensions, new()
                {
                    ["act"] = "CheckOut",
                    ["cs2"] = e.CredentialId.ToString(),
                    ["cs2Label"] = "CredentialId",
                    ["cs3"] = e.CredentialName,
                    ["cs3Label"] = "CredentialName",
                    ["reason"] = e.Reason ?? ""
                })),

            CredentialCheckedInEvent e => (
                "201", "Credential Checked In", 3,
                AddTo(extensions, new()
                {
                    ["act"] = "CheckIn",
                    ["cs2"] = e.CredentialId.ToString(),
                    ["cs2Label"] = "CredentialId"
                })),

            PasswordRotatedEvent e => (
                "202", "Password Rotated", e.Success ? 3 : 7,
                AddTo(extensions, new()
                {
                    ["act"] = "PasswordRotate",
                    ["outcome"] = e.Success ? "Success" : "Failure",
                    ["cs2"] = e.CredentialId.ToString(),
                    ["cs2Label"] = "CredentialId",
                    ["cs3"] = e.CredentialName,
                    ["cs3Label"] = "CredentialName",
                    ["msg"] = e.ErrorMessage ?? ""
                })),

            SessionStartedEvent e => (
                "300", "Session Started", 5,
                AddTo(extensions, new()
                {
                    ["act"] = "SessionStart",
                    ["cs4"] = e.SessionId.ToString(),
                    ["cs4Label"] = "SessionId",
                    ["cs5"] = e.SessionType,
                    ["cs5Label"] = "SessionType",
                    ["dst"] = e.TargetDevice
                })),

            SessionTerminatedEvent e => (
                "301", "Session Terminated", 3,
                AddTo(extensions, new()
                {
                    ["act"] = "SessionEnd",
                    ["cs4"] = e.SessionId.ToString(),
                    ["cs4Label"] = "SessionId",
                    ["reason"] = e.Reason
                })),

            CommandBlockedEvent e => (
                "302", "Command Blocked", 8,
                AddTo(extensions, new()
                {
                    ["act"] = "CommandBlock",
                    ["cs4"] = e.SessionId.ToString(),
                    ["cs4Label"] = "SessionId",
                    ["cs6"] = e.Command,
                    ["cs6Label"] = "BlockedCommand",
                    ["msg"] = e.Rule
                })),

            PolicyViolationEvent e => (
                "400", "Policy Violation", 8,
                AddTo(extensions, new()
                {
                    ["act"] = "PolicyViolation",
                    ["cs1"] = e.ViolationType,
                    ["cs1Label"] = "ViolationType",
                    ["msg"] = e.Details
                })),

            ApprovalRequestedEvent e => (
                "500", "Approval Requested", 3,
                AddTo(extensions, new()
                {
                    ["act"] = "ApprovalRequest",
                    ["cs1"] = e.RequestId.ToString(),
                    ["cs1Label"] = "RequestId",
                    ["cs2"] = e.ResourceType,
                    ["cs2Label"] = "ResourceType"
                })),

            BreakGlassActivatedEvent e => (
                "900", "Break Glass Activated", 10,
                AddTo(extensions, new()
                {
                    ["act"] = "BreakGlass",
                    ["reason"] = e.Reason
                })),

            // Fallback for unknown event types
            _ => (
                "999", domainEvent.EventType, 3,
                AddTo(extensions, new()
                {
                    ["act"] = domainEvent.EventType
                }))
        };
    }

    private static Dictionary<string, string> AddTo(Dictionary<string, string> target, Dictionary<string, string> additional)
    {
        foreach (var kvp in additional)
            target[kvp.Key] = kvp.Value;
        return target;
    }

    /// <summary>
    /// Formats extension key=value pairs. Values with spaces, equals signs, or backslashes are escaped per CEF spec.
    /// </summary>
    private static string FormatExtensions(Dictionary<string, string> extensions)
    {
        var sb = new StringBuilder();
        var first = true;
        foreach (var kvp in extensions)
        {
            if (string.IsNullOrEmpty(kvp.Value)) continue;
            if (!first) sb.Append(' ');
            first = false;
            sb.Append(kvp.Key);
            sb.Append('=');
            sb.Append(EscapeExtensionValue(kvp.Value));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Escape pipe characters in CEF header fields.
    /// </summary>
    private static string EscapeHeader(string value)
        => value.Replace("\\", "\\\\").Replace("|", "\\|");

    /// <summary>
    /// Escape backslash, equals sign, and newlines in CEF extension values.
    /// </summary>
    private static string EscapeExtensionValue(string value)
        => value
            .Replace("\\", "\\\\")
            .Replace("=", "\\=")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r");
}
