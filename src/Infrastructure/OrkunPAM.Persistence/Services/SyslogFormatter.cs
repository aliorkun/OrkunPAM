using System.Text;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Formats domain events into RFC 5424 syslog format.
/// Format: &lt;PRI&gt;VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID SD-PARAM] MSG
/// </summary>
public static class SyslogFormatter
{
    private const int SyslogVersion = 1;
    private const string AppName = "OrkunPAM";
    private static readonly string Hostname = Environment.MachineName;
    private static readonly string ProcessId = Environment.ProcessId.ToString();

    /// <summary>
    /// Syslog facility: local0 (16) — standard for custom applications.
    /// </summary>
    private const int Facility = 16; // local0

    /// <summary>
    /// Format a domain event as an RFC 5424 syslog message.
    /// </summary>
    /// <param name="domainEvent">The domain event to format.</param>
    /// <param name="cefPayload">Optional CEF-formatted payload to embed as the MSG portion.</param>
    public static string Format(IDomainEvent domainEvent, string? cefPayload = null)
    {
        var severity = MapSeverity(domainEvent);
        var priority = Facility * 8 + severity;
        var timestamp = domainEvent.OccurredAtUtc.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ");
        var msgId = domainEvent.EventType;

        // Structured data
        var sd = BuildStructuredData(domainEvent);

        // MSG portion: use CEF payload if provided, otherwise plain text
        var msg = cefPayload ?? BuildPlainMessage(domainEvent);

        // RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG
        return $"<{priority}>{SyslogVersion} {timestamp} {Hostname} {AppName} {ProcessId} {SanitizeSdName(msgId)} {sd} {msg}";
    }

    /// <summary>
    /// Maps domain events to RFC 5424 severity levels (0=Emergency ... 7=Debug).
    /// </summary>
    private static int MapSeverity(IDomainEvent domainEvent) => domainEvent switch
    {
        BreakGlassActivatedEvent => 1,    // Alert
        PolicyViolationEvent => 2,        // Critical
        CommandBlockedEvent => 3,         // Error
        UserLoginFailedEvent => 4,        // Warning
        PasswordRotatedEvent e => e.Success ? 6 : 3, // Info or Error
        SessionStartedEvent => 6,         // Informational
        SessionTerminatedEvent => 6,      // Informational
        CredentialCheckedOutEvent => 5,   // Notice
        CredentialCheckedInEvent => 6,    // Informational
        UserLoggedInEvent => 6,           // Informational
        ApprovalRequestedEvent => 5,      // Notice
        _ => 6                            // Informational (default)
    };

    /// <summary>
    /// Build RFC 5424 structured data element with PAM-specific parameters.
    /// </summary>
    private static string BuildStructuredData(IDomainEvent domainEvent)
    {
        var sb = new StringBuilder();
        sb.Append("[pam@0 eventType=\"");
        sb.Append(EscapeSdValue(domainEvent.EventType));
        sb.Append('"');

        if (domainEvent is PamEvent pamEvent)
        {
            if (pamEvent.ActorUserId.HasValue)
            {
                sb.Append(" actorId=\"");
                sb.Append(pamEvent.ActorUserId.Value);
                sb.Append('"');
            }
            if (!string.IsNullOrEmpty(pamEvent.ActorUsername))
            {
                sb.Append(" actorUser=\"");
                sb.Append(EscapeSdValue(pamEvent.ActorUsername));
                sb.Append('"');
            }
            if (!string.IsNullOrEmpty(pamEvent.ActorIp))
            {
                sb.Append(" actorIp=\"");
                sb.Append(EscapeSdValue(pamEvent.ActorIp));
                sb.Append('"');
            }
        }

        // Event-specific structured data
        switch (domainEvent)
        {
            case SessionStartedEvent e:
                sb.Append($" sessionId=\"{e.SessionId}\" sessionType=\"{EscapeSdValue(e.SessionType)}\" target=\"{EscapeSdValue(e.TargetDevice)}\"");
                break;
            case SessionTerminatedEvent e:
                sb.Append($" sessionId=\"{e.SessionId}\" reason=\"{EscapeSdValue(e.Reason)}\"");
                break;
            case CommandBlockedEvent e:
                sb.Append($" sessionId=\"{e.SessionId}\" command=\"{EscapeSdValue(e.Command)}\" rule=\"{EscapeSdValue(e.Rule)}\"");
                break;
            case CredentialCheckedOutEvent e:
                sb.Append($" credentialId=\"{e.CredentialId}\" credentialName=\"{EscapeSdValue(e.CredentialName)}\"");
                break;
            case CredentialCheckedInEvent e:
                sb.Append($" credentialId=\"{e.CredentialId}\"");
                break;
            case PasswordRotatedEvent e:
                sb.Append($" credentialId=\"{e.CredentialId}\" success=\"{e.Success}\"");
                break;
            case BreakGlassActivatedEvent e:
                sb.Append($" reason=\"{EscapeSdValue(e.Reason)}\"");
                break;
            case PolicyViolationEvent e:
                sb.Append($" violationType=\"{EscapeSdValue(e.ViolationType)}\"");
                break;
            case ApprovalRequestedEvent e:
                sb.Append($" requestId=\"{e.RequestId}\" resourceType=\"{EscapeSdValue(e.ResourceType)}\"");
                break;
        }

        sb.Append(']');
        return sb.ToString();
    }

    /// <summary>
    /// Build a human-readable plain text message as fallback (when not using CEF).
    /// </summary>
    private static string BuildPlainMessage(IDomainEvent domainEvent) => domainEvent switch
    {
        UserLoggedInEvent e => $"User '{e.ActorUsername}' logged in via {e.AuthSource} from {e.ActorIp}",
        UserLoginFailedEvent e => $"Login failed for '{e.ActorUsername}' from {e.ActorIp}: {e.Reason}",
        CredentialCheckedOutEvent e => $"Credential '{e.CredentialName}' checked out by '{e.ActorUsername}'",
        CredentialCheckedInEvent e => $"Credential {e.CredentialId} checked in by '{e.ActorUsername}'",
        PasswordRotatedEvent e => $"Password rotation for '{e.CredentialName}': {(e.Success ? "success" : "failed")}",
        SessionStartedEvent e => $"Session {e.SessionId} started: {e.SessionType} to {e.TargetDevice} by '{e.ActorUsername}'",
        SessionTerminatedEvent e => $"Session {e.SessionId} terminated: {e.Reason}",
        CommandBlockedEvent e => $"Command blocked in session {e.SessionId}: '{e.Command}' (rule: {e.Rule})",
        PolicyViolationEvent e => $"Policy violation [{e.ViolationType}]: {e.Details}",
        ApprovalRequestedEvent e => $"Approval requested {e.RequestId} for {e.ResourceType} by '{e.ActorUsername}'",
        BreakGlassActivatedEvent e => $"BREAK GLASS activated by '{e.ActorUsername}': {e.Reason}",
        _ => $"Event: {domainEvent.EventType}"
    };

    /// <summary>
    /// Sanitize MSGID for RFC 5424 compliance (printable ASCII, no spaces, max 32 chars).
    /// </summary>
    private static string SanitizeSdName(string value)
    {
        if (string.IsNullOrEmpty(value)) return "-";
        var sanitized = value.Replace(" ", "_");
        return sanitized.Length > 32 ? sanitized[..32] : sanitized;
    }

    /// <summary>
    /// Escape characters in structured data values per RFC 5424 (backslash, double-quote, close-bracket).
    /// </summary>
    private static string EscapeSdValue(string value)
        => value
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("]", "\\]");
}
