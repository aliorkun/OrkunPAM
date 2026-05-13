using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Integration;

public class WebhookConfig : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public byte[]? SecretEnc { get; set; } // AES-GCM encrypted HMAC signing secret
    public string EventTypesJson { get; set; } = "[]"; // JSON array of event types to send
    public bool IsEnabled { get; set; } = true;
    public int TimeoutSeconds { get; set; } = 10;
    public int RetryCount { get; set; } = 3;
    public DateTime? LastDeliveryAtUtc { get; set; }
    public bool LastDeliverySuccess { get; set; }
}

public class ItsmConfig : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty; // "ServiceNow", "Jira"
    public string BaseUrl { get; set; } = string.Empty;
    public string? ApiKeyEnc { get; set; } // Encrypted
    public string? Username { get; set; }
    public string? PasswordEnc { get; set; } // Encrypted
    public bool RequireTicket { get; set; } // Require ticket number for sessions/checkouts
    public bool ValidateTicket { get; set; } // Call ITSM API to validate ticket exists
    public bool IsEnabled { get; set; } = true;
}

public class NotificationConfig : Entity
{
    public string Channel { get; set; } = string.Empty; // "email", "sms", "push"
    public string ConfigJson { get; set; } = "{}"; // SMTP settings, SMS gateway, etc.
    public bool IsEnabled { get; set; } = true;
}

public class SiemTarget : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 514;
    public string Protocol { get; set; } = "UDP"; // UDP, TCP, TLS
    public int Facility { get; set; } = 16; // local0
    public string Format { get; set; } = "CEF"; // CEF, Syslog-KV
    public string EventFilterJson { get; set; } = "[]"; // empty = all events
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastSentAtUtc { get; set; }
    public int TotalEventsSent { get; set; }
    public string? LastError { get; set; }
    // TLS options — only applies when Protocol == "TLS"
    public bool AllowSelfSigned { get; set; } = false;
    public string? CaCertThumbprint { get; set; } // SHA-1 thumbprint for cert pinning (optional)
}
