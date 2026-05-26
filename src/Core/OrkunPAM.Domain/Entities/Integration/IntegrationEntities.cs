using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Integration;

// === External Vault Federation (#284 — PV #12) ===

public enum ExternalVaultType { HashiCorpVault, AzureKeyVault, AwsSecretsManager }
public enum ExternalVaultAuthMethod { Token, AppRole, ManagedIdentity, ServicePrincipal }
public enum ExternalSyncMode { Passthrough, Sync }
public enum ExternalSyncStatus { Pending, Ok, Error }

public class ExternalVaultConnection : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public ExternalVaultType VaultType { get; set; }
    public string Endpoint { get; set; } = string.Empty;
    public ExternalVaultAuthMethod AuthMethod { get; set; }
    public byte[]? AuthSecretEnc { get; set; }
    public string? Namespace { get; set; }
    public string? MountPath { get; set; }
    public string? KeyVaultName { get; set; }
    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public bool SyncEnabled { get; set; }
    public int SyncIntervalMinutes { get; set; } = 60;
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastSyncAtUtc { get; set; }
    public string? LastSyncError { get; set; }

    public ICollection<ExternalCredentialMapping> Mappings { get; set; } = new List<ExternalCredentialMapping>();
}

public class ExternalCredentialMapping : AuditableEntity
{
    public Guid ConnectionId { get; set; }
    public ExternalVaultConnection Connection { get; set; } = null!;
    public string ExternalPath { get; set; } = string.Empty;
    public string? UsernameField { get; set; }
    public string? PasswordField { get; set; }
    public Guid? MappedCredentialId { get; set; }
    public ExternalSyncMode SyncMode { get; set; } = ExternalSyncMode.Passthrough;
    public ExternalSyncStatus SyncStatus { get; set; } = ExternalSyncStatus.Pending;
    public DateTime? LastFetchedAtUtc { get; set; }
    public DateTime? LastSyncedAtUtc { get; set; }
    public string? LastError { get; set; }
}

// === PKI / Smart Card Authentication (#115) ===

public class TrustedCaCertificate : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string PemCertificate { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;   // SHA-1 hex
    public string Subject { get; set; } = string.Empty;
    public string? Issuer { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string? OcspUrl { get; set; }
    public string? CrlUrl { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool CheckRevocation { get; set; } = true;
}

public class PkiUserCertificate : AuditableEntity
{
    public Guid UserId { get; set; }
    public string CertThumbprint { get; set; } = string.Empty;  // SHA-1 hex
    public string SubjectDn { get; set; } = string.Empty;
    public string IssuingCaThumbprint { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
    public bool RequirePkiOnly { get; set; }  // blocks password login when true
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastUsedAtUtc { get; set; }
}

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
