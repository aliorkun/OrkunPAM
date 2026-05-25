using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Identity;

public class LdapConfiguration : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 389;
    public bool UseSsl { get; set; } = true;
    public string BaseDn { get; set; } = string.Empty;
    public string? BindDn { get; set; }
    public byte[]? BindPasswordEnc { get; set; }
    public string UserSearchFilter { get; set; } = "(&(objectClass=user)(sAMAccountName={0}))";
    public string GroupSearchFilter { get; set; } = "(objectClass=group)";
    public string? UserAttributeMapping { get; set; } // JSON
    public string? GroupMapping { get; set; } // JSON
    public int SyncIntervalMinutes { get; set; } = 60;
    public DateTime? LastSyncAtUtc { get; set; }
    public bool IsEnabled { get; set; } = true;
}

public class SamlProvider : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string EntityId { get; set; } = string.Empty;
    public string? MetadataUrl { get; set; }
    public string? MetadataXml { get; set; }
    public string? SigningCertThumbprint { get; set; }
    public string? AssertionConsumerUrl { get; set; }
    public string? SingleLogoutUrl { get; set; }
    public string? AttributeMapping { get; set; } // JSON
    public string? GroupAttributeName { get; set; }
    public string? GroupMapping { get; set; } // JSON
    public bool IsEnabled { get; set; } = true;
}

// OIDC Federation (#271 UM #48)
public class OidcProvider : AuditableEntity
{
    public string Name { get; set; } = string.Empty;           // slug used in URLs (e.g., "azure-ad")
    public string DisplayName { get; set; } = string.Empty;    // shown on login button
    public string Authority { get; set; } = string.Empty;      // issuer URL (e.g., https://login.microsoftonline.com/{tenant}/v2.0)
    public string ClientId { get; set; } = string.Empty;
    public byte[]? ClientSecretEnc { get; set; }               // AES-256-GCM encrypted
    public string Scopes { get; set; } = "openid profile email";
    public string? GroupClaimType { get; set; }                // e.g., "groups" or "roles"
    public string? GroupRoleMapping { get; set; }              // JSON: {"pam-admin": "GlobalAdmin"}
    public bool AutoProvisionUsers { get; set; } = true;
    public string DefaultRole { get; set; } = "Viewer";
    public bool IsEnabled { get; set; } = true;
}
