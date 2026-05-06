using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.DirectAccess;

/// <summary>
/// TACACS+ server configuration for network device AAA.
/// </summary>
public class TacacsConfig : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public int ListenPort { get; set; } = 49;
    public string SharedSecret { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public string? AllowedClientsCidr { get; set; } // JSON array of CIDR
    public string? DefaultDomain { get; set; }
    public bool MfaEnabled { get; set; }
}

/// <summary>
/// RADIUS server configuration for network device AAA.
/// </summary>
public class RadiusConfig : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public int AuthPort { get; set; } = 1812;
    public int AcctPort { get; set; } = 1813;
    public string SharedSecret { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public string? AllowedClientsCidr { get; set; }
    public bool MfaEnabled { get; set; }
}

/// <summary>
/// Custom AVP (Attribute-Value Pair) definitions for TACACS+/RADIUS.
/// </summary>
public class AvpDefinition : Entity
{
    public string Protocol { get; set; } = string.Empty; // "TACACS+" or "RADIUS"
    public string AttributeName { get; set; } = string.Empty;
    public int? AttributeId { get; set; } // RADIUS attribute number
    public string? DefaultValue { get; set; }
    public string? Description { get; set; }
}
