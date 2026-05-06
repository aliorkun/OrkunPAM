using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Device;

public class Device : AuditableEntity
{
    public string Hostname { get; set; } = string.Empty;
    public string? Fqdn { get; set; }
    public string? IpAddress { get; set; }
    public DeviceType DeviceType { get; set; }
    public string? OperatingSystem { get; set; }
    public int? ConnectionPort { get; set; }
    public ConnectionProtocol ConnectionProtocol { get; set; }
    public Guid? PlatformId { get; set; }
    public Platform? Platform { get; set; }
    public bool IsManaged { get; set; } = true;
    public bool? IsReachable { get; set; }
    public DateTime? LastReachableCheck { get; set; }
    public string? AdObjectGuid { get; set; }
    public ImportSource ImportSource { get; set; } = ImportSource.Manual;
    public string? Tags { get; set; }
    public string? Notes { get; set; }
    public DeviceStatus Status { get; set; } = DeviceStatus.Active;

    public ICollection<DeviceGroupMember> DeviceGroupMembers { get; set; } = new List<DeviceGroupMember>();
    public ICollection<DeviceCredential> DeviceCredentials { get; set; } = new List<DeviceCredential>();
}

public class Platform : Entity
{
    public string Name { get; set; } = string.Empty;
    public ConnectionProtocol DefaultProtocol { get; set; }
    public int DefaultPort { get; set; }
    public string? RotationConnector { get; set; }
    public string? ConnectionTemplateJson { get; set; }
}

public class DeviceGroup : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public DeviceGroupType GroupType { get; set; }
    public string? DynamicFilterJson { get; set; }
    public int? VlanId { get; set; }
    public string? SubnetCidr { get; set; }
    public Guid? ParentGroupId { get; set; }
    public DeviceGroup? ParentGroup { get; set; }

    public ICollection<DeviceGroupMember> Members { get; set; } = new List<DeviceGroupMember>();
}

public class DeviceGroupMember
{
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid DeviceGroupId { get; set; }
    public DeviceGroup DeviceGroup { get; set; } = null!;
}

public class DeviceCredential
{
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid CredentialId { get; set; }
    public CredentialPurpose Purpose { get; set; }
    public bool IsPrimary { get; set; }
}
