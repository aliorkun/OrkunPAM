using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Access;

/// <summary>
/// Device Realm: access matrix grouping User Groups → Device Groups (Kron PAM model).
/// Defines which user groups can access which device groups, with optional session policy.
/// </summary>
public class DeviceRealm : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public Guid? SessionPolicyId { get; set; }

    public ICollection<DeviceRealmUserGroup> UserGroups { get; set; } = new List<DeviceRealmUserGroup>();
    public ICollection<DeviceRealmDeviceGroup> DeviceGroups { get; set; } = new List<DeviceRealmDeviceGroup>();
}

public class DeviceRealmUserGroup
{
    public Guid DeviceRealmId { get; set; }
    public DeviceRealm DeviceRealm { get; set; } = null!;
    public Guid UserGroupId { get; set; }
    public Group UserGroup { get; set; } = null!;
}

public class DeviceRealmDeviceGroup
{
    public Guid DeviceRealmId { get; set; }
    public DeviceRealm DeviceRealm { get; set; } = null!;
    public Guid DeviceGroupId { get; set; }
    public DeviceGroup DeviceGroup { get; set; } = null!;
}
