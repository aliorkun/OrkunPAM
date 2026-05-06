using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Identity;

public class Group : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public GroupSource GroupSource { get; set; } = GroupSource.Local;
    public string? ExternalGroupId { get; set; }
    public Guid? ParentGroupId { get; set; }
    public Group? ParentGroup { get; set; }

    public ICollection<UserGroup> UserGroups { get; set; } = new List<UserGroup>();
    public ICollection<GroupRole> GroupRoles { get; set; } = new List<GroupRole>();
    public ICollection<Group> ChildGroups { get; set; } = new List<Group>();
}

public class Role : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; }

    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class Permission
{
    public string Code { get; set; } = string.Empty; // e.g. "vault.credential.checkout"
    public string Module { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public class RolePermission
{
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
    public string PermissionCode { get; set; } = string.Empty;
    public Permission Permission { get; set; } = null!;
}

public class GroupRole
{
    public Guid GroupId { get; set; }
    public Group Group { get; set; } = null!;
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
}

public class Policy : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string PolicyType { get; set; } = string.Empty;
    public PolicyScope Scope { get; set; } = PolicyScope.Global;
    public Guid? ScopeId { get; set; }
    public string PolicyJson { get; set; } = "{}";
    public int Priority { get; set; }
    public bool IsEnabled { get; set; } = true;
}
