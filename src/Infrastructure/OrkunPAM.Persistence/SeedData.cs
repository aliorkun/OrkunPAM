using OrkunPAM.Domain.Entities.Identity;

namespace OrkunPAM.Persistence;

public static class SeedData
{
    public static readonly Guid AdminRoleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public static readonly Guid VaultAdminId = Guid.Parse("00000000-0000-0000-0000-000000000002");
    public static readonly Guid SessionAdminId = Guid.Parse("00000000-0000-0000-0000-000000000003");
    public static readonly Guid AuditorId = Guid.Parse("00000000-0000-0000-0000-000000000004");
    public static readonly Guid ReadOnlyId = Guid.Parse("00000000-0000-0000-0000-000000000005");
    public static readonly Guid HelpDeskId = Guid.Parse("00000000-0000-0000-0000-000000000006");
    public static readonly Guid DeviceAdminId = Guid.Parse("00000000-0000-0000-0000-000000000007");

    public static IEnumerable<Role> GetRoles() =>
    [
        new() { Id = AdminRoleId, Name = "GlobalAdmin", Description = "Full system access", IsSystemRole = true },
        new() { Id = VaultAdminId, Name = "VaultAdmin", Description = "Vault management", IsSystemRole = true },
        new() { Id = SessionAdminId, Name = "SessionAdmin", Description = "Session management", IsSystemRole = true },
        new() { Id = DeviceAdminId, Name = "DeviceAdmin", Description = "Device management", IsSystemRole = true },
        new() { Id = AuditorId, Name = "Auditor", Description = "Read-only audit access", IsSystemRole = true },
        new() { Id = ReadOnlyId, Name = "ReadOnly", Description = "View-only access", IsSystemRole = true },
        new() { Id = HelpDeskId, Name = "HelpDesk", Description = "User support", IsSystemRole = true },
    ];

    public static IEnumerable<Permission> GetPermissions() =>
    [
        // User Management
        new() { Code = "user.view", Module = "UserManagement", Description = "View users" },
        new() { Code = "user.create", Module = "UserManagement", Description = "Create users" },
        new() { Code = "user.edit", Module = "UserManagement", Description = "Edit users" },
        new() { Code = "user.delete", Module = "UserManagement", Description = "Delete users" },
        new() { Code = "user.lock", Module = "UserManagement", Description = "Lock/unlock users" },
        new() { Code = "user.resetpassword", Module = "UserManagement", Description = "Reset user passwords" },
        new() { Code = "group.view", Module = "UserManagement", Description = "View groups" },
        new() { Code = "group.manage", Module = "UserManagement", Description = "Create/edit/delete groups" },
        new() { Code = "role.view", Module = "UserManagement", Description = "View roles" },
        new() { Code = "role.manage", Module = "UserManagement", Description = "Create/edit roles" },
        new() { Code = "role.assign", Module = "UserManagement", Description = "Assign roles to users/groups" },

        // Vault
        new() { Code = "vault.view", Module = "Vault", Description = "View vault folders and credential metadata" },
        new() { Code = "vault.credential.create", Module = "Vault", Description = "Create credentials" },
        new() { Code = "vault.credential.edit", Module = "Vault", Description = "Edit credentials" },
        new() { Code = "vault.credential.delete", Module = "Vault", Description = "Delete credentials" },
        new() { Code = "vault.credential.checkout", Module = "Vault", Description = "Check out (retrieve) passwords" },
        new() { Code = "vault.credential.checkin", Module = "Vault", Description = "Check in passwords" },
        new() { Code = "vault.credential.rotate", Module = "Vault", Description = "Rotate passwords" },
        new() { Code = "vault.credential.share", Module = "Vault", Description = "Share credentials" },
        new() { Code = "vault.folder.manage", Module = "Vault", Description = "Create/edit/delete folders" },
        new() { Code = "vault.permission.manage", Module = "Vault", Description = "Manage vault permissions" },
        new() { Code = "vault.discovery.manage", Module = "Vault", Description = "Manage discovery jobs" },
        new() { Code = "vault.rotation.manage", Module = "Vault", Description = "Manage rotation policies" },

        // Device
        new() { Code = "device.view", Module = "DeviceManagement", Description = "View devices" },
        new() { Code = "device.create", Module = "DeviceManagement", Description = "Create devices" },
        new() { Code = "device.edit", Module = "DeviceManagement", Description = "Edit devices" },
        new() { Code = "device.delete", Module = "DeviceManagement", Description = "Delete devices" },
        new() { Code = "device.import", Module = "DeviceManagement", Description = "Import devices" },
        new() { Code = "device.group.manage", Module = "DeviceManagement", Description = "Manage device groups" },

        // Session
        new() { Code = "session.ssh.connect", Module = "SessionManager", Description = "Start SSH sessions" },
        new() { Code = "session.rdp.connect", Module = "SessionManager", Description = "Start RDP sessions" },
        new() { Code = "session.vnc.connect", Module = "SessionManager", Description = "Start VNC sessions" },
        new() { Code = "session.sql.connect", Module = "SessionManager", Description = "Start SQL sessions" },
        new() { Code = "session.view", Module = "SessionManager", Description = "View session history" },
        new() { Code = "session.monitor", Module = "SessionManager", Description = "Monitor live sessions" },
        new() { Code = "session.shadow", Module = "SessionManager", Description = "Shadow active sessions" },
        new() { Code = "session.terminate", Module = "SessionManager", Description = "Terminate sessions" },
        new() { Code = "session.recording.view", Module = "SessionManager", Description = "View session recordings" },
        new() { Code = "session.policy.manage", Module = "SessionManager", Description = "Manage session policies" },

        // AAPM
        new() { Code = "aapm.client.view", Module = "AAPM", Description = "View API clients" },
        new() { Code = "aapm.client.manage", Module = "AAPM", Description = "Manage API clients" },

        // Compliance
        new() { Code = "compliance.view", Module = "Compliance", Description = "View compliance status" },
        new() { Code = "compliance.manage", Module = "Compliance", Description = "Manage compliance frameworks" },
        new() { Code = "compliance.attestation.manage", Module = "Compliance", Description = "Manage attestation campaigns" },

        // Reporting
        new() { Code = "report.view", Module = "Reporting", Description = "View reports" },
        new() { Code = "report.create", Module = "Reporting", Description = "Create custom reports" },
        new() { Code = "report.schedule", Module = "Reporting", Description = "Schedule reports" },
        new() { Code = "dashboard.manage", Module = "Reporting", Description = "Manage dashboards" },

        // Audit
        new() { Code = "audit.view", Module = "System", Description = "View audit logs" },
        new() { Code = "audit.export", Module = "System", Description = "Export audit logs" },

        // System
        new() { Code = "system.config", Module = "System", Description = "Manage system configuration" },
        new() { Code = "system.backup", Module = "System", Description = "Manage backups" },
        new() { Code = "system.license", Module = "System", Description = "Manage licenses" },

        // Workflow
        new() { Code = "workflow.manage", Module = "Workflow", Description = "Manage approval workflows" },
        new() { Code = "workflow.approve", Module = "Workflow", Description = "Approve/deny requests" },
    ];

    public static IEnumerable<RolePermission> GetRolePermissions()
    {
        var all = GetPermissions().Select(p => p.Code).ToList();

        // GlobalAdmin gets everything (but we also use wildcard check in code)
        foreach (var code in all)
            yield return new() { RoleId = AdminRoleId, PermissionCode = code };

        // VaultAdmin
        foreach (var code in all.Where(c => c.StartsWith("vault.")))
            yield return new() { RoleId = VaultAdminId, PermissionCode = code };

        // SessionAdmin
        foreach (var code in all.Where(c => c.StartsWith("session.")))
            yield return new() { RoleId = SessionAdminId, PermissionCode = code };

        // DeviceAdmin
        foreach (var code in all.Where(c => c.StartsWith("device.")))
            yield return new() { RoleId = DeviceAdminId, PermissionCode = code };

        // Auditor - view + audit
        foreach (var code in all.Where(c => c.EndsWith(".view") || c.StartsWith("audit.")))
            yield return new() { RoleId = AuditorId, PermissionCode = code };

        // ReadOnly - only view
        foreach (var code in all.Where(c => c.EndsWith(".view")))
            yield return new() { RoleId = ReadOnlyId, PermissionCode = code };

        // HelpDesk
        var helpDeskPerms = new[] { "user.view", "user.lock", "user.resetpassword", "group.view", "vault.view", "device.view", "session.view" };
        foreach (var code in helpDeskPerms)
            yield return new() { RoleId = HelpDeskId, PermissionCode = code };
    }
}
