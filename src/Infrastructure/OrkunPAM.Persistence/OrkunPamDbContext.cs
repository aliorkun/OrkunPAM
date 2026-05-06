using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Crypto;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence;

public class OrkunPamDbContext : DbContext, IUnitOfWork
{
    // Identity
    public DbSet<User> Users => Set<User>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<Policy> Policies => Set<Policy>();
    public DbSet<UserGroup> UserGroups => Set<UserGroup>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<GroupRole> GroupRoles => Set<GroupRole>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

    // Vault
    public DbSet<VaultFolder> VaultFolders => Set<VaultFolder>();
    public DbSet<Credential> Credentials => Set<Credential>();
    public DbSet<CredentialPermission> CredentialPermissions => Set<CredentialPermission>();
    public DbSet<PasswordHistory> PasswordHistories => Set<PasswordHistory>();
    public DbSet<RotationPolicy> RotationPolicies => Set<RotationPolicy>();
    public DbSet<CheckOutHistory> CheckOutHistories => Set<CheckOutHistory>();
    public DbSet<CredentialShare> CredentialShares => Set<CredentialShare>();

    // Device
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<Platform> Platforms => Set<Platform>();
    public DbSet<DeviceGroup> DeviceGroups => Set<DeviceGroup>();
    public DbSet<DeviceGroupMember> DeviceGroupMembers => Set<DeviceGroupMember>();
    public DbSet<DeviceCredential> DeviceCredentials => Set<DeviceCredential>();

    // Session
    public DbSet<ProxySession> ProxySessions => Set<ProxySession>();
    public DbSet<SessionPolicy> SessionPolicies => Set<SessionPolicy>();
    public DbSet<CommandLog> CommandLogs => Set<CommandLog>();

    // Crypto
    public DbSet<MasterKey> MasterKeys => Set<MasterKey>();
    public DbSet<DataEncryptionKey> DataEncryptionKeys => Set<DataEncryptionKey>();

    // System
    public DbSet<AuditLogEntry> AuditLogs => Set<AuditLogEntry>();
    public DbSet<SystemConfig> SystemConfigs => Set<SystemConfig>();
    public DbSet<BackgroundJob> BackgroundJobs => Set<BackgroundJob>();

    public OrkunPamDbContext(DbContextOptions<OrkunPamDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // === Identity ===
        modelBuilder.Entity<User>(e =>
        {
            e.HasIndex(u => u.NormalizedUsername).IsUnique();
            e.HasIndex(u => u.Email);
            e.Property(u => u.Username).HasMaxLength(256);
            e.Property(u => u.NormalizedUsername).HasMaxLength(256);
            e.Property(u => u.DisplayName).HasMaxLength(512);
            e.Property(u => u.Email).HasMaxLength(512);
            e.HasQueryFilter(u => !u.IsDeleted);
        });

        modelBuilder.Entity<UserGroup>(e =>
        {
            e.HasKey(ug => new { ug.UserId, ug.GroupId });
            e.HasOne(ug => ug.User).WithMany(u => u.UserGroups).HasForeignKey(ug => ug.UserId);
            e.HasOne(ug => ug.Group).WithMany(g => g.UserGroups).HasForeignKey(ug => ug.GroupId);
        });

        modelBuilder.Entity<UserRole>(e =>
        {
            e.HasKey(ur => new { ur.UserId, ur.RoleId });
        });

        modelBuilder.Entity<GroupRole>(e =>
        {
            e.HasKey(gr => new { gr.GroupId, gr.RoleId });
        });

        modelBuilder.Entity<Role>(e =>
        {
            e.HasIndex(r => r.Name).IsUnique();
            e.Property(r => r.Name).HasMaxLength(128);
        });

        modelBuilder.Entity<Permission>(e =>
        {
            e.HasKey(p => p.Code);
            e.Property(p => p.Code).HasMaxLength(128);
            e.Property(p => p.Module).HasMaxLength(64);
        });

        modelBuilder.Entity<RolePermission>(e =>
        {
            e.HasKey(rp => new { rp.RoleId, rp.PermissionCode });
            e.HasOne(rp => rp.Permission).WithMany().HasForeignKey(rp => rp.PermissionCode);
        });

        modelBuilder.Entity<Group>(e =>
        {
            e.Property(g => g.Name).HasMaxLength(256);
            e.HasOne(g => g.ParentGroup).WithMany(g => g.ChildGroups).HasForeignKey(g => g.ParentGroupId);
        });

        // === Vault ===
        modelBuilder.Entity<VaultFolder>(e =>
        {
            e.Property(f => f.Name).HasMaxLength(256);
            e.HasOne(f => f.ParentFolder).WithMany(f => f.ChildFolders).HasForeignKey(f => f.ParentFolderId);
        });

        modelBuilder.Entity<Credential>(e =>
        {
            e.Property(c => c.Name).HasMaxLength(512);
            e.Property(c => c.Username).HasMaxLength(512);
            e.HasIndex(c => new { c.FolderId, c.Status });
            e.HasOne(c => c.RotationPolicy).WithMany().HasForeignKey(c => c.RotationPolicyId);
        });

        modelBuilder.Entity<PasswordHistory>(e =>
        {
            e.HasKey(ph => ph.Id);
            e.Property(ph => ph.Id).ValueGeneratedOnAdd();
            e.HasIndex(ph => ph.CredentialId);
        });

        modelBuilder.Entity<CheckOutHistory>(e =>
        {
            e.HasKey(ch => ch.Id);
            e.Property(ch => ch.Id).ValueGeneratedOnAdd();
            e.HasIndex(ch => new { ch.CredentialId, ch.CheckedOutAtUtc });
        });

        // === Device ===
        modelBuilder.Entity<Device>(e =>
        {
            e.Property(d => d.Hostname).HasMaxLength(256);
            e.Property(d => d.IpAddress).HasMaxLength(45);
            e.HasIndex(d => d.Hostname);
            e.HasIndex(d => d.IpAddress);
        });

        modelBuilder.Entity<DeviceGroupMember>(e =>
        {
            e.HasKey(dgm => new { dgm.DeviceId, dgm.DeviceGroupId });
        });

        modelBuilder.Entity<DeviceCredential>(e =>
        {
            e.HasKey(dc => new { dc.DeviceId, dc.CredentialId });
        });

        // === Session ===
        modelBuilder.Entity<ProxySession>(e =>
        {
            e.HasIndex(s => new { s.UserId, s.StartedAtUtc });
            e.HasIndex(s => s.Status);
        });

        modelBuilder.Entity<CommandLog>(e =>
        {
            e.HasKey(cl => cl.Id);
            e.Property(cl => cl.Id).ValueGeneratedOnAdd();
            e.HasIndex(cl => cl.SessionId);
        });

        // === Crypto ===
        modelBuilder.Entity<MasterKey>(e =>
        {
            e.HasKey(mk => mk.Id);
            e.Property(mk => mk.Id).ValueGeneratedOnAdd();
            e.HasIndex(mk => mk.KeyVersion).IsUnique();
        });

        modelBuilder.Entity<DataEncryptionKey>(e =>
        {
            e.HasKey(dek => dek.Id);
            e.Property(dek => dek.Id).ValueGeneratedOnAdd();
            e.HasIndex(dek => dek.KeyVersion).IsUnique();
        });

        // === System ===
        modelBuilder.Entity<AuditLogEntry>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.Id).ValueGeneratedOnAdd();
            e.HasIndex(a => a.Timestamp);
            e.HasIndex(a => new { a.ActorUserId, a.Timestamp });
            e.HasIndex(a => new { a.TargetType, a.TargetId });
            e.Property(a => a.EventType).HasMaxLength(128);
        });

        modelBuilder.Entity<SystemConfig>(e =>
        {
            e.HasKey(sc => sc.Key);
            e.Property(sc => sc.Key).HasMaxLength(256);
        });

        // Seed built-in roles
        SeedData(modelBuilder);
    }

    private static void SeedData(ModelBuilder modelBuilder)
    {
        var adminRoleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
        var vaultAdminId = Guid.Parse("00000000-0000-0000-0000-000000000002");
        var sessionAdminId = Guid.Parse("00000000-0000-0000-0000-000000000003");
        var auditorId = Guid.Parse("00000000-0000-0000-0000-000000000004");
        var readOnlyId = Guid.Parse("00000000-0000-0000-0000-000000000005");
        var helpDeskId = Guid.Parse("00000000-0000-0000-0000-000000000006");

        modelBuilder.Entity<Role>().HasData(
            new Role { Id = adminRoleId, Name = "GlobalAdmin", Description = "Full system access", IsSystemRole = true },
            new Role { Id = vaultAdminId, Name = "VaultAdmin", Description = "Vault management access", IsSystemRole = true },
            new Role { Id = sessionAdminId, Name = "SessionAdmin", Description = "Session management access", IsSystemRole = true },
            new Role { Id = auditorId, Name = "Auditor", Description = "Read-only audit access", IsSystemRole = true },
            new Role { Id = readOnlyId, Name = "ReadOnly", Description = "View-only access", IsSystemRole = true },
            new Role { Id = helpDeskId, Name = "HelpDesk", Description = "User support access", IsSystemRole = true }
        );
    }

    public override Task<int> SaveChangesAsync(CancellationToken ct = default)
    {
        // Auto-set audit fields
        foreach (var entry in ChangeTracker.Entries<AuditableEntity>())
        {
            if (entry.State == EntityState.Modified)
                entry.Entity.UpdatedAtUtc = DateTime.UtcNow;
        }
        return base.SaveChangesAsync(ct);
    }
}
