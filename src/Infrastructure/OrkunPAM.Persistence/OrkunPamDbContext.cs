using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Aapm;
using OrkunPAM.Domain.Entities.Analytics;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Domain.Entities.Crypto;
using OrkunPAM.Domain.Entities.DirectAccess;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Entities.Security;
using OrkunPAM.Domain.Entities.Workflow;
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
    public DbSet<LdapConfiguration> LdapConfigurations => Set<LdapConfiguration>();
    public DbSet<SamlProvider> SamlProviders => Set<SamlProvider>();
    public DbSet<UserGroup> UserGroups => Set<UserGroup>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<GroupRole> GroupRoles => Set<GroupRole>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<UserPasswordHistory> UserPasswordHistories => Set<UserPasswordHistory>();

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

    // Analytics
    public DbSet<CommandRiskRule> CommandRiskRules => Set<CommandRiskRule>();
    public DbSet<UserBehaviorBaseline> UserBehaviorBaselines => Set<UserBehaviorBaseline>();
    public DbSet<Anomaly> Anomalies => Set<Anomaly>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<AlertHistory> AlertHistories => Set<AlertHistory>();

    // Direct Access
    public DbSet<TacacsConfig> TacacsConfigs => Set<TacacsConfig>();
    public DbSet<RadiusConfig> RadiusConfigs => Set<RadiusConfig>();
    public DbSet<AvpDefinition> AvpDefinitions => Set<AvpDefinition>();

    // Compliance
    public DbSet<ComplianceFramework> ComplianceFrameworks => Set<ComplianceFramework>();
    public DbSet<ControlAssessment> ControlAssessments => Set<ControlAssessment>();
    public DbSet<SodRule> SodRules => Set<SodRule>();
    public DbSet<AttestationCampaign> AttestationCampaigns => Set<AttestationCampaign>();
    public DbSet<AttestationDecision> AttestationDecisions => Set<AttestationDecision>();

    // Vault Discovery
    public DbSet<DiscoveryJob> DiscoveryJobs => Set<DiscoveryJob>();
    public DbSet<DiscoveredAccount> DiscoveredAccounts => Set<DiscoveredAccount>();

    // AAPM
    public DbSet<ApiClient> ApiClients => Set<ApiClient>();
    public DbSet<ApiClientCredentialAccess> ApiClientCredentialAccess => Set<ApiClientCredentialAccess>();
    public DbSet<ApiAccessLog> ApiAccessLogs => Set<ApiAccessLog>();

    // Workflow
    public DbSet<WorkflowDefinition> WorkflowDefinitions => Set<WorkflowDefinition>();
    public DbSet<ApprovalRequest> ApprovalRequests => Set<ApprovalRequest>();
    public DbSet<ApprovalStep> ApprovalSteps => Set<ApprovalStep>();

    // Crypto
    public DbSet<MasterKey> MasterKeys => Set<MasterKey>();
    public DbSet<DataEncryptionKey> DataEncryptionKeys => Set<DataEncryptionKey>();

    // System
    public DbSet<AuditLogEntry> AuditLogs => Set<AuditLogEntry>();
    public DbSet<SystemConfig> SystemConfigs => Set<SystemConfig>();
    public DbSet<BackgroundJob> BackgroundJobs => Set<BackgroundJob>();

    // Security
    public DbSet<BreakGlassEvent> BreakGlassEvents => Set<BreakGlassEvent>();
    public DbSet<JitAccessRequest> JitAccessRequests => Set<JitAccessRequest>();
    public DbSet<VendorAccess> VendorAccesses => Set<VendorAccess>();

    // SIEM (#63)
    public DbSet<SiemTarget> SiemTargets => Set<SiemTarget>();

    // Backup (#55)
    public DbSet<BackupRecord> BackupRecords => Set<BackupRecord>();

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

        modelBuilder.Entity<UserPasswordHistory>(e =>
        {
            e.HasKey(h => h.Id);
            e.Property(h => h.Id).ValueGeneratedOnAdd();
            e.HasOne(h => h.User).WithMany(u => u.PasswordHistories).HasForeignKey(h => h.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(h => new { h.UserId, h.CreatedAtUtc });
            e.Property(h => h.PasswordHash).HasMaxLength(512);
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
            e.Property(s => s.SessionTokenHash).HasMaxLength(64);
            e.HasIndex(s => s.SessionTokenHash).IsUnique().HasFilter("[SessionTokenHash] IS NOT NULL");
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

        // === Analytics ===
        modelBuilder.Entity<Anomaly>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.Id).ValueGeneratedOnAdd();
            e.HasIndex(a => new { a.UserId, a.DetectedAtUtc });
        });

        modelBuilder.Entity<AlertHistory>(e =>
        {
            e.HasKey(h => h.Id);
            e.Property(h => h.Id).ValueGeneratedOnAdd();
        });

        // === Compliance ===
        modelBuilder.Entity<AttestationDecision>(e =>
        {
            e.HasKey(d => d.Id);
            e.Property(d => d.Id).ValueGeneratedOnAdd();
        });

        // === AAPM ===
        modelBuilder.Entity<ApiClient>(e =>
        {
            e.HasIndex(ac => ac.ClientId).IsUnique();
        });

        modelBuilder.Entity<ApiClientCredentialAccess>(e =>
        {
            e.HasKey(x => new { x.ApiClientId, x.CredentialId });
        });

        modelBuilder.Entity<ApiAccessLog>(e =>
        {
            e.HasKey(l => l.Id);
            e.Property(l => l.Id).ValueGeneratedOnAdd();
            e.HasIndex(l => new { l.ApiClientId, l.RequestedAtUtc });
        });

        // === Workflow ===
        modelBuilder.Entity<ApprovalRequest>(e =>
        {
            e.HasIndex(ar => new { ar.RequesterId, ar.Status });
        });

        modelBuilder.Entity<ApprovalStep>(e =>
        {
            e.HasKey(s => s.Id);
            e.Property(s => s.Id).ValueGeneratedOnAdd();
            e.HasOne(s => s.Request).WithMany(r => r.Steps).HasForeignKey(s => s.RequestId);
        });

        // === Vendor Access (#127) ===
        modelBuilder.Entity<VendorAccess>(e =>
        {
            e.HasIndex(v => v.InviteToken).IsUnique();
            e.HasIndex(v => v.Status);
            e.Property(v => v.VendorName).HasMaxLength(256);
            e.Property(v => v.Company).HasMaxLength(256);
            e.Property(v => v.Email).HasMaxLength(512);
            e.Property(v => v.InviteToken).HasMaxLength(128);
        });

        // Seed built-in data
        modelBuilder.Entity<Role>().HasData(SeedData.GetRoles());
        modelBuilder.Entity<Permission>().HasData(SeedData.GetPermissions());
        modelBuilder.Entity<RolePermission>().HasData(SeedData.GetRolePermissions());
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
