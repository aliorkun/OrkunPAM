using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Analytics;
using OrkunPAM.Domain.Entities.Audit;
using OrkunPAM.Domain.Entities.Cloud;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Entities.Network;

namespace OrkunPAM.Persistence;

public sealed class OrkunPamDbContext : DbContext
{
    public OrkunPamDbContext(DbContextOptions<OrkunPamDbContext> opts) : base(opts) { }

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
    public DbSet<RotationScript> RotationScripts => Set<RotationScript>();
    public DbSet<CheckOutHistory> CheckOutHistories => Set<CheckOutHistory>();
    public DbSet<CredentialShare> CredentialShares => Set<CredentialShare>();

    // Devices
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<Platform> Platforms => Set<Platform>();
    public DbSet<DeviceGroup> DeviceGroups => Set<DeviceGroup>();
    public DbSet<DeviceGroupMember> DeviceGroupMembers => Set<DeviceGroupMember>();
    public DbSet<DeviceCredential> DeviceCredentials => Set<DeviceCredential>();

    // Sessions
    public DbSet<ProxySession> ProxySessions => Set<ProxySession>();
    public DbSet<SessionPolicy> SessionPolicies => Set<SessionPolicy>();
    public DbSet<CommandLog> CommandLogs => Set<CommandLog>();
    public DbSet<SessionObserverLog> SessionObserverLogs => Set<SessionObserverLog>();
    public DbSet<ScreenCaptureFrame> ScreenCaptureFrames => Set<ScreenCaptureFrame>();

    // Analytics
    public DbSet<CommandRiskRule> CommandRiskRules => Set<CommandRiskRule>();
    public DbSet<UserBehaviorBaseline> UserBehaviorBaselines => Set<UserBehaviorBaseline>();
    public DbSet<Anomaly> Anomalies => Set<Anomaly>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<AlertHistory> AlertHistories => Set<AlertHistory>();

    // Network
    public DbSet<TacacsConfig> TacacsConfigs => Set<TacacsConfig>();
    public DbSet<RadiusConfig> RadiusConfigs => Set<RadiusConfig>();
    public DbSet<AvpDefinition> AvpDefinitions => Set<AvpDefinition>();

    // Compliance
    public DbSet<ComplianceFramework> ComplianceFrameworks => Set<ComplianceFramework>();
    public DbSet<ControlAssessment> ControlAssessments => Set<ControlAssessment>();
    public DbSet<SodRule> SodRules => Set<SodRule>();
    public DbSet<AccessCertificationCampaign> AccessCertificationCampaigns => Set<AccessCertificationCampaign>();
    public DbSet<AccessCertificationItem> AccessCertificationItems => Set<AccessCertificationItem>();

    // Audit
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    // Integration
    public DbSet<SiemConfig> SiemConfigs => Set<SiemConfig>();
    public DbSet<WebhookConfig> WebhookConfigs => Set<WebhookConfig>();
    public DbSet<Itsm> Itsms => Set<Itsm>();
    public DbSet<SoarConfig> SoarConfigs => Set<SoarConfig>();

    // Access Control (Realm Model)
    public DbSet<AssignedCredential> AssignedCredentials => Set<AssignedCredential>();
    public DbSet<DeviceRealm> DeviceRealms => Set<DeviceRealm>();
    public DbSet<DeviceRealmUserGroup> DeviceRealmUserGroups => Set<DeviceRealmUserGroup>();
    public DbSet<DeviceRealmDeviceGroup> DeviceRealmDeviceGroups => Set<DeviceRealmDeviceGroup>();

    // Command Filter
    public DbSet<CommandFilterPolicy> CommandFilterPolicies => Set<CommandFilterPolicy>();
    public DbSet<CommandFilterPolicyRule> CommandFilterPolicyRules => Set<CommandFilterPolicyRule>();

    // MFA
    public DbSet<MfaDevice> MfaDevices => Set<MfaDevice>();
    public DbSet<SmsOtpToken> SmsOtpTokens => Set<SmsOtpToken>();

    // Discovery & Certificates
    public DbSet<DiscoveredAccount> DiscoveredAccounts => Set<DiscoveredAccount>();
    public DbSet<CertificateEntry> CertificateEntries => Set<CertificateEntry>();
    public DbSet<CredentialTemplate> CredentialTemplates => Set<CredentialTemplate>();

    // Threat Intelligence
    public DbSet<ThreatIndicator> ThreatIndicators => Set<ThreatIndicator>();
    public DbSet<ThreatFeedSource> ThreatFeedSources => Set<ThreatFeedSource>();

    // Reports
    public DbSet<ReportSchedule> ReportSchedules => Set<ReportSchedule>();
    public DbSet<CustomReportDefinition> CustomReportDefinitions => Set<CustomReportDefinition>();

    // Cloud
    public DbSet<CloudProvider> CloudProviders => Set<CloudProvider>();

    // Vendor
    public DbSet<VendorAccess> VendorAccesses => Set<VendorAccess>();

    // Scheduled Sessions
    public DbSet<ScheduledSession> ScheduledSessions => Set<ScheduledSession>();

    // Geolocation
    public DbSet<GeoAccessRule> GeoAccessRules => Set<GeoAccessRule>();

    // Device Trust
    public DbSet<TrustedDevice> TrustedDevices => Set<TrustedDevice>();

    // Watermark
    public DbSet<SessionWatermark> SessionWatermarks => Set<SessionWatermark>();

    // Connection Profiles
    public DbSet<ConnectionProfile> ConnectionProfiles => Set<ConnectionProfile>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        base.OnModelCreating(model);
        // All configuration is handled by conventions + data annotations on entities.
    }
}
