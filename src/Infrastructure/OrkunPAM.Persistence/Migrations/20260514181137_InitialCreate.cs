using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace OrkunPAM.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AlertHistories",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    AlertRuleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TriggeredAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Details = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ActionsTaken = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AcknowledgedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AcknowledgedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlertHistories", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AlertRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ConditionJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ActionJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CooldownMinutes = table.Column<int>(type: "int", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlertRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Anomalies",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AnomalyType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Severity = table.Column<byte>(type: "tinyint", nullable: false),
                    Details = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DetectedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsAcknowledged = table.Column<bool>(type: "bit", nullable: false),
                    AcknowledgedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AcknowledgedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Anomalies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ApiAccessLogs",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ApiClientId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ClientIpAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Outcome = table.Column<byte>(type: "tinyint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiAccessLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ApiClients",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ClientSecretHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AllowedIpRanges = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ServiceAccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    RateLimitPerMinute = table.Column<int>(type: "int", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LastUsedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiClients", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ApprovalRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkflowId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ResourceType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ResourceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CurrentStep = table.Column<int>(type: "int", nullable: false),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TicketNumber = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApprovalRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AttestationCampaigns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ScopeJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ReviewerRuleJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    StartsAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DeadlineUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    AutoRevokeOnMiss = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AttestationCampaigns", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AttestationDecisions",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CampaignId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ReviewerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SubjectUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ResourceType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ResourceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Decision = table.Column<byte>(type: "tinyint", nullable: true),
                    DecisionAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Comments = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AttestationDecisions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false),
                    EventCategory = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EventType = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    ActorUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ActorUsername = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ActorIpAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TargetType = table.Column<string>(type: "nvarchar(450)", nullable: true),
                    TargetId = table.Column<string>(type: "nvarchar(450)", nullable: true),
                    Details = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Outcome = table.Column<byte>(type: "tinyint", nullable: false),
                    TraceId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PreviousHash = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    EntryHash = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    IsTampered = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AvpDefinitions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Protocol = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AttributeName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AttributeId = table.Column<int>(type: "int", nullable: true),
                    DefaultValue = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AvpDefinitions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BackgroundJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    JobType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CronExpression = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LastRunAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NextRunAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastRunResult = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    ConfigurationJson = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BackgroundJobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BackupRecords",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FileName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    FilePath = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Scope = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    FileSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    IntegrityHash = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IntegrityVerified = table.Column<bool>(type: "bit", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ErrorMessage = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    InitiatedBy = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BackupRecords", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BreakGlassEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterUsername = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequesterIpAddress = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ResourceType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ResourceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ResourceName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EmergencyReason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TicketNumber = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AcknowledgedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    AcknowledgedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AcknowledgedByUsername = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AcknowledgementNotes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BreakGlassEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CheckOutHistories",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CheckedOutAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CheckedInAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TicketNumber = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ApprovedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    WasAutoCheckedIn = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CheckOutHistories", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CommandLogs",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Command = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RiskScore = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    WasBlocked = table.Column<bool>(type: "bit", nullable: false),
                    BlockReason = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CommandLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CommandRiskRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Pattern = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RiskScore = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Category = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CommandRiskRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ComplianceFrameworks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Version = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsBuiltIn = table.Column<bool>(type: "bit", nullable: false),
                    ControlsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ComplianceFrameworks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ControlAssessments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FrameworkId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ControlCode = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    EvidenceJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AssessedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AssessedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ControlAssessments", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CredentialShares",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SharedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SharedToUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PermissionLevel = table.Column<byte>(type: "tinyint", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    MaxUseCount = table.Column<int>(type: "int", nullable: true),
                    UseCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CredentialShares", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DataEncryptionKeys",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    KeyVersion = table.Column<int>(type: "int", nullable: false),
                    Purpose = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EncryptedByMasterKeyVersion = table.Column<int>(type: "int", nullable: false),
                    EncryptedKeyMaterial = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DataEncryptionKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeviceGroups",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    GroupType = table.Column<byte>(type: "tinyint", nullable: false),
                    DynamicFilterJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    VlanId = table.Column<int>(type: "int", nullable: true),
                    SubnetCidr = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ParentGroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceGroups", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeviceGroups_DeviceGroups_ParentGroupId",
                        column: x => x.ParentGroupId,
                        principalTable: "DeviceGroups",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "DiscoveredAccounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DiscoveryJobId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AccountName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AccountType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DiscoveredAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    TakeoverStatus = table.Column<byte>(type: "tinyint", nullable: false),
                    LinkedCredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveredAccounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DiscoveryJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DiscoveryType = table.Column<byte>(type: "tinyint", nullable: false),
                    TargetScopeJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Schedule = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LastRunAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastRunResult = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveryJobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Groups",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    GroupSource = table.Column<byte>(type: "tinyint", nullable: false),
                    ExternalGroupId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ParentGroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Groups", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Groups_Groups_ParentGroupId",
                        column: x => x.ParentGroupId,
                        principalTable: "Groups",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "JitAccessRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterUsername = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequesterIpAddress = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ResourceType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ResourceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ResourceName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequestedDurationMinutes = table.Column<int>(type: "int", nullable: false),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApprovedByUsername = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DenyReason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ActivatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RevokeReason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RevokedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    RevokedByUsername = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ExtensionRequested = table.Column<bool>(type: "bit", nullable: false),
                    ExtensionRequestedMinutes = table.Column<int>(type: "int", nullable: true),
                    ExtensionReason = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JitAccessRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LdapConfigurations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Host = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Port = table.Column<int>(type: "int", nullable: false),
                    UseSsl = table.Column<bool>(type: "bit", nullable: false),
                    BaseDn = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BindDn = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    BindPasswordEnc = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    UserSearchFilter = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    GroupSearchFilter = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserAttributeMapping = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    GroupMapping = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SyncIntervalMinutes = table.Column<int>(type: "int", nullable: false),
                    LastSyncAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LdapConfigurations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MasterKeys",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    KeyVersion = table.Column<int>(type: "int", nullable: false),
                    EncryptedKeyMaterial = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    KeyStatus = table.Column<byte>(type: "tinyint", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RotatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MasterKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Permissions",
                columns: table => new
                {
                    Code = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Module = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Permissions", x => x.Code);
                });

            migrationBuilder.CreateTable(
                name: "Platforms",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DefaultProtocol = table.Column<byte>(type: "tinyint", nullable: false),
                    DefaultPort = table.Column<int>(type: "int", nullable: false),
                    RotationConnector = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ConnectionTemplateJson = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Platforms", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Policies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PolicyType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Scope = table.Column<byte>(type: "tinyint", nullable: false),
                    ScopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    PolicyJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Priority = table.Column<int>(type: "int", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Policies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ProxySessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionPolicyId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    SessionType = table.Column<byte>(type: "tinyint", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    EndedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DurationSeconds = table.Column<int>(type: "int", nullable: true),
                    ClientIpAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TargetIpAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TargetPort = table.Column<int>(type: "int", nullable: true),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    TerminatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    TerminationReason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TicketNumber = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RecordingPath = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RecordingSizeBytes = table.Column<long>(type: "bigint", nullable: true),
                    HasKeystrokeLog = table.Column<bool>(type: "bit", nullable: false),
                    HasOcrData = table.Column<bool>(type: "bit", nullable: false),
                    RiskScore = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Tags = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProxySessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RadiusConfigs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AuthPort = table.Column<int>(type: "int", nullable: false),
                    AcctPort = table.Column<int>(type: "int", nullable: false),
                    SharedSecret = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    AllowedClientsCidr = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RadiusConfigs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsSystemRole = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RotationPolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IntervalDays = table.Column<int>(type: "int", nullable: false),
                    PasswordComplexityJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RotateOnCheckIn = table.Column<bool>(type: "bit", nullable: false),
                    NotifyBeforeDays = table.Column<int>(type: "int", nullable: false),
                    ConnectorType = table.Column<int>(type: "int", nullable: false),
                    RetryCount = table.Column<int>(type: "int", nullable: false),
                    RetryIntervalMinutes = table.Column<int>(type: "int", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RotationPolicies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SamlProviders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EntityId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    MetadataUrl = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MetadataXml = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SigningCertThumbprint = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AssertionConsumerUrl = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SingleLogoutUrl = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AttributeMapping = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    GroupAttributeName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    GroupMapping = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SamlProviders", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SessionPolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    MaxDurationMinutes = table.Column<int>(type: "int", nullable: true),
                    IdleTimeoutMinutes = table.Column<int>(type: "int", nullable: true),
                    AllowFileTransfer = table.Column<bool>(type: "bit", nullable: false),
                    AllowClipboard = table.Column<bool>(type: "bit", nullable: false),
                    AllowDriveMapping = table.Column<bool>(type: "bit", nullable: false),
                    AllowPrinting = table.Column<bool>(type: "bit", nullable: false),
                    RecordingEnabled = table.Column<bool>(type: "bit", nullable: false),
                    KeystrokeLogging = table.Column<bool>(type: "bit", nullable: false),
                    RequireReason = table.Column<bool>(type: "bit", nullable: false),
                    RequireTicket = table.Column<bool>(type: "bit", nullable: false),
                    TwoPersonRule = table.Column<bool>(type: "bit", nullable: false),
                    EnableWatermark = table.Column<bool>(type: "bit", nullable: false),
                    CommandFilterMode = table.Column<byte>(type: "tinyint", nullable: false),
                    CommandFilterRulesJson = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SessionPolicies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SiemTargets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Host = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Port = table.Column<int>(type: "int", nullable: false),
                    Protocol = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Facility = table.Column<int>(type: "int", nullable: false),
                    Format = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EventFilterJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LastSentAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    TotalEventsSent = table.Column<int>(type: "int", nullable: false),
                    LastError = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AllowSelfSigned = table.Column<bool>(type: "bit", nullable: false),
                    CaCertThumbprint = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SiemTargets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SodRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RoleA = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleB = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SodRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SystemConfigs",
                columns: table => new
                {
                    Key = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Value = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEncrypted = table.Column<bool>(type: "bit", nullable: false),
                    Category = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SystemConfigs", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "TacacsConfigs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ListenPort = table.Column<int>(type: "int", nullable: false),
                    SharedSecret = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    AllowedClientsCidr = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DefaultDomain = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TacacsConfigs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserBehaviorBaselines",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TypicalHoursJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KnownIpsJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KnownDevicesJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    BaselineDate = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserBehaviorBaselines", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Username = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    NormalizedUsername = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Email = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AuthSource = table.Column<byte>(type: "tinyint", nullable: false),
                    ExternalId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    MfaSecret = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    MfaType = table.Column<byte>(type: "tinyint", nullable: false),
                    Phone = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    IsTemporary = table.Column<bool>(type: "bit", nullable: false),
                    TemporaryExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PasswordLastChanged = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PasswordExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    MustChangePassword = table.Column<bool>(type: "bit", nullable: false),
                    LastLoginAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastLoginIp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    FailedLoginCount = table.Column<int>(type: "int", nullable: false),
                    LockoutEndUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Language = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Timezone = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    MfaEnrollmentToken = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    MfaEnrollmentTokenExpiry = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VaultFolders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ParentFolderId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsPersonalVault = table.Column<bool>(type: "bit", nullable: false),
                    OwnerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultFolders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VaultFolders_VaultFolders_ParentFolderId",
                        column: x => x.ParentFolderId,
                        principalTable: "VaultFolders",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "WorkflowDefinitions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TriggerType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    StepsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkflowDefinitions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ApiClientCredentialAccess",
                columns: table => new
                {
                    ApiClientId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiClientCredentialAccess", x => new { x.ApiClientId, x.CredentialId });
                    table.ForeignKey(
                        name: "FK_ApiClientCredentialAccess_ApiClients_ApiClientId",
                        column: x => x.ApiClientId,
                        principalTable: "ApiClients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ApprovalSteps",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    RequestId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    StepOrder = table.Column<int>(type: "int", nullable: false),
                    ApproverId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApproverGroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ActualApproverId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Decision = table.Column<byte>(type: "tinyint", nullable: false),
                    DecisionAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Comments = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApprovalSteps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApprovalSteps_ApprovalRequests_RequestId",
                        column: x => x.RequestId,
                        principalTable: "ApprovalRequests",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Devices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Hostname = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Fqdn = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IpAddress = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    DeviceType = table.Column<byte>(type: "tinyint", nullable: false),
                    OperatingSystem = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ConnectionPort = table.Column<int>(type: "int", nullable: true),
                    ConnectionProtocol = table.Column<byte>(type: "tinyint", nullable: false),
                    PlatformId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    IsManaged = table.Column<bool>(type: "bit", nullable: false),
                    IsReachable = table.Column<bool>(type: "bit", nullable: true),
                    LastReachableCheck = table.Column<DateTime>(type: "datetime2", nullable: true),
                    AdObjectGuid = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ImportSource = table.Column<byte>(type: "tinyint", nullable: false),
                    Tags = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    SshHostKeyFingerprint = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Devices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Devices_Platforms_PlatformId",
                        column: x => x.PlatformId,
                        principalTable: "Platforms",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "GroupRoles",
                columns: table => new
                {
                    GroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupRoles", x => new { x.GroupId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_GroupRoles_Groups_GroupId",
                        column: x => x.GroupId,
                        principalTable: "Groups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_GroupRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RolePermissions",
                columns: table => new
                {
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PermissionCode = table.Column<string>(type: "nvarchar(128)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RolePermissions", x => new { x.RoleId, x.PermissionCode });
                    table.ForeignKey(
                        name: "FK_RolePermissions_Permissions_PermissionCode",
                        column: x => x.PermissionCode,
                        principalTable: "Permissions",
                        principalColumn: "Code",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RolePermissions_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserGroups",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    GroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserGroups", x => new { x.UserId, x.GroupId });
                    table.ForeignKey(
                        name: "FK_UserGroups_Groups_GroupId",
                        column: x => x.GroupId,
                        principalTable: "Groups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserGroups_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserPasswordHistories",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserPasswordHistories", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserPasswordHistories_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserRoles",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_UserRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoles_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FolderId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CredentialType = table.Column<byte>(type: "tinyint", nullable: false),
                    Username = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    PasswordEnc = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    PrivateKeyEnc = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    AdditionalDataEnc = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    KeyVersion = table.Column<int>(type: "int", nullable: false),
                    Tags = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsDiscovered = table.Column<bool>(type: "bit", nullable: false),
                    IsTakenOver = table.Column<bool>(type: "bit", nullable: false),
                    RotationPolicyId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    LastRotatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NextRotationAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CheckedOutByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CheckedOutAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CheckOutExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    MaxCheckoutMinutes = table.Column<int>(type: "int", nullable: false),
                    RequiresApproval = table.Column<bool>(type: "bit", nullable: false),
                    Status = table.Column<byte>(type: "tinyint", nullable: false),
                    Version = table.Column<int>(type: "int", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Credentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Credentials_RotationPolicies_RotationPolicyId",
                        column: x => x.RotationPolicyId,
                        principalTable: "RotationPolicies",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Credentials_VaultFolders_FolderId",
                        column: x => x.FolderId,
                        principalTable: "VaultFolders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceCredentials",
                columns: table => new
                {
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Purpose = table.Column<byte>(type: "tinyint", nullable: false),
                    IsPrimary = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceCredentials", x => new { x.DeviceId, x.CredentialId });
                    table.ForeignKey(
                        name: "FK_DeviceCredentials_Devices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "Devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceGroupMembers",
                columns: table => new
                {
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceGroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceGroupMembers", x => new { x.DeviceId, x.DeviceGroupId });
                    table.ForeignKey(
                        name: "FK_DeviceGroupMembers_DeviceGroups_DeviceGroupId",
                        column: x => x.DeviceGroupId,
                        principalTable: "DeviceGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DeviceGroupMembers_Devices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "Devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CredentialPermissions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    FolderId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    PrincipalType = table.Column<byte>(type: "tinyint", nullable: false),
                    PrincipalId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PermissionLevel = table.Column<byte>(type: "tinyint", nullable: false),
                    CanShare = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CredentialPermissions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CredentialPermissions_Credentials_CredentialId",
                        column: x => x.CredentialId,
                        principalTable: "Credentials",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_CredentialPermissions_VaultFolders_FolderId",
                        column: x => x.FolderId,
                        principalTable: "VaultFolders",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "PasswordHistories",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CredentialId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PasswordEnc = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    ChangedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ChangedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ChangeReason = table.Column<byte>(type: "tinyint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordHistories", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasswordHistories_Credentials_CredentialId",
                        column: x => x.CredentialId,
                        principalTable: "Credentials",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "Permissions",
                columns: new[] { "Code", "Description", "Module" },
                values: new object[,]
                {
                    { "aapm.client.manage", "Manage API clients", "AAPM" },
                    { "aapm.client.view", "View API clients", "AAPM" },
                    { "audit.export", "Export audit logs", "System" },
                    { "audit.view", "View audit logs", "System" },
                    { "compliance.attestation.manage", "Manage attestation campaigns", "Compliance" },
                    { "compliance.manage", "Manage compliance frameworks", "Compliance" },
                    { "compliance.view", "View compliance status", "Compliance" },
                    { "dashboard.manage", "Manage dashboards", "Reporting" },
                    { "device.create", "Create devices", "DeviceManagement" },
                    { "device.delete", "Delete devices", "DeviceManagement" },
                    { "device.edit", "Edit devices", "DeviceManagement" },
                    { "device.group.manage", "Manage device groups", "DeviceManagement" },
                    { "device.import", "Import devices", "DeviceManagement" },
                    { "device.view", "View devices", "DeviceManagement" },
                    { "group.manage", "Create/edit/delete groups", "UserManagement" },
                    { "group.view", "View groups", "UserManagement" },
                    { "report.create", "Create custom reports", "Reporting" },
                    { "report.schedule", "Schedule reports", "Reporting" },
                    { "report.view", "View reports", "Reporting" },
                    { "role.assign", "Assign roles to users/groups", "UserManagement" },
                    { "role.manage", "Create/edit roles", "UserManagement" },
                    { "role.view", "View roles", "UserManagement" },
                    { "session.monitor", "Monitor live sessions", "SessionManager" },
                    { "session.policy.manage", "Manage session policies", "SessionManager" },
                    { "session.rdp.connect", "Start RDP sessions", "SessionManager" },
                    { "session.recording.view", "View session recordings", "SessionManager" },
                    { "session.shadow", "Shadow active sessions", "SessionManager" },
                    { "session.sql.connect", "Start SQL sessions", "SessionManager" },
                    { "session.ssh.connect", "Start SSH sessions", "SessionManager" },
                    { "session.terminate", "Terminate sessions", "SessionManager" },
                    { "session.view", "View session history", "SessionManager" },
                    { "session.vnc.connect", "Start VNC sessions", "SessionManager" },
                    { "system.backup", "Manage backups", "System" },
                    { "system.config", "Manage system configuration", "System" },
                    { "system.license", "Manage licenses", "System" },
                    { "user.create", "Create users", "UserManagement" },
                    { "user.delete", "Delete users", "UserManagement" },
                    { "user.edit", "Edit users", "UserManagement" },
                    { "user.lock", "Lock/unlock users", "UserManagement" },
                    { "user.resetpassword", "Reset user passwords", "UserManagement" },
                    { "user.view", "View users", "UserManagement" },
                    { "vault.credential.checkin", "Check in passwords", "Vault" },
                    { "vault.credential.checkout", "Check out (retrieve) passwords", "Vault" },
                    { "vault.credential.create", "Create credentials", "Vault" },
                    { "vault.credential.delete", "Delete credentials", "Vault" },
                    { "vault.credential.edit", "Edit credentials", "Vault" },
                    { "vault.credential.rotate", "Rotate passwords", "Vault" },
                    { "vault.credential.share", "Share credentials", "Vault" },
                    { "vault.discovery.manage", "Manage discovery jobs", "Vault" },
                    { "vault.folder.manage", "Create/edit/delete folders", "Vault" },
                    { "vault.permission.manage", "Manage vault permissions", "Vault" },
                    { "vault.rotation.manage", "Manage rotation policies", "Vault" },
                    { "vault.view", "View vault folders and credential metadata", "Vault" },
                    { "workflow.approve", "Approve/deny requests", "Workflow" },
                    { "workflow.manage", "Manage approval workflows", "Workflow" }
                });

            migrationBuilder.InsertData(
                table: "Roles",
                columns: new[] { "Id", "CreatedAtUtc", "CreatedBy", "Description", "IsSystemRole", "Name", "UpdatedAtUtc", "UpdatedBy" },
                values: new object[,]
                {
                    { new Guid("00000000-0000-0000-0000-000000000001"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4170), null, "Full system access", true, "GlobalAdmin", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4174), null },
                    { new Guid("00000000-0000-0000-0000-000000000002"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4213), null, "Vault management", true, "VaultAdmin", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4213), null },
                    { new Guid("00000000-0000-0000-0000-000000000003"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4227), null, "Session management", true, "SessionAdmin", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4228), null },
                    { new Guid("00000000-0000-0000-0000-000000000004"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4233), null, "Read-only audit access", true, "Auditor", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4234), null },
                    { new Guid("00000000-0000-0000-0000-000000000005"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4236), null, "View-only access", true, "ReadOnly", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4237), null },
                    { new Guid("00000000-0000-0000-0000-000000000006"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4239), null, "User support", true, "HelpDesk", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4239), null },
                    { new Guid("00000000-0000-0000-0000-000000000007"), new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4230), null, "Device management", true, "DeviceAdmin", new DateTime(2026, 5, 14, 18, 11, 36, 530, DateTimeKind.Utc).AddTicks(4231), null }
                });

            migrationBuilder.InsertData(
                table: "RolePermissions",
                columns: new[] { "PermissionCode", "RoleId" },
                values: new object[,]
                {
                    { "aapm.client.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "aapm.client.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "audit.export", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "audit.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "compliance.attestation.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "compliance.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "compliance.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "dashboard.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "device.create", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "device.delete", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "device.edit", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "device.group.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "device.import", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "device.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "group.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "group.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "report.create", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "report.schedule", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "report.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "role.assign", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "role.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "role.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.monitor", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.policy.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.rdp.connect", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.recording.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.shadow", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.sql.connect", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.ssh.connect", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.terminate", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "session.vnc.connect", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "system.backup", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "system.config", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "system.license", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "user.create", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "user.delete", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "user.edit", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "user.lock", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "user.resetpassword", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "user.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.checkin", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.checkout", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.create", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.delete", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.edit", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.rotate", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.share", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.discovery.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.folder.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.permission.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.rotation.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.view", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "workflow.approve", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "workflow.manage", new Guid("00000000-0000-0000-0000-000000000001") },
                    { "vault.credential.checkin", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.credential.checkout", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.credential.create", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.credential.delete", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.credential.edit", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.credential.rotate", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.credential.share", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.discovery.manage", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.folder.manage", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.permission.manage", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.rotation.manage", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "vault.view", new Guid("00000000-0000-0000-0000-000000000002") },
                    { "session.monitor", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.policy.manage", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.rdp.connect", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.recording.view", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.shadow", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.sql.connect", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.ssh.connect", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.terminate", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.view", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "session.vnc.connect", new Guid("00000000-0000-0000-0000-000000000003") },
                    { "aapm.client.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "audit.export", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "audit.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "compliance.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "device.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "group.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "report.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "role.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "session.recording.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "session.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "user.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "vault.view", new Guid("00000000-0000-0000-0000-000000000004") },
                    { "aapm.client.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "audit.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "compliance.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "device.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "group.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "report.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "role.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "session.recording.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "session.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "user.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "vault.view", new Guid("00000000-0000-0000-0000-000000000005") },
                    { "device.view", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "group.view", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "session.view", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "user.lock", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "user.resetpassword", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "user.view", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "vault.view", new Guid("00000000-0000-0000-0000-000000000006") },
                    { "device.create", new Guid("00000000-0000-0000-0000-000000000007") },
                    { "device.delete", new Guid("00000000-0000-0000-0000-000000000007") },
                    { "device.edit", new Guid("00000000-0000-0000-0000-000000000007") },
                    { "device.group.manage", new Guid("00000000-0000-0000-0000-000000000007") },
                    { "device.import", new Guid("00000000-0000-0000-0000-000000000007") },
                    { "device.view", new Guid("00000000-0000-0000-0000-000000000007") }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Anomalies_UserId_DetectedAtUtc",
                table: "Anomalies",
                columns: new[] { "UserId", "DetectedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_ApiAccessLogs_ApiClientId_RequestedAtUtc",
                table: "ApiAccessLogs",
                columns: new[] { "ApiClientId", "RequestedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_ApiClients_ClientId",
                table: "ApiClients",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApprovalRequests_RequesterId_Status",
                table: "ApprovalRequests",
                columns: new[] { "RequesterId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_ApprovalSteps_RequestId",
                table: "ApprovalSteps",
                column: "RequestId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_ActorUserId_Timestamp",
                table: "AuditLogs",
                columns: new[] { "ActorUserId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_TargetType_TargetId",
                table: "AuditLogs",
                columns: new[] { "TargetType", "TargetId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Timestamp",
                table: "AuditLogs",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_CheckOutHistories_CredentialId_CheckedOutAtUtc",
                table: "CheckOutHistories",
                columns: new[] { "CredentialId", "CheckedOutAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CommandLogs_SessionId",
                table: "CommandLogs",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_CredentialPermissions_CredentialId",
                table: "CredentialPermissions",
                column: "CredentialId");

            migrationBuilder.CreateIndex(
                name: "IX_CredentialPermissions_FolderId",
                table: "CredentialPermissions",
                column: "FolderId");

            migrationBuilder.CreateIndex(
                name: "IX_Credentials_FolderId_Status",
                table: "Credentials",
                columns: new[] { "FolderId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_Credentials_RotationPolicyId",
                table: "Credentials",
                column: "RotationPolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_DataEncryptionKeys_KeyVersion",
                table: "DataEncryptionKeys",
                column: "KeyVersion",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceGroupMembers_DeviceGroupId",
                table: "DeviceGroupMembers",
                column: "DeviceGroupId");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceGroups_ParentGroupId",
                table: "DeviceGroups",
                column: "ParentGroupId");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_Hostname",
                table: "Devices",
                column: "Hostname");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_IpAddress",
                table: "Devices",
                column: "IpAddress");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_PlatformId",
                table: "Devices",
                column: "PlatformId");

            migrationBuilder.CreateIndex(
                name: "IX_GroupRoles_RoleId",
                table: "GroupRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_Groups_ParentGroupId",
                table: "Groups",
                column: "ParentGroupId");

            migrationBuilder.CreateIndex(
                name: "IX_MasterKeys_KeyVersion",
                table: "MasterKeys",
                column: "KeyVersion",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PasswordHistories_CredentialId",
                table: "PasswordHistories",
                column: "CredentialId");

            migrationBuilder.CreateIndex(
                name: "IX_ProxySessions_Status",
                table: "ProxySessions",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_ProxySessions_UserId_StartedAtUtc",
                table: "ProxySessions",
                columns: new[] { "UserId", "StartedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_RolePermissions_PermissionCode",
                table: "RolePermissions",
                column: "PermissionCode");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_Name",
                table: "Roles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserGroups_GroupId",
                table: "UserGroups",
                column: "GroupId");

            migrationBuilder.CreateIndex(
                name: "IX_UserPasswordHistories_UserId_CreatedAtUtc",
                table: "UserPasswordHistories",
                columns: new[] { "UserId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_RoleId",
                table: "UserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email");

            migrationBuilder.CreateIndex(
                name: "IX_Users_NormalizedUsername",
                table: "Users",
                column: "NormalizedUsername",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VaultFolders_ParentFolderId",
                table: "VaultFolders",
                column: "ParentFolderId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AlertHistories");

            migrationBuilder.DropTable(
                name: "AlertRules");

            migrationBuilder.DropTable(
                name: "Anomalies");

            migrationBuilder.DropTable(
                name: "ApiAccessLogs");

            migrationBuilder.DropTable(
                name: "ApiClientCredentialAccess");

            migrationBuilder.DropTable(
                name: "ApprovalSteps");

            migrationBuilder.DropTable(
                name: "AttestationCampaigns");

            migrationBuilder.DropTable(
                name: "AttestationDecisions");

            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "AvpDefinitions");

            migrationBuilder.DropTable(
                name: "BackgroundJobs");

            migrationBuilder.DropTable(
                name: "BackupRecords");

            migrationBuilder.DropTable(
                name: "BreakGlassEvents");

            migrationBuilder.DropTable(
                name: "CheckOutHistories");

            migrationBuilder.DropTable(
                name: "CommandLogs");

            migrationBuilder.DropTable(
                name: "CommandRiskRules");

            migrationBuilder.DropTable(
                name: "ComplianceFrameworks");

            migrationBuilder.DropTable(
                name: "ControlAssessments");

            migrationBuilder.DropTable(
                name: "CredentialPermissions");

            migrationBuilder.DropTable(
                name: "CredentialShares");

            migrationBuilder.DropTable(
                name: "DataEncryptionKeys");

            migrationBuilder.DropTable(
                name: "DeviceCredentials");

            migrationBuilder.DropTable(
                name: "DeviceGroupMembers");

            migrationBuilder.DropTable(
                name: "DiscoveredAccounts");

            migrationBuilder.DropTable(
                name: "DiscoveryJobs");

            migrationBuilder.DropTable(
                name: "GroupRoles");

            migrationBuilder.DropTable(
                name: "JitAccessRequests");

            migrationBuilder.DropTable(
                name: "LdapConfigurations");

            migrationBuilder.DropTable(
                name: "MasterKeys");

            migrationBuilder.DropTable(
                name: "PasswordHistories");

            migrationBuilder.DropTable(
                name: "Policies");

            migrationBuilder.DropTable(
                name: "ProxySessions");

            migrationBuilder.DropTable(
                name: "RadiusConfigs");

            migrationBuilder.DropTable(
                name: "RolePermissions");

            migrationBuilder.DropTable(
                name: "SamlProviders");

            migrationBuilder.DropTable(
                name: "SessionPolicies");

            migrationBuilder.DropTable(
                name: "SiemTargets");

            migrationBuilder.DropTable(
                name: "SodRules");

            migrationBuilder.DropTable(
                name: "SystemConfigs");

            migrationBuilder.DropTable(
                name: "TacacsConfigs");

            migrationBuilder.DropTable(
                name: "UserBehaviorBaselines");

            migrationBuilder.DropTable(
                name: "UserGroups");

            migrationBuilder.DropTable(
                name: "UserPasswordHistories");

            migrationBuilder.DropTable(
                name: "UserRoles");

            migrationBuilder.DropTable(
                name: "WorkflowDefinitions");

            migrationBuilder.DropTable(
                name: "ApiClients");

            migrationBuilder.DropTable(
                name: "ApprovalRequests");

            migrationBuilder.DropTable(
                name: "DeviceGroups");

            migrationBuilder.DropTable(
                name: "Devices");

            migrationBuilder.DropTable(
                name: "Credentials");

            migrationBuilder.DropTable(
                name: "Permissions");

            migrationBuilder.DropTable(
                name: "Groups");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "Platforms");

            migrationBuilder.DropTable(
                name: "RotationPolicies");

            migrationBuilder.DropTable(
                name: "VaultFolders");
        }
    }
}
