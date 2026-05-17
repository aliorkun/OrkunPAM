using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddCloudPam : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CloudAccounts",
                columns: table => new
                {
                    Id                   = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name                 = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Provider             = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    AccountIdentifier    = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Region               = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    AccessKeyIdEnc       = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SecretKeyEnc         = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AdditionalConfigJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEnabled            = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    LastSyncAtUtc        = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ResourceCount        = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    LastSyncError        = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedAtUtc         = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc         = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedByUserId      = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedByUserId      = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table => table.PrimaryKey("PK_CloudAccounts", x => x.Id));

            migrationBuilder.CreateIndex(
                name: "IX_CloudAccounts_Provider",
                table: "CloudAccounts",
                column: "Provider");

            migrationBuilder.CreateTable(
                name: "CloudResources",
                columns: table => new
                {
                    Id             = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CloudAccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Provider       = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    NativeId       = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    Name           = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    ResourceType   = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Region         = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    Status         = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    IpAddress      = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    MetadataJson   = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEnabled      = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    LastSeenAtUtc  = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc   = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc   = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloudResources", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CloudResources_CloudAccounts_CloudAccountId",
                        column: x => x.CloudAccountId,
                        principalTable: "CloudAccounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CloudResources_CloudAccountId",
                table: "CloudResources",
                column: "CloudAccountId");

            migrationBuilder.CreateIndex(
                name: "IX_CloudResources_Provider_ResourceType",
                table: "CloudResources",
                columns: new[] { "Provider", "ResourceType" });

            migrationBuilder.CreateTable(
                name: "CloudJitRequests",
                columns: table => new
                {
                    Id                    = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByUserId     = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByUsername   = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CloudResourceId       = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Permission            = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Justification         = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Status                = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false, defaultValue: "Pending"),
                    RequestedAtUtc        = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DurationMinutes       = table.Column<int>(type: "int", nullable: false, defaultValue: 60),
                    ExpiresAtUtc          = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ApprovedByUserId      = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApprovedByUsername    = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    GrantedAtUtc          = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CloudGrantReference   = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    RevokedAtUtc          = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RevokeReason          = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    TicketNumber          = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    CreatedAtUtc          = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc          = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedByUserId       = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    UpdatedByUserId       = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloudJitRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CloudJitRequests_CloudResources_CloudResourceId",
                        column: x => x.CloudResourceId,
                        principalTable: "CloudResources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CloudJitRequests_Status",
                table: "CloudJitRequests",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_CloudJitRequests_RequestedAtUtc",
                table: "CloudJitRequests",
                column: "RequestedAtUtc");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "CloudJitRequests");
            migrationBuilder.DropTable(name: "CloudResources");
            migrationBuilder.DropTable(name: "CloudAccounts");
        }
    }
}
