using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddSessionDelegation : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "SessionDelegations",
            columns: table => new
            {
                Id                = table.Column<Guid>(nullable: false),
                DelegatorUserId   = table.Column<Guid>(nullable: false),
                DelegatorUsername = table.Column<string>(maxLength: 256, nullable: true),
                DelegateUserId    = table.Column<Guid>(nullable: false),
                DelegateUsername  = table.Column<string>(maxLength: 256, nullable: true),
                DeviceId          = table.Column<Guid>(nullable: true),
                DeviceGroupId     = table.Column<Guid>(nullable: true),
                CredentialId      = table.Column<Guid>(nullable: true),
                GrantedAtUtc      = table.Column<DateTime>(nullable: false),
                ExpiresAtUtc      = table.Column<DateTime>(nullable: false),
                RevokedAtUtc      = table.Column<DateTime>(nullable: true),
                Status            = table.Column<string>(maxLength: 32, nullable: false, defaultValue: "Active"),
                MaxSessionCount   = table.Column<int>(nullable: false, defaultValue: 1),
                UsageCount        = table.Column<int>(nullable: false, defaultValue: 0),
                DelegationNote    = table.Column<string>(maxLength: 1024, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SessionDelegations", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_SessionDelegations_DelegateUserId_Status",
            table: "SessionDelegations",
            columns: new[] { "DelegateUserId", "Status" });

        migrationBuilder.CreateIndex(
            name: "IX_SessionDelegations_DelegatorUserId",
            table: "SessionDelegations",
            column: "DelegatorUserId");

        migrationBuilder.CreateIndex(
            name: "IX_SessionDelegations_Status_ExpiresAtUtc",
            table: "SessionDelegations",
            columns: new[] { "Status", "ExpiresAtUtc" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "SessionDelegations");
    }
}
