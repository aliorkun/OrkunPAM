using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddAssignedCredential : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AssignedCredentials",
            columns: table => new
            {
                Id            = table.Column<Guid>(nullable: false),
                CredentialId  = table.Column<Guid>(nullable: false),
                PrincipalType = table.Column<byte>(nullable: false),
                PrincipalId   = table.Column<Guid>(nullable: false),
                DeviceGroupId = table.Column<Guid>(nullable: true),
                IsEnabled     = table.Column<bool>(nullable: false, defaultValue: true),
                Notes         = table.Column<string>(maxLength: 1024, nullable: true),
                CreatedAtUtc  = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc  = table.Column<DateTime>(nullable: false),
                CreatedBy     = table.Column<Guid>(nullable: true),
                UpdatedBy     = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AssignedCredentials", x => x.Id);
                table.ForeignKey("FK_AssignedCredentials_Credentials",
                    x => x.CredentialId, "Credentials", "Id", onDelete: ReferentialAction.Cascade);
                table.ForeignKey("FK_AssignedCredentials_DeviceGroups",
                    x => x.DeviceGroupId, "DeviceGroups", "Id", onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateIndex(
            name: "IX_AssignedCredentials_CredentialId",
            table: "AssignedCredentials",
            column: "CredentialId");

        migrationBuilder.CreateIndex(
            name: "IX_AssignedCredentials_PrincipalId",
            table: "AssignedCredentials",
            column: "PrincipalId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "AssignedCredentials");
    }
}
