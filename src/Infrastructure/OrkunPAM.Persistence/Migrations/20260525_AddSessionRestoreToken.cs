using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddSessionRestoreToken : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "SessionRestoreTokens",
            columns: table => new
            {
                Id                = table.Column<Guid>(nullable: false),
                OriginalSessionId = table.Column<Guid>(nullable: false),
                UserId            = table.Column<Guid>(nullable: false),
                DeviceId          = table.Column<Guid>(nullable: false),
                CredentialId      = table.Column<Guid>(nullable: true),
                Protocol          = table.Column<string>(maxLength: 32, nullable: false),
                CreatedAtUtc      = table.Column<DateTime>(nullable: false),
                ExpiresAtUtc      = table.Column<DateTime>(nullable: false),
                IsUsed            = table.Column<bool>(nullable: false, defaultValue: false),
                RestoredSessionId = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SessionRestoreTokens", x => x.Id);
                table.ForeignKey(
                    name: "FK_SessionRestoreTokens_ProxySessions_OriginalSessionId",
                    column: x => x.OriginalSessionId,
                    principalTable: "ProxySessions",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_SessionRestoreTokens_UserId_IsUsed",
            table: "SessionRestoreTokens",
            columns: new[] { "UserId", "IsUsed" });

        migrationBuilder.CreateIndex(
            name: "IX_SessionRestoreTokens_ExpiresAtUtc",
            table: "SessionRestoreTokens",
            column: "ExpiresAtUtc");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "SessionRestoreTokens");
    }
}
