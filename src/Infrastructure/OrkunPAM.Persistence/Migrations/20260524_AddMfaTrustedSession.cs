using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddMfaTrustedSession : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "MfaTrustedSessions",
            columns: table => new
            {
                Id                = table.Column<Guid>(nullable: false),
                UserId            = table.Column<Guid>(nullable: false),
                BrowserFingerprint = table.Column<string>(maxLength: 64, nullable: false),
                DeviceLabel       = table.Column<string>(maxLength: 256, nullable: true),
                TrustExpiresAtUtc = table.Column<DateTime>(nullable: false),
                GrantedFromIp     = table.Column<string>(maxLength: 64, nullable: true),
                GrantedAtUtc      = table.Column<DateTime>(nullable: false),
                LastUsedAtUtc     = table.Column<DateTime>(nullable: true),
                IsRevoked         = table.Column<bool>(nullable: false, defaultValue: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_MfaTrustedSessions", x => x.Id);
                table.ForeignKey(
                    name: "FK_MfaTrustedSessions_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_MfaTrustedSessions_UserId_IsRevoked",
            table: "MfaTrustedSessions",
            columns: new[] { "UserId", "IsRevoked" });

        migrationBuilder.CreateIndex(
            name: "IX_MfaTrustedSessions_BrowserFingerprint",
            table: "MfaTrustedSessions",
            column: "BrowserFingerprint");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "MfaTrustedSessions");
    }
}
