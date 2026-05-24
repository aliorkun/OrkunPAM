using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddSessionShadow : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "SessionShadows",
            columns: table => new
            {
                Id               = table.Column<Guid>(nullable: false),
                SessionId        = table.Column<Guid>(nullable: false),
                ShadowByUserId   = table.Column<Guid>(nullable: false),
                ShadowByUsername = table.Column<string>(maxLength: 256, nullable: true),
                StartedAtUtc     = table.Column<DateTime>(nullable: false),
                EndedAtUtc       = table.Column<DateTime>(nullable: true),
                ShadowIp         = table.Column<string>(maxLength: 64, nullable: true),
                IsActive         = table.Column<bool>(nullable: false, defaultValue: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SessionShadows", x => x.Id);
                table.ForeignKey(
                    name: "FK_SessionShadows_ProxySessions_SessionId",
                    column: x => x.SessionId,
                    principalTable: "ProxySessions",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_SessionShadows_SessionId",
            table: "SessionShadows",
            column: "SessionId");

        migrationBuilder.CreateIndex(
            name: "IX_SessionShadows_SessionId_IsActive",
            table: "SessionShadows",
            columns: new[] { "SessionId", "IsActive" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "SessionShadows");
    }
}
