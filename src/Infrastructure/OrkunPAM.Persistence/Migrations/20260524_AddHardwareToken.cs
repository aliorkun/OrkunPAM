using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddHardwareToken : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "HardwareTokens",
            columns: table => new
            {
                Id              = table.Column<Guid>(nullable: false),
                UserId          = table.Column<Guid>(nullable: false),
                SerialNumber    = table.Column<string>(maxLength: 128, nullable: false),
                SecretKeyEnc    = table.Column<byte[]>(nullable: false),
                TokenType       = table.Column<int>(nullable: false, defaultValue: 0),
                CounterValue    = table.Column<long>(nullable: false, defaultValue: 0L),
                Algorithm       = table.Column<int>(nullable: false, defaultValue: 0),
                Digits          = table.Column<int>(nullable: false, defaultValue: 6),
                PeriodSeconds   = table.Column<int>(nullable: false, defaultValue: 30),
                IsActive        = table.Column<bool>(nullable: false, defaultValue: true),
                Label           = table.Column<string>(maxLength: 256, nullable: true),
                ProvisionedAtUtc = table.Column<DateTime>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_HardwareTokens", x => x.Id);
                table.ForeignKey(
                    name: "FK_HardwareTokens_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_HardwareTokens_UserId",
            table: "HardwareTokens",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_HardwareTokens_UserId_IsActive",
            table: "HardwareTokens",
            columns: new[] { "UserId", "IsActive" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "HardwareTokens");
    }
}
