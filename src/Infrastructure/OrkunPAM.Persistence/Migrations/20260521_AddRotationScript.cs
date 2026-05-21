using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddRotationScript : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "RotationScripts",
            columns: table => new
            {
                Id              = table.Column<Guid>(nullable: false),
                Name            = table.Column<string>(maxLength: 200, nullable: false),
                Description     = table.Column<string>(maxLength: 1000, nullable: true),
                DeviceType      = table.Column<string>(maxLength: 100, nullable: false, defaultValue: "Custom"),
                ScriptType      = table.Column<byte>(nullable: false, defaultValue: (byte)0),
                ScriptContent   = table.Column<string>(nullable: false, defaultValue: ""),
                TestScriptContent = table.Column<string>(nullable: true),
                IsEnabled       = table.Column<bool>(nullable: false, defaultValue: true),
                CredentialId    = table.Column<Guid>(nullable: true),
                DeviceGroupId   = table.Column<Guid>(nullable: true),
                CreatedAtUtc    = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc    = table.Column<DateTime>(nullable: false),
                CreatedBy       = table.Column<Guid>(nullable: true),
                UpdatedBy       = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_RotationScripts", x => x.Id);
                table.ForeignKey(
                    name: "FK_RotationScripts_Credentials",
                    column: x => x.CredentialId,
                    principalTable: "Credentials",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateIndex(
            name: "IX_RotationScripts_CredentialId",
            table: "RotationScripts",
            column: "CredentialId");

        migrationBuilder.CreateIndex(
            name: "IX_RotationScripts_IsEnabled",
            table: "RotationScripts",
            column: "IsEnabled");

        migrationBuilder.AddColumn<Guid>(
            name: "RotationScriptId",
            table: "Credentials",
            nullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_Credentials_RotationScriptId",
            table: "Credentials",
            column: "RotationScriptId");

        migrationBuilder.AddForeignKey(
            name: "FK_Credentials_RotationScripts",
            table: "Credentials",
            column: "RotationScriptId",
            principalTable: "RotationScripts",
            principalColumn: "Id",
            onDelete: ReferentialAction.SetNull);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey("FK_Credentials_RotationScripts", "Credentials");
        migrationBuilder.DropIndex("IX_Credentials_RotationScriptId", "Credentials");
        migrationBuilder.DropColumn("RotationScriptId", "Credentials");
        migrationBuilder.DropTable("RotationScripts");
    }
}
