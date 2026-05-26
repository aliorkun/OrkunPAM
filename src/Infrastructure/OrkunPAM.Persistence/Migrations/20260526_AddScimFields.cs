using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddScimFields : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // SCIM fields on Users
        migrationBuilder.AddColumn<string>(
            name: "ScimExternalId",
            table: "Users",
            maxLength: 256,
            nullable: true);

        migrationBuilder.AddColumn<bool>(
            name: "ScimProvisioned",
            table: "Users",
            nullable: false,
            defaultValue: false);

        migrationBuilder.AddColumn<DateTime>(
            name: "ScimLastSyncedAt",
            table: "Users",
            nullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_Users_ScimExternalId",
            table: "Users",
            column: "ScimExternalId");

        // SCIM Bearer Tokens table
        migrationBuilder.CreateTable(
            name: "ScimTokens",
            columns: t => new
            {
                Id              = t.Column<Guid>(nullable: false),
                Name            = t.Column<string>(maxLength: 256, nullable: false),
                TokenHash       = t.Column<string>(maxLength: 64, nullable: false),
                TokenPrefix     = t.Column<string>(maxLength: 16, nullable: false),
                IsActive        = t.Column<bool>(nullable: false, defaultValue: true),
                CreatedAtUtc    = t.Column<DateTime>(nullable: false),
                ExpiresAtUtc    = t.Column<DateTime>(nullable: true),
                LastUsedAtUtc   = t.Column<DateTime>(nullable: true),
                CreatedByUserId = t.Column<Guid>(nullable: true)
            },
            constraints: t =>
            {
                t.PrimaryKey("PK_ScimTokens", x => x.Id);
                t.ForeignKey(
                    name: "FK_ScimTokens_Users_CreatedByUserId",
                    column: x => x.CreatedByUserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ScimTokens_TokenHash",
            table: "ScimTokens",
            column: "TokenHash",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ScimTokens_CreatedByUserId",
            table: "ScimTokens",
            column: "CreatedByUserId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "ScimTokens");
        migrationBuilder.DropIndex("IX_Users_ScimExternalId", "Users");
        migrationBuilder.DropColumn("ScimExternalId", "Users");
        migrationBuilder.DropColumn("ScimProvisioned", "Users");
        migrationBuilder.DropColumn("ScimLastSyncedAt", "Users");
    }
}
