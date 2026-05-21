using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddApiKey : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<bool>(
            name: "IsServiceAccount",
            table: "Users",
            nullable: false,
            defaultValue: false);

        migrationBuilder.CreateTable(
            name: "ApiKeys",
            columns: table => new
            {
                Id                   = table.Column<Guid>(nullable: false),
                Name                 = table.Column<string>(maxLength: 256, nullable: false),
                Description          = table.Column<string>(maxLength: 1024, nullable: true),
                Prefix               = table.Column<string>(maxLength: 16, nullable: false),
                KeyHash              = table.Column<byte[]>(nullable: false),
                HmacSecretEnc        = table.Column<byte[]>(nullable: false),
                ServiceAccountUserId = table.Column<Guid>(nullable: false),
                AllowedIpCidrsJson   = table.Column<string>(nullable: true),
                AllowedScopesJson    = table.Column<string>(nullable: true),
                ExpiresAtUtc         = table.Column<DateTime>(nullable: true),
                LastUsedAtUtc        = table.Column<DateTime>(nullable: true),
                UsageCount           = table.Column<long>(nullable: false, defaultValue: 0L),
                IsActive             = table.Column<bool>(nullable: false, defaultValue: true),
                CreatedAtUtc         = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc         = table.Column<DateTime>(nullable: false),
                CreatedBy            = table.Column<Guid>(nullable: true),
                UpdatedBy            = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApiKeys", x => x.Id);
                table.ForeignKey(
                    name: "FK_ApiKeys_Users_ServiceAccountUserId",
                    column: x => x.ServiceAccountUserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_Prefix",
            table: "ApiKeys",
            column: "Prefix",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_ServiceAccountUserId",
            table: "ApiKeys",
            column: "ServiceAccountUserId");

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_IsActive",
            table: "ApiKeys",
            column: "IsActive");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "ApiKeys");
        migrationBuilder.DropColumn(name: "IsServiceAccount", table: "Users");
    }
}
