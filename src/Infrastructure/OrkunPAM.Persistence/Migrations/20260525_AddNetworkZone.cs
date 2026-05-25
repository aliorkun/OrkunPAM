using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddNetworkZone : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "NetworkZones",
            columns: table => new
            {
                Id                  = table.Column<Guid>(nullable: false),
                Name                = table.Column<string>(maxLength: 256, nullable: false),
                Description         = table.Column<string>(maxLength: 1024, nullable: true),
                IpRangesJson        = table.Column<string>(nullable: true),
                JumpHostAddress     = table.Column<string>(maxLength: 512, nullable: true),
                JumpHostCredentialId = table.Column<Guid>(nullable: true),
                ProxyBindAddress    = table.Column<string>(maxLength: 256, nullable: true),
                IsDefault           = table.Column<bool>(nullable: false, defaultValue: false),
                Notes               = table.Column<string>(nullable: true),
                CreatedAtUtc        = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc        = table.Column<DateTime>(nullable: false),
                CreatedBy           = table.Column<Guid>(nullable: true),
                UpdatedBy           = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_NetworkZones", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_NetworkZones_Name",
            table: "NetworkZones",
            column: "Name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_NetworkZones_IsDefault",
            table: "NetworkZones",
            column: "IsDefault");

        migrationBuilder.AddColumn<Guid>(
            name: "NetworkZoneId",
            table: "Devices",
            nullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_Devices_NetworkZoneId",
            table: "Devices",
            column: "NetworkZoneId");

        migrationBuilder.AddForeignKey(
            name: "FK_Devices_NetworkZones_NetworkZoneId",
            table: "Devices",
            column: "NetworkZoneId",
            principalTable: "NetworkZones",
            principalColumn: "Id",
            onDelete: ReferentialAction.SetNull);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(name: "FK_Devices_NetworkZones_NetworkZoneId", table: "Devices");
        migrationBuilder.DropIndex(name: "IX_Devices_NetworkZoneId", table: "Devices");
        migrationBuilder.DropColumn(name: "NetworkZoneId", table: "Devices");
        migrationBuilder.DropTable(name: "NetworkZones");
    }
}
