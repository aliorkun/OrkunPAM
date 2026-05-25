using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddDeviceMfaPolicy : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "DeviceMfaPolicies",
            columns: table => new
            {
                Id                  = table.Column<Guid>(nullable: false),
                Name                = table.Column<string>(maxLength: 256, nullable: false),
                Description         = table.Column<string>(maxLength: 1024, nullable: true),
                DeviceGroupId       = table.Column<Guid>(nullable: true),
                DeviceId            = table.Column<Guid>(nullable: true),
                RequiredMfaLevel    = table.Column<string>(maxLength: 32, nullable: false, defaultValue: "Any"),
                EnforceAtSessionStart = table.Column<bool>(nullable: false, defaultValue: true),
                IsEnabled           = table.Column<bool>(nullable: false, defaultValue: true),
                CreatedAtUtc        = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc        = table.Column<DateTime>(nullable: false),
                CreatedBy           = table.Column<Guid>(nullable: true),
                UpdatedBy           = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_DeviceMfaPolicies", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_DeviceMfaPolicies_IsEnabled",
            table: "DeviceMfaPolicies",
            column: "IsEnabled");

        migrationBuilder.CreateIndex(
            name: "IX_DeviceMfaPolicies_DeviceGroupId",
            table: "DeviceMfaPolicies",
            column: "DeviceGroupId");

        migrationBuilder.CreateIndex(
            name: "IX_DeviceMfaPolicies_DeviceId",
            table: "DeviceMfaPolicies",
            column: "DeviceId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "DeviceMfaPolicies");
    }
}
