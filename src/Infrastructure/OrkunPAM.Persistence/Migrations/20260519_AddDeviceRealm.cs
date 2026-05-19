using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddDeviceRealm : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "DeviceRealms",
            columns: table => new
            {
                Id              = table.Column<Guid>(nullable: false),
                Name            = table.Column<string>(maxLength: 256, nullable: false),
                Description     = table.Column<string>(maxLength: 1024, nullable: true),
                IsEnabled       = table.Column<bool>(nullable: false, defaultValue: true),
                SessionPolicyId = table.Column<Guid>(nullable: true),
                CreatedAtUtc    = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc    = table.Column<DateTime>(nullable: false),
                CreatedBy       = table.Column<Guid>(nullable: true),
                UpdatedBy       = table.Column<Guid>(nullable: true)
            },
            constraints: table => { table.PrimaryKey("PK_DeviceRealms", x => x.Id); });

        migrationBuilder.CreateIndex(
            name: "IX_DeviceRealms_Name",
            table: "DeviceRealms",
            column: "Name",
            unique: true);

        migrationBuilder.CreateTable(
            name: "DeviceRealmUserGroups",
            columns: table => new
            {
                DeviceRealmId = table.Column<Guid>(nullable: false),
                UserGroupId   = table.Column<Guid>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_DeviceRealmUserGroups", x => new { x.DeviceRealmId, x.UserGroupId });
                table.ForeignKey("FK_DeviceRealmUserGroups_DeviceRealms",
                    x => x.DeviceRealmId, "DeviceRealms", "Id", onDelete: ReferentialAction.Cascade);
                table.ForeignKey("FK_DeviceRealmUserGroups_Groups",
                    x => x.UserGroupId, "Groups", "Id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_DeviceRealmUserGroups_UserGroupId",
            table: "DeviceRealmUserGroups",
            column: "UserGroupId");

        migrationBuilder.CreateTable(
            name: "DeviceRealmDeviceGroups",
            columns: table => new
            {
                DeviceRealmId = table.Column<Guid>(nullable: false),
                DeviceGroupId = table.Column<Guid>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_DeviceRealmDeviceGroups", x => new { x.DeviceRealmId, x.DeviceGroupId });
                table.ForeignKey("FK_DeviceRealmDeviceGroups_DeviceRealms",
                    x => x.DeviceRealmId, "DeviceRealms", "Id", onDelete: ReferentialAction.Cascade);
                table.ForeignKey("FK_DeviceRealmDeviceGroups_DeviceGroups",
                    x => x.DeviceGroupId, "DeviceGroups", "Id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_DeviceRealmDeviceGroups_DeviceGroupId",
            table: "DeviceRealmDeviceGroups",
            column: "DeviceGroupId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "DeviceRealmDeviceGroups");
        migrationBuilder.DropTable(name: "DeviceRealmUserGroups");
        migrationBuilder.DropTable(name: "DeviceRealms");
    }
}
