using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations;

[DbContext(typeof(OrkunPamDbContext))]
[Migration("20260521_AddPeripheralRedirectionPolicy")]
public sealed class AddPeripheralRedirectionPolicy : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.CreateTable(
            name: "PeripheralRedirectionPolicies",
            columns: t => new
            {
                Id                      = t.Column<Guid>(nullable: false),
                Name                    = t.Column<string>(maxLength: 256, nullable: false),
                Description             = t.Column<string>(maxLength: 1024, nullable: true),
                IsEnabled               = t.Column<bool>(nullable: false, defaultValue: true),
                AllowClipboard          = t.Column<bool>(nullable: false, defaultValue: false),
                AllowDriveRedirection   = t.Column<bool>(nullable: false, defaultValue: false),
                AllowPrinterRedirection = t.Column<bool>(nullable: false, defaultValue: true),
                AllowUsbRedirection     = t.Column<bool>(nullable: false, defaultValue: false),
                AllowAudioRedirection   = t.Column<bool>(nullable: false, defaultValue: false),
                AllowSmartCardRedirection = t.Column<bool>(nullable: false, defaultValue: true),
                DeviceGroupId           = t.Column<Guid>(nullable: true),
                CreatedAtUtc            = t.Column<DateTime>(nullable: false),
                UpdatedAtUtc            = t.Column<DateTime>(nullable: false),
                CreatedBy               = t.Column<Guid>(nullable: true),
                UpdatedBy               = t.Column<Guid>(nullable: true)
            },
            constraints: t =>
            {
                t.PrimaryKey("PK_PeripheralRedirectionPolicies", x => x.Id);
            });

        m.CreateIndex("IX_PeripheralRedirectionPolicies_IsEnabled",
            "PeripheralRedirectionPolicies", "IsEnabled");
        m.CreateIndex("IX_PeripheralRedirectionPolicies_DeviceGroupId",
            "PeripheralRedirectionPolicies", "DeviceGroupId");
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropTable("PeripheralRedirectionPolicies");
    }
}
