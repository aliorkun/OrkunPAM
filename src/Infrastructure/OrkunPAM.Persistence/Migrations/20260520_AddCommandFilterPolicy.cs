using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddCommandFilterPolicy : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "CommandFilterPolicies",
            columns: table => new
            {
                Id           = table.Column<Guid>(nullable: false),
                Name         = table.Column<string>(maxLength: 256, nullable: false),
                Description  = table.Column<string>(maxLength: 1024, nullable: true),
                IsEnabled    = table.Column<bool>(nullable: false, defaultValue: true),
                Mode         = table.Column<byte>(nullable: false, defaultValue: (byte)2),
                DeviceGroupId = table.Column<Guid>(nullable: true),
                CreatedAtUtc  = table.Column<DateTime>(nullable: false, defaultValueSql: "GETUTCDATE()"),
                UpdatedAtUtc  = table.Column<DateTime>(nullable: false, defaultValueSql: "GETUTCDATE()"),
                CreatedBy     = table.Column<Guid>(nullable: true),
                UpdatedBy     = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_CommandFilterPolicies", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "CommandFilterPolicyRules",
            columns: table => new
            {
                Id           = table.Column<Guid>(nullable: false),
                PolicyId     = table.Column<Guid>(nullable: false),
                Pattern      = table.Column<string>(maxLength: 512, nullable: false),
                IsRegex      = table.Column<bool>(nullable: false, defaultValue: false),
                Action       = table.Column<string>(maxLength: 32, nullable: false, defaultValue: "Deny"),
                RiskScore    = table.Column<int>(nullable: false, defaultValue: 50),
                Justification = table.Column<string>(maxLength: 1024, nullable: true),
                SortOrder    = table.Column<int>(nullable: false, defaultValue: 0)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_CommandFilterPolicyRules", x => x.Id);
                table.ForeignKey(
                    name: "FK_CommandFilterPolicyRules_CommandFilterPolicies_PolicyId",
                    column: x => x.PolicyId,
                    principalTable: "CommandFilterPolicies",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_CommandFilterPolicies_IsEnabled",
            table: "CommandFilterPolicies",
            column: "IsEnabled");

        migrationBuilder.CreateIndex(
            name: "IX_CommandFilterPolicyRules_PolicyId",
            table: "CommandFilterPolicyRules",
            column: "PolicyId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("CommandFilterPolicyRules");
        migrationBuilder.DropTable("CommandFilterPolicies");
    }
}
