using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddAssignedCredentialUniqueIndex : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Partial unique index for rows where DeviceGroupId IS NOT NULL
        migrationBuilder.CreateIndex(
            name: "IX_AssignedCredentials_Unique_Assignment",
            table: "AssignedCredentials",
            columns: new[] { "CredentialId", "PrincipalType", "PrincipalId", "DeviceGroupId" },
            unique: true,
            filter: "[DeviceGroupId] IS NOT NULL");

        // Partial unique index for rows where DeviceGroupId IS NULL
        migrationBuilder.CreateIndex(
            name: "IX_AssignedCredentials_Unique_Assignment_NoDevGroup",
            table: "AssignedCredentials",
            columns: new[] { "CredentialId", "PrincipalType", "PrincipalId" },
            unique: true,
            filter: "[DeviceGroupId] IS NULL");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_AssignedCredentials_Unique_Assignment",
            table: "AssignedCredentials");

        migrationBuilder.DropIndex(
            name: "IX_AssignedCredentials_Unique_Assignment_NoDevGroup",
            table: "AssignedCredentials");
    }
}
