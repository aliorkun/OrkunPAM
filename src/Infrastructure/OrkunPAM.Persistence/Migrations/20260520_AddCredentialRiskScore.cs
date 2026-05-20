using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddCredentialRiskScore : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTime>(
            name: "ExpiresAtUtc",
            table: "Credentials",
            nullable: true);

        migrationBuilder.AddColumn<int>(
            name: "RiskScore",
            table: "Credentials",
            nullable: false,
            defaultValue: 0);

        migrationBuilder.AddColumn<string>(
            name: "RiskLevel",
            table: "Credentials",
            maxLength: 16,
            nullable: false,
            defaultValue: "Low");

        migrationBuilder.AddColumn<DateTime>(
            name: "RiskScoredAtUtc",
            table: "Credentials",
            nullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_Credentials_RiskLevel",
            table: "Credentials",
            column: "RiskLevel");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex("IX_Credentials_RiskLevel", "Credentials");
        migrationBuilder.DropColumn("ExpiresAtUtc", "Credentials");
        migrationBuilder.DropColumn("RiskScore", "Credentials");
        migrationBuilder.DropColumn("RiskLevel", "Credentials");
        migrationBuilder.DropColumn("RiskScoredAtUtc", "Credentials");
    }
}
