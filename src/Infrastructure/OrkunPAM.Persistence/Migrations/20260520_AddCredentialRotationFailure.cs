using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddCredentialRotationFailure : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "LastRotationError",
            table: "Credentials",
            maxLength: 1024,
            nullable: true);

        migrationBuilder.AddColumn<int>(
            name: "RotationFailureCount",
            table: "Credentials",
            nullable: false,
            defaultValue: 0);

        migrationBuilder.AddColumn<DateTime>(
            name: "LastRotationFailedAtUtc",
            table: "Credentials",
            nullable: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn("LastRotationError", "Credentials");
        migrationBuilder.DropColumn("RotationFailureCount", "Credentials");
        migrationBuilder.DropColumn("LastRotationFailedAtUtc", "Credentials");
    }
}
