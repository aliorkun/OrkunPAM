using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddFido2AuthenticatorType : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AuthenticatorType",
            table: "Fido2Credentials",
            maxLength: 32,
            nullable: false,
            defaultValue: "cross-platform");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "AuthenticatorType", table: "Fido2Credentials");
    }
}
