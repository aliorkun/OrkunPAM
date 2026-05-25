using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddOidcProvider : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "OidcProviders",
            columns: table => new
            {
                Id               = table.Column<Guid>(nullable: false),
                Name             = table.Column<string>(maxLength: 100, nullable: false),
                DisplayName      = table.Column<string>(maxLength: 200, nullable: false),
                Authority        = table.Column<string>(maxLength: 500, nullable: false),
                ClientId         = table.Column<string>(maxLength: 300, nullable: false),
                ClientSecretEnc  = table.Column<byte[]>(nullable: true),
                Scopes           = table.Column<string>(maxLength: 500, nullable: false, defaultValue: "openid profile email"),
                GroupClaimType   = table.Column<string>(maxLength: 100, nullable: true),
                GroupRoleMapping = table.Column<string>(maxLength: 2000, nullable: true),
                AutoProvisionUsers = table.Column<bool>(nullable: false, defaultValue: true),
                DefaultRole      = table.Column<string>(maxLength: 100, nullable: false, defaultValue: "Viewer"),
                IsEnabled        = table.Column<bool>(nullable: false, defaultValue: true),
                CreatedAtUtc     = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc     = table.Column<DateTime>(nullable: false),
                CreatedBy        = table.Column<Guid>(nullable: true),
                UpdatedBy        = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_OidcProviders", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_OidcProviders_Name",
            table: "OidcProviders",
            column: "Name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_OidcProviders_IsEnabled",
            table: "OidcProviders",
            column: "IsEnabled");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "OidcProviders");
    }
}
