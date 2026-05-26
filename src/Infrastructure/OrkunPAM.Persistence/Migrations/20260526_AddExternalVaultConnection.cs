using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddExternalVaultConnection : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "ExternalVaultConnections",
            columns: table => new
            {
                Id                  = table.Column<Guid>(nullable: false),
                Name                = table.Column<string>(maxLength: 256, nullable: false),
                VaultType           = table.Column<string>(maxLength: 64, nullable: false),
                Endpoint            = table.Column<string>(maxLength: 2048, nullable: false),
                AuthMethod          = table.Column<string>(maxLength: 64, nullable: false),
                AuthSecretEnc       = table.Column<byte[]>(nullable: true),
                Namespace           = table.Column<string>(maxLength: 256, nullable: true),
                MountPath           = table.Column<string>(maxLength: 512, nullable: true),
                KeyVaultName        = table.Column<string>(maxLength: 256, nullable: true),
                TenantId            = table.Column<string>(maxLength: 256, nullable: true),
                ClientId            = table.Column<string>(maxLength: 256, nullable: true),
                SyncEnabled         = table.Column<bool>(nullable: false, defaultValue: false),
                SyncIntervalMinutes = table.Column<int>(nullable: false, defaultValue: 60),
                IsEnabled           = table.Column<bool>(nullable: false, defaultValue: true),
                LastSyncAtUtc       = table.Column<DateTime>(nullable: true),
                LastSyncError       = table.Column<string>(nullable: true),
                CreatedAtUtc        = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc        = table.Column<DateTime>(nullable: false),
                CreatedBy           = table.Column<Guid>(nullable: true),
                UpdatedBy           = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ExternalVaultConnections", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ExternalVaultConnections_Name",
            table: "ExternalVaultConnections",
            column: "Name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ExternalVaultConnections_IsEnabled",
            table: "ExternalVaultConnections",
            column: "IsEnabled");

        migrationBuilder.CreateTable(
            name: "ExternalCredentialMappings",
            columns: table => new
            {
                Id                  = table.Column<Guid>(nullable: false),
                ConnectionId        = table.Column<Guid>(nullable: false),
                ExternalPath        = table.Column<string>(maxLength: 1024, nullable: false),
                UsernameField       = table.Column<string>(maxLength: 256, nullable: true),
                PasswordField       = table.Column<string>(maxLength: 256, nullable: true),
                MappedCredentialId  = table.Column<Guid>(nullable: true),
                SyncMode            = table.Column<string>(maxLength: 32, nullable: false),
                SyncStatus          = table.Column<string>(maxLength: 32, nullable: false),
                LastFetchedAtUtc    = table.Column<DateTime>(nullable: true),
                LastSyncedAtUtc     = table.Column<DateTime>(nullable: true),
                LastError           = table.Column<string>(nullable: true),
                CreatedAtUtc        = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc        = table.Column<DateTime>(nullable: false),
                CreatedBy           = table.Column<Guid>(nullable: true),
                UpdatedBy           = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ExternalCredentialMappings", x => x.Id);
                table.ForeignKey(
                    name: "FK_ExternalCredentialMappings_ExternalVaultConnections_ConnectionId",
                    column: x => x.ConnectionId,
                    principalTable: "ExternalVaultConnections",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ExternalCredentialMappings_ConnectionId",
            table: "ExternalCredentialMappings",
            column: "ConnectionId");

        migrationBuilder.CreateIndex(
            name: "IX_ExternalCredentialMappings_MappedCredentialId",
            table: "ExternalCredentialMappings",
            column: "MappedCredentialId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "ExternalCredentialMappings");
        migrationBuilder.DropTable(name: "ExternalVaultConnections");
    }
}
