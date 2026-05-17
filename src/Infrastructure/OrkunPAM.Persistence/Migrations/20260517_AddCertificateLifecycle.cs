using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddCertificateLifecycle : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ManagedCertificates",
                columns: table => new
                {
                    Id               = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SubjectCN        = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    SubjectAltNames  = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Issuer           = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                    Thumbprint       = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    SerialNumber     = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    NotBefore        = table.Column<DateTime>(type: "datetime2", nullable: false),
                    NotAfter         = table.Column<DateTime>(type: "datetime2", nullable: false),
                    KeyUsage         = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KeyAlgorithm     = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    KeySizeBits      = table.Column<int>(type: "int", nullable: false),
                    PemCertificateEnc = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DeviceId         = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    FolderId         = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Notes            = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Source           = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false, defaultValue: "Manual"),
                    CreatedAtUtc     = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy        = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ManagedCertificates", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ManagedCertificates_Thumbprint",
                table: "ManagedCertificates",
                column: "Thumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ManagedCertificates_NotAfter",
                table: "ManagedCertificates",
                column: "NotAfter");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "ManagedCertificates");
        }
    }
}
