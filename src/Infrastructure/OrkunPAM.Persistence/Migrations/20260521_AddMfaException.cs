using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddMfaException : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "MfaExceptions",
            columns: table => new
            {
                Id                  = table.Column<Guid>(nullable: false),
                UserId              = table.Column<Guid>(nullable: false),
                RequestedByUserId   = table.Column<Guid>(nullable: false),
                ApprovedByUserId    = table.Column<Guid>(nullable: true),
                Reason              = table.Column<string>(maxLength: 2048, nullable: false),
                Status              = table.Column<byte>(nullable: false, defaultValue: (byte)0),
                ExpiresAtUtc        = table.Column<DateTime>(nullable: false),
                RevokedAtUtc        = table.Column<DateTime>(nullable: true),
                MaxUsageCount       = table.Column<int>(nullable: false, defaultValue: 1),
                UsageCount          = table.Column<int>(nullable: false, defaultValue: 0),
                IpCidrRestriction   = table.Column<string>(maxLength: 256, nullable: true),
                AppliedMfaTypesJson = table.Column<string>(maxLength: 512, nullable: true),
                CreatedAtUtc        = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc        = table.Column<DateTime>(nullable: false),
                CreatedBy           = table.Column<Guid>(nullable: true),
                UpdatedBy           = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_MfaExceptions", x => x.Id);
                table.ForeignKey(
                    name: "FK_MfaExceptions_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_MfaExceptions_UserId",
            table: "MfaExceptions",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_MfaExceptions_Status",
            table: "MfaExceptions",
            column: "Status");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "MfaExceptions");
    }
}
