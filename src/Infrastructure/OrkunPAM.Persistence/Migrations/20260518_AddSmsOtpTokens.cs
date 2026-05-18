using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddSmsOtpTokens : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SmsOtpTokens",
                columns: table => new
                {
                    Id              = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId          = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    HashedCode      = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ExpiresAtUtc    = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsUsed          = table.Column<bool>(type: "bit", nullable: false),
                    FailedAttempts  = table.Column<int>(type: "int", nullable: false),
                    CreatedAtUtc    = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RequestedFromIp = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SmsOtpTokens", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SmsOtpTokens_UserId",
                table: "SmsOtpTokens",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_SmsOtpTokens_ExpiresAtUtc",
                table: "SmsOtpTokens",
                column: "ExpiresAtUtc");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "SmsOtpTokens");
        }
    }
}
