using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionTokenHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SessionTokenHash",
                table: "ProxySessions",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProxySessions_SessionTokenHash",
                table: "ProxySessions",
                column: "SessionTokenHash",
                unique: true,
                filter: "[SessionTokenHash] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ProxySessions_SessionTokenHash",
                table: "ProxySessions");

            migrationBuilder.DropColumn(
                name: "SessionTokenHash",
                table: "ProxySessions");
        }
    }
}
