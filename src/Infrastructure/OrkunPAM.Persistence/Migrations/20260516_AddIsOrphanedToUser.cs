using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddIsOrphanedToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsOrphaned",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "OrphanedDetectedAtUtc",
                table: "Users",
                type: "datetime2",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_IsOrphaned",
                table: "Users",
                column: "IsOrphaned",
                filter: "[IsOrphaned] = 1");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_IsOrphaned",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "IsOrphaned",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "OrphanedDetectedAtUtc",
                table: "Users");
        }
    }
}
