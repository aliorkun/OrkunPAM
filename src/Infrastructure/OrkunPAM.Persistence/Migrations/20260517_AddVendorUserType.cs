using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddVendorUserType : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte>(
                name: "UserType",
                table: "Users",
                type: "tinyint",
                nullable: false,
                defaultValue: (byte)0);

            migrationBuilder.AddColumn<Guid>(
                name: "VendorSponsorUserId",
                table: "Users",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VendorDeviceIdsJson",
                table: "Users",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_UserType",
                table: "Users",
                column: "UserType",
                filter: "[UserType] != 0");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_UserType",
                table: "Users");

            migrationBuilder.DropColumn(name: "UserType", table: "Users");
            migrationBuilder.DropColumn(name: "VendorSponsorUserId", table: "Users");
            migrationBuilder.DropColumn(name: "VendorDeviceIdsJson", table: "Users");
        }
    }
}
