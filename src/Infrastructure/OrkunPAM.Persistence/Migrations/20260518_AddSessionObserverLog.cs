using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddSessionObserverLog : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SessionObserverLogs",
                columns: table => new
                {
                    Id              = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionId       = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ObserverUserId  = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ObserverUsername = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    JoinedAtUtc     = table.Column<DateTime>(type: "datetime2", nullable: false),
                    LeftAtUtc       = table.Column<DateTime>(type: "datetime2", nullable: true),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SessionObserverLogs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SessionObserverLogs_SessionId",
                table: "SessionObserverLogs",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_SessionObserverLogs_ObserverUserId",
                table: "SessionObserverLogs",
                column: "ObserverUserId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "SessionObserverLogs");
        }
    }
}
