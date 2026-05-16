using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddReportSchedule : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ReportSchedules",
                columns: table => new
                {
                    Id             = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name           = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    ReportType     = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Frequency      = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false, defaultValue: "daily"),
                    DayOfWeek      = table.Column<int>(type: "int", nullable: false, defaultValue: 1),
                    DayOfMonth     = table.Column<int>(type: "int", nullable: false, defaultValue: 1),
                    RunAtHourUtc   = table.Column<int>(type: "int", nullable: false, defaultValue: 8),
                    OutputFormat   = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false, defaultValue: "csv"),
                    Recipients     = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: false),
                    IsActive       = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    LastRunAtUtc   = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NextRunAtUtc   = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastRunStatus  = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAtUtc   = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table => table.PrimaryKey("PK_ReportSchedules", x => x.Id));

            migrationBuilder.CreateIndex(
                name: "IX_ReportSchedules_IsActive_NextRunAtUtc",
                table: "ReportSchedules",
                columns: new[] { "IsActive", "NextRunAtUtc" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "ReportSchedules");
        }
    }
}
