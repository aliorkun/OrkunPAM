using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddScreenCaptureFrame : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "ScreenCaptureFrames",
            columns: table => new
            {
                Id            = table.Column<long>(nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                SessionId     = table.Column<Guid>(nullable: false),
                CapturedAtUtc = table.Column<DateTime>(nullable: false),
                FrameIndex    = table.Column<int>(nullable: false),
                Width         = table.Column<int>(nullable: true),
                Height        = table.Column<int>(nullable: true),
                DataBase64    = table.Column<string>(nullable: true),
                SessionType   = table.Column<string>(maxLength: 50, nullable: false, defaultValue: "Unknown")
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ScreenCaptureFrames", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ScreenCaptureFrames_SessionId",
            table: "ScreenCaptureFrames",
            column: "SessionId");

        migrationBuilder.CreateIndex(
            name: "IX_ScreenCaptureFrames_SessionId_FrameIndex",
            table: "ScreenCaptureFrames",
            columns: new[] { "SessionId", "FrameIndex" },
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "ScreenCaptureFrames");
    }
}
