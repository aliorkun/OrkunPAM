using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    public partial class AddThreatIntelligence : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ThreatFeedConfigs",
                columns: table => new
                {
                    Id                     = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name                   = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    FeedUrl                = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    ApiKeyEnc              = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RefreshIntervalMinutes = table.Column<int>(type: "int", nullable: false, defaultValue: 60),
                    IsEnabled              = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    FeedType               = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false, defaultValue: "Custom"),
                    LastRefreshedAtUtc     = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastIndicatorCount     = table.Column<int>(type: "int", nullable: true),
                    LastError              = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedAtUtc           = table.Column<DateTime>(type: "datetime2", nullable: false),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatFeedConfigs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ThreatIndicators",
                columns: table => new
                {
                    Id            = table.Column<long>(type: "bigint", nullable: false)
                                        .Annotation("SqlServer:Identity", "1, 1"),
                    IndicatorType = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false, defaultValue: "IP"),
                    Value         = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Severity      = table.Column<byte>(type: "tinyint", nullable: false, defaultValue: (byte)2),
                    Source        = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Description   = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ExpiresAtUtc  = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc  = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc  = table.Column<DateTime>(type: "datetime2", nullable: false),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatIndicators", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ThreatIndicators_Type_Value",
                table: "ThreatIndicators",
                columns: new[] { "IndicatorType", "Value" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ThreatIndicators_ExpiresAtUtc",
                table: "ThreatIndicators",
                column: "ExpiresAtUtc");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "ThreatIndicators");
            migrationBuilder.DropTable(name: "ThreatFeedConfigs");
        }
    }
}
