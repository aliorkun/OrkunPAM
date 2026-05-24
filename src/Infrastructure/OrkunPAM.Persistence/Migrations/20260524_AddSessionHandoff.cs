using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddSessionHandoff : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "SessionHandoffs",
            columns: table => new
            {
                Id                  = table.Column<Guid>(nullable: false),
                SessionId           = table.Column<Guid>(nullable: false),
                RequestedByUserId   = table.Column<Guid>(nullable: false),
                RequestedByUsername = table.Column<string>(maxLength: 256, nullable: true),
                RequestedToUserId   = table.Column<Guid>(nullable: false),
                RequestedToUsername = table.Column<string>(maxLength: 256, nullable: true),
                RequestedAtUtc      = table.Column<DateTime>(nullable: false),
                AcceptedAtUtc       = table.Column<DateTime>(nullable: true),
                Status              = table.Column<string>(maxLength: 32, nullable: false, defaultValue: "Pending"),
                TransferNotes       = table.Column<string>(maxLength: 1024, nullable: true),
                ExpiresAtUtc        = table.Column<DateTime>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SessionHandoffs", x => x.Id);
                table.ForeignKey(
                    name: "FK_SessionHandoffs_ProxySessions_SessionId",
                    column: x => x.SessionId,
                    principalTable: "ProxySessions",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_SessionHandoffs_SessionId",
            table: "SessionHandoffs",
            column: "SessionId");

        migrationBuilder.CreateIndex(
            name: "IX_SessionHandoffs_RequestedToUserId_Status",
            table: "SessionHandoffs",
            columns: new[] { "RequestedToUserId", "Status" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "SessionHandoffs");
    }
}
