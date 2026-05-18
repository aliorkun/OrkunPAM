using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddSessionAnnotations : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "SessionAnnotations",
            columns: table => new
            {
                Id             = table.Column<Guid>(nullable: false),
                SessionId      = table.Column<Guid>(nullable: false),
                AuthorUserId   = table.Column<Guid>(nullable: false),
                AuthorUsername = table.Column<string>(maxLength: 256, nullable: true),
                Note           = table.Column<string>(maxLength: 4000, nullable: false),
                CreatedAtUtc   = table.Column<DateTime>(nullable: false)
            },
            constraints: table => { table.PrimaryKey("PK_SessionAnnotations", x => x.Id); });

        migrationBuilder.CreateIndex(
            name: "IX_SessionAnnotations_SessionId",
            table: "SessionAnnotations",
            column: "SessionId");

        migrationBuilder.CreateIndex(
            name: "IX_SessionAnnotations_CreatedAtUtc",
            table: "SessionAnnotations",
            column: "CreatedAtUtc");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "SessionAnnotations");
    }
}
