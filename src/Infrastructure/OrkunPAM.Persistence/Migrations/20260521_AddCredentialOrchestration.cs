using Microsoft.EntityFrameworkCore.Migrations;

namespace OrkunPAM.Persistence.Migrations;

public partial class AddCredentialOrchestration : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "CredentialOrchestrationSets",
            columns: table => new
            {
                Id              = table.Column<Guid>(nullable: false),
                Name            = table.Column<string>(maxLength: 200, nullable: false),
                Description     = table.Column<string>(maxLength: 1000, nullable: true),
                ExecutionMode   = table.Column<byte>(nullable: false, defaultValue: (byte)0),
                RollbackOnFailure = table.Column<bool>(nullable: false, defaultValue: false),
                NotifyOnComplete  = table.Column<bool>(nullable: false, defaultValue: false),
                ScheduleCron    = table.Column<string>(maxLength: 100, nullable: true),
                CreatedAtUtc    = table.Column<DateTime>(nullable: false),
                UpdatedAtUtc    = table.Column<DateTime>(nullable: false),
                CreatedBy       = table.Column<Guid>(nullable: true),
                UpdatedBy       = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_CredentialOrchestrationSets", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "CredentialOrchestrationMembers",
            columns: table => new
            {
                Id             = table.Column<Guid>(nullable: false),
                SetId          = table.Column<Guid>(nullable: false),
                CredentialId   = table.Column<Guid>(nullable: false),
                ExecutionOrder = table.Column<int>(nullable: false, defaultValue: 0)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_CredentialOrchestrationMembers", x => x.Id);
                table.ForeignKey(
                    name: "FK_OrchMember_Set",
                    column: x => x.SetId,
                    principalTable: "CredentialOrchestrationSets",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_OrchMember_Credential",
                    column: x => x.CredentialId,
                    principalTable: "Credentials",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "CredentialOrchestrationRuns",
            columns: table => new
            {
                Id                = table.Column<Guid>(nullable: false),
                SetId             = table.Column<Guid>(nullable: false),
                StartedAtUtc      = table.Column<DateTime>(nullable: false),
                CompletedAtUtc    = table.Column<DateTime>(nullable: true),
                Status            = table.Column<byte>(nullable: false, defaultValue: (byte)0),
                Log               = table.Column<string>(nullable: true),
                SuccessCount      = table.Column<int>(nullable: false, defaultValue: 0),
                FailureCount      = table.Column<int>(nullable: false, defaultValue: 0),
                TriggeredByUserId = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_CredentialOrchestrationRuns", x => x.Id);
                table.ForeignKey(
                    name: "FK_OrchRun_Set",
                    column: x => x.SetId,
                    principalTable: "CredentialOrchestrationSets",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_CredentialOrchestrationMembers_SetId",
            table: "CredentialOrchestrationMembers",
            column: "SetId");

        migrationBuilder.CreateIndex(
            name: "IX_CredentialOrchestrationRuns_SetId",
            table: "CredentialOrchestrationRuns",
            column: "SetId");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("CredentialOrchestrationRuns");
        migrationBuilder.DropTable("CredentialOrchestrationMembers");
        migrationBuilder.DropTable("CredentialOrchestrationSets");
    }
}
