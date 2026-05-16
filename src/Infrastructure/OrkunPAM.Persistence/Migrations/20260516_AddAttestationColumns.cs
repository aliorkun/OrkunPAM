using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAttestationColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ReviewerUserId",
                table: "AttestationCampaigns",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "CompletedAtUtc",
                table: "AttestationCampaigns",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SubjectUsername",
                table: "AttestationDecisions",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ResourceName",
                table: "AttestationDecisions",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AttestationDecisions_CampaignId",
                table: "AttestationDecisions",
                column: "CampaignId");

            migrationBuilder.CreateIndex(
                name: "IX_AttestationCampaigns_Status",
                table: "AttestationCampaigns",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AttestationDecisions_CampaignId",
                table: "AttestationDecisions");

            migrationBuilder.DropIndex(
                name: "IX_AttestationCampaigns_Status",
                table: "AttestationCampaigns");

            migrationBuilder.DropColumn(
                name: "ReviewerUserId",
                table: "AttestationCampaigns");

            migrationBuilder.DropColumn(
                name: "CompletedAtUtc",
                table: "AttestationCampaigns");

            migrationBuilder.DropColumn(
                name: "SubjectUsername",
                table: "AttestationDecisions");

            migrationBuilder.DropColumn(
                name: "ResourceName",
                table: "AttestationDecisions");
        }
    }
}
