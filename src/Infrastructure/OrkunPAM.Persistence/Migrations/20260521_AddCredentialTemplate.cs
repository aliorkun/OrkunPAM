using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OrkunPAM.Persistence.Migrations;

[DbContext(typeof(OrkunPamDbContext))]
[Migration("20260521_AddCredentialTemplate")]
public sealed class AddCredentialTemplate : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.CreateTable(
            name: "CredentialTemplates",
            columns: t => new
            {
                Id                   = t.Column<Guid>(nullable: false),
                Name                 = t.Column<string>(maxLength: 120, nullable: false),
                Description          = t.Column<string>(maxLength: 500, nullable: true),
                DeviceType           = t.Column<string>(maxLength: 80, nullable: false),
                DefaultUsername      = t.Column<string>(maxLength: 120, nullable: true),
                CredentialKind       = t.Column<string>(maxLength: 40, nullable: false, defaultValue: "Linux"),
                RotationPeriodDays   = t.Column<int>(nullable: false, defaultValue: 90),
                PasswordMinLength    = t.Column<int>(nullable: false, defaultValue: 16),
                PasswordRequireSpecial = t.Column<bool>(nullable: false, defaultValue: true),
                SshKeyRotation       = t.Column<bool>(nullable: false, defaultValue: false),
                Notes                = t.Column<string>(maxLength: 1000, nullable: true),
                IsBuiltIn            = t.Column<bool>(nullable: false, defaultValue: false),
                CreatedAtUtc         = t.Column<DateTime>(nullable: false),
                UpdatedAtUtc         = t.Column<DateTime>(nullable: false),
                CreatedBy            = t.Column<Guid>(nullable: true),
                UpdatedBy            = t.Column<Guid>(nullable: true)
            },
            constraints: t =>
            {
                t.PrimaryKey("PK_CredentialTemplates", x => x.Id);
            });

        m.CreateIndex("IX_CredentialTemplates_Name", "CredentialTemplates", "Name", unique: true);

        // Seed built-in templates
        var now = new DateTime(2026, 5, 21, 0, 0, 0, DateTimeKind.Utc);
        var rows = new[]
        {
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000001"), Name = "linux-root",     DeviceType = "Linux",   DefaultUsername = "root",              CredentialKind = "Linux",   RotationPeriodDays = 90, PasswordMinLength = 20, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "Linux root account — SSH rotation", Notes = "Standard template for Linux privileged access" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000002"), Name = "linux-service",  DeviceType = "Linux",   DefaultUsername = "svc_",              CredentialKind = "Linux",   RotationPeriodDays = 60, PasswordMinLength = 16, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "Linux service account — SSH rotation", Notes = "For non-root service accounts on Linux" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000003"), Name = "windows-admin",  DeviceType = "Windows", DefaultUsername = "Administrator",     CredentialKind = "Windows", RotationPeriodDays = 60, PasswordMinLength = 20, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "Windows local Administrator — WinRM rotation", Notes = "Built-in admin account for Windows servers" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000004"), Name = "windows-service",DeviceType = "Windows", DefaultUsername = "svc_",              CredentialKind = "Windows", RotationPeriodDays = 90, PasswordMinLength = 16, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "Windows service account — WinRM rotation", Notes = "For service accounts on Windows" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000005"), Name = "mssql-sa",       DeviceType = "MSSQL",   DefaultUsername = "sa",                CredentialKind = "DB",      RotationPeriodDays = 30, PasswordMinLength = 24, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "SQL Server SA account — SQL rotation", Notes = "SA account for Microsoft SQL Server" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000006"), Name = "cisco-enable",   DeviceType = "Cisco",   DefaultUsername = "cisco_admin",       CredentialKind = "Network", RotationPeriodDays = 90, PasswordMinLength = 16, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "Cisco enable / admin account — TACACS+ rotation", Notes = "Cisco IOS/NX-OS privileged access" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000007"), Name = "juniper-admin",  DeviceType = "Juniper", DefaultUsername = "admin",             CredentialKind = "Network", RotationPeriodDays = 90, PasswordMinLength = 16, PasswordRequireSpecial = true,  SshKeyRotation = true,  Description = "Juniper admin account — SSH rotation", Notes = "JunOS admin access with SSH key rotation support" },
            new { Id = Guid.Parse("00000001-0000-0000-0000-000000000008"), Name = "nas-admin",      DeviceType = "NAS",     DefaultUsername = "admin",             CredentialKind = "NAS",     RotationPeriodDays = 60, PasswordMinLength = 16, PasswordRequireSpecial = true,  SshKeyRotation = false, Description = "NAS admin account — SSH/API rotation", Notes = "For NAS devices (NetApp, Synology, QNAP)" },
        };

        foreach (var r in rows)
        {
            m.Sql($"""
                INSERT INTO CredentialTemplates
                    (Id, Name, Description, DeviceType, DefaultUsername, CredentialKind,
                     RotationPeriodDays, PasswordMinLength, PasswordRequireSpecial, SshKeyRotation,
                     Notes, IsBuiltIn, CreatedAtUtc, UpdatedAtUtc)
                VALUES
                    ('{r.Id}', '{r.Name}', '{r.Description}', '{r.DeviceType}', '{r.DefaultUsername}', '{r.CredentialKind}',
                     {r.RotationPeriodDays}, {r.PasswordMinLength}, {(r.PasswordRequireSpecial ? 1 : 0)}, {(r.SshKeyRotation ? 1 : 0)},
                     '{r.Notes}', 1, '{now:O}', '{now:O}')
                """ );
        }
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropTable("CredentialTemplates");
    }
}
