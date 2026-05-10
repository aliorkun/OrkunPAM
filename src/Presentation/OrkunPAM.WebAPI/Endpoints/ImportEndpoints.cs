using System.Globalization;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ImportEndpoints
{
    public static void MapImportEndpoints(this WebApplication app)
    {
        var import = app.MapGroup("/api/v1/import").WithTags("Import").RequireAuthorization();

        // === CSV Device Import ===
        import.MapPost("/devices/csv", async (HttpRequest request, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            if (!request.HasFormContentType)
                return Results.BadRequest(new { success = false, errors = new[] { "Expected multipart/form-data with CSV file" } });

            var form = await request.ReadFormAsync();
            var file = form.Files.FirstOrDefault();
            if (file == null || file.Length == 0)
                return Results.BadRequest(new { success = false, errors = new[] { "No file uploaded" } });

            if (file.Length > 5_000_000)
                return Results.BadRequest(new { success = false, errors = new[] { "File too large. Maximum 5 MB." } });

            using var reader = new StreamReader(file.OpenReadStream());
            var content = await reader.ReadToEndAsync();
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length < 2)
                return Results.BadRequest(new { success = false, errors = new[] { "CSV must have header + at least 1 data row" } });

            // Parse header
            var headers = lines[0].Trim().Split(',').Select(h => h.Trim().ToLowerInvariant()).ToArray();
            var hostnameIdx = Array.IndexOf(headers, "hostname");
            var ipIdx = Array.IndexOf(headers, "ip") >= 0 ? Array.IndexOf(headers, "ip") : Array.IndexOf(headers, "ipaddress");
            var typeIdx = Array.IndexOf(headers, "type") >= 0 ? Array.IndexOf(headers, "type") : Array.IndexOf(headers, "devicetype");
            var portIdx = Array.IndexOf(headers, "port");
            var osIdx = Array.IndexOf(headers, "os") >= 0 ? Array.IndexOf(headers, "os") : Array.IndexOf(headers, "operatingsystem");

            if (hostnameIdx < 0)
                return Results.BadRequest(new { success = false, errors = new[] { "CSV must have 'hostname' column" } });

            var imported = 0;
            var errors = new List<string>();

            for (int i = 1; i < lines.Length; i++)
            {
                var cols = lines[i].Trim().Split(',');
                if (cols.Length <= hostnameIdx || string.IsNullOrWhiteSpace(cols[hostnameIdx])) continue;

                try
                {
                    var hostname = cols[hostnameIdx].Trim().Trim('"');

                    if (IsCsvInjection(hostname))
                    {
                        errors.Add($"Row {i + 1}: Hostname contains invalid characters");
                        continue;
                    }

                    // Skip duplicates
                    if (await db.Devices.AnyAsync(d => d.Hostname == hostname)) continue;

                    var device = new Device
                    {
                        Hostname = hostname,
                        IpAddress = ipIdx >= 0 && cols.Length > ipIdx ? cols[ipIdx].Trim().Trim('"') : null,
                        ConnectionPort = portIdx >= 0 && cols.Length > portIdx && int.TryParse(cols[portIdx].Trim(), out var port) ? port : null,
                        OperatingSystem = osIdx >= 0 && cols.Length > osIdx ? cols[osIdx].Trim().Trim('"') : null,
                        DeviceType = typeIdx >= 0 && cols.Length > typeIdx && Enum.TryParse<DeviceType>(cols[typeIdx].Trim().Trim('"'), true, out var dt) ? dt : DeviceType.Other,
                        ConnectionProtocol = ConnectionProtocol.Ssh,
                        ImportSource = ImportSource.Csv
                    };

                    db.Devices.Add(device);
                    imported++;
                }
                catch (Exception ex)
                {
                    errors.Add($"Row {i + 1}: {ex.Message}");
                }
            }

            await db.SaveChangesAsync();
            logger.LogInformation("CSV import completed: {Imported} devices imported, {Errors} errors", imported, errors.Count);

            return Results.Ok(new
            {
                success = true,
                data = new { imported, skipped = lines.Length - 1 - imported - errors.Count, errors = errors.Take(10) }
            });
        }).DisableAntiforgery();

        // === Bulk Credential Import ===
        import.MapPost("/credentials", async (BulkCredentialImportRequest req,
            OrkunPamDbContext db, OrkunPAM.Cryptography.IVaultEncryptionService vault, ILogger<Program> logger) =>
        {
            var imported = 0;
            var errors = new List<string>();

            foreach (var item in req.Credentials)
            {
                try
                {
                    byte[]? encPassword = null;
                    if (!string.IsNullOrEmpty(item.Password))
                    {
                        var enc = vault.EncryptString(item.Password);
                        if (enc.IsFailure) { errors.Add($"{item.Name}: encryption failed"); continue; }
                        encPassword = enc.Value;
                    }

                    var cred = new Credential
                    {
                        FolderId = req.FolderId,
                        Name = item.Name,
                        CredentialType = item.Type,
                        Username = item.Username,
                        PasswordEnc = encPassword,
                        Tags = item.Tags,
                        KeyVersion = 1,
                        Status = CredentialStatus.Active
                    };
                    db.Credentials.Add(cred);
                    imported++;
                }
                catch (Exception ex)
                {
                    errors.Add($"{item.Name}: {ex.Message}");
                }
            }

            await db.SaveChangesAsync();
            logger.LogInformation("Bulk credential import: {Imported} imported, {Errors} errors", imported, errors.Count);

            return Results.Ok(new { success = true, data = new { imported, errors = errors.Take(10) } });
        });

        // === Bulk User Import ===
        import.MapPost("/users", async (BulkUserImportRequest req,
            OrkunPamDbContext db, OrkunPAM.Identity.Services.IPasswordHasher hasher, ILogger<Program> logger) =>
        {
            var imported = 0;
            var errors = new List<string>();

            foreach (var item in req.Users)
            {
                try
                {
                    var normalized = item.Username.Trim().ToUpperInvariant();
                    if (await db.Users.AnyAsync(u => u.NormalizedUsername == normalized))
                    {
                        errors.Add($"{item.Username}: already exists");
                        continue;
                    }

                    if (string.IsNullOrEmpty(item.Password))
                    {
                        errors.Add($"{item.Username}: password is required");
                        continue;
                    }

                    var user = new OrkunPAM.Domain.Entities.Identity.User
                    {
                        Username = item.Username.Trim(),
                        NormalizedUsername = normalized,
                        DisplayName = item.DisplayName,
                        Email = item.Email,
                        PasswordHash = hasher.Hash(item.Password),
                        AuthSource = AuthSource.Local,
                        Status = UserStatus.Active,
                        PasswordLastChanged = DateTime.UtcNow
                    };
                    db.Users.Add(user);
                    imported++;
                }
                catch (Exception ex)
                {
                    errors.Add($"{item.Username}: {ex.Message}");
                }
            }

            await db.SaveChangesAsync();
            logger.LogInformation("Bulk user import: {Imported} imported, {Errors} errors", imported, errors.Count);

            return Results.Ok(new { success = true, data = new { imported, errors = errors.Take(10) } });
        });
    }

    private static bool IsCsvInjection(string? value) =>
        !string.IsNullOrEmpty(value) && (value[0] == '=' || value[0] == '+' || value[0] == '-' || value[0] == '@');
}

public record BulkCredentialImportRequest(Guid FolderId, CredentialImportItem[] Credentials);
public record CredentialImportItem(string Name, string? Username, string? Password, CredentialType Type, string? Tags);
public record BulkUserImportRequest(UserImportItem[] Users);
public record UserImportItem(string Username, string? Password, string? DisplayName, string? Email);
