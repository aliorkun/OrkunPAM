using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Deployment.WindowsInstaller;

namespace OrkunPAM.Installer.CustomAction;

public static class CustomActions
{
    [CustomAction]
    public static ActionResult CA_WriteConfig(Session session)
    {
        session.Log("Begin CA_WriteConfig");
        try
        {
            var installDir = session.CustomActionData["INSTALLDIR"];
            var dataDir    = session.CustomActionData["DATADIR"];
            var apiPort    = session.CustomActionData["APIPORT"] ?? "5050";
            var webPort    = session.CustomActionData["WEBPORT"] ?? "5001";
            var passphrase = session.CustomActionData["VAULTPASSPHRASE"];

            if (string.IsNullOrEmpty(passphrase))
                passphrase = GeneratePassphrase();

            var apiConfig = new
            {
                ConnectionStrings = new { Default = $"Data Source={dataDir}orkunpam.db" },
                Jwt = new { Issuer = "OrkunPAM", Audience = "OrkunPAM", KeyDirectory = Path.Combine(dataDir, "keys") },
                Vault = new { MasterPassphrase = passphrase },
                ProxyService = new { Secret = GenerateSecret(32) },
                Cors = new { AllowedOrigins = new[] { $"https://localhost:{webPort}" } },
                Serilog = new
                {
                    WriteTo = new[] { new { Name = "File", Args = new { path = Path.Combine(dataDir, "logs", "orkunpam-.log"), rollingInterval = "Day" } } }
                }
            };

            var apiConfigPath = Path.Combine(installDir, "API", "appsettings.Production.json");
            File.WriteAllText(apiConfigPath, JsonSerializer.Serialize(apiConfig, new JsonSerializerOptions { WriteIndented = true }));
            session.Log($"API config written to {apiConfigPath}");

            var webConfig = new
            {
                ApiBaseUrl = $"http://localhost:{apiPort}",
                Kestrel = new
                {
                    Endpoints = new
                    {
                        Https = new { Url = $"https://+:{webPort}" }
                    }
                }
            };

            var webConfigPath = Path.Combine(installDir, "Web", "appsettings.Production.json");
            File.WriteAllText(webConfigPath, JsonSerializer.Serialize(webConfig, new JsonSerializerOptions { WriteIndented = true }));
            session.Log($"Web config written to {webConfigPath}");

            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\OrkunPAM");
            key?.SetValue("VaultPassphraseHint", "See installation notes");

            return ActionResult.Success;
        }
        catch (Exception ex)
        {
            session.Log($"CA_WriteConfig failed: {ex}");
            return ActionResult.Failure;
        }
    }

    [CustomAction]
    public static ActionResult CA_GenerateVaultKey(Session session)
    {
        session.Log("Begin CA_GenerateVaultKey");
        try
        {
            var dataDir = session.CustomActionData["DATADIR"];
            var keysDir = Path.Combine(dataDir, "keys");
            Directory.CreateDirectory(keysDir);

            var passphrase = GeneratePassphrase();

            var passphraseFile = Path.Combine(keysDir, "vault-passphrase.txt");
            File.WriteAllText(passphraseFile,
                $"OrkunPAM Vault Passphrase (generated {DateTime.Now})\n{passphrase}\n\n" +
                "IMPORTANT: Store this passphrase securely and delete this file.\n" +
                "You will need it to decrypt backups and in case of disaster recovery.");

            var acl = new System.Security.AccessControl.FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                "Administrators",
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(passphraseFile).SetAccessControl(acl);

            var apiConfigPath = Path.Combine(session.CustomActionData["INSTALLDIR"], "API", "appsettings.Production.json");
            if (File.Exists(apiConfigPath))
            {
                var json = File.ReadAllText(apiConfigPath);
                json = json.Replace("\"MasterPassphrase\": \"\"", $"\"MasterPassphrase\": \"{passphrase}\"");
                File.WriteAllText(apiConfigPath, json);
            }

            session.Log($"Vault passphrase generated and stored at {passphraseFile}");
            return ActionResult.Success;
        }
        catch (Exception ex)
        {
            session.Log($"CA_GenerateVaultKey failed: {ex}");
            return ActionResult.Failure;
        }
    }

    [CustomAction]
    public static ActionResult CA_CreateAdminUser(Session session)
    {
        session.Log("Begin CA_CreateAdminUser");
        try
        {
            var dataDir  = session.CustomActionData["DATADIR"];
            var username = session.CustomActionData["ADMINUSER"];
            var password = session.CustomActionData["ADMINPASSWORD"];

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                session.Log("Admin user not configured, skipping");
                return ActionResult.Success;
            }

            var salt = RandomNumberGenerator.GetBytes(16);
            using var kdf = new Rfc2898DeriveBytes(password, salt, 200_000, HashAlgorithmName.SHA256);
            var hash = Convert.ToBase64String(kdf.GetBytes(32));
            var passwordHash = $"pbkdf2$200000$sha256${Convert.ToBase64String(salt)}${hash}";

            var dbPath = Path.Combine(dataDir, "orkunpam.db");
            var userId = Guid.NewGuid().ToString("D");
            var now    = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            var sqliteConnStr = $"Data Source={dbPath}";
            using var conn = new Microsoft.Data.Sqlite.SqliteConnection(sqliteConnStr);
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT OR IGNORE INTO Users
                    (Id, Username, NormalizedUsername, DisplayName, Email,
                     PasswordHash, IsActive, IsDeleted, MfaEnabled,
                     CreatedAtUtc, UpdatedAtUtc)
                VALUES
                    (@Id, @Username, @NormalizedUsername, @DisplayName, @Email,
                     @PasswordHash, 1, 0, 0, @Now, @Now)";
            cmd.Parameters.AddWithValue("@Id", userId);
            cmd.Parameters.AddWithValue("@Username", username);
            cmd.Parameters.AddWithValue("@NormalizedUsername", username.ToUpperInvariant());
            cmd.Parameters.AddWithValue("@DisplayName", "System Administrator");
            cmd.Parameters.AddWithValue("@Email", $"{username}@localhost");
            cmd.Parameters.AddWithValue("@PasswordHash", passwordHash);
            cmd.Parameters.AddWithValue("@Now", now);
            cmd.ExecuteNonQuery();

            cmd.CommandText = @"
                INSERT OR IGNORE INTO UserRoles (UserId, RoleId)
                SELECT @UserId, Id FROM Roles WHERE Name = 'SuperAdmin' LIMIT 1";
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("@UserId", userId);
            cmd.ExecuteNonQuery();

            session.Log($"Admin user '{username}' created successfully");
            return ActionResult.Success;
        }
        catch (Exception ex)
        {
            session.Log($"CA_CreateAdminUser failed: {ex}");
            return ActionResult.Failure;
        }
    }

    private static string GeneratePassphrase()
    {
        const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*";
        var bytes = RandomNumberGenerator.GetBytes(48);
        return new string(bytes.Select(b => chars[b % chars.Length]).ToArray());
    }

    private static string GenerateSecret(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        return Convert.ToBase64String(bytes)[..length];
    }
}
