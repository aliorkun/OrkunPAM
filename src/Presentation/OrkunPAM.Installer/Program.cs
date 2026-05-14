using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OrkunPAM.Installer;

/// <summary>
/// OrkunPAM Interactive CLI Installer.
/// Guides the administrator through installation, configuration, service registration,
/// firewall setup, database initialization, and TLS certificate provisioning.
/// </summary>
public static class Program
{
    public const string Version = "0.3.0";
    private const string ProductName = "OrkunPAM";

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        // Handle --uninstall flag
        if (args.Contains("--uninstall"))
            return Uninstall();

        // Handle --version flag
        if (args.Contains("--version"))
        {
            Console.WriteLine($"{ProductName} Installer v{Version}");
            return 0;
        }

        try
        {
            return await RunInstaller();
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Installation failed with an unexpected error: {ex.Message}");
            ConsoleHelper.WriteInfo($"Stack trace: {ex.StackTrace}");
            return 1;
        }
    }

    private static async Task<int> RunInstaller()
    {
        // ── Step 1: Welcome Banner ──────────────────────────────────────
        PrintBanner();

        // ── Step 2: Administrator check ─────────────────────────────────
        if (!IsRunningAsAdmin())
        {
            ConsoleHelper.WriteError("This installer must be run as Administrator.");
            ConsoleHelper.WriteInfo("Right-click the executable and select 'Run as administrator'.");
            return 1;
        }
        ConsoleHelper.WriteSuccess("Running with administrator privileges.");
        Console.WriteLine();

        // ── Step 3: License Agreement ───────────────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("LICENSE AGREEMENT");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();
        Console.WriteLine("  OrkunPAM - Enterprise Privileged Access Management");
        Console.WriteLine("  Copyright (c) 2024-2026. All rights reserved.");
        Console.WriteLine();
        Console.WriteLine("  This software is proprietary and confidential.");
        Console.WriteLine("  Unauthorized copying, distribution, or use is strictly prohibited.");
        Console.WriteLine("  By proceeding, you agree to the terms of the license agreement.");
        Console.WriteLine();

        if (!ConsoleHelper.Confirm("Do you accept the license agreement?", defaultYes: false))
        {
            ConsoleHelper.WriteWarning("Installation cancelled. License agreement not accepted.");
            return 1;
        }
        Console.WriteLine();

        // ── Step 4: Installation Directory ──────────────────────────────
        var config = new InstallerConfig();

        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("INSTALLATION DIRECTORY");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();

        config.InstallDirectory = ConsoleHelper.Prompt(
            "Installation directory", config.InstallDirectory);
        Console.WriteLine();

        // ── Step 5: Component Selection ─────────────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("COMPONENT SELECTION");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();
        Console.WriteLine("  Select components to install (Y = install, N = skip):");
        Console.WriteLine();

        config.InstallWebApi = ConsoleHelper.Confirm("WebAPI (REST API backend)", defaultYes: true);
        config.InstallBlazorUi = ConsoleHelper.Confirm("Blazor UI (Web management console)", defaultYes: true);
        config.InstallSshProxy = ConsoleHelper.Confirm("SSH Proxy (port 2222)", defaultYes: true);
        config.InstallRdpProxy = ConsoleHelper.Confirm("RDP Proxy (port 3389)", defaultYes: true);
        config.InstallHttpProxy = ConsoleHelper.Confirm("HTTP Proxy (port 8443)", defaultYes: true);

        if (config.GetSelectedComponents().Count == 0)
        {
            ConsoleHelper.WriteError("No components selected. Installation cancelled.");
            return 1;
        }

        Console.WriteLine();
        ConsoleHelper.WriteInfo($"Selected: {string.Join(", ", config.GetSelectedComponents())}");
        Console.WriteLine();

        // ── Step 6: Database Connection ─────────────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("DATABASE CONFIGURATION");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();
        Console.WriteLine("  Enter SQL Server connection string.");
        Console.WriteLine("  Example: Server=localhost;Database=OrkunPAM;Trusted_Connection=True;TrustServerCertificate=True");
        Console.WriteLine();

        while (true)
        {
            config.DatabaseConnectionString = ConsoleHelper.Prompt(
                "Connection string",
                "Server=localhost;Database=OrkunPAM;Trusted_Connection=True;TrustServerCertificate=True");

            ConsoleHelper.WriteStep("Testing database connection...");
            var dbOk = await DatabaseInitializer.TestConnectionAsync(config.DatabaseConnectionString);

            if (dbOk) break;

            if (!ConsoleHelper.Confirm("Retry with a different connection string?", defaultYes: true))
            {
                ConsoleHelper.WriteWarning("Continuing without database validation. Migrations may fail.");
                break;
            }
        }
        Console.WriteLine();

        // ── Step 7: Master Encryption Passphrase ────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("ENCRYPTION SETUP");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();
        Console.WriteLine("  The master passphrase protects the encryption key hierarchy.");
        Console.WriteLine("  Store this securely - it cannot be recovered if lost.");
        Console.WriteLine("  Minimum 16 characters recommended.");
        Console.WriteLine();

        while (true)
        {
            config.MasterPassphrase = ConsoleHelper.PromptPassword("Master passphrase");

            if (config.MasterPassphrase.Length < 12)
            {
                ConsoleHelper.WriteError("Passphrase must be at least 12 characters.");
                continue;
            }

            var confirm = ConsoleHelper.PromptPassword("Confirm passphrase");
            if (config.MasterPassphrase != confirm)
            {
                ConsoleHelper.WriteError("Passphrases do not match. Try again.");
                continue;
            }

            break;
        }
        ConsoleHelper.WriteSuccess("Master passphrase accepted.");
        Console.WriteLine();

        // ── Step 8: Admin User Creation ─────────────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("ADMIN USER");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();

        config.AdminUsername = ConsoleHelper.Prompt("Admin username", "admin");

        while (true)
        {
            config.AdminPassword = ConsoleHelper.PromptPassword("Admin password");

            if (config.AdminPassword.Length < 12)
            {
                ConsoleHelper.WriteError("Password must be at least 12 characters.");
                continue;
            }

            if (!HasPasswordComplexity(config.AdminPassword))
            {
                ConsoleHelper.WriteError("Password must contain uppercase, lowercase, digit, and special character.");
                continue;
            }

            var confirm = ConsoleHelper.PromptPassword("Confirm admin password");
            if (config.AdminPassword != confirm)
            {
                ConsoleHelper.WriteError("Passwords do not match. Try again.");
                continue;
            }

            break;
        }
        ConsoleHelper.WriteSuccess($"Admin user '{config.AdminUsername}' configured.");
        Console.WriteLine();

        // ── Step 9: TLS Certificate Setup ───────────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("TLS CERTIFICATE");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();

        config.Hostname = ConsoleHelper.Prompt("Server hostname/FQDN", Environment.MachineName);

        config.GenerateSelfSignedCert = ConsoleHelper.Confirm(
            "Generate self-signed certificate?", defaultYes: true);

        if (!config.GenerateSelfSignedCert)
        {
            config.CertificatePath = ConsoleHelper.Prompt("Path to PFX certificate file");
            config.CertificatePassword = ConsoleHelper.PromptPassword("Certificate password");

            if (!CertificateGenerator.ValidatePfx(config.CertificatePath, config.CertificatePassword))
            {
                ConsoleHelper.WriteWarning("Certificate validation failed. Continuing anyway.");
            }
        }
        Console.WriteLine();

        // ── Step 10: Confirmation ───────────────────────────────────────
        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("INSTALLATION SUMMARY");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();
        ConsoleHelper.WriteInfo($"Install Directory:  {config.InstallDirectory}");
        ConsoleHelper.WriteInfo($"Components:         {string.Join(", ", config.GetSelectedComponents())}");
        ConsoleHelper.WriteInfo($"Database:           {MaskConnectionString(config.DatabaseConnectionString)}");
        ConsoleHelper.WriteInfo($"Admin User:         {config.AdminUsername}");
        ConsoleHelper.WriteInfo($"Hostname:           {config.Hostname}");
        ConsoleHelper.WriteInfo($"TLS Certificate:    {(config.GenerateSelfSignedCert ? "Self-signed (RSA 4096)" : config.CertificatePath)}");

        if (config.InstallWebApi) ConsoleHelper.WriteInfo($"WebAPI URL:         https://{config.Hostname}:{config.WebApiPort}");
        if (config.InstallBlazorUi) ConsoleHelper.WriteInfo($"Blazor UI URL:      https://{config.Hostname}:{config.BlazorPort}");
        if (config.InstallSshProxy) ConsoleHelper.WriteInfo($"SSH Proxy:          port {config.SshProxyPort}");
        if (config.InstallRdpProxy) ConsoleHelper.WriteInfo($"RDP Proxy:          port {config.RdpProxyPort}");
        if (config.InstallHttpProxy) ConsoleHelper.WriteInfo($"HTTP Proxy:         port {config.HttpProxyPort}");
        Console.WriteLine();

        if (!ConsoleHelper.Confirm("Proceed with installation?", defaultYes: true))
        {
            ConsoleHelper.WriteWarning("Installation cancelled by user.");
            return 1;
        }
        Console.WriteLine();

        // ══════════════════════════════════════════════════════════════
        //  INSTALLATION EXECUTION
        // ══════════════════════════════════════════════════════════════

        ConsoleHelper.WriteSeparator();
        ConsoleHelper.WriteHeader("INSTALLING...");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();

        var errors = new List<string>();

        // 1. Create directory structure
        ConsoleHelper.WriteStep("Creating directory structure...");
        try
        {
            CreateDirectories(config);
            ConsoleHelper.WriteSuccess("Directory structure created.");
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Directory creation failed: {ex.Message}");
            return 1;
        }

        // 2. Generate or copy TLS certificate
        if (config.GenerateSelfSignedCert)
        {
            try
            {
                var (pfxPath, certPassword) = CertificateGenerator.GenerateSelfSigned(
                    config.Hostname, config.CertsDirectory);
                config.CertificatePath = pfxPath;
                config.CertificatePassword = certPassword;
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteError($"Certificate generation failed: {ex.Message}");
                errors.Add("TLS certificate generation failed");
            }
        }

        // 3. Generate configuration files
        ConsoleHelper.WriteStep("Generating configuration files...");
        try
        {
            GenerateConfigFiles(config);
            ConsoleHelper.WriteSuccess("Configuration files generated.");
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Config generation failed: {ex.Message}");
            errors.Add("Configuration file generation failed");
        }

        // 4. Database setup
        ConsoleHelper.WriteStep("Setting up database...");
        try
        {
            var dbCreated = await DatabaseInitializer.EnsureDatabaseExistsAsync(config.DatabaseConnectionString);
            if (dbCreated)
            {
                await DatabaseInitializer.ApplyMigrationsAsync(config.DatabaseConnectionString);

                // Hash admin password and create user
                var (hash, salt) = HashPassword(config.AdminPassword);
                await DatabaseInitializer.CreateAdminUserAsync(
                    config.DatabaseConnectionString, config.AdminUsername, hash, salt);
            }
            else
            {
                errors.Add("Database creation/migration failed");
            }
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Database setup failed: {ex.Message}");
            errors.Add("Database setup failed");
        }

        // 5. Register Windows Services
        ConsoleHelper.WriteStep("Registering Windows Services...");
        foreach (var service in config.GetServiceDefinitions())
        {
            if (!ServiceInstaller.CreateService(service, config.InstallDirectory))
            {
                errors.Add($"Service registration failed: {service.DisplayName}");
            }
        }

        // 6. Configure firewall rules
        FirewallManager.CreateRulesForConfig(config);

        // 7. Start services
        ConsoleHelper.WriteStep("Starting services...");
        foreach (var service in config.GetServiceDefinitions())
        {
            if (!ServiceInstaller.StartService(service.Name))
            {
                ConsoleHelper.WriteWarning($"Service '{service.DisplayName}' could not be started. " +
                                           "It may start after binaries are deployed.");
            }
        }

        // ── Final Summary ───────────────────────────────────────────────
        Console.WriteLine();
        ConsoleHelper.WriteSeparator();

        if (errors.Count == 0)
        {
            ConsoleHelper.WriteHeader("INSTALLATION COMPLETE");
        }
        else
        {
            ConsoleHelper.WriteHeader("INSTALLATION COMPLETED WITH WARNINGS");
        }

        ConsoleHelper.WriteSeparator();
        Console.WriteLine();

        if (errors.Count > 0)
        {
            ConsoleHelper.WriteWarning("The following issues occurred:");
            foreach (var error in errors)
            {
                ConsoleHelper.WriteInfo($"- {error}");
            }
            Console.WriteLine();
        }

        ConsoleHelper.WriteSuccess("OrkunPAM has been installed.");
        Console.WriteLine();
        ConsoleHelper.WriteInfo($"Install Directory: {config.InstallDirectory}");
        ConsoleHelper.WriteInfo($"Config Directory:  {config.ConfigDirectory}");
        ConsoleHelper.WriteInfo($"Logs Directory:    {config.LogsDirectory}");
        Console.WriteLine();

        if (config.InstallWebApi)
            ConsoleHelper.WriteInfo($"WebAPI:     https://{config.Hostname}:{config.WebApiPort}/api/v1/");

        if (config.InstallBlazorUi)
            ConsoleHelper.WriteInfo($"Blazor UI:  https://{config.Hostname}:{config.BlazorPort}/");

        if (config.InstallSshProxy)
            ConsoleHelper.WriteInfo($"SSH Proxy:  {config.Hostname}:{config.SshProxyPort}");

        if (config.InstallRdpProxy)
            ConsoleHelper.WriteInfo($"RDP Proxy:  {config.Hostname}:{config.RdpProxyPort}");

        if (config.InstallHttpProxy)
            ConsoleHelper.WriteInfo($"HTTP Proxy: {config.Hostname}:{config.HttpProxyPort}");

        Console.WriteLine();
        ConsoleHelper.WriteInfo($"Admin User: {config.AdminUsername}");
        ConsoleHelper.WriteInfo("Change the admin password after first login.");
        Console.WriteLine();

        if (config.GenerateSelfSignedCert)
        {
            ConsoleHelper.WriteWarning("A self-signed certificate was generated.");
            ConsoleHelper.WriteInfo("Replace with a trusted certificate for production use.");
            ConsoleHelper.WriteInfo($"Certificate: {config.CertificatePath}");
        }

        Console.WriteLine();
        ConsoleHelper.WriteInfo("To uninstall, run: OrkunPAM.Installer.exe --uninstall");
        Console.WriteLine();

        // Zero sensitive data from memory
        ClearSensitiveData(config);

        return errors.Count == 0 ? 0 : 2; // 2 = partial success
    }

    private static int Uninstall()
    {
        PrintBanner();
        ConsoleHelper.WriteHeader("UNINSTALL OrkunPAM");
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();

        if (!IsRunningAsAdmin())
        {
            ConsoleHelper.WriteError("Uninstaller must be run as Administrator.");
            return 1;
        }

        if (!ConsoleHelper.Confirm("Are you sure you want to uninstall OrkunPAM?", defaultYes: false))
        {
            ConsoleHelper.WriteWarning("Uninstall cancelled.");
            return 1;
        }

        Console.WriteLine();

        // Stop and remove services
        string[] serviceNames =
        [
            "OrkunPAM.WebAPI",
            "OrkunPAM.Web",
            "OrkunPAM.SshProxy",
            "OrkunPAM.RdpProxy",
            "OrkunPAM.HttpProxy"
        ];

        ConsoleHelper.WriteStep("Stopping and removing services...");
        foreach (var svc in serviceNames)
        {
            ServiceInstaller.StopService(svc);
            ServiceInstaller.DeleteService(svc);
        }

        // Remove firewall rules
        ConsoleHelper.WriteStep("Removing firewall rules...");
        FirewallManager.RemoveAllRules();

        ConsoleHelper.WriteSuccess("OrkunPAM services and firewall rules removed.");
        ConsoleHelper.WriteWarning("Installation directory and database were NOT removed.");
        ConsoleHelper.WriteInfo("Remove them manually if desired.");

        return 0;
    }

    private static void PrintBanner()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
   ___       _                 ____   _    __  __
  / _ \ _ __| | ___   _ _ __ |  _ \ / \  |  \/  |
 | | | | '__| |/ / | | | '_ \| |_) / _ \ | |\/| |
 | |_| | |  |   <| |_| | | | |  __/ ___ \| |  | |
  \___/|_|  |_|\_\\__,_|_| |_|_| /_/   \_\_|  |_|
");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  Enterprise Privileged Access Management");
        Console.WriteLine($"  Installer v{Version}");
        Console.ResetColor();
        Console.WriteLine();
        ConsoleHelper.WriteSeparator();
        Console.WriteLine();
    }

    private static bool IsRunningAsAdmin()
    {
        if (!OperatingSystem.IsWindows()) return false;

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static void CreateDirectories(InstallerConfig config)
    {
        string[] dirs =
        [
            config.InstallDirectory,
            config.DataDirectory,
            config.LogsDirectory,
            config.CertsDirectory,
            config.ConfigDirectory,
        ];

        foreach (var dir in dirs)
        {
            Directory.CreateDirectory(dir);
        }

        // Create component subdirectories
        foreach (var component in config.GetSelectedComponents())
        {
            Directory.CreateDirectory(Path.Combine(config.InstallDirectory, component));
        }
    }

    private static void GenerateConfigFiles(InstallerConfig config)
    {
        // Read template
        var templatePath = Path.Combine(AppContext.BaseDirectory, "appsettings.template.json");
        string template;

        if (File.Exists(templatePath))
        {
            template = File.ReadAllText(templatePath);
        }
        else
        {
            // Fallback: generate a minimal config
            template = GenerateMinimalTemplate();
        }

        // Replace placeholders
        var content = template
            .Replace("{{DATABASE_CONNECTION_STRING}}", EscapeJsonValue(config.DatabaseConnectionString))
            .Replace("{{INSTALL_DIRECTORY}}", EscapeJsonValue(config.InstallDirectory))
            .Replace("{{DATA_DIRECTORY}}", EscapeJsonValue(config.DataDirectory))
            .Replace("{{LOGS_DIRECTORY}}", EscapeJsonValue(config.LogsDirectory))
            .Replace("{{VERSION}}", Version)
            .Replace("{{WEBAPI_PORT}}", config.WebApiPort.ToString())
            .Replace("{{BLAZOR_PORT}}", config.BlazorPort.ToString())
            .Replace("{{CERTIFICATE_PATH}}", EscapeJsonValue(config.CertificatePath))
            .Replace("{{CERTIFICATE_PASSWORD}}", EscapeJsonValue(config.CertificatePassword))
            .Replace("{{SSH_PROXY_PORT}}", config.SshProxyPort.ToString())
            .Replace("{{SSH_PROXY_ENABLED}}", config.InstallSshProxy.ToString().ToLower())
            .Replace("{{RDP_PROXY_PORT}}", config.RdpProxyPort.ToString())
            .Replace("{{RDP_PROXY_ENABLED}}", config.InstallRdpProxy.ToString().ToLower())
            .Replace("{{HTTP_PROXY_PORT}}", config.HttpProxyPort.ToString())
            .Replace("{{HTTP_PROXY_ENABLED}}", config.InstallHttpProxy.ToString().ToLower());

        // Write appsettings.json to each component directory
        foreach (var component in config.GetSelectedComponents())
        {
            var componentConfigDir = Path.Combine(config.InstallDirectory, component);
            var outputPath = Path.Combine(componentConfigDir, "appsettings.json");
            File.WriteAllText(outputPath, content);
        }

        // Also write a master copy in the config directory
        var masterPath = Path.Combine(config.ConfigDirectory, "appsettings.json");
        File.WriteAllText(masterPath, content);
    }

    private static string GenerateMinimalTemplate()
    {
        var config = new
        {
            ConnectionStrings = new { DefaultConnection = "{{DATABASE_CONNECTION_STRING}}" },
            Kestrel = new
            {
                Endpoints = new
                {
                    Https = new
                    {
                        Url = "https://0.0.0.0:{{WEBAPI_PORT}}",
                        Certificate = new
                        {
                            Path = "{{CERTIFICATE_PATH}}",
                            Password = "{{CERTIFICATE_PASSWORD}}"
                        }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }

    private static (string Hash, string Salt) HashPassword(string password)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(32);
        var salt = Convert.ToBase64String(saltBytes);

        var hash = Convert.ToBase64String(
            Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                saltBytes,
                iterations: 600_000,
                HashAlgorithmName.SHA512,
                outputLength: 64));

        return (hash, salt);
    }

    private static bool HasPasswordComplexity(string password)
    {
        return password.Any(char.IsUpper) &&
               password.Any(char.IsLower) &&
               password.Any(char.IsDigit) &&
               password.Any(c => !char.IsLetterOrDigit(c));
    }

    private static string MaskConnectionString(string connectionString)
    {
        // Mask password in connection string for display
        var parts = connectionString.Split(';');
        var masked = new List<string>();

        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("Password=", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("Pwd=", StringComparison.OrdinalIgnoreCase))
            {
                var key = trimmed.Split('=')[0];
                masked.Add($"{key}=****");
            }
            else
            {
                masked.Add(trimmed);
            }
        }

        return string.Join(";", masked);
    }

    private static string EscapeJsonValue(string value)
    {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    private static void ClearSensitiveData(InstallerConfig config)
    {
        // Best-effort zeroing of sensitive strings in memory
        // Note: .NET strings are immutable, so this is advisory.
        // The GC may retain copies. For true zero-memory, use SecureString or byte arrays.
        config.MasterPassphrase = new string('\0', config.MasterPassphrase.Length);
        config.AdminPassword = new string('\0', config.AdminPassword.Length);
        config.CertificatePassword = new string('\0', config.CertificatePassword.Length);
    }
}
