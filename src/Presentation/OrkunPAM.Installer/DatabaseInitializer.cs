using Microsoft.Data.SqlClient;

namespace OrkunPAM.Installer;

/// <summary>
/// Tests database connectivity and applies schema migrations.
/// </summary>
public static class DatabaseInitializer
{
    /// <summary>
    /// Tests the SQL Server connection string.
    /// </summary>
    public static async Task<bool> TestConnectionAsync(string connectionString)
    {
        ConsoleHelper.WriteStep("Testing database connection...");

        try
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            ConsoleHelper.WriteSuccess($"Database connection successful.");
            ConsoleHelper.WriteInfo($"  Server: {connection.DataSource}");
            ConsoleHelper.WriteInfo($"  Database: {connection.Database}");
            ConsoleHelper.WriteInfo($"  Server Version: {connection.ServerVersion}");

            await connection.CloseAsync();
            return true;
        }
        catch (SqlException ex)
        {
            ConsoleHelper.WriteError($"Database connection failed: {ex.Message}");
            ConsoleHelper.WriteInfo("Please verify:");
            ConsoleHelper.WriteInfo("  - SQL Server is running");
            ConsoleHelper.WriteInfo("  - Connection string is correct");
            ConsoleHelper.WriteInfo("  - Firewall allows SQL Server connections (port 1433)");
            ConsoleHelper.WriteInfo("  - User has appropriate permissions");
            return false;
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Unexpected error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Creates the database if it does not exist.
    /// </summary>
    public static async Task<bool> EnsureDatabaseExistsAsync(string connectionString)
    {
        try
        {
            var builder = new SqlConnectionStringBuilder(connectionString);
            var databaseName = builder.InitialCatalog;

            if (string.IsNullOrEmpty(databaseName))
            {
                ConsoleHelper.WriteError("No database name specified in connection string (Initial Catalog).");
                return false;
            }

            // Connect to master to check/create database
            builder.InitialCatalog = "master";
            await using var connection = new SqlConnection(builder.ConnectionString);
            await connection.OpenAsync();

            // Check if database exists
            var checkCmd = connection.CreateCommand();
            checkCmd.CommandText = $"SELECT DB_ID(@dbName)";
            checkCmd.Parameters.AddWithValue("@dbName", databaseName);
            var dbId = await checkCmd.ExecuteScalarAsync();

            if (dbId == DBNull.Value || dbId == null)
            {
                ConsoleHelper.WriteStep($"Creating database: {databaseName}...");
                var createCmd = connection.CreateCommand();
                createCmd.CommandText = $"CREATE DATABASE [{databaseName}]";
                await createCmd.ExecuteNonQueryAsync();
                ConsoleHelper.WriteSuccess($"Database '{databaseName}' created.");
            }
            else
            {
                ConsoleHelper.WriteInfo($"Database '{databaseName}' already exists.");
            }

            return true;
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Database creation error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Applies database migrations by creating the core schemas used by OrkunPAM.
    /// </summary>
    public static async Task<bool> ApplyMigrationsAsync(string connectionString)
    {
        ConsoleHelper.WriteStep("Applying database migrations...");

        try
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            // Create the 11 OrkunPAM schemas
            string[] schemas =
            [
                "auth", "vault", "device", "session", "audit",
                "workflow", "report", "policy", "discovery",
                "analytics", "system"
            ];

            foreach (var schema in schemas)
            {
                var cmd = connection.CreateCommand();
                cmd.CommandText = $@"
                    IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = @schema)
                    BEGIN
                        EXEC('CREATE SCHEMA [{schema}]')
                    END";
                cmd.Parameters.AddWithValue("@schema", schema);
                await cmd.ExecuteNonQueryAsync();
            }

            ConsoleHelper.WriteSuccess($"Database schemas created ({schemas.Length} schemas).");

            // Create migration tracking table
            var migrationCmd = connection.CreateCommand();
            migrationCmd.CommandText = @"
                IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES
                               WHERE TABLE_SCHEMA = 'system' AND TABLE_NAME = 'Migrations')
                BEGIN
                    CREATE TABLE [system].[Migrations] (
                        [Id] INT IDENTITY(1,1) PRIMARY KEY,
                        [MigrationName] NVARCHAR(256) NOT NULL,
                        [AppliedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
                        [Version] NVARCHAR(32) NOT NULL,
                        [Checksum] NVARCHAR(64) NULL
                    )
                END";
            await migrationCmd.ExecuteNonQueryAsync();

            // Record installation migration
            var recordCmd = connection.CreateCommand();
            recordCmd.CommandText = @"
                INSERT INTO [system].[Migrations] ([MigrationName], [Version])
                VALUES (@name, @version)";
            recordCmd.Parameters.AddWithValue("@name", "InitialInstallation");
            recordCmd.Parameters.AddWithValue("@version", Program.Version);
            await recordCmd.ExecuteNonQueryAsync();

            ConsoleHelper.WriteSuccess("Database migrations applied successfully.");
            return true;
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Migration error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Creates the initial admin user in the database.
    /// </summary>
    public static async Task<bool> CreateAdminUserAsync(
        string connectionString,
        string username,
        string passwordHash,
        string salt)
    {
        ConsoleHelper.WriteStep("Creating admin user...");

        try
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            // Create Users table if not exists
            var createTableCmd = connection.CreateCommand();
            createTableCmd.CommandText = @"
                IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES
                               WHERE TABLE_SCHEMA = 'auth' AND TABLE_NAME = 'Users')
                BEGIN
                    CREATE TABLE [auth].[Users] (
                        [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
                        [Username] NVARCHAR(128) NOT NULL UNIQUE,
                        [PasswordHash] NVARCHAR(512) NOT NULL,
                        [Salt] NVARCHAR(128) NOT NULL,
                        [Email] NVARCHAR(256) NULL,
                        [IsActive] BIT NOT NULL DEFAULT 1,
                        [IsAdmin] BIT NOT NULL DEFAULT 0,
                        [MfaEnabled] BIT NOT NULL DEFAULT 0,
                        [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
                        [LastLoginAt] DATETIME2 NULL,
                        [FailedLoginCount] INT NOT NULL DEFAULT 0,
                        [LockedUntil] DATETIME2 NULL
                    )
                END";
            await createTableCmd.ExecuteNonQueryAsync();

            // Insert admin user
            var insertCmd = connection.CreateCommand();
            insertCmd.CommandText = @"
                IF NOT EXISTS (SELECT 1 FROM [auth].[Users] WHERE [Username] = @username)
                BEGIN
                    INSERT INTO [auth].[Users] ([Username], [PasswordHash], [Salt], [IsAdmin])
                    VALUES (@username, @passwordHash, @salt, 1)
                END";
            insertCmd.Parameters.AddWithValue("@username", username);
            insertCmd.Parameters.AddWithValue("@passwordHash", passwordHash);
            insertCmd.Parameters.AddWithValue("@salt", salt);
            await insertCmd.ExecuteNonQueryAsync();

            ConsoleHelper.WriteSuccess($"Admin user '{username}' created.");
            return true;
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Admin user creation error: {ex.Message}");
            return false;
        }
    }
}
