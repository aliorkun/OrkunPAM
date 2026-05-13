namespace OrkunPAM.SqlProxy;

public sealed class SqlProxyOptions
{
    /// <summary>TCP port the proxy listens on. Default 1433 (standard SQL Server).</summary>
    public int ListenPort { get; set; } = 1433;

    /// <summary>Bind address. Null = 0.0.0.0 (all interfaces).</summary>
    public string? ListenAddress { get; set; }

    public int MaxConcurrentSessions { get; set; } = 50;

    /// <summary>Directory where per-session SQL query logs (JSONL) are stored.</summary>
    public string QueryLogDirectory { get; set; } = "sql-logs";

    /// <summary>Query logs older than this are deleted. RFP §66 requires ≥6 months.</summary>
    public int RetentionDays { get; set; } = 183;

    /// <summary>Fallback idle timeout in minutes. Overridden at runtime by the global Session Policy.</summary>
    public int IdleTimeoutMinutes { get; set; } = 60;

    /// <summary>
    /// When true, DDL statements that could cause data loss are blocked:
    /// DROP TABLE/DATABASE/SCHEMA, TRUNCATE, ALTER DATABASE, SHUTDOWN, xp_cmdshell.
    /// </summary>
    public bool BlockDangerousDdl { get; set; } = true;
}
