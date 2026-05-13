using System.Text;
using System.Text.Json;

namespace OrkunPAM.SqlProxy.Session;

/// <summary>
/// Appends SQL query log entries to a per-session JSONL file.
/// Each line is a JSON object: {timestamp, sessionId, pamUser, targetHost, database, query, blocked}.
/// Thread-safe via SemaphoreSlim.
/// </summary>
internal sealed class SqlQueryLogger : IAsyncDisposable
{
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    private SqlQueryLogger(StreamWriter writer) => _writer = writer;

    public static async Task<SqlQueryLogger> CreateAsync(
        string directory, string sessionId)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{sessionId}.sql.jsonl");
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
            bufferSize: 4096, useAsync: true);
        var writer = new StreamWriter(file, Encoding.UTF8, leaveOpen: false);
        return await Task.FromResult(new SqlQueryLogger(writer));
    }

    public string? FilePath => (_writer.BaseStream as FileStream)?.Name;

    /// <summary>Write a query log entry. Non-blocking; errors are swallowed.</summary>
    public void LogQuery(string sessionId, string pamUser, string targetHost, string database,
        string query, bool blocked)
    {
        if (_disposed) return;
        _ = LogQueryAsync(sessionId, pamUser, targetHost, database, query, blocked);
    }

    private async Task LogQueryAsync(string sessionId, string pamUser, string targetHost,
        string database, string query, bool blocked)
    {
        if (_disposed) return;

        var entry = new
        {
            timestamp = DateTimeOffset.UtcNow.ToString("O"),
            sessionId,
            pamUser,
            targetHost,
            database,
            query = query.Length > 8192 ? query[..8192] + "...[truncated]" : query,
            blocked
        };

        var line = JsonSerializer.Serialize(entry);

        await _lock.WaitAsync();
        try
        {
            if (!_disposed)
            {
                await _writer.WriteLineAsync(line);
                await _writer.FlushAsync();
            }
        }
        catch { /* swallow — logging must never kill a session */ }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        await _lock.WaitAsync();
        try
        {
            await _writer.FlushAsync();
            await _writer.DisposeAsync();
        }
        finally
        {
            _lock.Release();
            _lock.Dispose();
        }
    }
}
