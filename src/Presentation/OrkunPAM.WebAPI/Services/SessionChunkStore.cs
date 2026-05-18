using System.Collections.Concurrent;
using System.Text;

namespace OrkunPAM.WebAPI.Services;

/// <summary>
/// In-memory ring buffer for live session terminal output.
/// SSH/Telnet proxies POST chunks here; admin UI polls to retrieve new content.
/// Max 256 KB per session — oldest data is discarded when the buffer is full.
/// </summary>
public sealed class SessionChunkStore
{
    private const int MaxBufferBytes = 256 * 1024;

    private sealed class SessionBuffer
    {
        public readonly StringBuilder Text = new();
        public int Version;           // incremented on every append
        public int TotalChars;        // monotonically increasing char offset
        public int ActiveObservers;
    }

    private readonly ConcurrentDictionary<Guid, SessionBuffer> _buffers = new();

    public void Append(Guid sessionId, string text)
    {
        if (string.IsNullOrEmpty(text)) return;

        var buf = _buffers.GetOrAdd(sessionId, _ => new SessionBuffer());
        lock (buf)
        {
            buf.Text.Append(text);
            buf.TotalChars += text.Length;
            buf.Version++;

            // Trim if overfull
            if (buf.Text.Length > MaxBufferBytes)
                buf.Text.Remove(0, buf.Text.Length - MaxBufferBytes);
        }
    }

    /// <summary>Returns text added after <paramref name="fromCharOffset"/> and the new total offset.</summary>
    public (string text, int newOffset) Read(Guid sessionId, int fromCharOffset)
    {
        if (!_buffers.TryGetValue(sessionId, out var buf))
            return (string.Empty, 0);

        lock (buf)
        {
            var start = buf.TotalChars - buf.Text.Length; // oldest char still in buffer
            if (fromCharOffset >= buf.TotalChars)
                return (string.Empty, buf.TotalChars);

            var skip = Math.Max(0, fromCharOffset - start);
            var content = buf.Text.ToString(skip, buf.Text.Length - skip);
            return (content, buf.TotalChars);
        }
    }

    public void IncrementObservers(Guid sessionId)
    {
        var buf = _buffers.GetOrAdd(sessionId, _ => new SessionBuffer());
        Interlocked.Increment(ref buf.ActiveObservers);
    }

    public void DecrementObservers(Guid sessionId)
    {
        if (_buffers.TryGetValue(sessionId, out var buf))
            Interlocked.Decrement(ref buf.ActiveObservers);
    }

    public int GetObserverCount(Guid sessionId) =>
        _buffers.TryGetValue(sessionId, out var buf) ? buf.ActiveObservers : 0;

    public void Remove(Guid sessionId) => _buffers.TryRemove(sessionId, out _);
}
