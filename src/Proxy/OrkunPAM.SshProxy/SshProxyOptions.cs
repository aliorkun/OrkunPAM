namespace OrkunPAM.SshProxy;

public sealed class SshProxyOptions
{
    public int ListenPort { get; set; } = 2222;
    public string? ListenAddress { get; set; }
    public string? KeyDirectory { get; set; }
    public int MaxConcurrentSessions { get; set; } = 100;
    public string RecordingDirectory { get; set; } = "recordings";
}
