namespace OrkunPAM.VncProxy;

internal sealed class VncProxyOptions
{
    public int ListenPort { get; set; } = 5900;
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int MaxConcurrentSessions { get; set; } = 50;
    public string RecordingDirectory { get; set; } = "vnc-recordings";
    public int RetentionDays { get; set; } = 90;
}
