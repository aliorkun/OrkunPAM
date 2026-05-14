namespace OrkunPAM.HttpProxy;

internal sealed class HttpProxyOptions
{
    public int ListenPort { get; set; } = 8080;
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int MaxConcurrentSessions { get; set; } = 50;
    public string LogDirectory { get; set; } = "http-logs";
    public int RetentionDays { get; set; } = 90;
    public List<string> UrlBlacklist { get; set; } = [];
    public List<string> UrlWhitelist { get; set; } = [];
}
