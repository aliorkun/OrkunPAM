using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Generates reports based on report type and parameters.
/// </summary>
public interface IReportService
{
    Task<Result<ReportOutput>> RunAsync(string reportType, Dictionary<string, string>? parameters, CancellationToken ct = default);
}

public record ReportOutput(string Title, string ContentType, byte[] Data, int RowCount);
