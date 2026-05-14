using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Reports;

public record RunReportQuery(
    string ReportType,
    Dictionary<string, string>? Parameters = null) : IRequest<Result<ReportOutput>>;
