using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Reports;

public sealed class RunReportQueryHandler : IRequestHandler<RunReportQuery, Result<ReportOutput>>
{
    private readonly IReportService _reportService;
    private readonly IAuditService _audit;
    private readonly ICurrentUserService _currentUser;
    private readonly ILogger<RunReportQueryHandler> _logger;

    public RunReportQueryHandler(
        IReportService reportService,
        IAuditService audit,
        ICurrentUserService currentUser,
        ILogger<RunReportQueryHandler> logger)
    {
        _reportService = reportService;
        _audit = audit;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<Result<ReportOutput>> Handle(RunReportQuery request, CancellationToken cancellationToken)
    {
        var result = await _reportService.RunAsync(request.ReportType, request.Parameters, cancellationToken);

        var outcome = result.IsSuccess ? AuditOutcome.Success : AuditOutcome.Failure;
        await _audit.LogAsync("Reporting", "ReportGenerated", _currentUser.UserId, _currentUser.Username,
            _currentUser.IpAddress, "Report", request.ReportType,
            new { request.ReportType, RowCount = result.IsSuccess ? result.Value.RowCount : 0 },
            outcome, cancellationToken);

        if (result.IsFailure)
            _logger.LogWarning("Report '{Type}' failed: {Error}", request.ReportType, result.Error.Message);
        else
            _logger.LogInformation("Report '{Type}' generated: {Rows} rows", request.ReportType, result.Value.RowCount);

        return result;
    }
}
