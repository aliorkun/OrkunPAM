using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Sessions;

public sealed class GetSessionsQueryHandler : IRequestHandler<GetSessionsQuery, Result<PagedResultDto<SessionDto>>>
{
    private readonly ISessionRepository _sessions;

    public GetSessionsQueryHandler(ISessionRepository sessions) => _sessions = sessions;

    public async Task<Result<PagedResultDto<SessionDto>>> Handle(GetSessionsQuery request, CancellationToken cancellationToken)
    {
        var paged = await _sessions.GetPagedAsync(
            request.Page, request.PageSize, request.Status, request.Type, request.UserId, cancellationToken);

        var dto = paged.ToDto(s => new SessionDto(
            s.Id, s.UserId, s.DeviceId, s.CredentialId,
            s.SessionType, s.Status, s.StartedAtUtc, s.EndedAtUtc,
            s.DurationSeconds, s.ClientIpAddress, s.TargetIpAddress,
            s.TargetPort, s.HasKeystrokeLog, s.HasOcrData, s.RiskScore));

        return Result<PagedResultDto<SessionDto>>.Success(dto);
    }
}
