using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Sessions;

public sealed class GetSessionRecordingQueryHandler : IRequestHandler<GetSessionRecordingQuery, Result<SessionRecordingDto>>
{
    private readonly ISessionRepository _sessions;

    public GetSessionRecordingQueryHandler(ISessionRepository sessions) => _sessions = sessions;

    public async Task<Result<SessionRecordingDto>> Handle(GetSessionRecordingQuery request, CancellationToken cancellationToken)
    {
        var session = await _sessions.GetByIdAsync(request.SessionId, cancellationToken);
        if (session is null)
            return Result<SessionRecordingDto>.Failure(Error.NotFound("Session", request.SessionId));

        var exists = !string.IsNullOrEmpty(session.RecordingPath) && File.Exists(session.RecordingPath);

        return Result<SessionRecordingDto>.Success(new SessionRecordingDto(
            session.Id,
            session.RecordingPath,
            session.RecordingSizeBytes,
            exists));
    }
}
