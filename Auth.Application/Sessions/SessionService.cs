using Auth.Application.Abstractions;
using Auth.Application.Tokens;
using Auth.Domain.Entity;

namespace Auth.Application.Sessions;

public sealed class SessionService
{
    private readonly ISessionRepository _sessions;
    private readonly ITokenValueGenerator _handles;
    private readonly ISystemClock _clock;
    private readonly IUnitOfWork _unitOfWork;

    public SessionService(
        ISessionRepository sessions,
        ITokenValueGenerator handles,
        ISystemClock clock,
        IUnitOfWork unitOfWork)
    {
        _sessions = sessions;
        _handles = handles;
        _clock = clock;
        _unitOfWork = unitOfWork;
    }

    public async Task<CreateSessionResult> CreateAsync(CreateSessionRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrEmpty(request.ClientId);

        var now = _clock.UtcNow;
        TokenValue? handle = null;

        if (request.IssueHandle)
        {
            handle = _handles.Generate();
        }

        var session = new Session
        {
            Id = Guid.NewGuid(),
            EmployeeId = request.EmployeeId,
            ClientId = request.ClientId,
            Device = request.Device,
            IpAddress = request.IpAddress,
            Metadata = request.Metadata,
            HandleHash = handle?.Hash,
            CreatedAt = now,
            ExpiresAt = request.Lifetime is { } lifetime ? now.Add(lifetime) : null
        };

        await _sessions.AddAsync(session, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return new CreateSessionResult(session.Id, handle?.Value);
    }
}
