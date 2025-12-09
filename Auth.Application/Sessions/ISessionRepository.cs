using Auth.Domain.Entity;

namespace Auth.Application.Sessions;

public interface ISessionRepository
{
    Task AddAsync(Session session, CancellationToken cancellationToken);

    Task<Session?> FindByHandleHashAsync(string handleHash, CancellationToken cancellationToken);

    Task<Session?> FindByIdAsync(Guid sessionId, CancellationToken cancellationToken);

    Task<Session?> FindByHandleHashForUpdateAsync(string handleHash, CancellationToken cancellationToken);

    Task<IReadOnlyList<Session>> GetByEmployeeIdAsync(Guid employeeId, CancellationToken cancellationToken);
}
