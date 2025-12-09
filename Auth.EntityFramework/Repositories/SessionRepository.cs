using Auth.Application.Sessions;
using Auth.Domain.Entity;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework.Repositories;

public sealed class SessionRepository : ISessionRepository
{
    private readonly AppDbContext _dbContext;

    public SessionRepository(AppDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(Session session, CancellationToken cancellationToken)
    {
        return _dbContext.Sessions.AddAsync(session, cancellationToken).AsTask();
    }

    public Task<Session?> FindByHandleHashAsync(string handleHash, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(handleHash);
        return _dbContext.Sessions.AsNoTracking().FirstOrDefaultAsync(x => x.HandleHash == handleHash, cancellationToken);
    }

    public Task<Session?> FindByIdAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        return _dbContext.Sessions
            .Include(x => x.Tokens)
            .FirstOrDefaultAsync(x => x.Id == sessionId, cancellationToken);
    }
}
