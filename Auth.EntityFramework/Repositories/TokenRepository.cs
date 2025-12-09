using System.Linq;
using Auth.Application.Tokens;
using Auth.Domain.Entity;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework.Repositories;

public sealed class TokenRepository : ITokenRepository
{
    private readonly AppDbContext _dbContext;

    public TokenRepository(AppDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(Token token, CancellationToken cancellationToken)
    {
        return _dbContext.Tokens.AddAsync(token, cancellationToken).AsTask();
    }

    public Task<Token?> FindByHashAsync(string hash, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(hash);
        return _dbContext.Tokens
            .Include(x => x.Employee)
            .Include(x => x.Session)
            .FirstOrDefaultAsync(x => x.Hash == hash, cancellationToken);
    }

    public async Task<IReadOnlyList<Token>> GetActiveDescendantsAsync(Guid tokenId, CancellationToken cancellationToken)
    {
        var result = new List<Token>();
        var queue = new Queue<Guid>();
        queue.Enqueue(tokenId);

        while (queue.Count > 0)
        {
            var currentId = queue.Dequeue();
            var children = await _dbContext.Tokens
                .Where(x => x.ParentTokenId == currentId && x.RevokedAt == null && x.ConsumedAt == null)
                .ToListAsync(cancellationToken);

            foreach (var child in children)
            {
                result.Add(child);
                queue.Enqueue(child.Id);
            }
        }

        return result;
    }
}
