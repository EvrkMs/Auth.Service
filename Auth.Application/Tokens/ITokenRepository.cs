using Auth.Domain.Entity;
using Auth.Domain.Tokens;

namespace Auth.Application.Tokens;

public interface ITokenRepository
{
    Task AddAsync(Token token, CancellationToken cancellationToken);

    Task<Token?> FindByHashAsync(string hash, CancellationToken cancellationToken);

    Task<IReadOnlyList<Token>> GetActiveDescendantsAsync(Guid tokenId, CancellationToken cancellationToken);
}
