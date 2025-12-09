using System.Security.Claims;

namespace Auth.Domain.Tokens;

public interface ITokenClaimsFactory
{
    ValueTask<IReadOnlyCollection<Claim>> CreateAsync(TokenClaimsContext context, CancellationToken cancellationToken = default);
}
