using System.Security.Claims;

namespace Auth.Application.Tokens;

public interface IAccessTokenEncoder
{
    Task<string> EncodeAsync(AccessTokenDescriptor descriptor, CancellationToken cancellationToken = default);
}

public sealed record AccessTokenDescriptor(
    string ClientId,
    IReadOnlyCollection<Claim> Claims,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);
