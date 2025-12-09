using System.Globalization;
using System.Security.Claims;

namespace Auth.Domain.Tokens;

public sealed class DefaultTokenClaimsFactory : ITokenClaimsFactory
{
    public ValueTask<IReadOnlyCollection<Claim>> CreateAsync(TokenClaimsContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var claims = new List<Claim>
        {
            new("sub", context.Employee.Id.ToString()),
            new("jti", context.Token.Id.ToString()),
            new("client_id", context.ClientId),
            new("token_type", context.Token.Type.ToString().ToLowerInvariant()),
            new("iat", ToUnixTimeSeconds(context.Token.CreatedAt).ToString(CultureInfo.InvariantCulture)),
            new("exp", ToUnixTimeSeconds(context.Token.ExpiresAt).ToString(CultureInfo.InvariantCulture)),
        };

        if (!string.IsNullOrWhiteSpace(context.Employee.DisplayName))
        {
            claims.Add(new Claim("name", context.Employee.DisplayName));
        }

        if (context.Scopes.Count > 0)
        {
            claims.Add(new Claim("scope", string.Join(' ', context.Scopes)));
        }

        if (!string.IsNullOrWhiteSpace(context.SessionHandle))
        {
            claims.Add(new Claim("sid", context.SessionHandle));
        }

        return ValueTask.FromResult<IReadOnlyCollection<Claim>>(claims);
    }

    private static long ToUnixTimeSeconds(DateTimeOffset value) => value.ToUnixTimeSeconds();
}
