using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Auth.Application.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Host.Oidc;

public sealed class JwtAccessTokenEncoder : IAccessTokenEncoder
{
    private readonly OidcOptions _options;
    private readonly OidcSigningKeyProvider _signingKeys;

    public JwtAccessTokenEncoder(OidcOptions options, OidcSigningKeyProvider signingKeys)
    {
        _options = options;
        _signingKeys = signingKeys;
    }

    public Task<string> EncodeAsync(AccessTokenDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        var issuer = (_options.Issuer ?? "http://localhost:8080").TrimEnd('/');
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = descriptor.ClientId,
            Subject = new ClaimsIdentity(descriptor.Claims),
            Expires = descriptor.ExpiresAt.UtcDateTime,
            NotBefore = descriptor.IssuedAt.UtcDateTime,
            SigningCredentials = _signingKeys.GetSigningCredentials()
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateEncodedJwt(tokenDescriptor);
        return Task.FromResult(token);
    }
}
