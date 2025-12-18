using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Auth.Application.Abstractions;
using Auth.Domain.Entity;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Oidc.Oidc;

public sealed class OidcIdTokenFactory
{
    private readonly OidcOptions _options;
    private readonly OidcSigningKeyProvider _signingKeys;
    private readonly ISystemClock _clock;

    public OidcIdTokenFactory(OidcOptions options, OidcSigningKeyProvider signingKeys, ISystemClock clock)
    {
        _options = options;
        _signingKeys = signingKeys;
        _clock = clock;
    }

    public Task<string> CreateAsync(Employee employee, Session session, string clientId, string? nonce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(employee);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        var issuer = (_options.Issuer ?? "http://localhost:8080").TrimEnd('/');
        var now = _clock.UtcNow;
        var expires = now.Add(_options.IdTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, employee.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now.UtcDateTime).ToString(), ClaimValueTypes.Integer64),
            new("sid", session.HandleHash ?? session.Id.ToString()),
            new("auth_time", EpochTime.GetIntDate(session.CreatedAt.UtcDateTime).ToString(), ClaimValueTypes.Integer64)
        };

        if (!string.IsNullOrWhiteSpace(employee.DisplayName))
        {
            claims.Add(new Claim("name", employee.DisplayName));
        }

        if (!string.IsNullOrWhiteSpace(employee.UserName))
        {
            claims.Add(new Claim("preferred_username", employee.UserName!));
        }

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims.Add(new Claim("nonce", nonce));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = clientId,
            Subject = new ClaimsIdentity(claims),
            Expires = expires.UtcDateTime,
            NotBefore = now.UtcDateTime,
            SigningCredentials = _signingKeys.GetSigningCredentials()
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateEncodedJwt(descriptor);
        return Task.FromResult(token);
    }
}
