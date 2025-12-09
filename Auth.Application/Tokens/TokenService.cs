using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using Auth.Application.Abstractions;
using Auth.Domain.Entity;
using Auth.Domain.Tokens;

namespace Auth.Application.Tokens;

public sealed class TokenService
{
    private readonly ITokenRepository _tokens;
    private readonly ITokenValueGenerator _values;
    private readonly ITokenClaimsFactory _claimsFactory;
    private readonly TokenOptions _options;
    private readonly ISystemClock _clock;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IAccessTokenEncoder? _accessTokenEncoder;

    public TokenService(
        ITokenRepository tokens,
        ITokenValueGenerator values,
        ITokenClaimsFactory claimsFactory,
        TokenOptions options,
        ISystemClock clock,
        IUnitOfWork unitOfWork,
        IAccessTokenEncoder? accessTokenEncoder = null)
    {
        _tokens = tokens;
        _values = values;
        _claimsFactory = claimsFactory;
        _options = options;
        _clock = clock;
        _unitOfWork = unitOfWork;
        _accessTokenEncoder = accessTokenEncoder;
    }

    public async Task<IssueTokenResult> IssueAsync(IssueTokenRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Employee);
        ArgumentException.ThrowIfNullOrEmpty(request.ClientId);

        var policy = _options.ResolvePolicy(request.ClientId);
        var now = _clock.UtcNow;

        var scopesString = request.Scopes.Count > 0 ? string.Join(' ', request.Scopes) : null;
        var accessToken = CreateToken(request.Employee, request.Session, request.ClientId, TokenType.Access, now, policy.AccessTokenLifetime, scopesString);
        accessToken.Metadata = request.Session?.Metadata;
        accessToken.Scopes = scopesString;

        var accessClaims = await _claimsFactory.CreateAsync(new TokenClaimsContext
        {
            Token = accessToken,
            Employee = request.Employee,
            ClientId = request.ClientId,
            Scopes = request.Scopes,
            SessionHandle = request.Session?.HandleHash
        }, cancellationToken);

        accessToken.Payload = SerializeClaims(accessClaims);
        var (accessTokenValue, accessTokenHash) = await CreateAccessTokenValueAsync(request.ClientId, accessClaims, accessToken.CreatedAt, accessToken.ExpiresAt, cancellationToken);
        accessToken.Hash = accessTokenHash;
        
        await _tokens.AddAsync(accessToken, cancellationToken);

        IssuedToken? refreshIssued = null;
        if (request.IncludeRefreshToken)
        {
            var refreshValue = _values.Generate();
            var refreshToken = CreateToken(request.Employee, request.Session, request.ClientId, TokenType.Refresh, now, policy.RefreshTokenLifetime, scopesString);
            refreshToken.Hash = refreshValue.Hash;
            refreshToken.ParentTokenId = request.ParentRefreshToken?.Id;

            await _tokens.AddAsync(refreshToken, cancellationToken);
            refreshIssued = new IssuedToken(refreshValue.Value, refreshToken.ExpiresAt, TokenType.Refresh);
        }

        await _unitOfWork.SaveChangesAsync(cancellationToken);

        var issuedAccess = new IssuedToken(accessTokenValue, accessToken.ExpiresAt, TokenType.Access);
        return new IssueTokenResult(issuedAccess, refreshIssued, policy, request.Scopes);
    }

    private async Task<(string Value, string Hash)> CreateAccessTokenValueAsync(string clientId, IReadOnlyCollection<Claim> claims, DateTimeOffset issuedAt, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        if (_accessTokenEncoder is null)
        {
            var fallback = _values.Generate();
            return (fallback.Value, fallback.Hash);
        }

        var descriptor = new AccessTokenDescriptor(clientId, claims, issuedAt, expiresAt);
        var value = await _accessTokenEncoder.EncodeAsync(descriptor, cancellationToken);
        return (value, _values.ComputeHash(value));
    }

    private Token CreateToken(Employee employee, Session? session, string clientId, TokenType type, DateTimeOffset now, TimeSpan lifetime, string? scopes = null)
    {
        return new Token
        {
            Id = Guid.NewGuid(),
            EmployeeId = employee.Id,
            ClientId = clientId,
            Type = type,
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime),
            SessionId = session?.Id,
            Session = session,
            SessionHandleHash = session?.HandleHash,
            Scopes = scopes
        };
    }

    private static string SerializeClaims(IReadOnlyCollection<Claim> claims)
    {
        var payload = claims.Select(claim => new ClaimDto(claim.Type, claim.Value));
        return JsonSerializer.Serialize(payload);
    }

    private sealed record ClaimDto(string Type, string Value);
}
