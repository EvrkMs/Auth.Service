using Auth.Application.Abstractions;
using Auth.Application.Sessions;
using Auth.Domain.Entity;
using Auth.Domain.Tokens;

namespace Auth.Application.Tokens;

public sealed class TokenRefreshService
{
    private static readonly string[] EmptyScopes = [];

    private readonly ITokenRepository _tokens;
    private readonly ISessionRepository _sessions;
    private readonly ITokenValueGenerator _values;
    private readonly TokenService _tokenService;
    private readonly TokenOptions _options;
    private readonly ISystemClock _clock;
    private readonly IUnitOfWork _unitOfWork;

    public TokenRefreshService(
        ITokenRepository tokens,
        ISessionRepository sessions,
        ITokenValueGenerator values,
        TokenService tokenService,
        TokenOptions options,
        ISystemClock clock,
        IUnitOfWork unitOfWork)
    {
        _tokens = tokens;
        _sessions = sessions;
        _values = values;
        _tokenService = tokenService;
        _options = options;
        _clock = clock;
        _unitOfWork = unitOfWork;
    }

    public async Task<IssueTokenResult> RefreshAsync(string refreshTokenValue, Employee? employee = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshTokenValue);

        var now = _clock.UtcNow;
        var hash = _values.ComputeHash(refreshTokenValue);
        var token = await _tokens.FindByHashAsync(hash, cancellationToken)
            ?? throw new InvalidOperationException("Refresh token not found.");

        if (token.Type != TokenType.Refresh)
        {
            throw new InvalidOperationException("Provided token is not refresh token.");
        }

        if (employee is not null && token.EmployeeId != employee.Id)
        {
            throw new InvalidOperationException("Refresh token does not belong to employee.");
        }

        var owner = employee ?? token.Employee
            ?? throw new InvalidOperationException("Refresh token missing employee information.");

        var policy = _options.ResolvePolicy(token.ClientId);

        if (!token.IsActive(now))
        {
            await HandleReuseAsync(token, policy, now, cancellationToken);
            throw new InvalidOperationException("Refresh token is no longer active.");
        }

        Session? session = null;
        if (token.SessionId is Guid sessionId)
        {
            session = await _sessions.FindByIdAsync(sessionId, cancellationToken);
            if (session is null || !session.IsActive(now))
            {
                throw new InvalidOperationException("Session expired or revoked.");
            }
        }

        var scopes = token.Scopes is { Length: > 0 }
            ? token.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : EmptyScopes;

        var includeRefresh = policy.RotateRefreshTokens;
        var result = await _tokenService.IssueAsync(new IssueTokenRequest(
            owner,
            session,
            token.ClientId,
            scopes,
            includeRefresh,
            includeRefresh ? token : null), cancellationToken);

        if (policy.RotateRefreshTokens)
        {
            token.ConsumedAt = now;
        }

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return result;
    }

    private async Task HandleReuseAsync(Token token, TokenPolicy policy, DateTimeOffset now, CancellationToken cancellationToken)
    {
        token.RevokedAt = now;

        if (!policy.RevokeDescendantsOnRefreshReuse)
        {
            await _unitOfWork.SaveChangesAsync(cancellationToken);
            return;
        }

        var descendants = await _tokens.GetActiveDescendantsAsync(token.Id, cancellationToken);
        foreach (var child in descendants)
        {
            child.RevokedAt = now;
        }

        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }
}
