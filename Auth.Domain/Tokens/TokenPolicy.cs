namespace Auth.Domain.Tokens;

public sealed record TokenPolicy(
    TimeSpan AccessTokenLifetime,
    TimeSpan RefreshTokenLifetime,
    bool RotateRefreshTokens,
    bool RevokeDescendantsOnRefreshReuse,
    RefreshTokenTransport RefreshTokenTransport);
