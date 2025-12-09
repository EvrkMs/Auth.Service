namespace Auth.Domain.Tokens;

public sealed class ClientTokenOptions
{
    public string ClientId { get; set; } = null!;

    public RefreshTokenTransport RefreshTokenTransport { get; set; } = RefreshTokenTransport.Cookie;

    public TimeSpan? AccessTokenLifetime { get; set; }

    public TimeSpan? RefreshTokenLifetime { get; set; }

    public bool? RotateRefreshTokens { get; set; }

    public bool? RevokeDescendantsOnRefreshReuse { get; set; }
}
