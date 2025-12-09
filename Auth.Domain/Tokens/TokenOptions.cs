namespace Auth.Domain.Tokens;

public sealed class TokenOptions
{
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    public bool RotateRefreshTokens { get; set; } = true;

    public bool RevokeDescendantsOnRefreshReuse { get; set; } = true;

    public IDictionary<string, ClientTokenOptions> Clients { get; } = new Dictionary<string, ClientTokenOptions>(StringComparer.Ordinal);

    public ClientTokenOptions GetClient(string clientId)
    {
        if (Clients.TryGetValue(clientId, out var options))
        {
            return options;
        }

        options = new ClientTokenOptions { ClientId = clientId };
        Clients[clientId] = options;
        return options;
    }

    public TokenPolicy ResolvePolicy(string clientId)
    {
        var client = GetClient(clientId);
        return new TokenPolicy(
            client.AccessTokenLifetime ?? AccessTokenLifetime,
            client.RefreshTokenLifetime ?? RefreshTokenLifetime,
            client.RotateRefreshTokens ?? RotateRefreshTokens,
            client.RevokeDescendantsOnRefreshReuse ?? RevokeDescendantsOnRefreshReuse,
            client.RefreshTokenTransport);
    }
}
