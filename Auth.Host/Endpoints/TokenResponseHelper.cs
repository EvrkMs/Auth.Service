using Auth.Application.Tokens;

namespace Auth.Host.Endpoints;

public static class TokenResponseHelper
{
    public static object BuildSuccess(IssueTokenResult result, string? idToken = null, DateTimeOffset? now = null)
    {
        var current = now ?? DateTimeOffset.UtcNow;
        var expiresIn = (int)(result.AccessToken.ExpiresAt - current).TotalSeconds;
        var scopeString = result.Scopes.Count > 0 ? string.Join(' ', result.Scopes) : string.Empty;

        return new
        {
            access_token = result.AccessToken.Value,
            expires_in = expiresIn,
            token_type = "Bearer",
            refresh_token = result.RefreshToken?.Value,
            refresh_token_expires_at = result.RefreshToken?.ExpiresAt,
            scope = scopeString,
            id_token = idToken
        };
    }
}
