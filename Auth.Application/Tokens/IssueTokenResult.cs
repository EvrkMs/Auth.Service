using Auth.Domain.Tokens;

namespace Auth.Application.Tokens;

public sealed record IssueTokenResult(
    IssuedToken AccessToken,
    IssuedToken? RefreshToken,
    TokenPolicy Policy,
    IReadOnlyCollection<string> Scopes);
