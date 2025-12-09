using Auth.Domain.Entity;

namespace Auth.Domain.Tokens;

public sealed class TokenClaimsContext
{
    public required Token Token { get; init; }

    public required Employee Employee { get; init; }

    public required string ClientId { get; init; }

    public IReadOnlyCollection<string> Scopes { get; init; } = Array.Empty<string>();

    public string? SessionHandle { get; init; }
}
