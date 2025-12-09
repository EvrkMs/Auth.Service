using Auth.Domain.Tokens;

namespace Auth.Application.Tokens;

public sealed record IssuedToken(string Value, DateTimeOffset ExpiresAt, TokenType Type);
