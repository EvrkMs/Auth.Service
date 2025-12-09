using Auth.Domain.Entity;

namespace Auth.Application.Tokens;

public sealed record IssueTokenRequest(
    Employee Employee,
    Session? Session,
    string ClientId,
    IReadOnlyCollection<string> Scopes,
    bool IncludeRefreshToken = true,
    Token? ParentRefreshToken = null);
