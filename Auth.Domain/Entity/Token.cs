using Auth.Domain.Tokens;

namespace Auth.Domain.Entity;

public class Token
{
    public Guid Id { get; set; }

    public Guid EmployeeId { get; set; }

    public Employee Employee { get; set; } = null!;

    public Guid? SessionId { get; set; }

    public Session? Session { get; set; }

    public string? SessionHandleHash { get; set; }

    public string ClientId { get; set; } = null!;

    public TokenType Type { get; set; }

    public string Hash { get; set; } = null!;

    public string? Payload { get; set; }

    public string? Scopes { get; set; }

    public string? Metadata { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public Guid? ParentTokenId { get; set; }

    public Token? ParentToken { get; set; }

    public ICollection<Token> Children { get; set; } = new List<Token>();

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ConsumedAt is null && now < ExpiresAt;
}
