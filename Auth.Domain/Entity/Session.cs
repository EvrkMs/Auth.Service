namespace Auth.Domain.Entity;

public class Session
{
    public Guid Id { get; set; }

    public Guid EmployeeId { get; set; }

    public Employee Employee { get; set; } = null!;

    public string ClientId { get; set; } = null!;

    public string? Device { get; set; }

    public string? IpAddress { get; set; }

    public string? Metadata { get; set; }

    public string? HandleHash { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }

    public ICollection<Token> Tokens { get; set; } = new List<Token>();

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && (ExpiresAt is null || now < ExpiresAt);
}
