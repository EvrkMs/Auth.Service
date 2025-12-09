namespace Auth.Host.Models.Sessions;

public sealed record SessionResponse(
    Guid Id,
    string Device,
    string? UserAgent,
    string? IpAddress,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastSeenAt,
    bool Revoked,
    DateTimeOffset? RevokedAt,
    string? RevocationReason,
    bool IsCurrent);
