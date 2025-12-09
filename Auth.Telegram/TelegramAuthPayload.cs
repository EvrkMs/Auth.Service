namespace Auth.Telegram;

public sealed record TelegramAuthPayload(
    long Id,
    string? FirstName,
    string? LastName,
    string? Username,
    string? PhotoUrl,
    DateTimeOffset AuthenticatedAt);
