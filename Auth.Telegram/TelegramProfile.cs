namespace Auth.Telegram;

public sealed record TelegramProfile(
    long Id,
    string? Username,
    string? FirstName,
    string? LastName,
    string? PhotoUrl,
    DateTimeOffset BoundAt);
