namespace Auth.Telegram;

public sealed record TelegramAuthData(
    long Id,
    string? FirstName,
    string? LastName,
    string? Username,
    string? PhotoUrl,
    long AuthDate,
    string Hash);
