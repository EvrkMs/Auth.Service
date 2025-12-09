using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Telegram;

public sealed class TelegramAuthValidator
{
    private readonly IOptionsMonitor<TelegramOptions> _options;
    private readonly ILogger<TelegramAuthValidator> _logger;
    private readonly TimeProvider _timeProvider;

    public TelegramAuthValidator(
        IOptionsMonitor<TelegramOptions> options,
        ILogger<TelegramAuthValidator> logger,
        TimeProvider? timeProvider = null)
    {
        _options = options;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public TelegramAuthPayload Validate(TelegramAuthData data)
    {
        if (data is null)
        {
            throw new TelegramValidationException("invalid_payload", "Не переданы данные Telegram.");
        }

        var options = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(options.BotToken))
        {
            throw new TelegramValidationException("bot_token_missing", "Телеграм бот не настроен.");
        }

        if (string.IsNullOrWhiteSpace(data.Hash))
        {
            throw new TelegramValidationException("hash_missing", "Отсутствует подпись Telegram.");
        }

        var dataCheckString = BuildDataCheckString(data);
        var computedHash = ComputeHash(options.BotToken, dataCheckString);
        byte[] providedHash;
        try
        {
            providedHash = Convert.FromHexString(data.Hash);
        }
        catch (FormatException ex)
        {
            _logger.LogWarning(ex, "Failed to parse Telegram hash");
            throw new TelegramValidationException("invalid_hash", "Некорректная подпись Telegram.");
        }

        if (!CryptographicOperations.FixedTimeEquals(computedHash, providedHash))
        {
            throw new TelegramValidationException("invalid_hash", "Подпись Telegram не совпадает.");
        }

        var authDate = DateTimeOffset.FromUnixTimeSeconds(data.AuthDate);
        var now = _timeProvider.GetUtcNow();
        var skew = TimeSpan.FromSeconds(Math.Max(options.AllowedClockSkewSeconds, 60));
        if (now - authDate > skew)
        {
            throw new TelegramValidationException("expired", "Данные Telegram устарели, попробуйте снова.");
        }

        return new TelegramAuthPayload(
            data.Id,
            data.FirstName,
            data.LastName,
            data.Username,
            data.PhotoUrl,
            authDate);
    }

    private static byte[] ComputeHash(string botToken, string dataCheckString)
    {
        var secretKey = SHA256.HashData(Encoding.UTF8.GetBytes(botToken));
        using var hmac = new HMACSHA256(secretKey);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(dataCheckString));
    }

    private static string BuildDataCheckString(TelegramAuthData data)
    {
        var pairs = new List<string>
        {
            $"auth_date={data.AuthDate}",
            $"id={data.Id}"
        };

        if (!string.IsNullOrEmpty(data.FirstName))
        {
            pairs.Add($"first_name={data.FirstName}");
        }

        if (!string.IsNullOrEmpty(data.LastName))
        {
            pairs.Add($"last_name={data.LastName}");
        }

        if (!string.IsNullOrEmpty(data.Username))
        {
            pairs.Add($"username={data.Username}");
        }

        if (!string.IsNullOrEmpty(data.PhotoUrl))
        {
            pairs.Add($"photo_url={data.PhotoUrl}");
        }

        pairs.Sort(StringComparer.Ordinal);
        return string.Join('\n', pairs);
    }
}
