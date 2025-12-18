using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Oidc.Services;

public sealed class AuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCodeEntry> _store = new(StringComparer.Ordinal);
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(5);

    public Task<string> CreateAsync(
        Guid userId,
        string clientId,
        string redirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        Guid sessionId,
        IReadOnlyCollection<string> scopes,
        string? nonce = null,
        TimeSpan? lifetime = null)
    {
        var code = GenerateCode();
        var entry = new AuthorizationCodeEntry
        {
            Code = code,
            UserId = userId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            SessionId = sessionId,
            Scopes = scopes,
            Nonce = nonce,
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime ?? DefaultLifetime)
        };

        _store[code] = entry;
        return Task.FromResult(code);
    }

    public Task<AuthorizationCodeEntry?> TryRedeemAsync(string code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return Task.FromResult<AuthorizationCodeEntry?>(null);
        }

        if (_store.TryRemove(code, out var entry))
        {
            if (entry.ExpiresAt > DateTimeOffset.UtcNow)
            {
                return Task.FromResult<AuthorizationCodeEntry?>(entry);
            }
        }

        return Task.FromResult<AuthorizationCodeEntry?>(null);
    }

    public static bool ValidatePkce(string verifier, string storedChallenge, string method)
    {
        if (string.IsNullOrWhiteSpace(storedChallenge))
        {
            return false;
        }

        if (method.Equals("plain", StringComparison.OrdinalIgnoreCase))
        {
            return string.Equals(verifier, storedChallenge, StringComparison.Ordinal);
        }

        if (!method.Equals("S256", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var encoder = Encoding.ASCII;
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(encoder.GetBytes(verifier ?? string.Empty));
        var computed = Base64UrlEncode(hash);
        return string.Equals(computed, storedChallenge, StringComparison.Ordinal);
    }

    private static string GenerateCode()
    {
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public sealed class AuthorizationCodeEntry
{
    public required string Code { get; init; }
    public required Guid UserId { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string CodeChallenge { get; init; }
    public required string CodeChallengeMethod { get; init; }
    public required Guid SessionId { get; init; }
    public required IReadOnlyCollection<string> Scopes { get; init; }
    public string? Nonce { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}
