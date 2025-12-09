using System.Security.Cryptography;
using System.Text;

namespace Auth.Application.Tokens;

public sealed class DefaultTokenValueGenerator : ITokenValueGenerator
{
    public TokenValue Generate(int size = 64)
    {
        if (size <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(size));
        }

        Span<byte> buffer = stackalloc byte[size];
        RandomNumberGenerator.Fill(buffer);

        var value = Convert.ToBase64String(buffer)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        var hash = ComputeHash(value);
        return new TokenValue(value, hash);
    }

    public string ComputeHash(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);

        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(value);
        var hashBytes = sha.ComputeHash(bytes);
        return Convert.ToHexString(hashBytes);
    }
}
