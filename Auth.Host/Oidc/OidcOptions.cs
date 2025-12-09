namespace Auth.Host.Oidc;

public sealed class OidcOptions
{
    public string Issuer { get; set; } = "http://localhost:8080";

    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Base64 encoded PKCS#8 RSA private key used for signing ID tokens.
    /// </summary>
    public string? SigningKey { get; set; }
}
