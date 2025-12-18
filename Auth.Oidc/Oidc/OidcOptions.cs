namespace Auth.Oidc.Oidc;

public sealed class OidcOptions
{
    public string Issuer { get; set; } = "http://localhost:8080";

    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Base64 encoded PKCS#8 RSA private key used for signing ID tokens.
    /// </summary>
    public string? SigningKey { get; set; }

    /// <summary>
    /// Optional path to a file that stores the Base64 encoded PKCS#8 signing key.
    /// When provided the key will be loaded from, or persisted to, this location.
    /// </summary>
    public string? SigningKeyPath { get; set; }
}
