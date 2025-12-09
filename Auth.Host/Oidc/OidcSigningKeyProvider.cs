using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Host.Oidc;

public sealed class OidcSigningKeyProvider
{
    private readonly SigningCredentials _credentials;
    private readonly JsonWebKey _jsonWebKey;

    public OidcSigningKeyProvider(OidcOptions options, ILogger<OidcSigningKeyProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        var rsa = RSA.Create();
        if (!string.IsNullOrWhiteSpace(options.SigningKey))
        {
            try
            {
                var privateKey = Convert.FromBase64String(options.SigningKey);
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("Failed to parse OIDC signing key. Provide a Base64 encoded PKCS#8 RSA key.", ex);
            }
        }
        else
        {
            rsa.KeySize = 2048;
            var export = rsa.ExportPkcs8PrivateKey();
            logger.LogWarning("Generated ephemeral OIDC signing key. Persist it by setting OIDC__SigningKey to: {Key}", Convert.ToBase64String(export));
        }

        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16))
        };

        _credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        jwk.Kid = securityKey.KeyId;
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        _jsonWebKey = jwk;
    }

    public SigningCredentials GetSigningCredentials() => _credentials;

    public JsonWebKey GetJsonWebKey() => _jsonWebKey;
}
