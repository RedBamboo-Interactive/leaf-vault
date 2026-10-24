using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Leaf.Vault.Client;

namespace Leaf.Vault.Signing;

/// <summary>
/// Signs badges as ES256 JWTs with the vault's non-exportable P-256 key and publishes the
/// public half as a JWKS. Claims come from the caller; the vault requires <c>net</c>
/// (local|remote), owns iat/exp itself and caps the lifetime per <c>net</c>.
/// </summary>
internal sealed class BadgeSigner : IDisposable
{
    private readonly ECDsaCng _ecdsa;
    private readonly TimeProvider _time;
    private readonly int _maxLocalSeconds;
    private readonly int _maxRemoteSeconds;
    private readonly Jwk _jwk;
    private readonly byte[] _header;

    public BadgeSigner(CngKey key, string providerKind, int maxLocalSeconds, int maxRemoteSeconds, TimeProvider? time = null)
    {
        _ecdsa = new ECDsaCng(key);
        ProviderKind = providerKind;
        _maxLocalSeconds = maxLocalSeconds;
        _maxRemoteSeconds = maxRemoteSeconds;
        _time = time ?? TimeProvider.System;

        var p = _ecdsa.ExportParameters(includePrivateParameters: false);
        if (p.Curve.Oid?.Value != "1.2.840.10045.3.1.7" && p.Curve.Oid?.FriendlyName is not ("nistP256" or "ECDSA_P256"))
            throw new CryptographicException("the badge key is not on curve P-256");
        var x = Base64Url(p.Q.X!);
        var y = Base64Url(p.Q.Y!);
        // RFC 7638 thumbprint: required members in lexicographic order, no whitespace.
        var kid = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));
        _jwk = new Jwk("EC", "P-256", x, y, kid, "sig", "ES256");
        _header = Encoding.UTF8.GetBytes(Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "ES256", typ = "JWT", kid })));
    }

    /// <summary>"tpm" or "software".</summary>
    public string ProviderKind { get; }

    public JwksResult Jwks() => new([_jwk]);

    public SignJwtResult Sign(JsonElement claims, int lifetimeSeconds)
    {
        if (claims.ValueKind != JsonValueKind.Object) throw Invalid("claims must be a JSON object");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? net = null;
        foreach (var claim in claims.EnumerateObject())
        {
            if (!seen.Add(claim.Name)) throw Invalid($"duplicate claim '{claim.Name}'");
            if (claim.Name is "iat" or "nbf" or "exp") throw Invalid($"'{claim.Name}' is set by the vault");
            if (claim.Name == NetClaims.Claim) net = claim.Value.ValueKind == JsonValueKind.String ? claim.Value.GetString() : null;
        }
        var cap = net switch
        {
            NetClaims.Local => _maxLocalSeconds,
            NetClaims.Remote => _maxRemoteSeconds,
            _ => throw Invalid("claim 'net' is required and must be \"local\" or \"remote\""),
        };
        if (lifetimeSeconds <= 0) throw Invalid("lifetimeSeconds must be positive");
        if (lifetimeSeconds > cap) throw new VaultException("lifetime_exceeds_cap", $"a '{net}' badge may last at most {cap} seconds");

        var now = _time.GetUtcNow();
        var iat = now.ToUnixTimeSeconds();
        var exp = iat + lifetimeSeconds;
        var payload = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(payload))
        {
            writer.WriteStartObject();
            foreach (var claim in claims.EnumerateObject()) claim.WriteTo(writer);
            writer.WriteNumber("iat", iat);
            writer.WriteNumber("exp", exp);
            writer.WriteEndObject();
        }

        var signingInput = Encoding.ASCII.GetBytes($"{Encoding.ASCII.GetString(_header)}.{Base64Url(payload.WrittenSpan)}");
        // IEEE P1363 (r||s, 64 bytes) is exactly the JWS ES256 signature encoding.
        var signature = _ecdsa.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignJwtResult($"{Encoding.ASCII.GetString(signingInput)}.{Base64Url(signature)}", _jwk.Kid,
            DateTimeOffset.FromUnixTimeSeconds(exp));
    }

    public void Dispose() => _ecdsa.Dispose();

    internal static string Base64Url(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static VaultException Invalid(string message) => new("invalid_claims", message);
}
