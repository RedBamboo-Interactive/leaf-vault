using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Leaf.Vault.Client;
using Leaf.Vault.Signing;
using Xunit;

namespace Leaf.Vault.Tests;

public sealed class SigningTests : IDisposable
{
    private readonly string _keyName = "LeafVaultTest-" + Guid.NewGuid().ToString("N");
    private readonly CngKey _key;
    private readonly BadgeSigner _signer;

    public SigningTests()
    {
        _key = CngKeySource.Software.TryCreate(_keyName) ?? throw new InvalidOperationException("software KSP unavailable");
        _signer = new BadgeSigner(_key, "software", maxLocalSeconds: 7 * 24 * 3600, maxRemoteSeconds: 3600);
    }

    public void Dispose()
    {
        _signer.Dispose();
        _key.Delete();
    }

    private static JsonElement Claims(object o) => JsonSerializer.SerializeToElement(o);

    [Fact]
    public void Signs_an_ES256_jwt_that_verifies_against_the_jwks()
    {
        var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var result = _signer.Sign(Claims(new { sub = "agent:test", net = "local", roles = new[] { "service" } }), 600);
        var (header, payload) = Verify(result.Token, _signer.Jwks());

        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.GetProperty("typ").GetString());
        Assert.Equal(result.Kid, header.GetProperty("kid").GetString());
        Assert.Equal("agent:test", payload.GetProperty("sub").GetString());
        Assert.Equal("local", payload.GetProperty("net").GetString());
        Assert.Equal("service", payload.GetProperty("roles")[0].GetString());
        var iat = payload.GetProperty("iat").GetInt64();
        Assert.InRange(iat, before, before + 5);
        Assert.Equal(iat + 600, payload.GetProperty("exp").GetInt64());
        Assert.Equal(result.ExpiresAt.ToUnixTimeSeconds(), payload.GetProperty("exp").GetInt64());
    }

    [Fact]
    public void Jwks_is_a_public_P256_key_with_an_RFC7638_kid()
    {
        var jwk = Assert.Single(_signer.Jwks().Keys);
        Assert.Equal(("EC", "P-256", "sig", "ES256"), (jwk.Kty, jwk.Crv, jwk.Use, jwk.Alg));
        Assert.Equal(32, Base64UrlDecode(jwk.X).Length);
        Assert.Equal(32, Base64UrlDecode(jwk.Y).Length);
        var thumbprint = SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{jwk.X}\",\"y\":\"{jwk.Y}\"}}"));
        Assert.Equal(BadgeSigner.Base64Url(thumbprint), jwk.Kid);
        Assert.DoesNotContain("\"d\"", JsonSerializer.Serialize(_signer.Jwks(), VaultProtocol.Json));
    }

    [Fact]
    public void The_key_is_not_exportable()
    {
        Assert.Equal(CngExportPolicies.None, _key.ExportPolicy);
        using var ecdsa = new ECDsaCng(_key);
        Assert.ThrowsAny<CryptographicException>(() => ecdsa.ExportParameters(includePrivateParameters: true));
        Assert.ThrowsAny<CryptographicException>(() => _key.Export(CngKeyBlobFormat.EccPrivateBlob));
    }

    [Theory]
    [InlineData("{\"sub\":\"a\"}", "invalid_claims")]
    [InlineData("{\"sub\":\"a\",\"net\":\"internet\"}", "invalid_claims")]
    [InlineData("{\"sub\":\"a\",\"net\":1}", "invalid_claims")]
    [InlineData("{\"net\":\"local\",\"exp\":9999999999}", "invalid_claims")]
    [InlineData("{\"net\":\"local\",\"iat\":1}", "invalid_claims")]
    [InlineData("{\"net\":\"local\",\"nbf\":1}", "invalid_claims")]
    [InlineData("{\"net\":\"remote\",\"net\":\"local\"}", "invalid_claims")]
    [InlineData("[1,2]", "invalid_claims")]
    public void Claims_must_carry_net_and_leave_time_to_the_vault(string claims, string code)
    {
        using var doc = JsonDocument.Parse(claims);
        Assert.Equal(code, Assert.Throws<VaultException>(() => _signer.Sign(doc.RootElement, 60)).Code);
    }

    [Fact]
    public void Lifetime_is_capped_per_net()
    {
        Assert.NotNull(_signer.Sign(Claims(new { net = "remote" }), 3600).Token);
        Assert.Equal("lifetime_exceeds_cap", Assert.Throws<VaultException>(() => _signer.Sign(Claims(new { net = "remote" }), 3601)).Code);
        Assert.NotNull(_signer.Sign(Claims(new { net = "local" }), 7 * 24 * 3600).Token);
        Assert.Equal("lifetime_exceeds_cap", Assert.Throws<VaultException>(() => _signer.Sign(Claims(new { net = "local" }), 7 * 24 * 3600 + 1)).Code);
        Assert.Equal("invalid_claims", Assert.Throws<VaultException>(() => _signer.Sign(Claims(new { net = "local" }), 0)).Code);
    }

    [Fact]
    public async Task Sign_and_jwks_work_over_the_pipe()
    {
        await using var vault = await TestVault.StartAsync();
        var result = await vault.Client.SignJwtAsync(Claims(new { sub = "service:redleaf", net = "local" }), TimeSpan.FromMinutes(5));
        var (_, payload) = Verify(result.Token, await vault.Client.JwksAsync());
        Assert.Equal("service:redleaf", payload.GetProperty("sub").GetString());
        var e = await Assert.ThrowsAsync<VaultException>(() => vault.Client.SignJwtAsync(Claims(new { sub = "x" }), TimeSpan.FromMinutes(5)));
        Assert.Equal("invalid_claims", e.Code);
        Assert.Equal("software", (await vault.Client.HealthAsync()).SigningProvider);
    }

    [SkippableFact]
    public void Tpm_key_signs_when_a_tpm_is_usable_in_this_session()
    {
        var name = "LeafVaultTest-Tpm-" + Guid.NewGuid().ToString("N");
        using var key = CngKeySource.Tpm.TryCreate(name);
        Skip.If(key is null, "no TPM usable through the Microsoft Platform Crypto Provider in this session");
        try
        {
            Assert.Equal(CngExportPolicies.None, key!.ExportPolicy);
            using var signer = new BadgeSigner(key, "tpm", 3600, 3600);
            var result = signer.Sign(Claims(new { net = "local" }), 60);
            Verify(result.Token, signer.Jwks());
            Assert.NotNull(CngKeySource.Tpm.TryOpen(name));
        }
        finally
        {
            key!.Delete();
        }
    }

    internal static (JsonElement Header, JsonElement Payload) Verify(string token, JwksResult jwks)
    {
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        var jwk = Assert.Single(jwks.Keys);
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64UrlDecode(jwk.X), Y = Base64UrlDecode(jwk.Y) },
        });
        var signature = Base64UrlDecode(parts[2]);
        Assert.Equal(64, signature.Length);
        Assert.True(ecdsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256));
        return (JsonDocument.Parse(Base64UrlDecode(parts[0])).RootElement, JsonDocument.Parse(Base64UrlDecode(parts[1])).RootElement);
    }

    internal static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}

public sealed class SigningSelectionTests
{
    private sealed class FakeSource(string kind, bool has, bool canCreate, List<string> calls) : ISigningKeySource
    {
        public string Kind => kind;
        public CngKey? TryOpen(string keyName) { calls.Add($"open:{kind}"); return has ? Make() : null; }
        public CngKey? TryCreate(string keyName) { calls.Add($"create:{kind}"); return canCreate ? Make() : null; }
        // An ephemeral (unnamed, unpersisted) key is enough to stand for "a key".
        private static CngKey Make() => CngKey.Create(CngAlgorithm.ECDsaP256);
    }

    private static (string? Kind, List<string> Calls) Run(bool tpmHas, bool tpmCreate, bool swHas, bool swCreate)
    {
        var calls = new List<string>();
        var picked = SigningKeySelector.Select([new FakeSource("tpm", tpmHas, tpmCreate, calls), new FakeSource("software", swHas, swCreate, calls)], "k");
        picked?.Key.Dispose();
        return (picked?.Kind, calls);
    }

    [Fact]
    public void An_existing_tpm_key_wins()
        => Expect("tpm", ["open:tpm"], Run(true, true, true, true));

    [Fact]
    public void An_existing_software_key_is_kept_even_when_a_tpm_could_create_one()
        => Expect("software", ["open:tpm", "open:software"], Run(false, true, true, true));

    [Fact]
    public void With_no_key_anywhere_the_tpm_is_tried_first()
        => Expect("tpm", ["open:tpm", "open:software", "create:tpm"], Run(false, true, false, true));

    [Fact]
    public void Without_a_tpm_a_software_key_is_created()
        => Expect("software", ["open:tpm", "open:software", "create:tpm", "create:software"], Run(false, false, false, true));

    [Fact]
    public void Nothing_available_means_signing_unavailable()
        => Assert.Null(Run(false, false, false, false).Kind);

    [Fact]
    public void Preference_maps_to_sources()
    {
        Assert.Equal(["tpm", "software"], SigningKeySelector.Sources("auto").Select(s => s.Kind));
        Assert.Equal(["software"], SigningKeySelector.Sources("software").Select(s => s.Kind));
    }

    [Fact]
    public void An_exportable_key_under_the_vault_name_is_refused()
    {
        var name = "LeafVaultTest-" + Guid.NewGuid().ToString("N");
        using var weak = CngKey.Create(CngAlgorithm.ECDsaP256, name, new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport });
        try
        {
            Assert.Throws<CryptographicException>(() => CngKeySource.Software.TryOpen(name));
        }
        finally
        {
            weak.Delete();
        }
    }

    private static void Expect(string kind, string[] calls, (string? Kind, List<string> Calls) actual)
    {
        Assert.Equal(kind, actual.Kind);
        Assert.Equal(calls, actual.Calls);
    }
}
