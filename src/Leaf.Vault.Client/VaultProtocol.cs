using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Leaf.Vault.Client;

/// <summary>
/// The control-pipe protocol, version 1. Each message is a 4-byte little-endian length
/// followed by that many bytes of UTF-8 JSON: a <see cref="VaultRequest"/> from the client,
/// a <see cref="VaultResponse"/> back. <see cref="Operations"/> is the complete operation
/// set. There is deliberately no operation that returns a secret value; secrets are used
/// through the egress proxy and never leave the vault.
/// </summary>
public static class VaultProtocol
{
    public const int Version = 1;
    public const string DefaultPipeName = "leaf-vault";
    public const string ServiceName = "LeafVault";
    public const int DefaultProxyPort = 18810;
    public const int MaxFrameBytes = 64 * 1024;

    /// <summary>Operation name → (argument type, result type). The server dispatches exactly this set.</summary>
    public static readonly IReadOnlyDictionary<string, (Type Args, Type Result)> Operations =
        new Dictionary<string, (Type, Type)>(StringComparer.Ordinal)
        {
            [VaultOps.Put] = (typeof(PutArgs), typeof(SecretStatus)),
            [VaultOps.Delete] = (typeof(NameArgs), typeof(DeleteResult)),
            [VaultOps.Status] = (typeof(StatusArgs), typeof(StatusResult)),
            [VaultOps.SignJwt] = (typeof(SignJwtArgs), typeof(SignJwtResult)),
            [VaultOps.Jwks] = (typeof(NoArgs), typeof(JwksResult)),
            [VaultOps.Health] = (typeof(NoArgs), typeof(HealthResult)),
        };

    /// <summary>Strict JSON: camelCase, unknown members rejected, nullability respected.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
    };

    /// <summary>
    /// The per-service SID Windows gives <c>NT SERVICE\{serviceName}</c>: S-1-5-80 followed by
    /// the SHA-1 of the upper-cased UTF-16LE name as five little-endian integers. Computed, so
    /// a client can check the pipe owner before the service is even installed.
    /// </summary>
    public static SecurityIdentifier ServiceSid(string serviceName)
    {
        var hash = SHA1.HashData(Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant()));
        var parts = new uint[5];
        for (var i = 0; i < 5; i++) parts[i] = BitConverter.ToUInt32(hash, i * 4);
        return new SecurityIdentifier("S-1-5-80-" + string.Join("-", parts));
    }

    public static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        if (payload.Length > MaxFrameBytes) throw new VaultException("frame_too_large", "message exceeds the frame limit");
        var header = new byte[4];
        BitConverter.TryWriteBytes(header, (uint)payload.Length);
        if (!BitConverter.IsLittleEndian) Array.Reverse(header);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Reads one frame; null when the peer closed cleanly before a new frame.</summary>
    public static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        var got = await ReadAtMostAsync(stream, header, ct).ConfigureAwait(false);
        if (got == 0) return null;
        if (got < 4) throw new VaultException("bad_frame", "truncated frame header");
        if (!BitConverter.IsLittleEndian) Array.Reverse(header);
        var length = BitConverter.ToUInt32(header);
        if (length > MaxFrameBytes) throw new VaultException("frame_too_large", "message exceeds the frame limit");
        var payload = new byte[length];
        if (await ReadAtMostAsync(stream, payload, ct).ConfigureAwait(false) < length)
            throw new VaultException("bad_frame", "truncated frame");
        return payload;
    }

    private static async Task<int> ReadAtMostAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
        }
        return total;
    }
}

public static class VaultOps
{
    public const string Put = "put";
    public const string Delete = "delete";
    public const string Status = "status";
    public const string SignJwt = "sign-jwt";
    public const string Jwks = "jwks";
    public const string Health = "health";
}

public static class InjectionTypes
{
    public const string Header = "header";
    public const string Query = "query";
    public const string Path = "path";
}

public static class NetClaims
{
    public const string Claim = "net";
    public const string Local = "local";
    public const string Remote = "remote";
}

public sealed record VaultRequest(int V, string Op, JsonElement? Args);

public sealed record VaultResponse(int V, bool Ok, JsonElement? Result, VaultError? Error);

public sealed record VaultError(string Code, string Message);

/// <summary>
/// Where a secret may go and how it is placed in the request. <c>Origin</c> is
/// scheme://host:port; plain http is accepted only with <c>AllowPlainHttp</c>.
/// </summary>
public sealed record SecretBinding(string Origin, Injection Inject, bool AllowPlainHttp = false);

/// <summary>
/// header: <c>Name</c> plus <c>Format</c> containing <c>{secret}</c> once (default "{secret}").
/// query: parameter <c>Name</c>. path: a path segment equal to <c>Placeholder</c> is replaced.
/// </summary>
public sealed record Injection(string Type, string? Name = null, string? Format = null, string? Placeholder = null);

/// <summary>
/// Write-only. <c>Value</c> may be omitted only to re-assert an existing secret's exact
/// binding and kind; changing either requires a new value in the same call.
/// </summary>
public sealed class PutArgs
{
    public required string Name { get; init; }
    public string? Value { get; init; }
    public required SecretBinding Binding { get; init; }
    public required string Kind { get; init; }

    public override string ToString() => $"PutArgs {{ Name = {Name}, Kind = {Kind} }}";
}

public sealed record NameArgs(string Name);

/// <summary>One secret by name, or all secrets when <c>Name</c> is null.</summary>
public sealed record StatusArgs(string? Name = null);

public sealed record NoArgs;

/// <summary>Everything about a secret except its value.</summary>
public sealed record SecretStatus(
    string Name,
    bool Configured,
    SecretBinding Binding,
    string Kind,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? LastVerified);

public sealed record DeleteResult(bool Deleted);

public sealed record StatusResult(IReadOnlyList<SecretStatus> Secrets);

/// <summary>
/// Caller-supplied claims (a JSON object that must include <c>net</c>: local|remote and must
/// not include iat, nbf or exp) and the requested lifetime, which the vault caps per <c>net</c>.
/// </summary>
public sealed record SignJwtArgs(JsonElement Claims, int LifetimeSeconds);

public sealed record SignJwtResult(string Token, string Kid, DateTimeOffset ExpiresAt);

public sealed record Jwk(string Kty, string Crv, string X, string Y, string Kid, string Use, string Alg);

public sealed record JwksResult(IReadOnlyList<Jwk> Keys);

/// <summary>Service up, store readable, signing provider (tpm|software|unavailable), proxy listening.</summary>
public sealed record HealthResult(
    string Service,
    bool StoreReadable,
    string SigningProvider,
    bool ProxyListening,
    string Version,
    int Protocol);

public sealed class VaultException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
