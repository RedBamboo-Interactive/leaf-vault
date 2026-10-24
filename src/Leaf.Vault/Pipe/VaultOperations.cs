using System.Text.Json;
using Leaf.Vault.Client;
using Leaf.Vault.Signing;
using Leaf.Vault.Store;

namespace Leaf.Vault.Pipe;

/// <summary>
/// Dispatches one control-pipe request. The handler table has exactly the operations of
/// <see cref="VaultProtocol.Operations"/>; none of them returns a secret value. Logs carry
/// the operation, the secret name and the outcome only.
/// </summary>
internal sealed class VaultOperations
{
    private readonly ILogger _log;

    internal IReadOnlyDictionary<string, Func<JsonElement, Task<object>>> Handlers { get; }

    public VaultOperations(SecretStore store, BadgeSigner? signer, VaultHealth health, ILogger<VaultOperations> log)
    {
        _log = log;
        Handlers = new Dictionary<string, Func<JsonElement, Task<object>>>(StringComparer.Ordinal)
        {
            [VaultOps.Put] = async a => await store.PutAsync(Args<PutArgs>(a)),
            [VaultOps.Delete] = async a => new DeleteResult(await store.DeleteAsync(Args<NameArgs>(a).Name)),
            [VaultOps.Status] = a => Task.FromResult<object>(Args<StatusArgs>(a).Name is { } name
                ? new StatusResult(store.Status(name) is { } s ? [s] : [])
                : new StatusResult(store.StatusAll())),
            [VaultOps.SignJwt] = a =>
            {
                var args = Args<SignJwtArgs>(a);
                var s = signer ?? throw new VaultException("signing_unavailable", "no signing key provider is available");
                return Task.FromResult<object>(s.Sign(args.Claims, args.LifetimeSeconds));
            },
            [VaultOps.Jwks] = a =>
            {
                Args<NoArgs>(a);
                return Task.FromResult<object>(signer?.Jwks() ?? throw new VaultException("signing_unavailable", "no signing key provider is available"));
            },
            [VaultOps.Health] = a =>
            {
                Args<NoArgs>(a);
                return Task.FromResult<object>(health.Get());
            },
        };
    }

    public async Task<byte[]> HandleAsync(byte[] frame)
    {
        string op = "?";
        try
        {
            var request = JsonSerializer.Deserialize<VaultRequest>(frame, VaultProtocol.Json)
                ?? throw new VaultException("bad_request", "empty request");
            op = request.Op ?? "?";
            if (request.V != VaultProtocol.Version)
                throw new VaultException("unsupported_version", $"protocol version {VaultProtocol.Version} is required");
            if (request.Op is null || !Handlers.TryGetValue(request.Op, out var handler))
                throw new VaultException("unknown_op", "unknown operation");
            var result = await handler(request.Args ?? EmptyObject).ConfigureAwait(false);
            _log.LogInformation("pipe {Op} {Secret}: ok", op, SecretNameOf(request));
            return Response(new VaultResponse(VaultProtocol.Version, true,
                JsonSerializer.SerializeToElement(result, result.GetType(), VaultProtocol.Json), null));
        }
        catch (VaultException e)
        {
            _log.LogWarning("pipe {Op}: refused {Code}", op, e.Code);
            return Error(e.Code, e.Message);
        }
        catch (JsonException)
        {
            _log.LogWarning("pipe {Op}: refused bad_request", op);
            return Error("bad_request", "malformed request");
        }
        catch (Exception e)
        {
            // The type only: an exception message could in principle carry request content.
            _log.LogError("pipe {Op}: failed with {Type}", op, e.GetType().Name);
            return Error("internal_error", "the vault could not complete the request");
        }
    }

    private static readonly JsonElement EmptyObject = JsonDocument.Parse("{}").RootElement.Clone();

    private static T Args<T>(JsonElement args)
        => args.Deserialize<T>(VaultProtocol.Json) ?? throw new VaultException("bad_request", "missing arguments");

    private static string SecretNameOf(VaultRequest request)
        => request.Args is { ValueKind: JsonValueKind.Object } a && a.TryGetProperty("name", out var n)
            && n.ValueKind == JsonValueKind.String && n.GetString() is { Length: > 0 and <= 64 } name
            && name.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-')
                ? name
                : "-";

    private static byte[] Error(string code, string message)
        => Response(new VaultResponse(VaultProtocol.Version, false, null, new VaultError(code, message)));

    private static byte[] Response(VaultResponse response) => JsonSerializer.SerializeToUtf8Bytes(response, VaultProtocol.Json);
}
