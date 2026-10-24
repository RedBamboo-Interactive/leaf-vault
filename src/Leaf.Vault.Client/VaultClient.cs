using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace Leaf.Vault.Client;

/// <summary>
/// Calls Leaf Vault over its control pipe, one connection per call. Before sending anything
/// it checks that the pipe is owned by the vault's service SID, so a process that created
/// <c>\\.\pipe\leaf-vault</c> first (pipe squatting) never receives a secret value.
/// </summary>
public sealed class VaultClient
{
    private readonly string _pipeName;
    private readonly SecurityIdentifier _expectedOwner;
    private readonly TimeSpan _timeout;

    public VaultClient(string pipeName = VaultProtocol.DefaultPipeName, SecurityIdentifier? expectedOwner = null, TimeSpan? timeout = null)
    {
        _pipeName = pipeName;
        _expectedOwner = expectedOwner ?? VaultProtocol.ServiceSid(VaultProtocol.ServiceName);
        _timeout = timeout ?? TimeSpan.FromSeconds(10);
    }

    /// <summary>The proxy base URL for a secret: point an HTTP client here instead of at the provider.</summary>
    public static Uri ProxyBase(string secretName, int port = VaultProtocol.DefaultProxyPort)
        => new($"http://127.0.0.1:{port}/s/{Uri.EscapeDataString(secretName)}/");

    public Task<SecretStatus> PutAsync(string name, string? value, SecretBinding binding, string kind, CancellationToken ct = default)
        => CallAsync<SecretStatus>(VaultOps.Put, new PutArgs { Name = name, Value = value, Binding = binding, Kind = kind }, ct);

    public async Task<bool> DeleteAsync(string name, CancellationToken ct = default)
        => (await CallAsync<DeleteResult>(VaultOps.Delete, new NameArgs(name), ct).ConfigureAwait(false)).Deleted;

    public async Task<IReadOnlyList<SecretStatus>> StatusAsync(string? name = null, CancellationToken ct = default)
        => (await CallAsync<StatusResult>(VaultOps.Status, new StatusArgs(name), ct).ConfigureAwait(false)).Secrets;

    public Task<SignJwtResult> SignJwtAsync(JsonElement claims, TimeSpan lifetime, CancellationToken ct = default)
        => CallAsync<SignJwtResult>(VaultOps.SignJwt, new SignJwtArgs(claims, (int)lifetime.TotalSeconds), ct);

    public Task<JwksResult> JwksAsync(CancellationToken ct = default)
        => CallAsync<JwksResult>(VaultOps.Jwks, new NoArgs(), ct);

    public Task<HealthResult> HealthAsync(CancellationToken ct = default)
        => CallAsync<HealthResult>(VaultOps.Health, new NoArgs(), ct);

    private async Task<T> CallAsync<T>(string op, object args, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);
        await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is TimeoutException or IOException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new VaultException("vault_unavailable", "Leaf Vault unavailable");
        }

        var owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
        if (owner is null || !owner.Equals(_expectedOwner))
            throw new VaultException("vault_impostor", "the vault pipe is not owned by the Leaf Vault service; refusing to talk to it");

        var request = new VaultRequest(VaultProtocol.Version, op, JsonSerializer.SerializeToElement(args, args.GetType(), VaultProtocol.Json));
        await VaultProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(request, VaultProtocol.Json), cts.Token).ConfigureAwait(false);
        var frame = await VaultProtocol.ReadFrameAsync(pipe, cts.Token).ConfigureAwait(false)
            ?? throw new VaultException("vault_unavailable", "Leaf Vault closed the connection");
        var response = JsonSerializer.Deserialize<VaultResponse>(frame, VaultProtocol.Json)
            ?? throw new VaultException("bad_response", "empty response");
        if (!response.Ok || response.Result is not { } result)
            throw new VaultException(response.Error?.Code ?? "error", response.Error?.Message ?? "request failed");
        return result.Deserialize<T>(VaultProtocol.Json) ?? throw new VaultException("bad_response", "empty result");
    }
}
