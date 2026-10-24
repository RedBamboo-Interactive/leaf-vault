using System.IO.Pipes;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Leaf.Vault.Client;
using Leaf.Vault.Pipe;
using Xunit;

namespace Leaf.Vault.Tests;

public sealed class ProtocolTests
{
    private static readonly string[] Expected = ["put", "delete", "status", "sign-jwt", "jwks", "health"];

    /// <summary>Property names that would mean a secret value travels back to a caller.</summary>
    private static readonly string[] Forbidden = ["value", "secret", "plaintext", "ciphertext", "password", "privatekey", "d"];

    [Fact]
    public void The_operation_set_is_exactly_the_six_and_none_returns_a_value()
    {
        Assert.Equal(Expected.Order(), VaultProtocol.Operations.Keys.Order());
        foreach (var (op, (_, result)) in VaultProtocol.Operations)
            foreach (var (path, name) in PropertyNames(result, op, []))
                Assert.False(Forbidden.Contains(name.ToLowerInvariant()), $"{path} looks like a secret value");
        // The status record is fixed: everything about a secret except its value.
        Assert.Equal(["Binding", "Configured", "CreatedAt", "Kind", "LastVerified", "Name", "UpdatedAt"],
            typeof(SecretStatus).GetProperties().Select(p => p.Name).Order());
        // Only put carries a value, inbound.
        Assert.Equal(["put"], VaultProtocol.Operations.Where(o => PropertyNames(o.Value.Args, o.Key, []).Any(p => p.Name == "Value")).Select(o => o.Key));
    }

    [Fact]
    public void The_server_dispatches_exactly_the_protocol_operations()
    {
        var vault = typeof(VaultApp).Assembly;
        var dir = Fake.TempDirectory();
        var store = Leaf.Vault.Store.SecretStore.Open(dir);
        var ops = new VaultOperations(store, null, new VaultHealth(store, null), NullLogger());
        Directory.Delete(dir, recursive: true);
        Assert.Equal(VaultProtocol.Operations.Keys.Order(), ops.Handlers.Keys.Order());
        // No other public or internal type in either assembly declares a read/get/reveal/export operation.
        foreach (var type in vault.GetTypes().Concat(typeof(VaultClient).Assembly.GetTypes()))
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                Assert.DoesNotMatch("^(Get|Read|Reveal|Export)(Secret|Value)", method.Name);
        // The only member that hands out a decrypted value is the proxy's TryUse; nothing in Pipe calls it.
        var users = vault.GetTypes().Where(t => t.Namespace == "Leaf.Vault.Pipe")
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(m => m.GetMethodBody()?.GetILAsByteArray() is { } il && CallsTryUse(m.Module, il));
        Assert.Empty(users);
    }

    [Fact]
    public void Put_args_never_print_their_value()
    {
        var args = new PutArgs { Name = "x", Value = Fake.Secret, Binding = Fake.Header("https://a.example"), Kind = "api-key" };
        Assert.DoesNotContain(Fake.Secret, args.ToString());
    }

    [Fact]
    public void Service_sid_matches_what_windows_computes_for_LeafVault()
    {
        // From `sc.exe showsid LeafVault`; derived from the name only, identical on every machine.
        Assert.Equal("S-1-5-80-4171154843-989396808-1414850432-3421582902-2320376132",
            VaultProtocol.ServiceSid("LeafVault").Value);
    }

    [Fact]
    public async Task Frames_roundtrip_and_oversized_frames_are_refused()
    {
        using var ms = new MemoryStream();
        await VaultProtocol.WriteFrameAsync(ms, "{\"a\":1}"u8.ToArray(), default);
        ms.Position = 0;
        Assert.Equal("{\"a\":1}", Encoding.UTF8.GetString((await VaultProtocol.ReadFrameAsync(ms, default))!));
        Assert.Null(await VaultProtocol.ReadFrameAsync(ms, default));

        using var big = new MemoryStream(BitConverter.GetBytes((uint)VaultProtocol.MaxFrameBytes + 1));
        Assert.Equal("frame_too_large", (await Assert.ThrowsAsync<VaultException>(() => VaultProtocol.ReadFrameAsync(big, default))).Code);
        await Assert.ThrowsAsync<VaultException>(() => VaultProtocol.WriteFrameAsync(new MemoryStream(), new byte[VaultProtocol.MaxFrameBytes + 1], default));
    }

    private static IEnumerable<(string Path, string Name)> PropertyNames(Type type, string path, HashSet<Type> seen)
    {
        if (type == typeof(string) || type.IsPrimitive || type == typeof(DateTimeOffset) || type == typeof(JsonElement) || !seen.Add(type)) yield break;
        var element = type.IsGenericType ? type.GetGenericArguments()[0] : type;
        if (element != type)
        {
            foreach (var p in PropertyNames(element, path, seen)) yield return p;
            yield break;
        }
        foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (prop.Name == "EqualityContract") continue;
            yield return ($"{path}.{prop.Name}", prop.Name);
            foreach (var p in PropertyNames(prop.PropertyType, $"{path}.{prop.Name}", seen)) yield return p;
        }
    }

    private static bool CallsTryUse(Module module, byte[] il)
    {
        var target = typeof(Leaf.Vault.Store.SecretStore).GetMethod("TryUse")!.MetadataToken;
        for (var i = 0; i + 4 < il.Length; i++)
            if (il[i] is 0x28 or 0x6F && BitConverter.ToInt32(il, i + 1) is var token && token == target
                && module.ResolveMethod(token)?.DeclaringType == typeof(Leaf.Vault.Store.SecretStore))
                return true;
        return false;
    }

    private static ILogger<VaultOperations> NullLogger() => Microsoft.Extensions.Logging.Abstractions.NullLogger<VaultOperations>.Instance;
}

public sealed class PipeTests : IAsyncLifetime
{
    private TestVault _vault = null!;
    private static readonly SecretBinding Eleven = Fake.Header("https://api.elevenlabs.io");

    public async Task InitializeAsync() => _vault = await TestVault.StartAsync();
    public async Task DisposeAsync() => await _vault.DisposeAsync();

    [Fact]
    public async Task Put_status_delete_through_the_client()
    {
        var put = await _vault.Client.PutAsync("elevenlabs", Fake.Secret, Eleven, "api-key");
        Assert.Equal("https://api.elevenlabs.io:443", put.Binding.Origin);
        var all = await _vault.Client.StatusAsync();
        Assert.Equal("elevenlabs", Assert.Single(all).Name);
        Assert.Empty(await _vault.Client.StatusAsync("missing"));
        var rebind = await Assert.ThrowsAsync<VaultException>(() =>
            _vault.Client.PutAsync("elevenlabs", null, Fake.Header("https://evil.example"), "api-key"));
        Assert.Equal("rebind_requires_value", rebind.Code);
        Assert.True(await _vault.Client.DeleteAsync("elevenlabs"));
        Assert.Empty(await _vault.Client.StatusAsync());
    }

    [Fact]
    public async Task No_response_to_any_operation_contains_the_value()
    {
        await _vault.Client.PutAsync("elevenlabs", Fake.Secret, Eleven, "api-key");
        var claims = JsonSerializer.SerializeToElement(new { sub = "agent:test", net = "local" });
        var requests = new (string Op, object Args)[]
        {
            ("put", new PutArgs { Name = "elevenlabs", Value = null, Binding = Eleven, Kind = "api-key" }),
            ("put", new PutArgs { Name = "elevenlabs", Value = null, Binding = Fake.Header("https://evil.example"), Kind = "api-key" }),
            ("status", new StatusArgs()),
            ("status", new StatusArgs("elevenlabs")),
            ("sign-jwt", new SignJwtArgs(claims, 60)),
            ("jwks", new NoArgs()),
            ("health", new NoArgs()),
            ("get", new NameArgs("elevenlabs")),
            ("read", new NameArgs("elevenlabs")),
            ("reveal", new NameArgs("elevenlabs")),
            ("export", new NoArgs()),
            ("delete", new NameArgs("elevenlabs")),
        };
        foreach (var (op, args) in requests)
        {
            var raw = await RawCallAsync(new VaultRequest(1, op, JsonSerializer.SerializeToElement(args, args.GetType(), VaultProtocol.Json)));
            Assert.DoesNotContain(Fake.Secret, raw);
            Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(Fake.Secret)), raw);
            if (op is "get" or "read" or "reveal" or "export") Assert.Contains("\"unknown_op\"", raw);
        }
        Assert.DoesNotContain(_vault.Logs.Lines, l => l.Contains(Fake.Secret));
    }

    [Fact]
    public async Task Wrong_version_and_malformed_requests_are_refused()
    {
        Assert.Contains("unsupported_version", await RawCallAsync(new VaultRequest(2, "health", null)));
        Assert.Contains("bad_request", await RawCallAsync(Encoding.UTF8.GetBytes("{not json")));
        Assert.Contains("bad_request", await RawCallAsync(Encoding.UTF8.GetBytes("{\"v\":1,\"op\":\"health\",\"args\":{},\"extra\":1}")));
        Assert.Contains("bad_request", await RawCallAsync(new VaultRequest(1, "status", JsonSerializer.SerializeToElement(new { name = "x", value = "y" }))));
    }

    [Fact]
    public async Task The_client_refuses_a_pipe_not_owned_by_the_expected_account()
    {
        var impostorCheck = new VaultClient(_vault.PipeName, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        var e = await Assert.ThrowsAsync<VaultException>(() => impostorCheck.PutAsync("x", Fake.Secret, Eleven, "api-key"));
        Assert.Equal("vault_impostor", e.Code);
        Assert.Empty(_vault.Store.StatusAll());
    }

    [Fact]
    public void The_pipe_dacl_is_owner_system_and_the_vault_only_and_denies_network()
    {
        using var client = new NamedPipeClientStream(".", _vault.PipeName, PipeDirection.InOut);
        client.Connect(5000);
        var security = client.GetAccessControl();
        Assert.Equal(Fake.Me, security.GetOwner(typeof(SecurityIdentifier)));
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
        Assert.All(rules, r => Assert.False(r.IsInherited));
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        Assert.Contains(rules, r => r.IdentityReference.Equals(network) && r.AccessControlType == AccessControlType.Deny);
        Assert.Contains(rules, r => r.IdentityReference.Equals(system) && r.AccessControlType == AccessControlType.Allow);
        var allowed = rules.Where(r => r.AccessControlType == AccessControlType.Allow).Select(r => r.IdentityReference).ToHashSet();
        Assert.Subset(new HashSet<IdentityReference> { Fake.Me, system }, allowed);
        // System grants only ReadWrite: no instance creation (squatting a second instance).
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(system) && r.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));
    }

    [Fact]
    public async Task Remote_clients_are_rejected_even_when_the_dacl_would_allow_them()
    {
        // The flag on its own: an Everyone ACL, no NETWORK deny, still refuses \\127.0.0.1 (SMB).
        var name = "leaf-vault-test-" + Guid.NewGuid().ToString("N");
        var open = new PipeSecurity();
        open.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        using var server = NativePipe.Create(name, open, firstInstance: true, maxInstances: 2, bufferSize: 4096);
        _ = server.WaitForConnectionAsync();
        await AssertRemoteRefused(name);
        // And the vault's own pipe.
        await AssertRemoteRefused(_vault.PipeName);
        using var local = new NamedPipeClientStream(".", name, PipeDirection.InOut);
        await local.ConnectAsync(5000);
        Assert.True(local.IsConnected);
    }

    [Fact]
    public async Task The_vault_refuses_to_start_when_the_pipe_name_is_already_taken()
    {
        var squat = new PipeSecurity();
        squat.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        var name = "leaf-vault-test-" + Guid.NewGuid().ToString("N");
        using var squatter = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, squat);
        var server = new PipeServer(new VaultOptions { OwnerSid = Fake.Me.Value, PipeName = name },
            _vault.App.Services.GetRequiredService<VaultOperations>(), Microsoft.Extensions.Logging.Abstractions.NullLogger<PipeServer>.Instance);
        var e = await Assert.ThrowsAsync<InvalidOperationException>(() => server.StartAsync(default));
        Assert.Contains("refusing to start", e.Message);
    }

    private static async Task AssertRemoteRefused(string name)
    {
        using var remote = new NamedPipeClientStream("127.0.0.1", name, PipeDirection.InOut);
        await Assert.ThrowsAnyAsync<Exception>(() => remote.ConnectAsync(3000));
    }

    private Task<string> RawCallAsync(VaultRequest request) => RawCallAsync(JsonSerializer.SerializeToUtf8Bytes(request, VaultProtocol.Json));

    private async Task<string> RawCallAsync(byte[] payload)
    {
        await using var pipe = new NamedPipeClientStream(".", _vault.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        await VaultProtocol.WriteFrameAsync(pipe, payload, default);
        return Encoding.UTF8.GetString((await VaultProtocol.ReadFrameAsync(pipe, default))!);
    }
}
