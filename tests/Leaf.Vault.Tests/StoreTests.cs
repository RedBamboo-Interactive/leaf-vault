using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Leaf.Vault.Client;
using Leaf.Vault.Store;
using Xunit;

namespace Leaf.Vault.Tests;

public sealed class StoreTests : IDisposable
{
    private readonly string _dir = Fake.TempDirectory();
    private static readonly SecretBinding Eleven = Fake.Header("https://api.elevenlabs.io");

    public void Dispose()
    {
        foreach (var f in Directory.EnumerateFiles(_dir)) File.SetAttributes(f, FileAttributes.Normal);
        Directory.Delete(_dir, recursive: true);
    }

    private static PutArgs Put(string name, string? value, SecretBinding binding, string kind = "api-key")
        => new() { Name = name, Value = value, Binding = binding, Kind = kind };

    [Fact]
    public async Task Roundtrip_survives_reopen_and_nothing_on_disk_is_plaintext()
    {
        var store = SecretStore.Open(_dir);
        var status = await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        Assert.Equal("https://api.elevenlabs.io:443", status.Binding.Origin);
        Assert.Equal("xi-api-key", status.Binding.Inject.Name);
        Assert.Equal("{secret}", status.Binding.Inject.Format);
        Assert.True(status.Configured);
        Assert.Null(status.LastVerified);

        var reopened = SecretStore.Open(_dir);
        Assert.True(reopened.TryUse("elevenlabs", out var binding, out var value));
        Assert.Equal(Fake.Secret, value);
        Assert.Equal(status.Binding, binding);
        Assert.Equal(status, reopened.Status("elevenlabs"));
        Assert.True(reopened.IsReadable());

        foreach (var file in Directory.EnumerateFiles(_dir))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.DoesNotContain(Fake.Secret, Encoding.UTF8.GetString(bytes));
            Assert.DoesNotContain(Fake.Secret, Encoding.Unicode.GetString(bytes));
        }
        Assert.Equal([MasterKey.FileName, SecretStore.FileName], Directory.EnumerateFiles(_dir).Select(Path.GetFileName).Order());
    }

    [Fact]
    public async Task Status_never_contains_the_value()
    {
        var store = SecretStore.Open(_dir);
        await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        await store.PutAsync(Put("steam", Fake.OtherSecret, new SecretBinding("https://api.steampowered.com", new Injection("query", "key"))));
        var json = JsonSerializer.Serialize(store.StatusAll(), VaultProtocol.Json) + JsonSerializer.Serialize(store.Status("steam"), VaultProtocol.Json);
        Assert.DoesNotContain(Fake.Secret, json);
        Assert.DoesNotContain(Fake.OtherSecret, json);
        Assert.Contains("\"name\":\"steam\"", json);
    }

    [Fact]
    public async Task Rebinding_requires_a_new_value_in_the_same_call()
    {
        var store = SecretStore.Open(_dir);
        var first = await store.PutAsync(Put("openai", Fake.Secret, Fake.Header("https://api.openai.com", "authorization", "Bearer {secret}")));
        var elsewhere = Fake.Header("https://evil.example", "authorization", "Bearer {secret}");

        var refused = await Assert.ThrowsAsync<VaultException>(() => store.PutAsync(Put("openai", null, elsewhere)));
        Assert.Equal("rebind_requires_value", refused.Code);
        var kindChange = await Assert.ThrowsAsync<VaultException>(() => store.PutAsync(Put("openai", null, first.Binding, "other")));
        Assert.Equal("rebind_requires_value", kindChange.Code);
        var headerChange = await Assert.ThrowsAsync<VaultException>(() =>
            store.PutAsync(Put("openai", null, Fake.Header("https://api.openai.com", "x-api-key"))));
        Assert.Equal("rebind_requires_value", headerChange.Code);
        Assert.True(store.TryUse("openai", out var kept, out _));
        Assert.Equal(first.Binding, kept);

        // Same binding without a value: a no-op that changes nothing.
        Assert.Equal(first, await store.PutAsync(Put("openai", null, Fake.Header("HTTPS://API.OPENAI.COM:443", "Authorization", "Bearer {secret}"))));
        var noValue = await Assert.ThrowsAsync<VaultException>(() => store.PutAsync(Put("new-one", null, Eleven)));
        Assert.Equal("value_required", noValue.Code);

        // With a new value the rebind is allowed; createdAt survives, lastVerified resets.
        var rebound = await store.PutAsync(Put("openai", Fake.OtherSecret, elsewhere));
        Assert.Equal("https://evil.example:443", rebound.Binding.Origin);
        Assert.Equal(first.CreatedAt, rebound.CreatedAt);
        Assert.True(store.TryUse("openai", out _, out var value));
        Assert.Equal(Fake.OtherSecret, value);
    }

    [Theory]
    [InlineData("http://192.168.1.20", false, "invalid_binding")]
    [InlineData("https://api.example.com/v1", false, "invalid_binding")]
    [InlineData("https://user:pw@api.example.com", false, "invalid_binding")]
    [InlineData("ftp://api.example.com", false, "invalid_binding")]
    [InlineData("not a url", false, "invalid_binding")]
    public async Task Bad_origins_are_refused(string origin, bool allowHttp, string code)
    {
        var store = SecretStore.Open(_dir);
        var e = await Assert.ThrowsAsync<VaultException>(() =>
            store.PutAsync(Put("x", Fake.Secret, new SecretBinding(origin, new Injection("header", "x-key"), allowHttp))));
        Assert.Equal(code, e.Code);
    }

    [Fact]
    public async Task Plain_http_needs_the_explicit_flag_and_ws_folds_into_http()
    {
        var store = SecretStore.Open(_dir);
        var hue = await store.PutAsync(Put("hue", Fake.Secret, new SecretBinding("http://192.168.1.20", new Injection("path", Placeholder: "LEAF_SECRET"), true)));
        Assert.Equal("http://192.168.1.20:80", hue.Binding.Origin);
        Assert.True(hue.Binding.AllowPlainHttp);
        var live = await store.PutAsync(Put("openai-live", Fake.Secret, new SecretBinding("wss://api.openai.com", new Injection("header", "Authorization", "Bearer {secret}"), true)));
        Assert.Equal("https://api.openai.com:443", live.Binding.Origin);
        Assert.False(live.Binding.AllowPlainHttp);
    }

    [Theory]
    [InlineData("header", "host", null, null)]
    [InlineData("header", "content-length", null, null)]
    [InlineData("header", "x-leaf-vault-destination", null, null)]
    [InlineData("header", "bad name", null, null)]
    [InlineData("header", "authorization", "Bearer", null)]
    [InlineData("header", "authorization", "{secret}{secret}", null)]
    [InlineData("header", "authorization", "Bearer {secret}\r\nX-Evil: 1", null)]
    [InlineData("query", null, null, null)]
    [InlineData("query", "key", "{secret}", null)]
    [InlineData("path", null, null, "short")]
    [InlineData("path", null, null, "has/slash_x")]
    [InlineData("cookie", "a", null, null)]
    public async Task Bad_injections_are_refused(string type, string? name, string? format, string? placeholder)
    {
        var store = SecretStore.Open(_dir);
        var e = await Assert.ThrowsAsync<VaultException>(() =>
            store.PutAsync(Put("x", Fake.Secret, new SecretBinding("https://api.example.com", new Injection(type, name, format, placeholder)))));
        Assert.Equal("invalid_binding", e.Code);
    }

    [Theory]
    [InlineData("Upper", "api-key", Fake.Secret, "invalid_name")]
    [InlineData("-lead", "api-key", Fake.Secret, "invalid_name")]
    [InlineData("a/b", "api-key", Fake.Secret, "invalid_name")]
    [InlineData("ok", "Bad Kind", Fake.Secret, "invalid_kind")]
    [InlineData("ok", "api-key", "short", "invalid_value")]
    [InlineData("ok", "api-key", "line\nbreak-value", "invalid_value")]
    public async Task Bad_names_kinds_and_values_are_refused(string name, string kind, string value, string code)
    {
        var store = SecretStore.Open(_dir);
        var e = await Assert.ThrowsAsync<VaultException>(() => store.PutAsync(Put(name, value, Eleven, kind)));
        Assert.Equal(code, e.Code);
        Assert.Empty(store.StatusAll());
    }

    [Fact]
    public async Task A_failed_write_leaves_the_old_file_and_memory_untouched()
    {
        var store = SecretStore.Open(_dir);
        await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        var path = Path.Combine(_dir, SecretStore.FileName);
        var before = File.ReadAllBytes(path);

        File.SetAttributes(path, FileAttributes.ReadOnly); // the rename over it now fails
        await Assert.ThrowsAnyAsync<Exception>(() => store.PutAsync(Put("second", Fake.OtherSecret, Eleven)));
        File.SetAttributes(path, FileAttributes.Normal);

        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Null(store.Status("second"));
        Assert.Empty(Directory.EnumerateFiles(_dir, "*.tmp"));
        Assert.True(SecretStore.Open(_dir).TryUse("elevenlabs", out _, out var value));
        Assert.Equal(Fake.Secret, value);
    }

    [Fact]
    public async Task A_crash_leftover_temp_file_is_ignored_and_removed()
    {
        var store = SecretStore.Open(_dir);
        await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        var stale = Path.Combine(_dir, SecretStore.FileName + ".deadbeef.tmp");
        File.WriteAllText(stale, "{\"v\":1,\"secrets\":[{\"trunc");

        var reopened = SecretStore.Open(_dir);
        Assert.NotNull(reopened.Status("elevenlabs"));
        Assert.False(File.Exists(stale));
    }

    [Fact]
    public async Task Concurrent_puts_are_serialized_and_all_persist()
    {
        var store = SecretStore.Open(_dir);
        await Task.WhenAll(Enumerable.Range(0, 24).Select(i => Task.Run(() => store.PutAsync(Put($"s{i}", Fake.Secret + i, Eleven)))));
        var reopened = SecretStore.Open(_dir);
        Assert.Equal(24, reopened.StatusAll().Count);
        Assert.True(reopened.TryUse("s7", out _, out var value));
        Assert.Equal(Fake.Secret + 7, value);
    }

    [Fact]
    public async Task Editing_the_binding_on_disk_breaks_decryption()
    {
        var store = SecretStore.Open(_dir);
        await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        var path = Path.Combine(_dir, SecretStore.FileName);
        var doc = JsonNode.Parse(File.ReadAllText(path))!;
        doc["secrets"]![0]!["binding"]!["origin"] = "https://evil.example:443";
        File.WriteAllText(path, doc.ToJsonString());

        var tampered = SecretStore.Open(_dir);
        Assert.False(tampered.IsReadable());
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => tampered.TryUse("elevenlabs", out _, out _));
    }

    [Fact]
    public async Task Delete_removes_the_record_from_disk()
    {
        var store = SecretStore.Open(_dir);
        await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        Assert.True(await store.DeleteAsync("elevenlabs"));
        Assert.False(await store.DeleteAsync("elevenlabs"));
        Assert.Empty(SecretStore.Open(_dir).StatusAll());
    }

    [Fact]
    public async Task Last_verified_is_recorded_and_persisted()
    {
        var store = SecretStore.Open(_dir);
        await store.PutAsync(Put("elevenlabs", Fake.Secret, Eleven));
        await store.MarkVerifiedAsync("elevenlabs");
        Assert.NotNull(SecretStore.Open(_dir).Status("elevenlabs")!.LastVerified);
    }

    [Fact]
    public void Master_key_is_dpapi_wrapped_and_stable()
    {
        var key = MasterKey.LoadOrCreate(_dir);
        Assert.Equal(32, key.Length);
        Assert.Equal(key, MasterKey.LoadOrCreate(_dir));
        var wrapped = File.ReadAllBytes(Path.Combine(_dir, MasterKey.FileName));
        Assert.True(wrapped.AsSpan().IndexOf(key) < 0);
    }
}

public sealed class OptionsTests
{
    [Theory]
    [InlineData("S-1-1-0", false)]        // Everyone
    [InlineData("S-1-5-11", false)]       // Authenticated Users
    [InlineData("S-1-5-32-545", false)]   // Users
    [InlineData("S-1-5-18", false)]       // SYSTEM
    [InlineData("S-1-5-21-1000000000-2000000000-3000000000-1001", true)]
    [InlineData("S-1-12-1-1000000000-2000000000-3000000000-4000000000", true)]
    public void Only_a_user_account_can_own_the_pipe(string sid, bool ok)
    {
        var options = new VaultOptions { OwnerSid = sid, DataDirectory = Path.GetTempPath() };
        if (ok) options.Validate();
        else Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void A_missing_owner_refuses_to_start()
        => Assert.Throws<InvalidOperationException>(new VaultOptions().Validate);
}
