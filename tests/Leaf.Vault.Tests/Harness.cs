using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using Leaf.Vault.Client;
using Leaf.Vault.Store;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Leaf.Vault.Tests;

/// <summary>Obvious fakes only. Nothing here resembles a real credential.</summary>
internal static class Fake
{
    public const string Secret = "FAKE-test-secret-0123456789+/=";
    public const string OtherSecret = "FAKE-other-secret-9876543210";

    public static SecurityIdentifier Me => WindowsIdentity.GetCurrent().User!;

    public static string TempDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "leaf-vault-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static SecretBinding Header(string origin, string name = "xi-api-key", string? format = null)
        => new(origin, new Injection(InjectionTypes.Header, name, format), origin.StartsWith("http://", StringComparison.Ordinal));
}

/// <summary>A complete vault (store, software signer, pipe, proxy) in a temp directory on a free port.</summary>
internal sealed class TestVault : IAsyncDisposable
{
    public string DataDirectory { get; } = Fake.TempDirectory();
    public string PipeName { get; } = "leaf-vault-test-" + Guid.NewGuid().ToString("N");
    public string KeyName { get; } = "LeafVaultTest-" + Guid.NewGuid().ToString("N");
    public WebApplication App { get; }
    public CapturingLogger Logs { get; } = new();
    public Uri ProxyRoot { get; private set; } = null!;
    public VaultClient Client { get; }
    public SecretStore Store => App.Services.GetRequiredService<SecretStore>();

    private TestVault()
    {
        var options = new VaultOptions
        {
            DataDirectory = DataDirectory,
            OwnerSid = Fake.Me.Value,
            PipeName = PipeName,
            ProxyPort = 0,
            SigningProvider = "software",
            SigningKeyName = KeyName,
            MaxLocalBadgeSeconds = 7 * 24 * 3600,
            MaxRemoteBadgeSeconds = 3600,
        };
        App = VaultApp.Build(options, b => b.Logging.AddProvider(Logs));
        // In tests the vault runs as the current user, so that is the expected pipe owner.
        Client = new VaultClient(PipeName, Fake.Me);
    }

    public static async Task<TestVault> StartAsync()
    {
        var vault = new TestVault();
        await vault.App.StartAsync();
        var address = vault.App.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        vault.ProxyRoot = new Uri(address.TrimEnd('/') + "/");
        return vault;
    }

    public Uri Proxy(string secretName, string pathAndQuery = "") => new(ProxyRoot, $"s/{secretName}/{pathAndQuery}");

    public async ValueTask DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        if (CngKey.Exists(KeyName)) CngKey.Open(KeyName).Delete();
        try { Directory.Delete(DataDirectory, recursive: true); } catch (IOException) { }
    }
}

/// <summary>A local HTTP(S) server standing in for a provider; records what it received.</summary>
internal sealed class FakeUpstream : IAsyncDisposable
{
    public ConcurrentQueue<Received> Requests { get; } = new();
    public WebApplication App { get; }
    public Uri Root { get; private set; } = null!;
    public string Origin => $"{Root.Scheme}://{Root.Host}:{Root.Port}";

    public sealed record Received(string Method, string RawTarget, Dictionary<string, string> Headers, string Body);

    private FakeUpstream(Func<HttpContext, Task> handler, System.Security.Cryptography.X509Certificates.X509Certificate2? tls)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => { if (tls is not null) l.UseHttps(tls); }));
        App = builder.Build();
        App.UseWebSockets();
        App.Run(async ctx =>
        {
            var body = "";
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                using var reader = new StreamReader(ctx.Request.Body);
                body = await reader.ReadToEndAsync();
            }
            Record(ctx, body);
            await handler(ctx);
        });
    }

    private void Record(HttpContext ctx, string body)
    {
        var raw = ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!.RawTarget;
        Requests.Enqueue(new Received(ctx.Request.Method, raw,
            ctx.Request.Headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString()), body));
    }

    public static async Task<FakeUpstream> StartAsync(Func<HttpContext, Task> handler,
        System.Security.Cryptography.X509Certificates.X509Certificate2? tls = null)
    {
        var upstream = new FakeUpstream(handler, tls);
        await upstream.App.StartAsync();
        var address = upstream.App.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        upstream.Root = new Uri(address.TrimEnd('/') + "/");
        return upstream;
    }

    public async ValueTask DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
    }
}

internal sealed class CapturingLogger : ILoggerProvider, ILogger
{
    public ConcurrentQueue<string> Lines { get; } = new();
    public ILogger CreateLogger(string categoryName) => this;
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Lines.Enqueue(formatter(state, exception) + (exception is null ? "" : " " + exception));
    public void Dispose() { }
}
