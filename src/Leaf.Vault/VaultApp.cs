using System.Net;
using System.Security.Principal;
using Leaf.Vault.Client;
using Leaf.Vault.Pipe;
using Leaf.Vault.Proxy;
using Leaf.Vault.Signing;
using Leaf.Vault.Store;

namespace Leaf.Vault;

/// <summary>Builds the vault host: store, signer, control pipe and the loopback egress proxy.</summary>
public static class VaultApp
{
    public static WebApplication Build(VaultOptions options, Action<WebApplicationBuilder>? configure = null)
    {
        options.Validate();
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            ApplicationName = "Leaf Vault",
            ContentRootPath = AppContext.BaseDirectory,
        });
        // Configuration is the VaultOptions passed in, nothing else: no appsettings, environment
        // variables or command line can add Kestrel endpoints or change behaviour.
        builder.Configuration.Sources.Clear();
        builder.Logging.AddFilter("Microsoft", LogLevel.Warning).AddFilter("System", LogLevel.Warning);
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Listen(IPAddress.Loopback, options.ProxyPort);
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 256L * 1024 * 1024;
        });
        configure?.Invoke(builder);

        if (options.RequireLockedDataDirectory)
        {
            // The installer creates the folder locked; the vault never creates it with inherited permissions.
            if (!Directory.Exists(options.DataDirectory))
                throw new InvalidOperationException($"refusing to start: {options.DataDirectory} does not exist (run scripts/install.ps1)");
            DataDirectoryGuard.Check(options.DataDirectory, WindowsIdentity.GetCurrent().User!, options.Owner());
        }
        var store = SecretStore.Open(options.DataDirectory);
        var selected = SigningKeySelector.Select(SigningKeySelector.Sources(options.SigningProvider), options.SigningKeyName);
        var signer = selected is { } s
            ? new BadgeSigner(s.Key, s.Kind, options.MaxLocalBadgeSeconds, options.MaxRemoteBadgeSeconds)
            : null;
        var health = new VaultHealth(store, signer);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton(health);
        builder.Services.AddSingleton(sp => new VaultOperations(store, signer, health, sp.GetRequiredService<ILogger<VaultOperations>>()));
        builder.Services.AddHostedService<PipeServer>();
        builder.Services.AddSingleton(new HttpMessageInvoker(EgressProxy.CreateHandler()));
        builder.Services.AddSingleton<EgressProxy>();

        var app = builder.Build();
        app.Logger.LogInformation("Leaf Vault {Version}: badge signing {Provider}", VaultHealth.Version, signer?.ProviderKind ?? "unavailable");
        app.Lifetime.ApplicationStarted.Register(() => health.ProxyListening = true);
        app.Lifetime.ApplicationStopping.Register(() => health.ProxyListening = false);
        app.Lifetime.ApplicationStopped.Register(() => signer?.Dispose());

        app.UseWebSockets();
        app.Use(LocalCallersOnly);
        app.MapGet("/health", () => Results.Json(health.Get(), VaultProtocol.Json));
        var proxy = app.Services.GetRequiredService<EgressProxy>();
        app.Map(EgressProxy.RoutePrefix + "{name}/{**path}", proxy.HandleAsync);
        app.MapFallback(ctx => EgressProxy.Problem(ctx, 404, "not_found", "use /s/{secretName}/{path} or /health"));
        return app;
    }

    /// <summary>
    /// The proxy serves local programs, not web pages: the Host must be this loopback listener
    /// (defeats DNS rebinding) and browser requests (Origin or Sec-Fetch-Site present) are refused.
    /// </summary>
    private static Task LocalCallersOnly(HttpContext ctx, RequestDelegate next)
    {
        var host = ctx.Request.Host;
        if (host.Port != ctx.Connection.LocalPort || host.Host is not ("127.0.0.1" or "localhost"))
            return EgressProxy.Problem(ctx, 421, "bad_host", "address the vault as 127.0.0.1 or localhost");
        if (ctx.Request.Headers.ContainsKey("Origin") || ctx.Request.Headers.ContainsKey("Sec-Fetch-Site"))
            return EgressProxy.Problem(ctx, 403, "browser_refused", "the vault proxy does not serve browser requests");
        return next(ctx);
    }
}
