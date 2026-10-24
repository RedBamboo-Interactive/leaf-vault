using Leaf.Vault;
using Leaf.Vault.Client;
using Microsoft.Extensions.Logging.EventLog;

// leaf-vault.json beside the executable (Program Files, administrators only) is the whole configuration.
var config = new ConfigurationBuilder()
    .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "leaf-vault.json"), optional: true)
    .Build();
var options = config.GetSection("Vault").Get<VaultOptions>() ?? new VaultOptions();

var app = VaultApp.Build(options, builder =>
{
    builder.Host.UseWindowsService(s => s.ServiceName = VaultProtocol.ServiceName);
    builder.Services.Configure<EventLogSettings>(e => { e.SourceName = "Leaf Vault"; e.LogName = "Application"; });
    // Refusals and failures only; per-request lines would flood the Application log.
    builder.Logging.AddFilter<EventLogLoggerProvider>(level => level >= LogLevel.Warning);
});
await app.RunAsync();
