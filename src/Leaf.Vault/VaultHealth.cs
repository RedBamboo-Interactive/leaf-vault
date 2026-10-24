using System.Reflection;
using Leaf.Vault.Client;
using Leaf.Vault.Signing;
using Leaf.Vault.Store;

namespace Leaf.Vault;

/// <summary>One health shape for the pipe and GET /health. It names no secrets.</summary>
internal sealed class VaultHealth(SecretStore store, BadgeSigner? signer)
{
    public static readonly string Version =
        typeof(VaultHealth).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    public bool ProxyListening { get; set; }

    public HealthResult Get() => new(
        "up",
        store.IsReadable(),
        signer?.ProviderKind ?? "unavailable",
        ProxyListening,
        Version,
        VaultProtocol.Version);
}
