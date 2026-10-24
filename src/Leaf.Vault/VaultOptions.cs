using System.Security.Principal;
using Leaf.Vault.Client;

namespace Leaf.Vault;

/// <summary>
/// Configuration, read from the "Vault" section of leaf-vault.json beside the executable
/// (written by scripts/install.ps1; Program Files, so only an administrator can change it).
/// </summary>
public sealed class VaultOptions
{
    public string DataDirectory { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Leaf Vault");

    /// <summary>The one interactive account allowed on the control pipe (besides SYSTEM).</summary>
    public string? OwnerSid { get; set; }

    public string PipeName { get; set; } = VaultProtocol.DefaultPipeName;

    /// <summary>Loopback port of the egress proxy; 0 picks a free port (tests).</summary>
    public int ProxyPort { get; set; } = VaultProtocol.DefaultProxyPort;

    /// <summary>"auto" (TPM, then software) or "software".</summary>
    public string SigningProvider { get; set; } = "auto";

    public string SigningKeyName { get; set; } = "LeafVault-Badge-ES256";

    public int MaxLocalBadgeSeconds { get; set; } = 365 * 24 * 3600;

    public int MaxRemoteBadgeSeconds { get; set; } = 3600;

    public SecurityIdentifier Owner()
    {
        if (string.IsNullOrWhiteSpace(OwnerSid)) throw new InvalidOperationException("Vault:OwnerSid is not configured");
        var sid = new SecurityIdentifier(OwnerSid);
        // Only a real user account (local/domain S-1-5-21-…, or Microsoft Entra S-1-12-1-…):
        // never Everyone, Users, Authenticated Users or another well-known group.
        if (!IsUserSid(sid)) throw new InvalidOperationException("Vault:OwnerSid must be a user account SID");
        return sid;
    }

    internal static bool IsUserSid(SecurityIdentifier sid)
        => sid.IsAccountSid() || sid.Value.StartsWith("S-1-12-1-", StringComparison.Ordinal);

    public void Validate()
    {
        Owner();
        if (ProxyPort is < 0 or > 65535) throw new InvalidOperationException("Vault:ProxyPort is out of range");
        if (SigningProvider is not ("auto" or "software")) throw new InvalidOperationException("Vault:SigningProvider must be auto or software");
        if (MaxLocalBadgeSeconds <= 0 || MaxRemoteBadgeSeconds <= 0) throw new InvalidOperationException("badge lifetime caps must be positive");
        if (!Path.IsPathFullyQualified(DataDirectory)) throw new InvalidOperationException("Vault:DataDirectory must be an absolute path");
    }
}
