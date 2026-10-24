using System.Security.Cryptography;

namespace Leaf.Vault.Signing;

/// <summary>Where the badge key can live. Kinds reported in health: "tpm" or "software".</summary>
internal interface ISigningKeySource
{
    string Kind { get; }
    CngKey? TryOpen(string keyName);
    CngKey? TryCreate(string keyName);
}

/// <summary>
/// A CNG key storage provider holding a persisted, non-exportable ECDSA P-256 key under the
/// service account. Any provider failure (no TPM, TPM not ready, provider absent) is "not
/// here", never an exception: selection falls through to the next source.
/// </summary>
internal sealed class CngKeySource(CngProvider provider, string kind) : ISigningKeySource
{
    public static readonly CngKeySource Tpm = new(CngProvider.MicrosoftPlatformCryptoProvider, "tpm");
    public static readonly CngKeySource Software = new(CngProvider.MicrosoftSoftwareKeyStorageProvider, "software");

    public string Kind { get; } = kind;

    /// <summary>A key under this name that is exportable or not P-256 is refused loudly, never used.</summary>
    public CngKey? TryOpen(string keyName)
    {
        CngKey key;
        try
        {
            if (!CngKey.Exists(keyName, provider)) return null;
            key = CngKey.Open(keyName, provider);
        }
        catch (CryptographicException)
        {
            return null;
        }
        // The TPM provider reports a re-opened key as generic "ECDSA" with its size; BadgeSigner checks the curve.
        if (key.AlgorithmGroup == CngAlgorithmGroup.ECDsa && key.KeySize == 256 && key.ExportPolicy == CngExportPolicies.None) return key;
        key.Dispose();
        throw new CryptographicException($"existing {Kind} key '{keyName}' is not a non-exportable P-256 key");
    }

    public CngKey? TryCreate(string keyName)
    {
        try
        {
            return CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
            {
                Provider = provider,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Signing,
                KeyCreationOptions = CngKeyCreationOptions.None,
            });
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}

internal static class SigningKeySelector
{
    /// <summary>
    /// An existing key wins over creating one, in source order, so a vault that started on
    /// software keeps its key (and every badge stays valid) if a TPM appears later. Only
    /// when no source has a key is one created, again in order: TPM first.
    /// </summary>
    public static (CngKey Key, string Kind)? Select(IReadOnlyList<ISigningKeySource> sources, string keyName)
    {
        foreach (var source in sources)
            if (source.TryOpen(keyName) is { } key) return (key, source.Kind);
        foreach (var source in sources)
            if (source.TryCreate(keyName) is { } key) return (key, source.Kind);
        return null;
    }

    public static IReadOnlyList<ISigningKeySource> Sources(string preference) => preference switch
    {
        "software" => [CngKeySource.Software],
        _ => [CngKeySource.Tpm, CngKeySource.Software],
    };
}
