using System.Security.Cryptography;

namespace Leaf.Vault.Store;

/// <summary>
/// The 256-bit vault key that encrypts every secret, stored wrapped with DPAPI in
/// CurrentUser scope. In the service, "current user" is NT SERVICE\LeafVault, so only a
/// process running as that account (or SYSTEM/an administrator going out of their way) can
/// unwrap it. LocalMachine scope is deliberately not used: any process on the machine,
/// including the owner's medium-integrity user, may unprotect a LocalMachine blob it can
/// read, which would leave the data-folder ACL as the only barrier. A copied data folder is
/// useless on another machine or under another account.
/// </summary>
internal static class MasterKey
{
    public const string FileName = "master.key";
    private static readonly byte[] Entropy = "leaf-vault/master-key/v1"u8.ToArray();

    public static byte[] LoadOrCreate(string dataDirectory)
    {
        var path = Path.Combine(dataDirectory, FileName);
        AtomicFile.RemoveStale(dataDirectory, FileName);
        if (!File.Exists(path))
        {
            var fresh = RandomNumberGenerator.GetBytes(32);
            var wrapped = ProtectedData.Protect(fresh, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                AtomicFile.Write(path, wrapped, overwrite: false);
                return fresh;
            }
            catch (IOException) when (File.Exists(path))
            {
                CryptographicOperations.ZeroMemory(fresh);
            }
        }
        var key = ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.CurrentUser);
        if (key.Length != 32) throw new CryptographicException("master key has the wrong length");
        return key;
    }
}
