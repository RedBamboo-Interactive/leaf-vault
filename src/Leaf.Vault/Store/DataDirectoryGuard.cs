using System.Security.AccessControl;
using System.Security.Principal;

namespace Leaf.Vault.Store;

/// <summary>
/// Refuses to run on a data directory anyone else can reach. The installer creates it locked
/// (LeafVault + SYSTEM, owner Administrators); this re-checks at every start, so a folder that
/// was pre-created, re-opened or loosened later stops the vault instead of feeding it.
/// </summary>
internal static class DataDirectoryGuard
{
    public static void Check(string dataDirectory, SecurityIdentifier self, SecurityIdentifier owner)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var allowedAccess = new HashSet<SecurityIdentifier> { self, system };
        var allowedOwners = new HashSet<SecurityIdentifier> { self, system, admins };

        CheckOne(new DirectoryInfo(dataDirectory).GetAccessControl(), dataDirectory, requireProtected: true);
        foreach (var entry in new DirectoryInfo(dataDirectory).EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
            CheckOne(entry is DirectoryInfo d ? d.GetAccessControl() : ((FileInfo)entry).GetAccessControl(), entry.FullName, requireProtected: false);

        void CheckOne(FileSystemSecurity security, string path, bool requireProtected)
        {
            if (requireProtected && !security.AreAccessRulesProtected)
                throw Refuse(path, "inherits permissions from its parent");
            if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier o || !allowedOwners.Contains(o) || o.Equals(owner))
                throw Refuse(path, "has an unexpected owner");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !allowedAccess.Contains((SecurityIdentifier)rule.IdentityReference))
                    throw Refuse(path, $"grants access to {rule.IdentityReference.Value}");
        }
    }

    private static InvalidOperationException Refuse(string path, string why)
        => new($"refusing to start: {path} {why}; it must be accessible to NT SERVICE\\LeafVault and SYSTEM only (re-run scripts/install.ps1)");
}
