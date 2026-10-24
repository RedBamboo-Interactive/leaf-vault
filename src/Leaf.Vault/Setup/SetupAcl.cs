using System.Security.AccessControl;
using System.Security.Principal;

namespace Leaf.Vault.Setup;

/// <summary>
/// The access rules the installer relies on, as pure checks over security descriptors so they
/// can be tested without elevation. The same rules as scripts/install.ps1.
/// </summary>
internal static class SetupAcl
{
    public static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    public static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    public static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);
    public static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>Every right that lets a holder change, replace, delete or re-permission a file or folder.</summary>
    private const FileSystemRights WriteMask =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.WriteAttributes | FileSystemRights.Delete
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership
        | (FileSystemRights)0x10000000 /* GENERIC_ALL */ | (FileSystemRights)0x40000000 /* GENERIC_WRITE */;

    /// <summary>
    /// The first account other than SYSTEM, Administrators, TrustedInstaller or CREATOR OWNER that
    /// may change this object, or null when only those can. Inherit-only entries do not apply to
    /// the object itself and are skipped.
    /// </summary>
    public static SecurityIdentifier? UntrustedWriter(FileSystemSecurity security)
    {
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid.Equals(System) || sid.Equals(Administrators) || sid.Equals(TrustedInstaller) || sid.Equals(CreatorOwner)) continue;
            if ((rule.FileSystemRights & WriteMask) != 0) return sid;
        }
        return null;
    }

    /// <summary>
    /// Anything run elevated must not be replaceable by the owner's normal session: the file and
    /// every folder above it, up to (not including) the drive root, must be writable by trusted
    /// accounts only. Throws <see cref="SetupException"/> naming the first offender.
    /// </summary>
    public static void AssertAdminOnlyWritable(string path, Func<string, FileSystemSecurity> read)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full);
        for (var current = full; !string.IsNullOrEmpty(current) && !string.Equals(current, root, StringComparison.OrdinalIgnoreCase);
             current = Path.GetDirectoryName(current))
        {
            if (UntrustedWriter(read(current)) is { } writer)
                throw new SetupException(SetupExit.UnsafeLocation,
                    $"{current} is writable by {writer.Value}; Leaf Vault setup only runs from a folder that administrators alone can change.");
        }
    }

    /// <summary>
    /// The data folder's only acceptable security: inheritance off, SYSTEM Full and the vault's
    /// service account Modify (both inherited by everything inside), owner Administrators.
    /// </summary>
    public static DirectorySecurity NewDataDirectorySecurity(SecurityIdentifier vaultSid)
    {
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(vaultSid, FileSystemRights.Modify, inherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// True when the data folder has exactly <see cref="NewDataDirectorySecurity"/>: no other
    /// entry, nothing inherited, owner Administrators.
    /// </summary>
    public static bool IsExactDataDirectorySecurity(DirectorySecurity security, SecurityIdentifier vaultSid)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !owner.Equals(Administrators)) return false;
        if (!security.AreAccessRulesProtected) return false;
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (rules.Length != 2) return false;
        foreach (var rule in rules)
        {
            var sid = (SecurityIdentifier)rule.IdentityReference;
            var expected = sid.Equals(System) ? FileSystemRights.FullControl
                : sid.Equals(vaultSid) ? FileSystemRights.Modify | FileSystemRights.Synchronize
                : (FileSystemRights?)null;
            if (expected is null || rule.AccessControlType != AccessControlType.Allow || rule.IsInherited) return false;
            if ((rule.FileSystemRights | FileSystemRights.Synchronize) != (expected.Value | FileSystemRights.Synchronize)) return false;
            if (rule.InheritanceFlags != (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)
                || rule.PropagationFlags != PropagationFlags.None) return false;
        }
        return true;
    }
}
