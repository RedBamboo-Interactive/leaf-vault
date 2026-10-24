using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Leaf.Vault.Client;

namespace Leaf.Vault.Setup;

/// <summary>Where the vault lives. Known folders from the system, never from environment variables.</summary>
public sealed record SetupPaths(string InstallDirectory, string DataDirectory, string StagingRoot)
{
    public const string ExeName = "Leaf.Vault.exe";
    public const string ConfigName = "leaf-vault.json";

    public string Exe => Path.Combine(InstallDirectory, ExeName);
    public string Config => Path.Combine(InstallDirectory, ConfigName);

    public static SetupPaths ForThisMachine()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return new(Path.Combine(programFiles, "Leaf Vault"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Leaf Vault"),
            Path.Combine(programFiles, "Leaf Vault Setup"));
    }
}

public sealed record InstalledService(string ImagePath, bool Running);

/// <summary>The existing leaf-vault.json, as far as setup cares.</summary>
public sealed record InstalledConfig(string? OwnerSid, int? ProxyPort);

/// <summary>Everything setup does to the machine, so the install and update logic can be tested without elevation.</summary>
public interface ISetupSystem
{
    bool IsElevated { get; }
    string SelfPath { get; }
    SecurityIdentifier? InteractiveUser();
    void AssertAdminOnlyWritable(string path);
    InstalledService? QueryService();
    InstalledConfig? ReadConfig(string path);
    void StopService();
    void StartService();
    bool DirectoryExists(string path);
    void CreateDirectory(string path);
    void MoveDirectory(string from, string to);
    void DeleteDirectory(string path);
    void CopyFile(string from, string to);
    void WriteFile(string path, string text);
    void CreateService(string exe);
    void ConfigureService();
    void GrantReadExecute(string directory, SecurityIdentifier sid);
    void RegisterEventSource();
    void CreateLockedDirectory(string path, DirectorySecurity security);
    DirectorySecurity ReadDirectorySecurity(string path);
    Task<HealthResult?> WaitForHealthAsync(int port, TimeSpan timeout);
    void Log(string line);
}

/// <summary>
/// Installs or updates Leaf Vault from the running executable, which must already sit in a
/// folder only administrators can change (RedLeaf's elevated bootstrap stages it there after
/// checking its SHA-256 against the signed release record). The same steps as scripts/install.ps1,
/// minus the build: program files, leaf-vault.json, the NT SERVICE\LeafVault service, the data
/// folder created already locked, start, and /health. An update keeps the owner, the port and
/// every secret, and puts the previous version back if the new one does not come up.
/// </summary>
public sealed class Installer(ISetupSystem system, SetupPaths paths)
{
    public static readonly SecurityIdentifier VaultSid = VaultProtocol.ServiceSid(VaultProtocol.ServiceName);
    public static readonly TimeSpan HealthTimeout = TimeSpan.FromSeconds(30);

    public async Task<HealthResult> RunAsync(SetupArguments args)
    {
        if (!system.IsElevated)
            throw new SetupException(SetupExit.NotElevated, "Leaf Vault setup needs administrator approval.");
        system.AssertAdminOnlyWritable(system.SelfPath);
        if (IsInside(system.SelfPath, paths.InstallDirectory))
            throw new SetupException(SetupExit.InvalidArguments, "Setup cannot run from the installed copy; run the downloaded release.");

        // The pipe belongs to whoever uses Leaf on this desktop, never to another account.
        if (system.InteractiveUser() is not { } interactive || !interactive.Equals(args.Owner))
            throw new SetupException(SetupExit.OwnerNotInteractiveUser,
                $"{args.Owner.Value} is not the account signed in to this Windows session.");

        var service = system.QueryService();
        if (service is not null && !string.Equals(service.ImagePath.Trim(), $"\"{paths.Exe}\"", StringComparison.OrdinalIgnoreCase))
            throw new SetupException(SetupExit.ServiceConflict,
                $"A {VaultProtocol.ServiceName} service already exists with another program ({service.ImagePath}).");
        var existing = service is not null ? system.ReadConfig(paths.Config) : null;
        if (existing?.OwnerSid is { } installedOwner && !string.Equals(installedOwner, args.Owner.Value, StringComparison.OrdinalIgnoreCase))
            throw new SetupException(SetupExit.OwnerMismatch,
                $"This Leaf Vault belongs to another Windows account ({installedOwner}).");
        var port = existing?.ProxyPort ?? args.PortOrDefault;

        // A folder that exists already is reused only if it is exactly what an installer creates:
        // nothing but an administrator could have made it so (owner Administrators, no other entry).
        if (system.DirectoryExists(paths.DataDirectory)
            && !SetupAcl.IsExactDataDirectorySecurity(system.ReadDirectorySecurity(paths.DataDirectory), VaultSid))
            throw new SetupException(SetupExit.DataDirectoryRefused,
                $"{paths.DataDirectory} exists and is not locked to Leaf Vault and SYSTEM; inspect it before installing.");

        system.Log($"Installing Leaf Vault {VaultHealth.Version} for {args.Owner.Value} on port {port}"
                   + (service is null ? " (new install)" : " (update, keeping the data)"));
        if (service is { Running: true }) system.StopService();

        string? backup = null;
        try
        {
            if (system.DirectoryExists(paths.InstallDirectory))
            {
                backup = Path.Combine(paths.StagingRoot, "previous-" + Guid.NewGuid().ToString("N"));
                system.MoveDirectory(paths.InstallDirectory, backup);
            }
            // Created under Program Files, so it inherits administrators-only write.
            system.CreateDirectory(paths.InstallDirectory);
            system.CopyFile(system.SelfPath, paths.Exe);
            system.WriteFile(paths.Config, ConfigJson(args.Owner, port, paths.DataDirectory));
            if (service is null) system.CreateService(paths.Exe);
            system.ConfigureService();
            system.GrantReadExecute(paths.InstallDirectory, VaultSid);
            system.RegisterEventSource();

            if (!system.DirectoryExists(paths.DataDirectory))
                system.CreateLockedDirectory(paths.DataDirectory, SetupAcl.NewDataDirectorySecurity(VaultSid));
            if (!SetupAcl.IsExactDataDirectorySecurity(system.ReadDirectorySecurity(paths.DataDirectory), VaultSid))
                throw new SetupException(SetupExit.DataDirectoryRefused,
                    $"{paths.DataDirectory} is not locked to Leaf Vault and SYSTEM; refusing to start the service.");

            system.StartService();
            var health = await system.WaitForHealthAsync(port, HealthTimeout);
            if (health is null)
                throw new SetupException(SetupExit.StartFailed, $"Leaf Vault started but http://127.0.0.1:{port}/health did not answer.");
            if (!string.Equals(health.Version, VaultHealth.Version, StringComparison.Ordinal))
                throw new SetupException(SetupExit.StartFailed, $"Leaf Vault answered as {health.Version}, not {VaultHealth.Version}.");

            if (backup is not null) TryDelete(backup);
            system.Log($"Installed Leaf Vault {health.Version}: store readable {health.StoreReadable}, badge signing {health.SigningProvider}.");
            return health;
        }
        catch (Exception error)
        {
            system.Log($"Setup failed: {error.Message}");
            if (backup is null)
            {
                TryStop();
                throw error as SetupException ?? new SetupException(SetupExit.StartFailed, error.Message, error);
            }
            if (Restore(backup))
                throw new SetupException(SetupExit.StartFailedRolledBack,
                    $"The new Leaf Vault did not come up ({error.Message}); the previous version is back.", error);
            throw new SetupException(SetupExit.StartFailed,
                $"The new Leaf Vault did not come up ({error.Message}) and the previous version could not be restored.", error);
        }
    }

    private bool Restore(string backup)
    {
        try
        {
            TryStop();
            if (system.DirectoryExists(paths.InstallDirectory)) system.DeleteDirectory(paths.InstallDirectory);
            system.MoveDirectory(backup, paths.InstallDirectory);
            system.StartService();
            system.Log("Restored the previous Leaf Vault.");
            return true;
        }
        catch (Exception error)
        {
            system.Log($"Could not restore the previous Leaf Vault: {error.Message}");
            return false;
        }
    }

    private void TryStop()
    {
        try { if (system.QueryService() is { Running: true }) system.StopService(); }
        catch (Exception error) { system.Log($"Could not stop the service: {error.Message}"); }
    }

    private void TryDelete(string directory)
    {
        try { system.DeleteDirectory(directory); }
        catch (Exception error) { system.Log($"Could not remove {directory}: {error.Message}"); }
    }

    internal static string ConfigJson(SecurityIdentifier owner, int port, string dataDirectory) =>
        new JsonObject
        {
            ["Vault"] = new JsonObject
            {
                ["OwnerSid"] = owner.Value,
                ["ProxyPort"] = port,
                ["DataDirectory"] = dataDirectory,
            },
        }.ToJsonString(new JsonSerializerOptions { WriteIndented = true });

    internal static InstalledConfig? ParseConfig(string json)
    {
        try
        {
            if (JsonNode.Parse(json)?["Vault"] is not JsonObject vault) return null;
            var owner = vault["OwnerSid"] is JsonValue o && o.TryGetValue<string>(out var sid) ? sid : null;
            var port = vault["ProxyPort"] is JsonValue p && p.TryGetValue<int>(out var number) && number is >= 1024 and <= 65535 ? number : (int?)null;
            return new InstalledConfig(owner, port);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool IsInside(string file, string directory)
    {
        var dir = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(file).StartsWith(dir, StringComparison.OrdinalIgnoreCase);
    }
}
