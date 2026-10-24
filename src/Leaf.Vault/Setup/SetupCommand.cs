namespace Leaf.Vault.Setup;

/// <summary><c>Leaf.Vault.exe setup install …</c>: the elevated install entrypoint. Returns a <see cref="SetupExit"/> code.</summary>
public static class SetupCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        var system = new WindowsSetupSystem();
        try
        {
            var parsed = SetupArguments.Parse(args);
            await new Installer(system, SetupPaths.ForThisMachine()).RunAsync(parsed);
            return (int)SetupExit.Installed;
        }
        catch (SetupException error)
        {
            system.Log($"Leaf Vault setup stopped ({(int)error.Code} {error.Code}): {error.Message}");
            return (int)error.Code;
        }
        catch (Exception error)
        {
            system.Log($"Leaf Vault setup failed unexpectedly: {error.Message}");
            return (int)SetupExit.Unexpected;
        }
    }
}
