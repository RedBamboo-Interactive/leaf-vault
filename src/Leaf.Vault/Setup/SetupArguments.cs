using System.Security.Principal;
using Leaf.Vault.Client;

namespace Leaf.Vault.Setup;

/// <summary>
/// <c>Leaf.Vault.exe setup install --owner-sid S-1-5-21-… [--port 18810]</c>. Anything else is
/// refused: the elevated command line is the whole input, so it stays small and strict.
/// </summary>
public sealed record SetupArguments(SecurityIdentifier Owner, int? Port)
{
    public static bool IsSetup(string[] args) => args.Length > 0 && args[0] == "setup";

    public static SetupArguments Parse(string[] args)
    {
        if (args.Length < 2 || args[0] != "setup" || args[1] != "install")
            throw Invalid("usage: Leaf.Vault.exe setup install --owner-sid <user SID> [--port <1024-65535>]");
        SecurityIdentifier? owner = null;
        int? port = null;
        for (var i = 2; i < args.Length; i += 2)
        {
            if (i + 1 >= args.Length) throw Invalid($"{args[i]} needs a value");
            var value = args[i + 1];
            switch (args[i])
            {
                case "--owner-sid" when owner is null:
                    try { owner = new SecurityIdentifier(value); }
                    catch (ArgumentException) { throw Invalid($"{value} is not a SID"); }
                    if (!VaultOptions.IsUserSid(owner)) throw Invalid($"{value} is not a user account SID");
                    break;
                case "--port" when port is null:
                    if (!int.TryParse(value, System.Globalization.NumberStyles.None, null, out var p) || p is < 1024 or > 65535)
                        throw Invalid($"{value} is not a port between 1024 and 65535");
                    port = p;
                    break;
                default:
                    throw Invalid($"unexpected argument {args[i]}");
            }
        }
        return new SetupArguments(owner ?? throw Invalid("--owner-sid is required"), port);
    }

    public int PortOrDefault => Port ?? VaultProtocol.DefaultProxyPort;

    private static SetupException Invalid(string message) => new(SetupExit.InvalidArguments, message);
}
