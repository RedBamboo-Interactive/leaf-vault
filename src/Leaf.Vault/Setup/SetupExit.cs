namespace Leaf.Vault.Setup;

/// <summary>
/// Exit codes of <c>Leaf.Vault.exe setup install</c>. They are a contract: RedLeaf turns each one
/// into a plain-language message, so a code never changes meaning. 20 and 21 belong to the
/// elevated bootstrap that stages the artifact before this program runs.
/// </summary>
public enum SetupExit
{
    Installed = 0,
    Unexpected = 1,
    NotElevated = 10,
    InvalidArguments = 11,
    UnsafeLocation = 12,
    OwnerNotInteractiveUser = 13,
    OwnerMismatch = 14,
    ServiceConflict = 15,
    DataDirectoryRefused = 16,
    StartFailedRolledBack = 17,
    StartFailed = 18,
    BootstrapHashMismatch = 20,
    BootstrapStagingFailed = 21,
}

public sealed class SetupException(SetupExit code, string message, Exception? inner = null) : Exception(message, inner)
{
    public SetupExit Code { get; } = code;
}
