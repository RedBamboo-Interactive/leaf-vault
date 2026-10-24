using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Leaf.Vault.Client;
using Leaf.Vault.Setup;
using Xunit;

namespace Leaf.Vault.Tests;

/// <summary>The installer's decisions, against a fake machine: nothing here needs elevation.</summary>
public sealed class SetupTests
{
    private static readonly SecurityIdentifier Owner = new("S-1-5-21-1000000001-1000000002-1000000003-1001");
    private static readonly SecurityIdentifier OtherUser = new("S-1-5-21-1000000001-1000000002-1000000003-1002");
    private static readonly SetupPaths Paths = new(@"C:\Program Files\Leaf Vault", @"C:\ProgramData\Leaf Vault", @"C:\Program Files\Leaf Vault Setup");
    private const string Staged = @"C:\Program Files\Leaf Vault Setup\0123\Leaf.Vault.exe";

    private static SetupArguments Args(int? port = null) => new(Owner, port);

    [Fact]
    public async Task Fresh_install_creates_everything_in_order_with_the_data_folder_locked_from_the_start()
    {
        var machine = new FakeMachine();
        var health = await new Installer(machine, Paths).RunAsync(Args());

        Assert.Equal(VaultHealth.Version, health.Version);
        Assert.Equal(
        [
            "assert-admin-only " + Staged, "create-dir " + Paths.InstallDirectory, $"copy {Staged} -> {Paths.Exe}",
            "write " + Paths.Config, "create-service " + Paths.Exe, "configure-service",
            $"grant-rx {Paths.InstallDirectory} {Installer.VaultSid.Value}", "register-event-source",
            "create-locked " + Paths.DataDirectory, "start", "health 18810",
        ], machine.Actions);
        Assert.True(SetupAcl.IsExactDataDirectorySecurity(machine.Directories[Paths.DataDirectory]!, Installer.VaultSid));
        var config = JsonNode.Parse(machine.Files[Paths.Config])!["Vault"]!;
        Assert.Equal(Owner.Value, config["OwnerSid"]!.GetValue<string>());
        Assert.Equal(18810, config["ProxyPort"]!.GetValue<int>());
        Assert.Equal(Paths.DataDirectory, config["DataDirectory"]!.GetValue<string>());
    }

    [Fact]
    public async Task Update_keeps_owner_port_and_data_and_removes_the_previous_copy_after_health()
    {
        var machine = FakeMachine.Installed(port: 18999);
        await new Installer(machine, Paths).RunAsync(Args(port: 18810));

        Assert.DoesNotContain(machine.Actions, a => a.StartsWith("create-service", StringComparison.Ordinal) || a.StartsWith("create-locked", StringComparison.Ordinal));
        Assert.Equal("stop", machine.Actions[1]);
        Assert.Contains(machine.Actions, a => a.StartsWith($"move {Paths.InstallDirectory} -> {Paths.StagingRoot}\\previous-", StringComparison.Ordinal));
        Assert.Contains(machine.Actions, a => a.StartsWith($"delete {Paths.StagingRoot}\\previous-", StringComparison.Ordinal));
        Assert.Contains("health 18999", machine.Actions);
        Assert.Equal(18999, JsonNode.Parse(machine.Files[Paths.Config])!["Vault"]!["ProxyPort"]!.GetValue<int>());
        Assert.Equal(machine.OriginalData, machine.Directories[Paths.DataDirectory]);
    }

    [Fact]
    public async Task Update_that_does_not_answer_health_puts_the_previous_version_back()
    {
        var machine = FakeMachine.Installed();
        machine.HealthAnswers = false;
        var error = await Assert.ThrowsAsync<SetupException>(() => new Installer(machine, Paths).RunAsync(Args()));

        Assert.Equal(SetupExit.StartFailedRolledBack, error.Code);
        var tail = machine.Actions.SkipWhile(a => a != "health 18810").Skip(1).ToArray();
        Assert.Equal("stop", tail[0]);
        Assert.Equal("delete " + Paths.InstallDirectory, tail[1]);
        Assert.StartsWith($"move {Paths.StagingRoot}\\previous-", tail[2], StringComparison.Ordinal);
        Assert.EndsWith("-> " + Paths.InstallDirectory, tail[2], StringComparison.Ordinal);
        Assert.Equal("start", tail[3]);
        Assert.True(machine.Directories.ContainsKey(Paths.InstallDirectory));
    }

    [Fact]
    public async Task Update_whose_rollback_also_fails_says_the_vault_is_not_running()
    {
        var machine = FakeMachine.Installed();
        machine.HealthAnswers = false;
        machine.FailStartAfter = 1;
        var error = await Assert.ThrowsAsync<SetupException>(() => new Installer(machine, Paths).RunAsync(Args()));
        Assert.Equal(SetupExit.StartFailed, error.Code);
        Assert.Contains("could not be restored", error.Message);
    }

    [Fact]
    public async Task A_vault_that_answers_with_another_version_is_not_accepted()
    {
        var machine = FakeMachine.Installed();
        machine.HealthVersion = "0.0.1+old";
        var error = await Assert.ThrowsAsync<SetupException>(() => new Installer(machine, Paths).RunAsync(Args()));
        Assert.Equal(SetupExit.StartFailedRolledBack, error.Code);
        Assert.Contains("0.0.1+old", error.Message);
    }

    [Fact]
    public async Task Failed_fresh_install_stops_the_service_and_reports_start_failed()
    {
        var machine = new FakeMachine { HealthAnswers = false };
        var error = await Assert.ThrowsAsync<SetupException>(() => new Installer(machine, Paths).RunAsync(Args()));
        Assert.Equal(SetupExit.StartFailed, error.Code);
        Assert.Equal("stop", machine.Actions[^1]);
    }

    [Fact]
    public async Task Not_elevated_changes_nothing()
    {
        var machine = new FakeMachine { Elevated = false };
        await AssertRefused(machine, SetupExit.NotElevated);
        Assert.Empty(machine.Actions);
    }

    [Fact]
    public async Task Running_from_a_folder_the_user_can_change_is_refused()
    {
        var machine = new FakeMachine { UnsafeSelf = true };
        await AssertRefused(machine, SetupExit.UnsafeLocation);
        Assert.Equal(["assert-admin-only " + Staged], machine.Actions);
    }

    [Fact]
    public async Task Running_from_the_installed_copy_is_refused()
    {
        var machine = new FakeMachine { Self = Paths.Exe };
        await AssertRefused(machine, SetupExit.InvalidArguments);
    }

    [Fact]
    public async Task Owner_must_be_the_account_signed_in_to_this_session()
    {
        await AssertRefused(new FakeMachine { Interactive = OtherUser }, SetupExit.OwnerNotInteractiveUser);
        await AssertRefused(new FakeMachine { Interactive = null }, SetupExit.OwnerNotInteractiveUser);
    }

    [Fact]
    public async Task Update_for_another_account_is_refused_without_touching_the_install()
    {
        var machine = FakeMachine.Installed(owner: OtherUser.Value);
        await AssertRefused(machine, SetupExit.OwnerMismatch);
        Assert.DoesNotContain("stop", machine.Actions);
    }

    [Fact]
    public async Task A_LeafVault_service_with_another_program_is_refused()
    {
        var machine = FakeMachine.Installed();
        machine.Service = new InstalledService(@"""C:\Users\someone\evil.exe""", true);
        await AssertRefused(machine, SetupExit.ServiceConflict);
    }

    [Fact]
    public async Task A_data_folder_that_exists_with_other_permissions_is_refused()
    {
        var loose = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
        loose.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        var machine = new FakeMachine();
        machine.Directories[Paths.DataDirectory] = loose;
        await AssertRefused(machine, SetupExit.DataDirectoryRefused);
        Assert.DoesNotContain(machine.Actions, a => a.StartsWith("create", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Reinstall_after_an_uninstall_that_kept_the_data_reuses_the_locked_folder()
    {
        var machine = new FakeMachine();
        var kept = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
        machine.Directories[Paths.DataDirectory] = kept;
        await new Installer(machine, Paths).RunAsync(Args());
        Assert.DoesNotContain(machine.Actions, a => a.StartsWith("create-locked", StringComparison.Ordinal));
        Assert.Same(kept, machine.Directories[Paths.DataDirectory]);
    }

    private static async Task AssertRefused(FakeMachine machine, SetupExit code)
    {
        var error = await Assert.ThrowsAsync<SetupException>(() => new Installer(machine, Paths).RunAsync(Args()));
        Assert.Equal(code, error.Code);
    }

    [Theory]
    [InlineData(new[] { "setup", "install", "--owner-sid", "S-1-5-21-1-2-3-1001" }, 18810)]
    [InlineData(new[] { "setup", "install", "--port", "18999", "--owner-sid", "S-1-12-1-1-2-3-4" }, 18999)]
    public void Arguments_parse(string[] args, int port)
    {
        var parsed = SetupArguments.Parse(args);
        Assert.Equal(port, parsed.PortOrDefault);
        Assert.True(SetupArguments.IsSetup(args));
    }

    [Theory]
    [InlineData("")]
    [InlineData("setup")]
    [InlineData("setup uninstall --owner-sid S-1-5-21-1-2-3-1001")]
    [InlineData("setup install")]
    [InlineData("setup install --owner-sid")]
    [InlineData("setup install --owner-sid S-1-1-0")]
    [InlineData("setup install --owner-sid S-1-5-32-545")]
    [InlineData("setup install --owner-sid not-a-sid")]
    [InlineData("setup install --owner-sid S-1-5-21-1-2-3-1001 --owner-sid S-1-5-21-1-2-3-1002")]
    [InlineData("setup install --owner-sid S-1-5-21-1-2-3-1001 --port 80")]
    [InlineData("setup install --owner-sid S-1-5-21-1-2-3-1001 --port +18810")]
    [InlineData(@"setup install --owner-sid S-1-5-21-1-2-3-1001 --data C:\x")]
    public void Arguments_outside_the_contract_are_refused(string commandLine)
    {
        var args = commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var error = Assert.Throws<SetupException>(() => SetupArguments.Parse(args));
        Assert.Equal(SetupExit.InvalidArguments, error.Code);
    }

    [Fact]
    public void The_service_itself_never_takes_the_setup_path()
    {
        Assert.False(SetupArguments.IsSetup([]));
        Assert.False(SetupArguments.IsSetup(["--urls", "http://0.0.0.0:1"]));
    }

    [Fact]
    public void Exit_codes_are_a_stable_contract()
    {
        // RedLeaf maps these numbers to messages; changing one breaks every installed RedLeaf.
        Assert.Equal(
            [(0, "Installed"), (1, "Unexpected"), (10, "NotElevated"), (11, "InvalidArguments"), (12, "UnsafeLocation"),
             (13, "OwnerNotInteractiveUser"), (14, "OwnerMismatch"), (15, "ServiceConflict"), (16, "DataDirectoryRefused"),
             (17, "StartFailedRolledBack"), (18, "StartFailed"), (20, "BootstrapHashMismatch"), (21, "BootstrapStagingFailed")],
            Enum.GetValues<SetupExit>().Select(v => ((int)v, v.ToString())));
    }

    [Fact]
    public void Config_round_trips_and_garbage_is_ignored()
    {
        var parsed = Installer.ParseConfig(Installer.ConfigJson(Owner, 18811, Paths.DataDirectory));
        Assert.Equal(new InstalledConfig(Owner.Value, 18811), parsed);
        Assert.Null(Installer.ParseConfig("not json"));
        Assert.Null(Installer.ParseConfig("{}"));
        Assert.Equal(new InstalledConfig(null, null), Installer.ParseConfig("""{"Vault":{"ProxyPort":80}}"""));
    }

    // --- ACL rules ---------------------------------------------------------------------------

    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    [Fact]
    public void New_data_folder_security_is_exactly_vault_and_system()
    {
        var security = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
        Assert.True(SetupAcl.IsExactDataDirectorySecurity(security, Installer.VaultSid));
        Assert.False(SetupAcl.IsExactDataDirectorySecurity(security, OtherUser));
    }

    [Fact]
    public void Data_folder_security_with_anything_else_is_not_exact()
    {
        var extra = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
        extra.AddAccessRule(new FileSystemAccessRule(Owner, FileSystemRights.ReadData, AccessControlType.Allow));
        Assert.False(SetupAcl.IsExactDataDirectorySecurity(extra, Installer.VaultSid));

        var inherits = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
        inherits.SetAccessRuleProtection(false, false);
        Assert.False(SetupAcl.IsExactDataDirectorySecurity(inherits, Installer.VaultSid));

        var owned = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
        owned.SetOwner(Owner);
        Assert.False(SetupAcl.IsExactDataDirectorySecurity(owned, Installer.VaultSid));

        var weaker = new DirectorySecurity();
        weaker.SetAccessRuleProtection(true, false);
        weaker.SetOwner(SetupAcl.Administrators);
        const InheritanceFlags both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        weaker.AddAccessRule(new FileSystemAccessRule(SetupAcl.System, FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
        weaker.AddAccessRule(new FileSystemAccessRule(Installer.VaultSid, FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
        Assert.False(SetupAcl.IsExactDataDirectorySecurity(weaker, Installer.VaultSid));
    }

    [Fact]
    public void Untrusted_writer_is_any_other_account_that_can_change_the_object()
    {
        var readOnly = new FileSecurity();
        readOnly.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        readOnly.AddAccessRule(new FileSystemAccessRule(SetupAcl.Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        readOnly.AddAccessRule(new FileSystemAccessRule(SetupAcl.TrustedInstaller, FileSystemRights.FullControl, AccessControlType.Allow));
        readOnly.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.Write, AccessControlType.Deny));
        Assert.Null(SetupAcl.UntrustedWriter(readOnly));

        foreach (var right in new[] { FileSystemRights.WriteData, FileSystemRights.AppendData, FileSystemRights.Delete,
                     FileSystemRights.ChangePermissions, FileSystemRights.TakeOwnership, FileSystemRights.Modify })
        {
            var writable = new FileSecurity();
            writable.AddAccessRule(new FileSystemAccessRule(Users, right, AccessControlType.Allow));
            Assert.Equal(Users, SetupAcl.UntrustedWriter(writable));
        }

        // Program Files' own "Users may create folders, inherit-only" entry does not apply to the folder itself.
        var inheritOnly = new DirectorySecurity();
        inheritOnly.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
        Assert.Null(SetupAcl.UntrustedWriter(inheritOnly));
    }

    [Fact]
    public void Admin_only_check_walks_every_folder_up_to_the_drive_root()
    {
        var read = new List<string>();
        var userWritable = new DirectorySecurity();
        userWritable.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify, AccessControlType.Allow));
        FileSystemSecurity Read(string path)
        {
            read.Add(path);
            return path == @"C:\Tools" ? userWritable : new DirectorySecurity();
        }

        SetupAcl.AssertAdminOnlyWritable(@"C:\Program Files\Leaf Vault Setup\x\Leaf.Vault.exe", Read);
        Assert.Equal([@"C:\Program Files\Leaf Vault Setup\x\Leaf.Vault.exe", @"C:\Program Files\Leaf Vault Setup\x",
            @"C:\Program Files\Leaf Vault Setup", @"C:\Program Files"], read);

        var error = Assert.Throws<SetupException>(() => SetupAcl.AssertAdminOnlyWritable(@"C:\Tools\sub\Leaf.Vault.exe", Read));
        Assert.Equal(SetupExit.UnsafeLocation, error.Code);
        Assert.Contains(@"C:\Tools", error.Message);
    }

    [Fact]
    public void Admin_only_check_on_this_machine_accepts_System32_and_refuses_a_user_temp_folder()
    {
        var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe");
        SetupAcl.AssertAdminOnlyWritable(system32, WindowsSetupSystem.ReadSecurity);

        var dir = Fake.TempDirectory();
        var file = Path.Combine(dir, "Leaf.Vault.exe");
        File.WriteAllText(file, "not a program");
        try
        {
            var error = Assert.Throws<SetupException>(() => SetupAcl.AssertAdminOnlyWritable(file, WindowsSetupSystem.ReadSecurity));
            Assert.Equal(SetupExit.UnsafeLocation, error.Code);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    /// <summary>A machine as a list of actions plus the directories and files setup would leave behind.</summary>
    private sealed class FakeMachine : ISetupSystem
    {
        public List<string> Actions { get; } = [];
        public Dictionary<string, DirectorySecurity?> Directories { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool Elevated { get; init; } = true;
        public bool UnsafeSelf { get; init; }
        public string Self { get; init; } = Staged;
        public SecurityIdentifier? Interactive { get; init; } = Owner;
        public InstalledService? Service { get; set; }
        public bool HealthAnswers { get; set; } = true;
        public string HealthVersion { get; set; } = VaultHealth.Version;
        public int? FailStartAfter { get; set; }
        public DirectorySecurity? OriginalData { get; private set; }
        private int _starts;

        public static FakeMachine Installed(string? owner = null, int port = 18810)
        {
            var machine = new FakeMachine { Service = new InstalledService($"\"{Paths.Exe}\"", true) };
            machine.Directories[Paths.InstallDirectory] = null;
            machine.Files[Paths.Config] = Installer.ConfigJson(new SecurityIdentifier(owner ?? Owner.Value), port, Paths.DataDirectory);
            machine.OriginalData = SetupAcl.NewDataDirectorySecurity(Installer.VaultSid);
            machine.Directories[Paths.DataDirectory] = machine.OriginalData;
            return machine;
        }

        public bool IsElevated => Elevated;
        public string SelfPath => Self;
        public SecurityIdentifier? InteractiveUser() => Interactive;

        public void AssertAdminOnlyWritable(string path)
        {
            Actions.Add("assert-admin-only " + path);
            if (UnsafeSelf) throw new SetupException(SetupExit.UnsafeLocation, path + " is writable");
        }

        public InstalledService? QueryService() => Service;
        public InstalledConfig? ReadConfig(string path) => Files.TryGetValue(path, out var json) ? Installer.ParseConfig(json) : null;
        public void StopService() { Actions.Add("stop"); Service = Service! with { Running = false }; }

        public void StartService()
        {
            Actions.Add("start");
            if (FailStartAfter is { } limit && _starts++ >= limit) throw new InvalidOperationException("service did not start");
            Service = (Service ?? new InstalledService($"\"{Paths.Exe}\"", false)) with { Running = true };
        }

        public bool DirectoryExists(string path) => Directories.ContainsKey(path);
        public void CreateDirectory(string path) { Actions.Add("create-dir " + path); Directories[path] = null; }

        public void MoveDirectory(string from, string to)
        {
            Actions.Add($"move {from} -> {to}");
            Directories[to] = Directories[from];
            Directories.Remove(from);
        }

        public void DeleteDirectory(string path) { Actions.Add("delete " + path); Directories.Remove(path); }
        public void CopyFile(string from, string to) => Actions.Add($"copy {from} -> {to}");
        public void WriteFile(string path, string text) { Actions.Add("write " + path); Files[path] = text; }
        public void CreateService(string exe) => Actions.Add("create-service " + exe);
        public void ConfigureService() => Actions.Add("configure-service");
        public void GrantReadExecute(string directory, SecurityIdentifier sid) => Actions.Add($"grant-rx {directory} {sid.Value}");
        public void RegisterEventSource() => Actions.Add("register-event-source");

        public void CreateLockedDirectory(string path, DirectorySecurity security)
        {
            Actions.Add("create-locked " + path);
            Directories[path] = security;
        }

        public DirectorySecurity ReadDirectorySecurity(string path) => Directories[path]!;

        public Task<HealthResult?> WaitForHealthAsync(int port, TimeSpan timeout)
        {
            Actions.Add($"health {port}");
            return Task.FromResult(HealthAnswers ? new HealthResult("up", true, "software", true, HealthVersion, VaultProtocol.Version) : null);
        }

        public void Log(string line) { }
    }
}
