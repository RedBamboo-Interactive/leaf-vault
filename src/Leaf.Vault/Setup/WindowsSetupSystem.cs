using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Leaf.Vault.Client;
using Microsoft.Win32;

namespace Leaf.Vault.Setup;

/// <summary>The real machine. Every program it runs is a Windows binary from System32, with a whitelisted environment.</summary>
internal sealed class WindowsSetupSystem : ISetupSystem
{
    private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly TimeSpan ServiceTimeout = TimeSpan.FromSeconds(30);
    private const string EventSourceKey = @"SYSTEM\CurrentControlSet\Services\EventLog\Application\Leaf Vault";

    public bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public string SelfPath => Environment.ProcessPath ?? throw new SetupException(SetupExit.Unexpected, "cannot locate the running executable");

    public SecurityIdentifier? InteractiveUser()
    {
        var user = SessionString(WtsUserName);
        var domain = SessionString(WtsDomainName);
        if (string.IsNullOrEmpty(user)) return null;
        try { return (SecurityIdentifier)new NTAccount(domain ?? "", user).Translate(typeof(SecurityIdentifier)); }
        catch (IdentityNotMappedException) { return null; }
    }

    public void AssertAdminOnlyWritable(string path) => SetupAcl.AssertAdminOnlyWritable(path, ReadSecurity);

    internal static FileSystemSecurity ReadSecurity(string path) => Directory.Exists(path)
        ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
        : new FileInfo(path).GetAccessControl(AccessControlSections.Access);

    public InstalledService? QueryService()
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{VaultProtocol.ServiceName}");
        if (key?.GetValue("ImagePath") is not string imagePath) return null;
        using var controller = new ServiceController(VaultProtocol.ServiceName);
        try { return new InstalledService(imagePath, controller.Status != ServiceControllerStatus.Stopped); }
        catch (InvalidOperationException) { return null; }
    }

    public InstalledConfig? ReadConfig(string path) => File.Exists(path) ? Installer.ParseConfig(File.ReadAllText(path)) : null;

    public void StopService()
    {
        using var controller = new ServiceController(VaultProtocol.ServiceName);
        if (controller.Status == ServiceControllerStatus.Stopped) return;
        if (controller.Status != ServiceControllerStatus.StopPending) controller.Stop();
        controller.WaitForStatus(ServiceControllerStatus.Stopped, ServiceTimeout);
    }

    public void StartService()
    {
        using var controller = new ServiceController(VaultProtocol.ServiceName);
        if (controller.Status != ServiceControllerStatus.Running) controller.Start();
        controller.WaitForStatus(ServiceControllerStatus.Running, ServiceTimeout);
    }

    public bool DirectoryExists(string path) => Directory.Exists(path);
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public void MoveDirectory(string from, string to)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(to)!);
        Directory.Move(from, to);
    }
    public void DeleteDirectory(string path) => Directory.Delete(path, recursive: true);
    public void CopyFile(string from, string to) => File.Copy(from, to, overwrite: false);
    public void WriteFile(string path, string text) => File.WriteAllText(path, text, new UTF8Encoding(false));

    public void CreateService(string exe) => Sc("create", VaultProtocol.ServiceName, "binPath=", $"\"{exe}\"", "start=", "auto",
        "obj=", $@"NT SERVICE\{VaultProtocol.ServiceName}", "DisplayName=", "Leaf Vault");

    public void ConfigureService()
    {
        Sc("config", VaultProtocol.ServiceName, "obj=", $@"NT SERVICE\{VaultProtocol.ServiceName}", "start=", "auto");
        Sc("sidtype", VaultProtocol.ServiceName, "unrestricted");
        Sc("failure", VaultProtocol.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000");
        Sc("failureflag", VaultProtocol.ServiceName, "1");
        Sc("description", VaultProtocol.ServiceName,
            @"Holds every Leaf secret and never returns one. Control pipe \\.\pipe\leaf-vault; egress proxy on 127.0.0.1.");
    }

    public void GrantReadExecute(string directory, SecurityIdentifier sid)
    {
        var info = new DirectoryInfo(directory);
        var security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(security);
    }

    public void RegisterEventSource()
    {
        using var key = Registry.LocalMachine.CreateSubKey(EventSourceKey);
        if (key.GetValue("EventMessageFile") is null)
            key.SetValue("EventMessageFile", @"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll", RegistryValueKind.ExpandString);
    }

    // Created with this security descriptor in one call: there is no moment with inherited access.
    public void CreateLockedDirectory(string path, DirectorySecurity security) => new DirectoryInfo(path).Create(security);

    public DirectorySecurity ReadDirectorySecurity(string path) =>
        new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);

    public async Task<HealthResult?> WaitForHealthAsync(int port, TimeSpan timeout)
    {
        // No proxy: the per-user proxy setting belongs to the owner's normal session.
        using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(2) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var health = await http.GetFromJsonAsync<HealthResult>($"http://127.0.0.1:{port}/health", VaultProtocol.Json);
                if (health is not null) return health;
            }
            catch (Exception error) when (error is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException) { }
            await Task.Delay(TimeSpan.FromSeconds(1));
        }
        return null;
    }

    public void Log(string line)
    {
        Console.WriteLine(line);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(EventSourceKey);
            if (key is not null) EventLog.WriteEntry("Leaf Vault", line, EventLogEntryType.Information);
        }
        catch (Exception) { /* the console line is enough */ }
    }

    private static void Sc(params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(System32, "sc.exe"))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = System32,
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        start.Environment.Clear();
        start.Environment["SystemRoot"] = Windows;
        start.Environment["windir"] = Windows;
        start.Environment["PATH"] = System32;
        using var process = Process.Start(start) ?? throw new SetupException(SetupExit.Unexpected, "sc.exe did not start");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new SetupException(SetupExit.Unexpected, $"sc.exe {arguments[0]} failed (exit {process.ExitCode}): {output.Result.Trim()} {error.Trim()}");
    }

    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;

    private static string? SessionString(int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, -1, infoClass, out var buffer, out _)) return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
