using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Leaf.Vault.Client;

namespace Leaf.Vault.Pipe;

/// <summary>
/// The control pipe. Its DACL allows the configured owner and SYSTEM to read and write, the
/// vault's own account to create instances, and denies NETWORK outright; remote clients are
/// also rejected at the pipe level (PIPE_REJECT_REMOTE_CLIENTS, see <see cref="NativePipe"/>). The first instance is created with FIRST_PIPE_INSTANCE,
/// so if another process squatted the name the vault fails instead of joining its pipe
/// (and <see cref="VaultClient"/> refuses any pipe not owned by the service SID).
/// </summary>
internal sealed class PipeServer(VaultOptions options, VaultOperations operations, ILogger<PipeServer> log) : BackgroundService
{
    public const int MaxInstances = 16;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(30);
    private int _alive;

    internal static PipeSecurity CreateSecurity(SecurityIdentifier owner)
    {
        var self = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("no process user SID");
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(self);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return security;
    }

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        var security = CreateSecurity(options.Owner());
        var listening = await CreateInstanceAsync(security, stop);
        log.LogInformation("control pipe listening on \\\\.\\pipe\\{Pipe}", options.PipeName);
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await listening.WaitForConnectionAsync(stop);
            }
            catch (OperationCanceledException)
            {
                Release(listening);
                break;
            }
            catch (IOException)
            {
                // The client vanished between connect and accept. Create the replacement before
                // releasing this one, so the pipe never drops to zero instances.
                var replacement = await CreateInstanceAsync(security, stop);
                Release(listening);
                listening = replacement;
                continue;
            }
            var connected = listening;
            // The next instance exists before this one is served, so the pipe never has zero
            // instances while the vault runs.
            listening = await CreateInstanceAsync(security, stop);
            _ = Task.Run(() => ServeAsync(connected, stop), CancellationToken.None);
        }
    }

    private async Task<NamedPipeServerStream> CreateInstanceAsync(PipeSecurity security, CancellationToken stop)
    {
        while (true)
        {
            // FIRST_PIPE_INSTANCE whenever none of ours exists: never join a pipe someone else created.
            var first = Volatile.Read(ref _alive) == 0;
            try
            {
                var pipe = NativePipe.Create(options.PipeName, security, first, MaxInstances, VaultProtocol.MaxFrameBytes);
                Interlocked.Increment(ref _alive);
                return pipe;
            }
            catch (UnauthorizedAccessException) when (first)
            {
                throw new InvalidOperationException($"\\\\.\\pipe\\{options.PipeName} already exists and is not the vault's; refusing to start");
            }
            catch (IOException) when (!first)
            {
                await Task.Delay(100, stop); // all instances busy
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(stop);
                idle.CancelAfter(IdleTimeout);
                var frame = await VaultProtocol.ReadFrameAsync(pipe, idle.Token);
                if (frame is null) break;
                var response = await operations.HandleAsync(frame);
                await VaultProtocol.WriteFrameAsync(pipe, response, idle.Token);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or VaultException)
        {
            // Idle, disconnected or a malformed frame: drop the connection.
        }
        catch (Exception e)
        {
            log.LogError("control pipe connection failed with {Type}", e.GetType().Name);
        }
        finally
        {
            Release(pipe);
        }
    }

    private void Release(NamedPipeServerStream pipe)
    {
        pipe.Dispose();
        Interlocked.Decrement(ref _alive);
    }
}
