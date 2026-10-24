using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Leaf.Vault.Pipe;

/// <summary>
/// CreateNamedPipeW with PIPE_REJECT_REMOTE_CLIENTS. .NET's NamedPipeServerStream does not set
/// that flag (verified: a \\127.0.0.1\pipe\ client over SMB connected), so the vault creates
/// its pipe instances itself and wraps the handle.
/// </summary>
internal static class NativePipe
{
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeRejectRemoteClients = 0x00000008; // byte type, byte read mode, blocking
    private const int ErrorAccessDenied = 5;
    private const int ErrorPipeBusy = 231;

    public static NamedPipeServerStream Create(string pipeName, PipeSecurity security, bool firstInstance, int maxInstances, int bufferSize)
    {
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = pinned.AddrOfPinnedObject(),
            };
            var handle = CreateNamedPipe(@"\\.\pipe\" + pipeName,
                PipeAccessDuplex | FileFlagOverlapped | (firstInstance ? FileFlagFirstPipeInstance : 0),
                PipeRejectRemoteClients, (uint)maxInstances, (uint)bufferSize, (uint)bufferSize, 0, ref attributes);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw error switch
                {
                    ErrorAccessDenied => new UnauthorizedAccessException($"cannot create \\\\.\\pipe\\{pipeName}"),
                    ErrorPipeBusy => new IOException("all pipe instances are busy"),
                    _ => new Win32Exception(error),
                };
            }
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        finally
        {
            pinned.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances,
        uint outBufferSize, uint inBufferSize, uint defaultTimeout, ref SecurityAttributes attributes);
}
