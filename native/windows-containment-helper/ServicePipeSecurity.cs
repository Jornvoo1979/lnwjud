using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.Containment;

/// <summary>
/// Creates local-only service pipes with a protected DACL. Clients can exchange
/// data, but only LocalSystem and administrators can create pipe instances.
/// </summary>
internal static class ServicePipeSecurity
{
    private const uint SddlRevision = 1;
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint PipeTypeByte = 0x00000000;
    private const uint PipeReadModeByte = 0x00000000;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private const int MaximumInstances = 16;
    private const int BufferBytes = 64 * 1024;
    private const string PipeSecurityDescriptor = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal nint SecurityDescriptor;
        internal int InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out nint securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateNamedPipeW")]
    private static extern nint CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maximumInstances,
        uint outputBufferSize,
        uint inputBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint LocalFree(nint memory);

    internal static NamedPipeServerStream CreateServer(string pipeName, bool firstInstance)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("SERVICE_PIPE_WINDOWS_REQUIRED");
        if (pipeName.Length is < 1 or > 80 || pipeName.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-')))
            throw new IOException("SERVICE_PIPE_NAME_INVALID");

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(PipeSecurityDescriptor, SddlRevision, out var descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SERVICE_PIPE_SECURITY_DESCRIPTOR_FAILED");
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = 0,
            };
            var openMode = PipeAccessDuplex | FileFlagOverlapped | (firstInstance ? FileFlagFirstPipeInstance : 0);
            var pipeMode = PipeTypeByte | PipeReadModeByte | PipeWait | PipeRejectRemoteClients;
            var handle = CreateNamedPipe(@"\\.\pipe\" + pipeName, openMode, pipeMode, MaximumInstances, BufferBytes, BufferBytes, 0, ref attributes);
            if (handle == 0 || handle == new nint(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SERVICE_PIPE_CREATE_FAILED");

            var safeHandle = new SafePipeHandle(handle, ownsHandle: true);
            try { return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, safeHandle); }
            catch { safeHandle.Dispose(); throw; }
        }
        finally { _ = LocalFree(descriptor); }
    }
}
