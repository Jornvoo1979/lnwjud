using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.WindowsHost;

internal sealed class ContainedProcess : IDisposable
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint StillActive = 259;
    private IntPtr _job;
    private IntPtr _process;
    private bool _disposed;

    private ContainedProcess() { }

    internal uint ProcessId { get; private set; }
    internal ulong CreationTime { get; private set; }
    internal string JobIdentity { get; private set; } = string.Empty;

    internal static ContainedProcess StartRestricted(string executable, IReadOnlyList<string> arguments, string cwd, SafeAccessTokenHandle token)
    {
        if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd))
            throw new IOException("WINDOWS_CONTAINMENT_ABSOLUTE_PATH_REQUIRED");
        if (arguments.Any(static value => value.Contains('\0'))) throw new IOException("WINDOWS_CONTAINMENT_INVALID_ARGUMENT");

        var instance = new ContainedProcess();
        ProcessInformation child = default;
        try
        {
            instance._job = CreateJobObjectW(IntPtr.Zero, null);
            if (instance._job == IntPtr.Zero) throw new IOException("WINDOWS_CONTAINMENT_JOB_UNAVAILABLE");

            var limits = new JobObjectExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(instance._job, 9, ref limits, (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
                throw new IOException("WINDOWS_CONTAINMENT_LIMITS_UNAVAILABLE");

            var command = new StringBuilder(Quote(executable));
            foreach (var argument in arguments) command.Append(' ').Append(Quote(argument));
            var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>() };
            if (!CreateProcessAsUserW(token, executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    CreateSuspended | CreateNoWindow, IntPtr.Zero, cwd, ref startup, out child))
                throw new IOException("WINDOWS_CONTAINMENT_CREATE_RESTRICTED_FAILED");

            instance._process = child.hProcess;
            instance.ProcessId = child.dwProcessId;
            if (!GetProcessTimes(child.hProcess, out var creation, out _, out _, out _))
                throw new IOException("WINDOWS_CONTAINMENT_PROCESS_IDENTITY_UNAVAILABLE");
            instance.CreationTime = ((ulong)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
            instance.JobIdentity = Guid.NewGuid().ToString("N");

            if (!AssignProcessToJobObject(instance._job, child.hProcess))
                throw new IOException("WINDOWS_CONTAINMENT_ASSIGN_FAILED");
            if (ResumeThread(child.hThread) == uint.MaxValue)
                throw new IOException("WINDOWS_CONTAINMENT_RESUME_FAILED");

            CloseHandle(child.hThread);
            child.hThread = IntPtr.Zero;
            return instance;
        }
        catch
        {
            if (child.hProcess != IntPtr.Zero)
            {
                TerminateProcess(child.hProcess, 1);
                WaitForSingleObject(child.hProcess, 10_000);
            }
            if (child.hThread != IntPtr.Zero) CloseHandle(child.hThread);
            instance.Dispose();
            throw;
        }
    }

    internal int WaitForVerifiedExit(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (ActiveProcesses != 0)
        {
            if (DateTime.UtcNow >= deadline) throw new TimeoutException("WINDOWS_CONTAINMENT_TIMEOUT");
            Thread.Sleep(10);
        }
        if (!GetExitCodeProcess(_process, out var code) || code == StillActive)
            throw new IOException("WINDOWS_CONTAINMENT_EXIT_UNVERIFIED");
        return unchecked((int)code);
    }

    internal uint ActiveProcesses
    {
        get
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ContainedProcess));
            if (!QueryInformationJobObject(_job, 1, out BasicAccountingInformation information,
                    (uint)Marshal.SizeOf<BasicAccountingInformation>(), IntPtr.Zero))
                throw new IOException("WINDOWS_CONTAINMENT_JOB_UNVERIFIED");
            return information.ActiveProcesses;
        }
    }

    internal void Cancel()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ContainedProcess));
        if (!TerminateJobObject(_job, 1)) throw new IOException("WINDOWS_CONTAINMENT_CANCEL_UNVERIFIED");
        _ = WaitForVerifiedExit(TimeSpan.FromSeconds(10));
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (_job != IntPtr.Zero) CloseHandle(_job);
        if (_process != IntPtr.Zero) CloseHandle(_process);
        _job = IntPtr.Zero;
        _process = IntPtr.Zero;
        _disposed = true;
    }

    private static string Quote(string value)
    {
        if (value.Contains('\0')) throw new IOException("WINDOWS_CONTAINMENT_INVALID_ARGUMENT");
        var result = new StringBuilder("\"");
        var slashes = 0;
        foreach (var character in value)
        {
            if (character == '\\') { slashes++; continue; }
            if (character == '"')
            {
                result.Append('\\', slashes * 2 + 1).Append(character);
                slashes = 0;
                continue;
            }
            result.Append('\\', slashes).Append(character);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr securityAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JobObjectExtendedLimitInformation information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out BasicAccountingInformation information, uint length, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUserW(SafeAccessTokenHandle token, string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment,
        string currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out FileTime creationTime, out FileTime exitTime, out FileTime kernelTime, out FileTime userTime);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
