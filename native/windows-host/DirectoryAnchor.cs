using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.WindowsHost;

internal sealed class DirectoryAnchor : IDisposable
{
    private const uint FileReadAttributes = 0x80;
    private const uint Synchronize = 0x00100000;
    private const uint ShareReadWrite = 0x3;
    private const uint OpenExistingDisposition = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint ObjectCaseInsensitiveNoReparse = 0x1040;
    private const uint DirectoryAttribute = 0x10;
    private const uint ReparseAttribute = 0x400;
    private const uint FileOpen = 1;
    private const uint FileCreate = 2;
    private const uint DirectorySynchronousOpenReparsePoint = 0x00200021;

    private readonly List<SafeFileHandle> _ancestors = new();
    private readonly ulong _volumeSerial;
    private SafeFileHandle? _destination;

    private DirectoryAnchor(string workspaceRoot, string relativePath, bool createDestination)
    {
        var absoluteWorkspace = Path.GetFullPath(workspaceRoot);
        if (!Path.IsPathFullyQualified(absoluteWorkspace) || absoluteWorkspace.StartsWith(@"\\", StringComparison.Ordinal))
            throw new IOException("WINDOWS_ANCHOR_INVALID_WORKSPACE");
        var root = Path.GetPathRoot(absoluteWorkspace);
        if (root is null || root.Length != 3 || root[1] != ':' || GetDriveTypeW(root) != 3)
            throw new IOException("WINDOWS_ANCHOR_UNSUPPORTED_VOLUME");

        var relativeSegments = relativePath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (relativeSegments.Length == 0 || relativeSegments.Any(static segment => !WorktreePathPolicy.IsSafeComponent(segment)))
            throw new IOException("WINDOWS_ANCHOR_INVALID_DESTINATION");

        try
        {
            var drive = CreateFileW(root, FileReadAttributes | Synchronize, ShareReadWrite, IntPtr.Zero, OpenExistingDisposition,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (drive.IsInvalid) throw new IOException("WINDOWS_ANCHOR_ROOT_UNAVAILABLE", new Win32Exception(Marshal.GetLastWin32Error()));
            _ancestors.Add(drive);
            EnsureDirectory(drive);
            _volumeSerial = RequireNtfs(drive);

            SafeFileHandle parent = drive;
            var workspaceSegments = absoluteWorkspace[root.Length..]
                .Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var segment in workspaceSegments)
            {
                parent = OpenRelative(parent, segment, false);
                _ancestors.Add(parent);
                EnsureDirectory(parent);
                RequireSameVolume(parent);
            }

            if (!PathsEqual(FinalPath(parent), absoluteWorkspace))
                throw new IOException("WINDOWS_ANCHOR_WORKSPACE_IDENTITY_CHANGED");

            for (var index = 0; index < relativeSegments.Length - 1; index++)
            {
                parent = OpenRelative(parent, relativeSegments[index], false);
                _ancestors.Add(parent);
                EnsureDirectory(parent);
                RequireSameVolume(parent);
            }

            _destination = OpenRelative(parent, relativeSegments[^1], createDestination);
            EnsureDirectory(_destination);
            RequireSameVolume(_destination);
            Identity = ReadIdentity(_destination);
            FinalPath = FinalPathOf(_destination);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal NativeFileIdentity Identity { get; }
    internal string FinalPath { get; }

    internal static DirectoryAnchor OpenExisting(string workspaceRoot, string relativePath) =>
        new(workspaceRoot, relativePath, false);

    internal static DirectoryAnchor CreateNew(string workspaceRoot, string relativePath)
    {
        if (!WorktreePathPolicy.IsAllowedRelativeDestination(relativePath))
            throw new IOException("WINDOWS_ANCHOR_DESTINATION_OUTSIDE_WORKTREE_ROOT");
        return new DirectoryAnchor(workspaceRoot, relativePath, true);
    }

    internal NativeFileIdentity ReopenAndVerify()
    {
        if (_destination is null || _destination.IsInvalid || _destination.IsClosed)
            throw new ObjectDisposedException(nameof(DirectoryAnchor));
        var current = ReadIdentity(_destination);
        if (current != Identity) throw new IOException("WINDOWS_ANCHOR_IDENTITY_CHANGED");
        if (!PathsEqual(FinalPathOf(_destination), FinalPath)) throw new IOException("WINDOWS_ANCHOR_PATH_CHANGED");
        return current;
    }

    private void RequireSameVolume(SafeFileHandle handle)
    {
        if (RequireNtfs(handle) != _volumeSerial) throw new IOException("WINDOWS_ANCHOR_VOLUME_CHANGED");
    }

    private static SafeFileHandle OpenRelative(SafeFileHandle root, string name, bool create)
    {
        if (!WorktreePathPolicy.IsSafeComponent(name)) throw new IOException("WINDOWS_ANCHOR_INVALID_NAME");
        var chars = Marshal.StringToHGlobalUni(name);
        var unicode = new UnicodeString
        {
            Length = checked((ushort)(name.Length * 2)),
            MaximumLength = checked((ushort)(name.Length * 2 + 2)),
            Buffer = chars,
        };
        var unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            Marshal.StructureToPtr(unicode, unicodePointer, false);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = root.DangerousGetHandle(),
                ObjectName = unicodePointer,
                Attributes = ObjectCaseInsensitiveNoReparse,
            };
            var status = NtCreateFile(out var handle, FileReadAttributes | Synchronize, ref attributes, out _, IntPtr.Zero,
                DirectoryAttribute, ShareReadWrite, create ? FileCreate : FileOpen,
                DirectorySynchronousOpenReparsePoint, IntPtr.Zero, 0);
            if (status != 0)
            {
                handle?.Dispose();
                throw new IOException($"WINDOWS_ANCHOR_OPEN_REFUSED_{status:X8}");
            }
            return handle;
        }
        finally
        {
            Marshal.FreeHGlobal(unicodePointer);
            Marshal.FreeHGlobal(chars);
        }
    }

    private static void EnsureDirectory(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, 9, out AttributeTag information, (uint)Marshal.SizeOf<AttributeTag>())
            || (information.FileAttributes & DirectoryAttribute) == 0
            || (information.FileAttributes & ReparseAttribute) != 0)
            throw new IOException("WINDOWS_ANCHOR_REPARSE_OR_INVALID_DIRECTORY");
    }

    private static ulong RequireNtfs(SafeFileHandle handle)
    {
        var volumeName = new StringBuilder(261);
        var fileSystem = new StringBuilder(261);
        if (!GetVolumeInformationByHandleW(handle, volumeName, (uint)volumeName.Capacity, out var serial, out _, out _, fileSystem, (uint)fileSystem.Capacity)
            || !fileSystem.ToString().Equals("NTFS", StringComparison.Ordinal))
            throw new IOException("WINDOWS_ANCHOR_UNSUPPORTED_FILESYSTEM");
        return serial;
    }

    private static NativeFileIdentity ReadIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, 18, out FileIdInfo information, (uint)Marshal.SizeOf<FileIdInfo>()))
            throw new IOException("WINDOWS_ANCHOR_IDENTITY_UNAVAILABLE");
        return new NativeFileIdentity(information.VolumeSerialNumber.ToString("X16"),
            Convert.ToHexString(information.FileId ?? Array.Empty<byte>()));
    }

    private static string FinalPathOf(SafeFileHandle handle)
    {
        var value = new StringBuilder(32768);
        var length = GetFinalPathNameByHandleW(handle, value, (uint)value.Capacity, 0);
        if (length == 0 || length >= value.Capacity) throw new IOException("WINDOWS_ANCHOR_FINAL_PATH_UNAVAILABLE");
        var result = value.ToString();
        if (!result.StartsWith(@"\\?\", StringComparison.Ordinal)) throw new IOException("WINDOWS_ANCHOR_UNSUPPORTED_FINAL_PATH");
        return result[4..];
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(left), Path.TrimEndingDirectorySeparator(right), StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        _destination?.Dispose();
        _destination = null;
        for (var index = _ancestors.Count - 1; index >= 0; index--) _ancestors[index].Dispose();
        _ancestors.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTag
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[]? FileId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string rootPathName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, StringBuilder volumeName, uint volumeNameSize,
        out uint volumeSerialNumber, out uint maximumComponentLength, out uint fileSystemFlags, StringBuilder fileSystemName, uint fileSystemNameSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass, out AttributeTag information, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass, out FileIdInfo information, uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder filePath, uint filePathSize, uint flags);

    [DllImport("ntdll.dll")]
    private static extern uint NtCreateFile(out SafeFileHandle file, uint desiredAccess, ref ObjectAttributes objectAttributes,
        out IoStatusBlock ioStatusBlock, IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);
}

internal readonly record struct NativeFileIdentity(string VolumeSerial, string FileId128);
