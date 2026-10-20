using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.WindowsHost;

internal sealed class RestrictedPrimaryToken : IDisposable
{
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint DisableMaxPrivilege = 0x1;
    private const int TokenTypeInformationClass = 8;
    private const int TokenPrimary = 1;

    private RestrictedPrimaryToken(SafeAccessTokenHandle handle, bool restricted, bool primary)
    {
        Handle = handle;
        IsRestricted = restricted;
        IsPrimary = primary;
    }

    internal SafeAccessTokenHandle Handle { get; }
    internal bool IsRestricted { get; }
    internal bool IsPrimary { get; }

    internal static RestrictedPrimaryToken Create()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAssignPrimary | TokenDuplicate | TokenQuery, out var source))
            throw new IOException("WINDOWS_TOKEN_OPEN_FAILED");
        using (source)
        {
            if (!CreateRestrictedToken(source, DisableMaxPrivilege, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out var restricted))
                throw new IOException("WINDOWS_TOKEN_RESTRICTION_FAILED");
            var size = sizeof(int);
            if (!GetTokenInformation(restricted, TokenTypeInformationClass, out var tokenType, size, out _))
            {
                restricted.Dispose();
                throw new IOException("WINDOWS_TOKEN_TYPE_UNAVAILABLE");
            }
            var primary = tokenType == TokenPrimary;
            if (!primary || !HasOnlyChangeNotifyPrivilegeEnabled(restricted))
            {
                restricted.Dispose();
                throw new IOException("WINDOWS_TOKEN_RESTRICTION_UNVERIFIED");
            }
            return new RestrictedPrimaryToken(restricted, true, true);
        }
    }

    private static bool HasOnlyChangeNotifyPrivilegeEnabled(SafeAccessTokenHandle token)
    {
        if (!LookupPrivilegeValueW(null, "SeChangeNotifyPrivilege", out var changeNotify))
            throw new IOException("WINDOWS_TOKEN_PRIVILEGE_IDENTITY_UNAVAILABLE");

        _ = GetTokenInformationBuffer(token, TokenPrivilegesInformationClass, IntPtr.Zero, 0, out var required);
        if (required <= 0) throw new IOException("WINDOWS_TOKEN_PRIVILEGES_UNAVAILABLE");

        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            if (!GetTokenInformationBuffer(token, TokenPrivilegesInformationClass, buffer, required, out _))
                throw new IOException("WINDOWS_TOKEN_PRIVILEGES_UNAVAILABLE");

            var count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > 1024) throw new IOException("WINDOWS_TOKEN_PRIVILEGES_INVALID");
            var entrySize = Marshal.SizeOf<LuidAndAttributes>();
            var offset = sizeof(uint);
            for (var index = 0; index < count; index++)
            {
                var entry = Marshal.PtrToStructure<LuidAndAttributes>(IntPtr.Add(buffer, offset + index * entrySize));
                if ((entry.Attributes & SePrivilegeEnabled) == 0) continue;
                if (entry.Luid.LowPart != changeNotify.LowPart || entry.Luid.HighPart != changeNotify.HighPart)
                    return false;
            }
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose() => Handle.Dispose();

    private const int TokenPrivilegesInformationClass = 3;
    private const uint SePrivilegeEnabled = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle existingTokenHandle, uint flags,
        uint disableSidCount, IntPtr sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete,
        uint restrictedSidCount, IntPtr sidsToRestrict, out SafeAccessTokenHandle newTokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass,
        out int tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformationBuffer(SafeAccessTokenHandle tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, int tokenInformationLength, out int returnLength);
}
