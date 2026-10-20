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
            var isRestricted = IsTokenRestricted(restricted);
            var size = sizeof(int);
            if (!GetTokenInformation(restricted, TokenTypeInformationClass, out var tokenType, size, out _))
            {
                restricted.Dispose();
                throw new IOException("WINDOWS_TOKEN_TYPE_UNAVAILABLE");
            }
            var primary = tokenType == TokenPrimary;
            if (!isRestricted || !primary)
            {
                restricted.Dispose();
                throw new IOException("WINDOWS_TOKEN_RESTRICTION_UNVERIFIED");
            }
            return new RestrictedPrimaryToken(restricted, true, true);
        }
    }

    public void Dispose() => Handle.Dispose();

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

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsTokenRestricted(SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass,
        out int tokenInformation, int tokenInformationLength, out int returnLength);
}
