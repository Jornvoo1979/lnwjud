using System.Security.Cryptography;
using System.Text;

namespace Lnwjud.WindowsHost;

internal static class NativeDigest
{
    internal static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
