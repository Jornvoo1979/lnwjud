namespace Lnwjud.WindowsHost;

internal static class WorktreePathPolicy
{
    internal static bool IsAllowedRelativeDestination(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 32767 || value.Contains('\0') || Path.IsPathRooted(value)) return false;
        var segments = value.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2) return false;
        if (segments.Any(static segment => !IsSafeComponent(segment))) return false;

        if (segments[0].Equals(".worktrees", StringComparison.OrdinalIgnoreCase)) return segments.Length >= 2;
        return segments.Length >= 3
            && segments[0].Equals(".lnwjud", StringComparison.OrdinalIgnoreCase)
            && segments[1].Equals("worktrees", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsSafeComponent(string name)
    {
        if (string.IsNullOrEmpty(name) || name is "." or ".." || name.EndsWith('.') || name.EndsWith(' ')) return false;
        if (name.IndexOfAny(new[] { ':', '\\', '/', '\0', '<', '>', '"', '|', '?', '*' }) >= 0) return false;
        if (name.Any(static value => value < 32)) return false;
        var stem = name.Split('.')[0].ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" or "CLOCK$") return false;
        if (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal))
            && "123456789¹²³".Contains(stem[3])) return false;
        return true;
    }
}
