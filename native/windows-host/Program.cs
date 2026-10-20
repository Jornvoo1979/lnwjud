using System.Text;
using System.Text.Json;

namespace Lnwjud.WindowsHost;

internal static class Program
{
    private const int MaxInputBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    private static int Main(string[] args)
    {
        if (args.Length != 0) return 64;
        HardenChildEnvironment();

        string? line;
        while ((line = Console.ReadLine()) is not null)
        {
            object response;
            string id = "unknown";
            try
            {
                if (Encoding.UTF8.GetByteCount(line) > MaxInputBytes)
                {
                    response = Failure(id, "FILE_TOO_LARGE", "Native host request exceeds the payload limit", true);
                }
                else
                {
                    using var document = JsonDocument.Parse(line);
                    response = Handle(document.RootElement, out id);
                }
            }
            catch
            {
                response = Failure(id, "INTERNAL_ERROR", "Windows native host request failed", true);
            }

            Console.WriteLine(JsonSerializer.Serialize(response, JsonOptions));
            Console.Out.Flush();
        }

        return 0;
    }

    private static object Handle(JsonElement envelope, out string id)
    {
        id = "unknown";
        if (envelope.ValueKind != JsonValueKind.Object) return Failure(id, "INVALID_INPUT", "Native host request must be one JSON object", false);
        foreach (var property in envelope.EnumerateObject())
        {
            if (property.Name is not ("id" or "operation" or "input" or "authorization"))
                return Failure(id, "INVALID_INPUT", "Native host request contains an unsupported field", false);
        }

        if (!envelope.TryGetProperty("id", out var idValue) || idValue.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(idValue.GetString()) || idValue.GetString()!.Length > 256)
            return Failure(id, "INVALID_INPUT", "Native host request id is invalid", false);
        id = idValue.GetString()!;

        if (!envelope.TryGetProperty("operation", out var operationValue) || operationValue.ValueKind != JsonValueKind.String)
            return Failure(id, "INVALID_INPUT", "Native host operation is invalid", false);
        var operation = operationValue.GetString() ?? string.Empty;
        if (!OperationName.IsMatch(operation)) return Failure(id, "INVALID_INPUT", "Native host operation is invalid", false);

        var input = envelope.TryGetProperty("input", out var value) ? value : default;
        return operation switch
        {
            "health" => Success(id, new
            {
                platform = "win32",
                backend = "windows-native-host",
                available = true,
                ready = true,
                deliveryState = "engineering_only",
                supportedInternalOperations = new[] { "worktree_anchor_probe", "restricted_token_probe" },
                worktreeMutationEnabled = false,
            }),
            "worktree_anchor_probe" => WorktreeAnchorProbe(id, input),
            "restricted_token_probe" => RestrictedTokenProbe(id, input),
            _ => Failure(id, "INVALID_INPUT", "Native host operation is not supported", false),
        };
    }

    private static object WorktreeAnchorProbe(string id, JsonElement input)
    {
        if (input.ValueKind != JsonValueKind.Object) return Failure(id, "INVALID_INPUT", "Worktree anchor input must be an object", false);
        if (!TryString(input, "workspaceRoot", out var workspaceRoot) || !TryString(input, "relativePath", out var relativePath))
            return Failure(id, "INVALID_INPUT", "Worktree anchor input is incomplete", false);
        if (!WorktreePathPolicy.IsAllowedRelativeDestination(relativePath))
            return Failure(id, "PATH_OUTSIDE_WORKSPACE", "Worktree destination is outside the managed worktree roots", false);

        using var anchor = DirectoryAnchor.OpenExisting(workspaceRoot, relativePath);
        var identity = anchor.Identity;
        return Success(id, new
        {
            state = "verified",
            identity = new
            {
                volumeSerial = identity.VolumeSerial,
                fileId128 = identity.FileId128,
                fileSystem = "NTFS",
                reparsePoint = false,
            },
            pathDigest = NativeDigest.Sha256(anchor.FinalPath),
        });
    }

    private static object RestrictedTokenProbe(string id, JsonElement input)
    {
        if (input.ValueKind != JsonValueKind.Object) return Failure(id, "INVALID_INPUT", "Restricted-token input must be an object", false);
        using var token = RestrictedPrimaryToken.Create();
        return Success(id, new
        {
            restricted = token.IsRestricted,
            primary = token.IsPrimary,
            launchEnabled = false,
        });
    }

    private static bool TryString(JsonElement input, string name, out string value)
    {
        value = string.Empty;
        if (!input.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
        value = property.GetString() ?? string.Empty;
        return value.Length is > 0 and <= 32767 && !value.Contains('\0');
    }

    private static object Success(string id, object value) => new { id, ok = true, value };

    private static object Failure(string id, string code, string message, bool recoverable) => new
    {
        id,
        ok = false,
        error = new { code, message, recoverable },
    };

    private static void HardenChildEnvironment()
    {
        foreach (var key in Environment.GetEnvironmentVariables().Keys.Cast<object>().Select(static value => Convert.ToString(value)).Where(static value => value is not null))
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(key!, "(api[_-]?key|token|password|secret)", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                Environment.SetEnvironmentVariable(key, null);
        }
        Environment.SetEnvironmentVariable("GIT_CONFIG_NOSYSTEM", "1");
        Environment.SetEnvironmentVariable("GIT_CONFIG_GLOBAL", "NUL");
        Environment.SetEnvironmentVariable("GIT_TERMINAL_PROMPT", "0");
        Environment.SetEnvironmentVariable("GCM_INTERACTIVE", "never");
        Environment.SetEnvironmentVariable("GIT_LFS_SKIP_SMUDGE", "1");
        Environment.SetEnvironmentVariable("GIT_OPTIONAL_LOCKS", "0");
    }

    private static readonly System.Text.RegularExpressions.Regex OperationName =
        new("^[A-Za-z][A-Za-z0-9_.-]{0,63}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
}
