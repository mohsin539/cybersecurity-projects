using System.Buffers;
using System.Text;

namespace ProxyCore.Security;

/// <summary>
/// Central input validation for all externally supplied strings (hostnames, users, log injection).
/// OWASP A03 (Injection), A05 (Misconfiguration): reject early, clip log fields.
/// </summary>
public static class InputValidator
{
    public const int MaxHostLength = 253;
    public const int MaxUserLength = 64;
    public const int MaxLogFieldLength = 128;

    private static readonly SearchValues<char> HostExtraChars =
        SearchValues.Create("-._");

    public static bool IsValidHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > MaxHostLength) return false;
        // Reject control chars / whitespace / CRLF (log + header injection)
        foreach (var c in host)
        {
            if (c <= 0x20 || c == 0x7F) return false;
        }
        if (host.EndsWith(".")) host = host.TrimEnd('.');
        if (host.Length == 0) return false;
        // Allow IP literals and DNS names
        var labels = host.Split('.');
        foreach (var label in labels)
        {
            if (label.Length == 0 || label.Length > 63) return false;
            if (char.IsAsciiLetterOrDigit(label[0]) is false &&
                !HostExtraChars.Contains(label[0])) return false;
            foreach (var c in label)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || HostExtraChars.Contains(c))) return false;
            }
            if (label[^1] == '-' ) return false;
        }
        return true;
    }

    public static bool IsValidUsername(string user)
    {
        if (string.IsNullOrEmpty(user) || user.Length > MaxUserLength) return false;
        foreach (var c in user)
        {
            if (c < 0x21 || c > 0x7E) return false; // printable ASCII, no spaces/CRLF
        }
        return true;
    }

    /// <summary>Clip + sanitize a raw external string for safe inclusion in log lines (A03 log injection).</summary>
    public static string Safe(string? value, int max = MaxLogFieldLength)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sb = new StringBuilder(Math.Min(value.Length, max));
        foreach (var c in value)
        {
            if (c == '\r' || c == '\n' || c == '\t') sb.Append(' ');
            else if (c >= 0x20 && c != 0x7F) sb.Append(c);
            if (sb.Length >= max) break;
        }
        return sb.ToString();
    }
}
