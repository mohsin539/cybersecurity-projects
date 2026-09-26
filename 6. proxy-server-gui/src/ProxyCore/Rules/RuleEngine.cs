using System.Text.Json.Serialization;

namespace ProxyCore.Rules;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RuleAction
{
    Allow = 0,
    Deny = 1,
    Route = 2
}

/// <summary>Match criteria. Null/empty fields are ignored; first-match-wins ordering.</summary>
public sealed class RuleMatch
{
    [JsonPropertyName("host")] public string? Host { get; set; }          // wildcard: *.example.com
    [JsonPropertyName("ip")] public string? Ip { get; set; }              // CIDR or single IP
    [JsonPropertyName("port")] public int? Port { get; set; }
    [JsonPropertyName("protocol")] public string? Protocol { get; set; }  // http|https|socks
    [JsonPropertyName("user")] public string? User { get; set; }

    public static RuleMatch Any => new();
}

public sealed class RuleDefinition
{
    [JsonPropertyName("id")] public int Id { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("action")] public RuleAction Action { get; set; } = RuleAction.Allow;
    [JsonPropertyName("route")] public string? Route { get; set; }       // upstream name when Action=Route
    [JsonPropertyName("match")] public RuleMatch Match { get; set; } = new();
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
}

public sealed record RuleDecision(RuleAction Action, RuleDefinition? Rule, string? RouteTo)
{
    public static RuleDecision AllowDefault { get; } = new(RuleAction.Allow, null, null);
    public static RuleDecision DenyDefault { get; } = new(RuleAction.Deny, null, null);
}

/// <summary>
/// Ordered first-match-wins rule engine. Matching is O(rules) with early exit;
/// intended scale (hundreds of rules) makes compiled tries unnecessary — kept simple, audit-friendly.
/// </summary>
public sealed class RuleEngine
{
    private volatile RuleDefinition[] _rules = Array.Empty<RuleDefinition>();
    public string DefaultAction { get; set; } = "allow"; // or "deny" (deny-by-default posture)

    public RuleEngine() { }
    public RuleEngine(IEnumerable<RuleDefinition> rules) => Replace(rules);

    public void Replace(IEnumerable<RuleDefinition> rules)
    {
        _rules = rules.Where(r => r.Enabled).ToArray();
    }

    public IReadOnlyList<RuleDefinition> Current => _rules;

    public RuleDecision Evaluate(RuleContext ctx)
    {
        foreach (var rule in _rules)
        {
            if (Matches(rule.Match, ctx))
            {
                return rule.Action switch
                {
                    RuleAction.Deny => new RuleDecision(RuleAction.Deny, rule, null),
                    RuleAction.Route => new RuleDecision(RuleAction.Route, rule, rule.Route),
                    _ => new RuleDecision(RuleAction.Allow, rule, null)
                };
            }
        }
        return string.Equals(DefaultAction, "deny", StringComparison.OrdinalIgnoreCase)
            ? RuleDecision.DenyDefault
            : RuleDecision.AllowDefault;
    }

    private static bool Matches(RuleMatch m, RuleContext ctx)
    {
        if (m.Port is int p && p != ctx.Port) return false;
        if (!string.IsNullOrEmpty(m.Protocol) &&
            !string.Equals(m.Protocol, ctx.Protocol, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(m.User) &&
            !string.Equals(m.User, ctx.User, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(m.Host) && !WildcardMatches(m.Host, ctx.Host)) return false;
        if (!string.IsNullOrEmpty(m.Ip) && ctx.TargetIp is { } ip && !CidrMatches(m.Ip, ip)) return false;
        return true;
    }

    public static bool WildcardMatches(string pattern, string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        if (pattern == "*" || pattern == "*.*") return pattern == "*" || host.Contains('.');
        if (pattern.StartsWith("*."))
        {
            var suffix = pattern[1..]; // ".example.com"
            return host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(host, pattern[2..], StringComparison.OrdinalIgnoreCase);
        }
        if (pattern.EndsWith("*"))
        {
            return host.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase);
        }
        return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
    }

    public static bool CidrMatches(string cidr, System.Net.IPAddress ip)
    {
        var parts = cidr.Split('/');
        if (!System.Net.IPAddress.TryParse(parts[0], out var base_)) return false;
        if (base_.AddressFamily != ip.AddressFamily) return false;
        var baseBytes = base_.GetAddressBytes();
        var ipBytes = ip.GetAddressBytes();
        var prefix = parts.Length == 2 ? int.Parse(parts[1]) : baseBytes.Length * 8;
        for (int i = 0; i < baseBytes.Length; i++)
        {
            if (prefix <= 0) break;
            var bits = Math.Min(8, prefix);
            var mask = bits == 8 ? (byte)0xFF : (byte)(0xFF << (8 - bits));
            if ((baseBytes[i] & mask) != (ipBytes[i] & mask)) return false;
            prefix -= bits;
        }
        return true;
    }
}

public sealed record RuleContext(
    string Host,
    int Port,
    string Protocol,
    string? User,
    System.Net.IPAddress? TargetIp,
    System.Net.IPAddress ClientIp);
