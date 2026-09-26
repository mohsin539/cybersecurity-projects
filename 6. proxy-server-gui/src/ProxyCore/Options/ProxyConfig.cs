using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyCore.Rules;

namespace ProxyCore.Options;

/// <summary>Root configuration model (schema-versioned). See ARCHITECTURE.md section 7.</summary>
public sealed class ProxyConfig
{
    [JsonPropertyName("schemaVersion")] public int SchemaVersion { get; set; } = 1;

    [JsonPropertyName("listeners")] public ListenersOptions Listeners { get; set; } = new();

    [JsonPropertyName("upstreams")] public List<UpstreamOptions> Upstreams { get; set; } = new();

    [JsonPropertyName("routing")] public RoutingOptions Routing { get; set; } = new();

    [JsonPropertyName("rules")] public List<RuleDefinition> Rules { get; set; } = new();

    [JsonPropertyName("limits")] public LimitsOptions Limits { get; set; } = new();

    [JsonPropertyName("security")] public SecurityOptions Security { get; set; } = new();

    [JsonPropertyName("logging")] public LoggingOptions Logging { get; set; } = new();

    public static ProxyConfig Default => new()
    {
        Rules = new List<RuleDefinition>
        {
            new() { Id = 1, Action = RuleAction.Allow, Match = RuleMatch.Any }
        },
        Security = new SecurityOptions
        {
            Clients = new ClientAllowlistOptions()
        }
    };
}

public sealed class ListenersOptions
{
    [JsonPropertyName("http")] public HttpListenerOptions Http { get; set; } = new();
    [JsonPropertyName("socks5")] public Socks5ListenerOptions Socks5 { get; set; } = new();
}

public sealed class HttpListenerOptions
{
    /// <summary>Bind address. Default loopback-only (SC-7 / CM-7 control).</summary>
    [JsonPropertyName("bind")] public string Bind { get; set; } = "127.0.0.1";
    [JsonPropertyName("port")] public int Port { get; set; } = 8080;
    [JsonPropertyName("authMode")] public AuthMode AuthMode { get; set; } = AuthMode.None;
}

public sealed class Socks5ListenerOptions
{
    [JsonPropertyName("bind")] public string Bind { get; set; } = "127.0.0.1";
    [JsonPropertyName("port")] public int Port { get; set; } = 1080;
    [JsonPropertyName("authMode")] public AuthMode AuthMode { get; set; } = AuthMode.None;
}

public sealed class UpstreamOptions
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("type")] public UpstreamType Type { get; set; } = UpstreamType.Direct;
    [JsonPropertyName("host")] public string? Host { get; set; }
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("healthCheck")] public bool HealthCheck { get; set; } = true;
}

public sealed class RoutingOptions
{
    [JsonPropertyName("default")] public string Default { get; set; } = "direct";
    [JsonPropertyName("failover")] public List<string> Failover { get; set; } = new();
}

public sealed class LimitsOptions
{
    [JsonPropertyName("maxConnections")] public int MaxConnections { get; set; } = 2000;
    /// <summary>Max concurrent sessions per client IP (brute/DoS containment, OWASP A04/A05).</summary>
    [JsonPropertyName("maxConnectionsPerClient")] public int MaxConnectionsPerClient { get; set; } = 128;
    /// <summary>Connect attempts per minute per client IP before temporary block.</summary>
    [JsonPropertyName("connectRatePerMinute")] public int ConnectRatePerMinute { get; set; } = 240;
    [JsonPropertyName("rateBlockSeconds")] public int RateBlockSeconds { get; set; } = 60;
    [JsonPropertyName("idleTimeoutSec")] public int IdleTimeoutSec { get; set; } = 300;
    [JsonPropertyName("connectTimeoutSec")] public int ConnectTimeoutSec { get; set; } = 15;
    [JsonPropertyName("maxHeaderBytes")] public int MaxHeaderBytes { get; set; } = 32768;
}

public sealed class SecurityOptions
{
    /// <summary>Deny loopback / link-local / site-local targets (SSRF guard, OWASP A10).</summary>
    [JsonPropertyName("denyPrivateTargets")] public bool DenyPrivateTargets { get; set; } = false;
    /// <summary>When true, remote hostnames are forwarded to the upstream instead of resolved locally (DNS-leak prevention).</summary>
    [JsonPropertyName("resolveViaUpstream")] public bool ResolveViaUpstream { get; set; } = false;
    [JsonPropertyName("secretVaultPath")] public string SecretVaultPath { get; set; } = "data/vault.bin";
    /// <summary>Max requests per second per client for plain-HTTP forwarding (OWASP A04).</summary>
    [JsonPropertyName("httpRatePerMinute")] public int HttpRatePerMinute { get; set; } = 600;
    /// <summary>
    /// Client-IP allowlist (CIDR or single IP; e.g. "192.168.1.0/24"). Empty/null = allow all.
    /// Recommended whenever the proxy binds beyond loopback (LAN/0.0.0.0) — AC-3/SC-7 posture.
    /// </summary>
    [JsonPropertyName("clients")] public ClientAllowlistOptions? Clients { get; set; }
}

public sealed class ClientAllowlistOptions
{
    /// <summary>CIDRs or single IPs allowed to use the proxy. Empty = allow all clients.</summary>
    [JsonPropertyName("allow")] public List<string> Allow { get; set; } = new();
    /// <summary>These CIDRs are always denied even if also matched by allow (e.g. guest subnet).</summary>
    [JsonPropertyName("deny")] public List<string> Deny { get; set; } = new();
}

public sealed class LoggingOptions
{
    [JsonPropertyName("level")] public string Level { get; set; } = "info";
    [JsonPropertyName("directory")] public string Directory { get; set; } = "logs";
    [JsonPropertyName("maxFileBytes")] public long MaxFileBytes { get; set; } = 104_857_600;
    [JsonPropertyName("maxFiles")] public int MaxFiles { get; set; } = 14;
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuthMode
{
    None = 0,
    Basic = 1,      // HTTP Basic / SOCKS5 userpass via secret vault
    IpAllowlist = 2
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum UpstreamType
{
    Direct = 0,
    Http = 1,
    Socks5 = 2
}

public static class ConfigLoader
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static string ConfigPath => AppPaths.ConfigFile;

    public static ProxyConfig Load()
    {
        if (!File.Exists(ConfigPath)) return ProxyConfig.Default;
        var json = File.ReadAllText(ConfigPath);
        var cfg = JsonSerializer.Deserialize<ProxyConfig>(json, JsonOpts) ?? ProxyConfig.Default;
        return cfg;
    }

    public static ProxyConfig Load(string path)
    {
        var json = File.ReadAllText(path);
        var cfg = JsonSerializer.Deserialize<ProxyConfig>(json, JsonOpts) ?? ProxyConfig.Default;
        return cfg;
    }

    public static void Save(ProxyConfig cfg, string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(cfg, new JsonSerializerOptions { WriteIndented = true });
        // Atomic write (CM-6 integrity): temp file + rename
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        if (File.Exists(path)) File.Replace(tmp, path, null);
        else File.Move(tmp, path);
    }
}
