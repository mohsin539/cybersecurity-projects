using ProxyCore.Audit;
using ProxyCore.Listeners;
using ProxyCore.Metrics;
using ProxyCore.Net;
using ProxyCore.Options;
using ProxyCore.Rules;
using ProxyCore.Security;

namespace ProxyCore;

public sealed class ProxyEngine
{
    private readonly ProxyConfig _cfg;
    private readonly RuleEngine _rules = new();
    private readonly MetricsRegistry _metrics = new();
    private readonly object _reloadLock = new();
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private AccessGuard? _guard;
    private UpstreamRouter? _router;
    private HttpProxyListener? _http;
    private Socks5ProxyListener? _socks;
    private DnsCache? _dns;
    private AuditLogger? _audit;
    private SecretVault? _vault;
    private CancellationTokenSource? _cts;

    /// <summary>Bind addresses actually resolved at listener start (for diagnostics/GUI).</summary>
    public string ResolvedHttpBind { get; private set; } = "";
    public string ResolvedSocksBind { get; private set; } = "";

    public ProxyEngine(ProxyConfig? cfg = null, string? baseDir = null)
    {
        _cfg = cfg ?? ConfigLoader.Load();
        BaseDir = baseDir ?? AppPaths.Home;
    }

    public string BaseDir { get; }

    private static ProxyCore.Options.LoggingOptions ResolveLogging(ProxyCore.Options.LoggingOptions o)
    {
        o.Directory = AppPaths.ResolveDir(o.Directory);
        return o;
    }

    public MetricsRegistry Metrics => _metrics;

    public async Task StartAsync()
    {
        _audit = new AuditLogger(ResolveLogging(_cfg.Logging));
        _vault = new SecretVault(AppPaths.VaultFile(_cfg.Security.SecretVaultPath));
        _guard = new AccessGuard(_cfg, _vault);
        _dns = new DnsCache();
        _router = new UpstreamRouter(_cfg, _rules, _guard, _dns, _metrics, _audit);
        _rules.Replace(_cfg.Rules);
        _http = new HttpProxyListener(_cfg, _rules, _guard, _router, _metrics, _audit, _dns);
        _socks = new Socks5ProxyListener(_cfg, _guard, _router, _metrics, _audit);
        _cts = new CancellationTokenSource();
        await _http.StartAsync(_cts.Token);
        await _socks.StartAsync(_cts.Token);
        ResolvedHttpBind = _http.BoundAddress;
        ResolvedSocksBind = _socks.BoundAddress;
        _audit.Log(AuditSeverity.Info, "engine.start", detail: "ProxyEngine started");
    }

    public void Stop()
    {
        _cts?.Cancel();
        _audit?.Log(AuditSeverity.Info, "engine.stop", detail: "ProxyEngine stopped");
        _audit?.Dispose();
    }

    public void ApplyRules(IEnumerable<RuleDefinition> rules)
    {
        lock (_reloadLock)
        {
            _cfg.Rules = rules.ToList();
            _rules.Replace(_cfg.Rules);
            _audit?.Log(AuditSeverity.Info, "config.change", detail: "rules applied: " + _cfg.Rules.Count);
        }
    }

    public IReadOnlyList<RuleDefinition> CurrentRules => _rules.Current;

    public HealthStatus Health()
    {
        return new HealthStatus
        {
            UptimeSec = (long)(DateTime.UtcNow - _startedUtc).TotalSeconds,
            ListenersUp = _http is not null && _socks is not null,
            Metrics = _metrics.Snapshot()
        };
    }
}

public sealed class HealthStatus
{
    public long UptimeSec { get; init; }
    public bool ListenersUp { get; init; }
    public MetricsSnapshot Metrics { get; init; } = new();
}
