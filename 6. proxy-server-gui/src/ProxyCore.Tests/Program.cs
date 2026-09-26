using ProxyCore.Audit;
using ProxyCore.Options;
using ProxyCore.Rules;
using ProxyCore.Security;

namespace ProxyCore.Tests;

public static class Program
{
    private static int _pass;
    private static int _fail;

    public static int Main()
    {
        RuleWildcard();
        RuleCidr();
        RuleEvaluationOrder();
        InputValidation();
        SsrfChecks();
        RateLimiterBlocks();
        AuditChainDetectsTamper();
        ConfigRoundTrip();
        VaultRoundTrip();
        Report();
        return _fail == 0 ? 0 : 1;
    }

    private static void RuleWildcard()
    {
        Assert(RuleEngine.WildcardMatches("*.example.com", "a.example.com"), "wildcard sub");
        Assert(RuleEngine.WildcardMatches("*.example.com", "example.com"), "wildcard apex");
        Assert(!RuleEngine.WildcardMatches("*.example.com", "badexample.com"), "wildcard no suffix match");
        Assert(RuleEngine.WildcardMatches("*", "anything"), "wildcard all");
    }

    private static void RuleCidr()
    {
        var ip = System.Net.IPAddress.Parse("10.1.2.3");
        Assert(RuleEngine.CidrMatches("10.0.0.0/8", ip), "cidr /8");
        Assert(!RuleEngine.CidrMatches("192.168.0.0/16", ip), "cidr mismatch");
        Assert(RuleEngine.CidrMatches("10.1.2.3", ip), "single ip");
    }

    private static void RuleEvaluationOrder()
    {
        var re = new RuleEngine(new[]
        {
            new RuleDefinition { Id = 1, Action = RuleAction.Deny, Match = new RuleMatch { Host = "*.blocked.test" } },
            new RuleDefinition { Id = 2, Action = RuleAction.Allow, Match = RuleMatch.Any }
        });
        var ctx = new RuleContext("x.blocked.test", 443, "https", null, null, System.Net.IPAddress.Loopback);
        var d = re.Evaluate(ctx);
        Assert(d.Action == RuleAction.Deny && d.Rule?.Id == 1, "deny-first");
        var ctx2 = new RuleContext("ok.test", 443, "https", null, null, System.Net.IPAddress.Loopback);
        Assert(re.Evaluate(ctx2).Action == RuleAction.Allow, "allow fallback");
    }

    private static void InputValidation()
    {
        Assert(InputValidator.IsValidHost("example.com"), "host ok");
        Assert(InputValidator.IsValidHost("a-b.example.com"), "host dash");
        Assert(!InputValidator.IsValidHost("bad host"), "host space");
        Assert(!InputValidator.IsValidHost("bad\rhost"), "host cr");
        Assert(!InputValidator.IsValidUsername("u\nser"), "user lf");
        Assert(InputValidator.Safe("a\r\nb") == "a  b", "safe clip");
    }

    private static void SsrfChecks()
    {
        Assert(SsrfGuard.IsForbidden(System.Net.IPAddress.Loopback), "loopback");
        Assert(SsrfGuard.IsForbidden("169.254.169.254"), "metadata ip");
        Assert(SsrfGuard.IsForbidden(System.Net.IPAddress.Parse("10.0.0.5")), "rfc1918 10/8");
        Assert(SsrfGuard.IsForbidden(System.Net.IPAddress.Parse("fc00::1")), "ula fc00");
        Assert(!SsrfGuard.IsForbidden(System.Net.IPAddress.Parse("93.184.216.34")), "public ok");
    }

    private static void RateLimiterBlocks()
    {
        var rl = new RateLimiter(3, 60);
        var ip = System.Net.IPAddress.Parse("77.1.2.3");
        Assert(rl.Allow(ip), "rl 1");
        Assert(rl.Allow(ip), "rl 2");
        Assert(rl.Allow(ip), "rl 3");
        Assert(!rl.Allow(ip), "rl 4 blocked");
    }

    private static void AuditChainDetectsTamper()
    {
        var dir = Path.Combine(Path.GetTempPath(), "proxytests-" + Guid.NewGuid().ToString("N"));
        var logger = new AuditLogger(new LoggingOptions { Directory = dir, MaxFileBytes = 10_000_000, MaxFiles = 2 });
        logger.Log(AuditSeverity.Info, "t1");
        logger.Log(AuditSeverity.Info, "t2");
        logger.Log(AuditSeverity.Info, "t3");
        logger.Dispose();
        var file = Directory.GetFiles(dir, "audit-*.jsonl").Single();
        var lines = File.ReadAllLines(file);
        Assert(lines.Length == 3, "3 events");
        Assert(lines[1].Contains("\"prev\""), "chain prev");
        Directory.Delete(dir, true);
    }

    private static void ConfigRoundTrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "cfg-" + Guid.NewGuid().ToString("N") + ".json");
        var cfg = new ProxyConfig
        {
            Rules = new List<RuleDefinition>
            {
                new() { Id = 7, Action = RuleAction.Deny, Match = new RuleMatch { Host = "*.x.test" } }
            }
        };
        ConfigLoader.Save(cfg, path);
        var loaded = ConfigLoader.Load(path);
        Assert(loaded.Rules[0].Id == 7, "cfg roundtrip");
        File.Delete(path);
    }

    private static void VaultRoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "vault-" + Guid.NewGuid().ToString("N") + Path.DirectorySeparatorChar);
        var v = new SecretVault(Path.Combine(dir, "vault.bin"));
        v.Set("user:alice", "s3cret!");
        var v2 = new SecretVault(Path.Combine(dir, "vault.bin"));
        Assert(v2.TryGet("user:alice", out var s) && s == "s3cret!", "vault roundtrip");
        Directory.Delete(dir, true);
    }

    private static void Assert(bool cond, string? msg = null)
    {
        if (cond) _pass++;
        else { _fail++; Console.WriteLine("FAIL: " + (msg ?? "<no msg>")); }
    }

    private static void Report()
    {
        Console.WriteLine($"PASS={_pass} FAIL={_fail}");
        Console.WriteLine(_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
    }
}
