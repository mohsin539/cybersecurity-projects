namespace ProxyCore.Net;

/// <summary>Raised when policy denies a session; mapped to HTTP 403 / SOCKS5 0x02 by listeners.</summary>
public sealed class ProxyDenyException : Exception
{
    public int? RuleId { get; }
    public ProxyDenyException(int? ruleId, string? message = null) : base(message ?? "Denied by policy") => RuleId = ruleId;
}
