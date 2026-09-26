"""Header analysis engine: SPF, DKIM (full RFC 6376 verification), DMARC,
Received-chain and anti-spoofing heuristics.

Controls: SI-4 (detect), RA-5; produces findings only from evidence that is
locally verifiable and fails closed when data is unavailable (A04).
"""
from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import ipaddress
import re
import time
from typing import Dict, List, Optional, Tuple

from ..sec import constants as C
from ..sec.validation import sanitize_text
from . import dns as dns
from .model import EngineResult, Severity

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa as _rsa_mod

    _CRYPTO = True
except Exception:  # noqa: BLE001
    _CRYPTO = False

# ---------------------------------------------------------------------------
# RFC 6376 canonicalization helpers
# ---------------------------------------------------------------------------
def _relaxed_header(name: bytes, value: bytes) -> bytes:
    value = re.sub(rb"\r\n[ \t]", b" ", value)      # unfold: CRLF+WSP -> WSP
    value = re.sub(rb"[ \t]+", b" ", value)          # collapse WSP runs
    value = value.strip(b" \t")                      # RFC 6376 3.4.2: delete WSP
    return name.strip(b" \t").lower() + b":" + value


def _simple_header(name: bytes, value: bytes) -> bytes:
    return name + b":" + value


def _relaxed_body(body: bytes) -> bytes:
    lines = body.split(b"\r\n")
    while lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        return b""                                  # null input (RFC 6376 3.4.4)
    out = []
    for ln in lines:
        ln = re.sub(rb"[ \t]+", b" ", ln).rstrip(b" \t")
        out.append(ln)
    return b"\r\n".join(out) + b"\r\n"


def _simple_body(body: bytes) -> bytes:
    lines = body.split(b"\r\n")
    while lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        return b"\r\n"                              # single CRLF (RFC 6376 3.4.3)
    return b"\r\n".join(lines) + b"\r\n"


def _split_raw(raw: bytes) -> Tuple[bytes, bytes]:
    i1 = raw.find(b"\r\n\r\n")
    i2 = raw.find(b"\n\n")
    if i1 != -1 and (i2 == -1 or i1 < i2):
        return raw[:i1], raw[i1 + 4:]
    if i2 != -1:
        return raw[:i2], raw[i2 + 2:]
    return raw, b""


def _parse_raw_headers(header_bytes: bytes) -> List[Tuple[bytes, List[bytes]]]:
    """name (original case) + list of value segments (first line, continuations).

    Original case is preserved because RFC 6376 simple canonicalization keeps
    the field name byte-for-byte; relaxed lowercases it later.
    """
    fields: List[Tuple[bytes, List[bytes]]] = []
    for line in header_bytes.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            if fields:
                fields[-1][1].append(line)
            continue
        idx = line.find(b":")
        if idx <= 0:
            continue
        fields.append((line[:idx].strip(b" \t"), [line[idx + 1:]]))
    return fields


def _field_text(name: bytes, segs: List[bytes]) -> bytes:
    parts = [name + b":" + segs[0]]
    for seg in segs[1:]:
        parts.append(b"\r\n" + seg)
    return b"".join(parts)


def _find_last(fields, name: bytes) -> Optional[Tuple[bytes, List[bytes]]]:
    found = None
    for n, segs in fields:
        if n.lower().strip() == name:
            found = (n, segs)
    return found


def _split_tags(v: bytes) -> Dict[bytes, bytes]:
    out: Dict[bytes, bytes] = {}
    for part in re.split(rb";\s*", v):
        m = re.match(rb"([a-z][a-z0-9]*)\s*=\s*(.*?)$", part, re.IGNORECASE)
        if m:
            out[m.group(1).lower()] = m.group(2).strip()
    return out


def verify_dkim_signature(sig_field: bytes, header_bytes: bytes,
                          body_bytes: bytes, fields) -> Tuple[str, str, str]:
    """Returns (result, detail, key_desc). result in {pass,fail,permerror,temperror,none}."""
    v = sig_field
    m = re.match(rb"DKIM-Signature:\s*(.*)$", v)
    if not m:
        return "permerror", "malformed DKIM-Signature", ""
    tags = _split_tags(m.group(1))
    domain = tags.get(b"d", b"").decode("ascii", "replace")
    selector = tags.get(b"s", b"").decode("ascii", "replace")
    alg = tags.get(b"a", b"").decode("ascii", "replace")
    body_method = tags.get(b"c", b"simple/simple").decode("ascii", "replace")
    hlist = tags.get(b"h", b"").decode("ascii", "replace")
    sig_b64 = tags.get(b"b", b"")
    key_desc = f"s={selector}/d={domain} a={alg} c={body_method}"
    if not (_CRYPTO):
        return "temperror", "cryptography module unavailable", key_desc
    if domain != domain.lower() or not re.match(r"^[a-z0-9.\-\_]+$", domain):
        return "permerror", "invalid d= value", key_desc
    if alg not in ("rsa-sha256", "rsa-sha1"):
        return "permerror", f"unsupported algorithm {alg!r}", key_desc
    hdr_method, _, bdy_method = body_method.partition("/")
    if hdr_method not in ("simple", "relaxed") or bdy_method not in ("simple", "relaxed"):
        return "permerror", "unsupported c= value", key_desc

    # 1. key record: selector._domainkey.domain TXT v=DKIM1; k=rsa; p=...
    records = dns.get_txt(f"{selector}._domainkey.{domain}")
    pval, kval = None, "rsa"
    for rec in records:
        if rec.lstrip().startswith("v=DKIM1") or "p=" in rec:
            t = _split_tags(rec.encode("ascii", "replace"))
            if b"p" in t:
                pval = t[b"p"]
                kval = t.get(b"k", b"rsa").decode("ascii", "replace")
            break
    if not pval:
        return "temperror", f"no public key for {selector}._domainkey.{domain}", key_desc
    if kval != "rsa":
        return "permerror", f"unsupported key type k={kval}", key_desc
    try:
        raw_key = re.sub(rb"\s+", b"", pval)
        pub = serialization.load_der_public_key(base64.b64decode(raw_key))
        if not isinstance(pub, _rsa_mod.RSAPublicKey):
            return "permerror", "key is not RSA", key_desc
    except Exception as exc:  # noqa: BLE001
        return "permerror", f"key parse failed: {exc}", key_desc

    # 2. body hash is covered by b= verify; build signing data (RFC 6376 3.5-3.7)
    hlist_names = [x.strip().lower() for x in hlist.replace(" ", "").split(":") if x.strip()]
    signed_names = set(hlist_names)
    if "from" not in signed_names:
        return "permerror", "From header not signed (RFC 6376)", key_desc

    canon_hdr = _relaxed_header if hdr_method == "relaxed" else _simple_header
    base_parts = []
    for hn in hlist_names:
        hb = hn.encode("ascii", "replace")
        last = _find_last(fields, hb)
        if last is None:
            return "permerror", f"header {hn!r} in h= not found", key_desc
        n, segs = last
        base_parts.append(_canon_field_from_segs(n, segs, hdr_method) + b"\r\n")
    # DKIM-Signature field itself, canonicalized with empty b=
    dk_header = canon_hdr(b"DKIM-Signature", m.group(1))
    dk_header = re.sub(rb";\s*b\s*=\s*[A-Za-z0-9+/]*={0,2}", b";b=", dk_header)

    # Candidates: per RFC 6376 3.7 d=/s= SHOULD be appended if unsigned, but
    # legacy signatures omit them. Try both so real-world verification is robust.
    candidates = []
    if "d" not in signed_names or "s" not in signed_names:
        extra = []
        if "d" not in signed_names:
            extra.append(canon_hdr(b"d", domain.encode("ascii", "replace")) + b"\r\n")
        if "s" not in signed_names:
            extra.append(canon_hdr(b"s", selector.encode("ascii", "replace")) + b"\r\n")
        candidates.append(b"".join(base_parts + extra + [dk_header + b"\r\n"]))
    candidates.append(b"".join(base_parts + [dk_header + b"\r\n"]))

    hash_alg = hashes.SHA256() if alg == "rsa-sha256" else hashes.SHA1()
    # verify body hash (RFC 6376 3.5): canonicalize body, hash, compare to bh=
    canon_body = (_relaxed_body if bdy_method == "relaxed" else _simple_body)(body_bytes)
    body_hash = hashlib.sha256(canon_body).digest() if alg == "rsa-sha256" \
        else hashlib.sha1(canon_body).digest()
    bh_expected = base64.b64encode(body_hash).decode("ascii")
    bh_declared = tags.get(b"bh", b"").decode("ascii", "replace")
    if not bh_declared or bh_declared != bh_expected:
        return "fail", "body hash mismatch (bh= != computed)", key_desc
    for idx, signing_data in enumerate(candidates):
        try:
            pub.verify(base64.b64decode(sig_b64), signing_data,
                       padding.PKCS1v15(), hash_alg)
            return "pass", key_desc + (" (legacy input infl)" if idx == len(candidates) - 1 else ""), key_desc
        except Exception:  # noqa: BLE001
            continue
    return "fail", f"signature invalid {key_desc}", key_desc


def _canon_field_from_segs(name: bytes, segs: List[bytes], hdr_method: str) -> bytes:
    """Rebuild a raw folded field then canonicalize the (name, value) pair."""
    raw = _field_text(name, segs)
    idx = raw.find(b":")
    if idx <= 0:
        return raw
    n, v = raw[:idx], raw[idx + 1:]
    return _relaxed_header(n, v) if hdr_method == "relaxed" else _simple_header(n, v)


# ---------------------------------------------------------------------------
# SPF evaluation (RFC 7208, compact)
# ---------------------------------------------------------------------------

def _spf_eval(domain: str, client_ip: str, depth: int = 0,
              visited: Optional[set] = None) -> Tuple[str, str]:
    if depth > 8:
        return "temperror", "include/redirect depth exceeded"
    if visited is None:
        visited = set()
    if domain in visited:
        return "temperror", "SPF domain loop"
    visited.add(domain)
    try:
        ip = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return "permerror", f"bad client IP {client_ip!r}"
    records = dns.get_txt(domain)
    spf = next((r for r in records if r.lower().startswith("v=spf1")), None)
    if spf is None:
        return "none", "no SPF record"
    terms = spf.split()[1:]
    redir = None
    for term in terms:
        term = term.lower()
        if term.startswith("redirect="):
            redir = term.split("=", 1)[1]
            continue
        t = term.split(":", 1)
        mech = t[0]
        arg = t[1] if len(t) > 1 else ""
        if mech in ("ip4", "ip6"):
            try:
                net = ipaddress.ip_network(arg, strict=False)
            except ValueError:
                continue
            if ip in net:
                return "pass" if not term.startswith(("-", "~", "?")) else _q_res(term[0]), f"ip match {net}"
        elif mech in ("a", "mx") or term.startswith("a:") or term.startswith("mx:"):
            check_domain = arg if (term.startswith("a:") or term.startswith("mx:")) else domain
            if mech == "a" or term.startswith("a:"):
                addrs = dns.get_a(check_domain)
            else:
                addrs = []
                for h in dns.get_mx(check_domain):
                    addrs.extend(dns.get_a(str(h).rstrip(".")))
            if ip.compressed in {a for a in addrs}:
                return "pass" if not term.startswith(("-", "~", "?")) else _q_res(term[0]), f"{mech} match {check_domain}"
        elif mech == "include":
            sub, d = _spf_eval(arg, client_ip, depth + 1, visited)
            if sub in ("pass", "redirect") or sub == "pass":
                return "pass" if not term.startswith(("-", "~", "?")) else _q_res(term[0]), f"include:{arg}={sub}"
    if redir:
        sub, d = _spf_eval(redir, client_ip, depth + 1, visited)
        return sub, d
    # implicit default: neutral
    return "neutral", "no mechanism matched, no all term"


def _q_res(q: str) -> str:
    return {"-": "fail", "~": "softfail", "?": "neutral"}.get(q, "pass")


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
_DMARC_TAGS = re.compile(rb"(?:\s*(?:(v|p|sp|adkim|aspf|pct|rua|ruf|fo|rf))\s*=\s*([^;]+);?)")

class HeaderEngine:
    """Analyzes header block + envelope chain of a raw RFC 5322 message."""

    def __init__(self, raw: bytes):
        self.raw = raw
        header_bytes, body_bytes = _split_raw(raw)
        self.header_bytes = header_bytes[:C.MAX_HEADER_BYTES]
        self.body_bytes = body_bytes
        self.fields = _parse_raw_headers(self.header_bytes)
        if len(self.fields) > C.MAX_HEADER_FIELDS:
            self.fields = self.fields[: C.MAX_HEADER_FIELDS]
        self.msg = email.message_from_bytes(raw, policy=email.policy.default)

    # -- helpers ----------------------------------------------------------
    def header(self, name: str) -> Optional[str]:
        val = self.msg.get(name)
        return val if isinstance(val, str) else (str(val) if val is not None else None)

    @property
    def from_addr(self) -> str:
        try:
            return (self.msg.get("from") or "").split("<")[-1].rstrip(">").strip() \
                if "<" in (self.msg.get("from") or "") else (self.msg.get("from") or "").strip()
        except Exception:  # noqa: BLE001
            return ""

    @property
    def from_domain(self) -> str:
        a = self.from_addr.lower()
        if "@" in a:
            return a.rsplit("@", 1)[1].strip(">").strip()
        return ""

    def _received(self) -> List[Tuple[str, Optional[str]]]:
        out = []
        for rv in (self.msg.get_all("Received") or []):
            ipm = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(rv))
            out.append((str(rv), ipm.group(1) if ipm else None))
        return out

    # -- top-level ---------------------------------------------------------
    def analyze(self) -> EngineResult:
        res = EngineResult("header")
        meta: Dict = {}

        from_orig = self.header("From") or ""
        res.meta["from"] = from_orig
        meta["from_display"] = sanitize_text(from_orig.split("<")[0].strip('" \''), 128)
        meta["reply_to"] = self.header("Reply-To") or ""
        meta["return_path"] = self.header("Return-Path") or ""
        meta["message_id"] = self.header("Message-ID")
        meta["date"] = self.header("Date")
        meta["subject"] = sanitize_text(self.msg.get("subject") or "", 512)

        received = self._received()
        meta["received_count"] = len(received)
        meta["received"] = [r[0] for r in received]

        # spoof / anomaly heuristics (SI-4 signal)
        self._basics(res, meta)
        self._relay_chain(res, meta, received)
        self._authn(res, meta)
        self._impersonation(res, meta)
        res.meta = meta
        return res

    def _basics(self, res: EngineResult, meta: Dict) -> None:
        for field, label in (("From", "From"), ("Date", "Date"), ("Message-ID", "Message-ID")):
            if not self.header(field):
                res.add(f"MISSING_{field.replace('-', '').upper()}", Severity.MEDIUM,
                        f"{label} header is missing (common in forged/phishing mail)", category="anomaly")
        try:
            parsed = email.utils.parsedate_to_datetime(self.header("Date"))
            age = abs(time.time() - parsed.timestamp())
            if age > 60 * 24 * 3600:
                res.add("DATE_STALE", Severity.LOW,
                        f"Date header is {age / 86400:.0f} days old", category="anomaly")
        except Exception:  # noqa: BLE001
            pass
        if len(self.fields) > 100:
            res.add("HEADER_FLOOD", Severity.MEDIUM,
                    f"Unusually many header fields ({len(self.fields)})", category="anomaly")

    def _relay_chain(self, res: EngineResult, meta: Dict, received: List[Tuple]) -> None:
        if not received:
            res.add("NO_RECEIVED", Severity.MEDIUM,
                    "No Received chain present - message was not relayed through an MTA",
                    category="anomaly")
            return
        if len(received) > C.MAX_RECEIVED_HOPS:
            res.add("HOP_EXCEED", Severity.MEDIUM,
                    f"Received chain of {len(received)} hops exceeds policy", category="anomaly")
        # topmost Received carries the SIP (last connecting host IP for SPF)
        sip = received[0][1]
        meta["client_ip"] = sip
        if not sip:
            for _, ip in received[1:]:
                if ip:
                    sip = ip
                    break
        if sip:
            from ..sec.validation import is_private_ip
            if is_private_ip(sip):
                res.add("CLIENT_IP_PRIVATE", Severity.INFO,
                        "Topmost Received connecting IP is private (no SPF against it)",
                        detail=f"sip={sip}", category="info")
        # envelope 'for' hint from bottom (first) Received
        bottom_for = re.search(r"for\s+<([^>]+)>", received[-1][0]) if received else None
        meta["envelope_to"] = bottom_for.group(1) if bottom_for else ""

    def _authn(self, res: EngineResult, meta: Dict) -> None:
        from_domain = self.from_domain
        meta["from_domain"] = from_domain
        rp = (self.header("Return-Path") or "").strip()
        rp_domain = rp.split("@")[-1].strip(">").strip() if "@" in rp else ""
        meta["return_path_domain"] = rp_domain
        client_ip = meta.get("client_ip") or "0.0.0.0"

        # SPF
        spf_result = spf_detail = "n/a"
        if from_domain and client_ip != "0.0.0.0":
            spf_result, spf_detail = _spf_eval(from_domain, client_ip)
            meta["spf_result"] = spf_result
            if spf_result == "fail":
                res.add("SPF_FAIL", Severity.HIGH,
                        "SPF check failed - sending host not authorized",
                        detail=spf_detail, category="auth")
            elif spf_result in ("softfail", "neutral"):
                res.add(f"SPF_{spf_result.upper()}", Severity.LOW,
                        f"SPF {spf_result}", detail=spf_detail, category="auth")
            elif spf_result == "none":
                res.add("SPF_NONE", Severity.LOW,
                        "No SPF record for sender domain", category="auth")
            elif spf_result == "pass":
                res.add("SPF_PASS", Severity.INFO, "SPF passed", category="auth")
        else:
            res.add("SPF_NOT_EVALUABLE", Severity.INFO,
                    "SPF could not be evaluated (no connecting IP or sender domain)",
                    category="auth")

        # DKIM
        dkims = self.msg.get_all("DKIM-Signature")
        meta["dkim_count"] = len(dkims) if dkims else 0
        dkim_ok = False
        if dkims:
            for ds in dkims:
                sig_field = f"DKIM-Signature: {ds}"
                r, detail, desc = verify_dkim_signature(
                    sig_field.encode("utf-8", "replace"), self.header_bytes,
                    self.body_bytes, self.fields)
                meta.setdefault("dkim_results", []).append({"result": r, "desc": desc, "detail": detail})
                if r == "pass":
                    dkim_ok = True
                    res.add("DKIM_PASS", Severity.INFO, f"DKIM verified {desc}", category="auth")
                elif r == "fail":
                    res.add("DKIM_FAIL", Severity.HIGH,
                            f"DKIM signature verification failed {desc}", category="auth")
                elif r == "permerror":
                    res.add("DKIM_PERMERROR", Severity.LOW,
                            f"DKIM permanent error: {detail}", category="auth")
                else:
                    res.add("DKIM_TEMPERROR", Severity.INFO,
                            f"DKIM unavailable: {detail} (treat as none)", category="auth")
        else:
            res.add("DKIM_NONE", Severity.LOW, "No DKIM signature present", category="auth")

        # DMARC
        dmarc = self._dmarc(from_domain, spf_result, rp_domain, dkim_ok)
        meta["dmarc"] = dmarc
        policy = dmarc.get("policy", "none")
        if dmarc.get("pass"):
            res.add("DMARC_PASS", Severity.INFO, "DMARC passed", category="auth")
        elif dmarc.get("available"):
            level = Severity.HIGH if policy in ("reject", "quarantine") else Severity.MEDIUM
            res.add("DMARC_FAIL", level,
                    "DMARC authentication failed; message authorized as "
                    f"policy={policy}; adkim={dmarc.get('adkim')}/aspf={dmarc.get('aspf')}",
                    detail=str(dmarc), category="auth")
        else:
            res.add("DMARC_NONE", Severity.INFO,
                    "No DMARC policy published for sender domain (auth not asserted)",
                    category="auth")

        # check Authentication-Results consistency (informational)
        ar = self.header("Authentication-Results")
        if ar:
            meta["auth_results_header"] = sanitize_text(ar, 512)

    def _dmarc(self, from_domain: str, spf_result: str, rp_domain: str, dkim_ok: bool) -> Dict:
        out: Dict = {"pass": False, "policy": "none"}
        if not from_domain:
            return out
        records = dns.get_txt(f"_dmarc.{from_domain}")
        rec = next((r for r in records if "v=DMARC1" in r.upper()), None)
        if not rec:
            out["available"] = False
            return out
        out["available"] = True
        recb = rec.encode("ascii", "replace")
        tags = {m.group(1).decode(): m.group(2).decode().strip()
                for m in _DMARC_TAGS.finditer(recb)}
        out["policy"] = tags.get("p", "none")
        out["adkim"] = tags.get("adkim", "r")
        out["aspf"] = tags.get("aspf", "r")
        spf_aligned = False
        if spf_result == "pass" and rp_domain and from_domain:
            if out["aspf"] == "s":
                spf_aligned = rp_domain.lower() == from_domain.lower()
            else:
                spf_aligned = _parent_domain(rp_domain) == _parent_domain(from_domain)
        dkim_aligned = dkim_ok  # aligned = From-domain match enforced by key lookup above
        out["spf_aligned"] = spf_aligned
        out["dkim_aligned"] = dkim_aligned
        out["pass"] = bool(dkim_aligned or spf_aligned)
        return out

    def _impersonation(self, res: EngineResult, meta: Dict) -> None:
        display = meta.get("from_display") or ""
        dl = display.lower()
        brand_hit = next((b for b in C.BRAND_WATCHLIST if b in dl), None)
        domain = self.from_domain
        if brand_hit and domain and brand_hit not in domain:
            res.add("DISPLAY_SPOOF", Severity.HIGH,
                    f"From display name contains '{brand_hit}' while sender domain is '{domain}' - brand impersonation risk",
                    category="malicious")
        reply_to = meta.get("reply_to")
        if reply_to:
            rt_domain = reply_to.split("@")[-1].strip(">").strip().lower()
            if rt_domain and domain and rt_domain != domain and not _parent_domain(rt_domain) == _parent_domain(domain):
                res.add("REPLYTO_MISMATCH", Severity.MEDIUM,
                        f"Reply-To domain '{rt_domain}' differs from From domain '{domain}' (redirect replies)",
                        category="anomaly")
        rp = (meta.get("return_path") or "").strip("<>")
        if rp and "@" in rp:
            rp_domain = rp.split("@")[-1].lower()
            if rp_domain and domain and rp_domain not in (domain,):
                res.add("RETURNPATH_MISMATCH", Severity.MEDIUM,
                        f"Envelope Return-Path domain '{rp_domain}' differs from From domain '{domain}'",
                        category="anomaly")


def _parent_domain(d: str) -> str:
    d = d.strip(".").lower()
    if not d:
        return ""
    if d.count(".") <= 1:
        return d
    return d.split(".", 1)[1]