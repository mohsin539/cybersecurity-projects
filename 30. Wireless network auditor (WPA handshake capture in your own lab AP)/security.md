# Security Model - Wireless Network Auditor

> Authorized lab use only. Scope enforcement is designed in, not bolted on: the
> engine refuses frames outside the registered lab AP allow-list.

## 1. Purpose and scope lock

- The tool audits **your own lab access point** (WPA/WPA2 handshake capture).
- `app/core/scope.py` `ScopeGuard` is the single enforcement point. Any frame
  whose BSSID is not in the allow-list is dropped before it reaches storage.
- The built-in simulator is itself scope-aware: it never generates out-of-scope frames.

## 2. Cryptographic posture

| Item | Choice | Notes |
|---|---|---|
| At-rest cipher | AES-256-GCM | cryptography AESGCM, nonce = 12 random bytes |
| Key wrapping | Windows DPAPI | CryptProtectData, user-bound (dpapi-v1) |
| CI / non-Windows fallback | PBKDF2-HMAC-SHA256, 210k iters | scheme pbkdf2-sha256-v1 |
| Integrity | SHA-256 hash chain | see section 4 |

- No plaintext PSK / passphrase is ever persisted.
- Every evidence row is sealed before insert; `open()` requires the master key.

## 3. Threat model and controls (OWASP Top 10 2021)

| OWASP | Threat to the tool | Control | Location |
|---|---|---|---|
| A01 Broken Access Control | Stolen vault readable | DPAPI binding + per-session keys | data/crypto.py |
| A02 Cryptographic Failures | Weak / no encryption | AES-256-GCM mandatory | data/crypto.py |
| A03 Injection | SSID into SQL / HTML | Parameterized SQL; HTML escaping in reports | data/vault.py, report/html_exporter.py |
| A04 Insecure Design | Broad capture | Lab allow-list in the engine | core/scope.py, core/engine.py |
| A05 Misconfiguration | Monitor-mode errors | Fail-closed defaults, pre-flight checks | core/engine.py |
| A06 Vulnerable Components | Old deps in .exe | requirements.txt pinned; PyInstaller vendored OpenSSL | requirements.txt |
| A07 Identification and Auth Failures | Weak unlock | PBKDF2-derived master key | data/crypto.py |
| A08 Integrity Failures | Tampered evidence | SHA-256 hash chain | data/hashchain.py |
| A09 Logging and Monitoring | No audit trail | Local audit table in vault | data/vault.py |
| A10 SSRF | Phone-home | Zero network egress; reports fully offline | everywhere |

## 4. Evidence hash chain

`HashChain.append` (data/hashchain.py) computes:

    h_n = SHA256( h_{n-1} || event_type || ts || payload_digest )

- Persisted in evidence.hashchain with atomic file replace.
- Every insert into the vault appends a link before returning.
- Any tamper breaks every subsequent link and is visible in the Integrity
  panel and every report footer.

## 5. Data-at-rest layout

- `wna_data/workspace/evidence.db` - SQLite vault (sealed rows only)
- `wna_data/workspace/evidence.hashchain` - chain head + length
- `wna_data/workspace/.keystore` - wrapped master key (DPAPI blob or PBKDF2 wrapper)
- `wna_data/workspace/reports/` - exported reports

## 6. Compliance alignment

- **OWASP Top 10 (2021)** - controls table above (A01-A10).
- **ISO/IEC 27001:2022 Annex A** - access control, cryptography, asset
  inventory (AP/client lists), audit logging, incident evidence pack (JSON+PCAP).
- **NIST CSF 2.0** - Govern (scope wizard, no egress), Identify (AP/client
  inventory, severity scoring), Protect (sealed vault, integrity chain),
  Detect (live dashboard, channel heatmap), Respond (remediation guidance per
  finding), Recover (re-audit templates).

## 7. Developer / release checklist

1. Run `python main.py --selftest` - must exit 0 before shipping.
2. Pin every new dependency in requirements.txt and re-wrap the PyInstaller spec.
3. Verify the exe launches (launch + 8 s heartbeat, then terminate).
4. Never log keystore paths or master-key material.
5. Prefer the encrypted vault; only export decrypted artifacts via the report UI.