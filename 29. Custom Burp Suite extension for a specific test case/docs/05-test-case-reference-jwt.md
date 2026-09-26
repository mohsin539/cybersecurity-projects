# 05 — Reference Test Case: WSTG-SESS-10 (JWT / Token Security)

The **JwtTokenTestPack** is the flagship `TestCase` implementation. It is the living
spec for "a specific test case" and the template for adding new ones.

## 1. Test objective

Determine whether the target application correctly validates **JSON Web Tokens**
(header, payload, signature, and life-cycle claims) in a way that resists the classic
attacks below.

## 2. Test steps (execution order)

Each step is executed by the `TestCaseEngine` under the **SafeExecutionSandbox**
(timeout, delay, budget, dry-run awareness).

| # | Step | Payload / action | Detection signal |
|---|---|---|---|
| S1 | Structure & alg sniff | Parse given token; record `alg`/`typ`/`kid`, literal base64url decode | Weak alg (`none`, `HS*` with RSA public key expected) |
| S2 | `alg:none` injection | Re-sign header w/ `alg=none`, empty signature (`e30.eyJ...` with `signature=""`) | Target accepts unsigned token (200 + privileged payload) |
| S3 | RS256 → HS256 confusion | Present RSA public key as HMAC secret; sign `alg=HS256` | Target verifies with public key; accepts forged HMAC |
| S4 | Sig stripping / truncated | Drop last chars of signature; append extra segment | Acceptance ≠ signature length/format check |
| S5 | `kid` path traversal | `kid=../../dev/null` style paths & SQL-ish injection | Error enum differs / key mismatch bypass |
| S6 | Expiry / `nbf` boundary | ±1s around exp/nbf; missing claims | Accepted outside validity window |
| S7 | Token replay / swap | Two tokens from different users (analyst-supplied pool) | User A token authorizes User B resource |
| S8 | JWE confusion (informational) | None — flags if target expects encrypted tokens but accepts plain JWT | Deviation from stated security profile |

Rules:
- S2–S5 are **active tests**: default `dryRun:true` meaning they are *drafted* and
  reported but not sent unless the operator approves the run.
- S6–S7 require the analyst to supply two tokens (in-memory, `ephemeral:true`).

## 3. Evidence model per finding

```json
{
  "id": "SESS-10-S3",
  "wstgId": "WSTG-SESS-10",
  "severity": "HIGH",
  "cvssLike": 8.1,
  "title": "RS256 to HS256 algorithm confusion",
  "requestFingerprint": "sha256://<request canonical hash>",
  "evidence": [{"step": "S3", "requestId": "r-00017", "responseId": "rsp-00017",
               "status": 200, "snippet": "…"}],
  "remediation": "Restrict accepted algs to allowlist; reject alg 'none'; forbid
                   JWT with HMAC key = public key; validate kid against key store.",
  "audit": {"ts": "…", "chainPrev": "…", "chainHash": "…"}
}
```

## 4. Pass criteria

- S2/S3/S4 false-positives ≤ 5% against the `vuln-app` fixture.
- 100% of run mutations appear in the audit log (ISO A.8.15).
- Dry-run mode never transmits; verified by integration test assertion.

## 5. Fixture (`vuln-app`)

A tiny Python target (`vuln-app/server.py`, dependency-free stdlib HTTP server) with
**intentional** JWT flaws (alg `none` accepted, HS256-keyed-with-public-key, permissive
`kid`, no exp check). Used for CI E2E and manual demo without risking real apps:
verified to return `200` for `alg=none` and to reject forged signatures (`401`).

## 6. Extending to a new test case

1. `class XxxTestPack implements TestCase` (SPI: `testCaseId()`, `steps()`, `onFinding()`).
2. Register in `src/main/resources/META-INF/testcases` manifest.
3. Add JSON-Schema entry for its params; add WSTG mapping in docs/02.
4. Follow `docs/05` as the spec template.