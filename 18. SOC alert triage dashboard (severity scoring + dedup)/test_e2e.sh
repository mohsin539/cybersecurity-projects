#!/bin/bash
# End-to-end verification for the SOC Alert Triage Dashboard (see security.md §6)
# Self-contained: boots its own server on :8081 with a fresh throwaway store,
# runs all checks, then cleans up. The dashboard on :8080 is not touched.
PORT=8081
BASE="localhost:$PORT"
DATA=data/test-store.json
PASS=0; FAIL=0; SRV_PID=""
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3 (got $1, want $2)"; fi; }
J() { node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{console.log(JSON.parse(d)$1)}catch(e){console.log('ERR')}})"; }

cleanup() {
  [ -n "$SRV_PID" ] && kill $SRV_PID 2>/dev/null
  rm -f lead.t1 analyst.t1 aud.t1 login*.json *.txt body.json audit.jsonl "$DATA" test-server.log
}
trap cleanup EXIT

echo "== boot test server on :$PORT (fresh store) =="
rm -f "$DATA"
DATA_FILE="$DATA" PORT=$PORT nohup node server.js > test-server.log 2>&1 < /dev/null &
SRV_PID=$!
for i in $(seq 1 20); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 0.3
done
curl -s -o /dev/null "$BASE/" || { bad "test server failed to boot"; exit 1; }
ok "test server booted"

echo "== A. auth =="
code=$(curl -sc lead.t1 -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"userId":"lead@t1"}' -o login.json -w '%{http_code}')
check "$code" "200" "lead login"
C=$(node -e "console.log(JSON.parse(require('fs').readFileSync('login.json')).csrf)")
code=$(curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"userId":"ghost@t1"}' -o /dev/null -w '%{http_code}')
check "$code" "401" "unknown user rejected"

echo "== B. queue & golden vector (fresh seed => occ=3, score=97) =="
Q=$(curl -sb lead.t1 "$BASE/api/queue")
N=$(echo "$Q" | J ".alerts.length")
if [ "$N" -ge 2 ] 2>/dev/null; then ok "queue returns alerts ($N)"; else bad "queue alerts ($N)"; fi
check "$(echo "$Q" | J ".alerts.find(a=>a.ruleId==='EDR-CRED-DUMP-01').currentBand")" "critical" "golden vector band critical"
check "$(echo "$Q" | J ".alerts.find(a=>a.ruleId==='EDR-CRED-DUMP-01').currentScore")" "97" "golden vector score 97 (doc 02 §4.2)"
check "$(echo "$Q" | J ".alerts.find(a=>a.ruleId==='EDR-CRED-DUMP-01').occurrenceCount")" "3" "seeded duplicates linked (occ=3)"

echo "== C. dedup (fresh alert, then immediate re-ingest) =="
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
cat > body.json <<EOF
{"source":"edr","ruleId":"EDR-TEST-DUP-99","ruleFamily":"credential-access","tactic":"credential-access","title":"Dedup test detection","entities":[{"type":"host","id":"TEST-HOST-1"}],"occurredAt":"$TS","confidence":0.7,"assetTier":2,"tiMatch":0,"kevListed":false,"epss":0}
EOF
R1=$(curl -sb lead.t1 -X POST "$BASE/api/ingest" -H "X-CSRF-Token: $C" -H 'Content-Type: application/json' -d @body.json)
check "$(echo "$R1" | J ".deduped")" "false" "first ingest creates canonical"
CAN=$(echo "$R1" | J ".canonicalId")
R2=$(curl -sb lead.t1 -X POST "$BASE/api/ingest" -H "X-CSRF-Token: $C" -H 'Content-Type: application/json' -d @body.json)
check "$(echo "$R2" | J ".deduped")" "true" "identical re-ingest deduplicated"
check "$(echo "$R2" | J ".canonicalId")" "$CAN" "linked to same canonical"

echo "== D. tenant isolation (A01) =="
code=$(curl -sb lead.t1 -H 'X-Tenant: t2' -o /dev/null -w '%{http_code}' "$BASE/api/queue")
check "$code" "403" "tenant spoof blocked"
code=$(curl -sc analyst.t1 -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"userId":"analyst@t2"}' -o login2.json -w '%{http_code}')
check "$code" "200" "t2 login"
T2=$(curl -sb analyst.t1 "$BASE/api/queue" | J ".alerts.length")
if [ "$T2" -ge 1 ] 2>/dev/null && [ "$T2" -lt "$N" ]; then ok "t2 sees only own tenant ($T2 vs t1 $N)"; else bad "t2 isolation ($T2 vs $N)"; fi
T2ID=$(curl -sb analyst.t1 "$BASE/api/queue" | J ".alerts[0].id")
code=$(curl -sb lead.t1 -o /dev/null -w '%{http_code}' "$BASE/api/alerts/$T2ID")
check "$code" "404" "cross-tenant object read blocked"

echo "== E. CSRF & ABAC =="
code=$(curl -sb lead.t1 -X POST "$BASE/api/ingest" -H 'Content-Type: application/json' -d '{}' -o /dev/null -w '%{http_code}')
check "$code" "403" "POST without CSRF blocked"
code=$(curl -sb lead.t1 -X POST "$BASE/api/auth/logout" -H 'Content-Type: application/json' -d '{}' -o /dev/null -w '%{http_code}')
check "$code" "403" "logout without CSRF blocked (regression fix)"
code=$(curl -sc analyst.t1 -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"userId":"analyst@t1"}' -o login3.json -w '%{http_code}')
C3=$(node -e "console.log(JSON.parse(require('fs').readFileSync('login3.json')).csrf)")
AID=$(curl -sb analyst.t1 "$BASE/api/queue" | J ".alerts.find(a=>a.currentBand==='critical').id")
code=$(curl -sb analyst.t1 -X POST "$BASE/api/alerts/$AID/disposition" -H "X-CSRF-Token: $C3" -H 'Content-Type: application/json' -d '{"status":"resolved"}' -o /dev/null -w '%{http_code}')
check "$code" "403" "tier1 cannot close critical (ABAC)"

echo "== F. disposition + audit =="
LID=$(curl -sb lead.t1 "$BASE/api/queue" | J ".alerts.find(a=>a.currentBand==='low').id")
code=$(curl -sb lead.t1 -X POST "$BASE/api/alerts/$LID/disposition" -H "X-CSRF-Token: $C" -H 'Content-Type: application/json' -d '{"status":"benign","reason":"verified safe"}' -o /dev/null -w '%{http_code}')
check "$code" "200" "lead disposition low band"
check "$(curl -sb lead.t1 "$BASE/api/audit" | J ".chainValid")" "true" "audit chain valid"
DC=$(curl -sb lead.t1 "$BASE/api/audit" | J ".events.filter(e=>e.action==='alert.disposition').length")
if [ "$DC" -ge 1 ] 2>/dev/null; then ok "disposition audited"; else bad "disposition audit missing"; fi
code=$(curl -sb lead.t1 -o audit.jsonl -w '%{http_code}' "$BASE/api/audit/export")
check "$code" "200" "audit JSONL export"

echo "== G. auditor =="
curl -sc aud.t1 -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d '{"userId":"auditor@t1"}' -o login4.json > /dev/null
X=$(curl -sb aud.t1 -H 'X-Tenant: *' "$BASE/api/queue")
if [ -n "$(echo "$X" | J ".crossTenantStats.t1")" ] && [ -n "$(echo "$X" | J ".crossTenantStats.t2")" ]; then
  ok "auditor cross-tenant counts (t1=$(echo "$X" | J ".crossTenantStats.t1"), t2=$(echo "$X" | J ".crossTenantStats.t2"))"
else bad "auditor stats"; fi

echo "== H. static & headers =="
check "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")" "200" "SPA served"
check "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$BASE/../server.js")" "404" "traversal blocked"
check "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/nope")" "404" "unknown static 404"
H=$(curl -sI "$BASE/" | grep -i 'content-security-policy' | head -1)
if [ -n "$H" ]; then ok "CSP header present"; else bad "CSP missing"; fi

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
