"""Demo: run the anonymizer CLI over sample log lines.

Usage:
    python scripts/demo_samples.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SAMPLE_LOGS = [
    "ERROR [auth-service] user john.smith@example.com failed login, ssn 123-45-6789",
    "INFO  [payments] card 4539665131016828 authorized for 99.95 USD",
    "WARN  [api-gateway] apikey=sk_live_PLACEHOLDER_REPLACE_ME",
    "DEBUG [db] slow query 312ms from ip 10.20.30.40 on table users",
    "INFO  [notification] sent SMS to +1 (555) 123-4567",
    "ERROR [ml] patient MRN:88452186 inference failed, dob 1987-04-12",
    "INFO  [ops] deployed release v2.4.1 scale replicas=6",
    "DEBUG [search] geolocation 37.7749, -122.4194 for query hotels",
]


def main():
    if sys.version_info >= (3, 11):
        result = subprocess.run(
            [sys.executable, "-m", "anonymizer", "--json", "--policy", "share-with-analytics"],
            input="\n".join(SAMPLE_LOGS),
            text=True,
            capture_output=True,
            cwd=str(ROOT / "src"),
        )
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        return
    import json
    sys.path.insert(0, str(ROOT / "src"))
    from anonymizer.services import AnonymizerService, AnonymizationRequest

    svc = AnonymizerService()
    result = svc.anonymize(AnonymizationRequest(
        lines=SAMPLE_LOGS,
        policy_id="share-with-analytics",
        token_salt="demo-tenant",
    ))
    print(json.dumps({
        "entity_stats": result.entity_stats,
        "processing_ms": result.total_processing_ms,
        "audit_events": result.audit_events,
    }, indent=2))
    for orig, red in zip(SAMPLE_LOGS, result.redacted_lines):
        print(f"\nIN : {orig}\nOUT: {red}")


if __name__ == "__main__":
    main()