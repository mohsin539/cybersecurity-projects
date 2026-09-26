"""Active Scanner - vulnerable-parameter identification (ARCHITECTURE.md 5.5).

Approved-target probing that determines whether a parameter actually executes
injected SQL. Non-destructive payloads + response differential analysis.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

import requests

UA = "SQLiDetect-Shield/1.0 (defensive scanner; approved targets only)"
_DB_ERROR_MARKERS = {
    "MySQL": ["mysqli", "mysql_fetch", "syntax error", "SQLSTATE[",
              "You have an error in your SQL"],
    "PostgreSQL": ["syntax error at or near", "position:", "PG::", "psycopg2",
                   "ERROR:  "],
    "MSSQL": ["unclosed quotation mark", "ole db", "sql server", "line 1"],
    "Oracle": ["ORA-", "java.sql.sqlexception", "oracle.jdbc"],
    "SQLite": ["sqlite_error", "unrecognized token", "no such column"],
}


@dataclass
class Probe:
    label: str
    kind: str
    payload: str


PROBES: List[Probe] = [
    Probe("quote-break", "error", "'"),
    Probe("double-quote", "error", '"'),
    Probe("paren-bomb", "error", "'(("),
    Probe("boolean-true", "boolean_true", "' OR '1'='1"),
    Probe("boolean-false", "boolean_false", "' AND '1'='2"),
    Probe("numeric-true", "boolean_true", " OR 1=1--"),
    Probe("numeric-false", "boolean_false", " AND 1=2--"),
    Probe("time-sleep", "time", " OR SLEEP(2)--"),
    Probe("time-pg", "time", " OR pg_sleep(2)--"),
    Probe("union-nulls", "union", "' UNION SELECT NULL,NULL,NULL--"),
]


@dataclass
class VulnParam:
    parameter: str
    source: str
    confirmed: bool
    injection_types: List[str] = field(default_factory=list)
    db_flavor: str = ""
    evidence: str = ""
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "parameter": self.parameter,
            "source": self.source,
            "confirmed": self.confirmed,
            "injection_types": self.injection_types,
            "db_flavor": self.db_flavor,
            "evidence": self.evidence,
            "latency_ms": self.latency_ms,
        }


class Scanner:
    def __init__(self, progress: Optional[Callable[[str], None]] = None,
                 timeout: float = 10.0, delay: float = 0.5,
                 verify_tls: bool = True):
        self.progress = progress or (lambda m: None)
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers["User-Agent"] = UA
        self.session.verify = verify_tls
        self._true_fp: Optional[str] = None

    def _log(self, msg: str):
        self.progress(msg)

    @staticmethod
    def _fingerprint(r: requests.Response) -> str:
        body = r.text[:4000] if r.text else ""
        return f"{r.status_code}:{len(r.content)}:{hash(body)}"

    @staticmethod
    def _hit_db(text: str) -> List[str]:
        low = text.lower()
        return [flavor for flavor, markers in _DB_ERROR_MARKERS.items()
                if any(m in low for m in markers)]

    def _probe(self, target: str, param: str, value: str, method: str,
               params: Dict[str, str], body: Dict[str, str]):
        injected = dict(params)
        if method.upper() == "GET":
            injected[param] = value
            return self.session.get(target, params=injected, timeout=self.timeout)
        b = dict(body)
        b[param] = value
        return self.session.post(target, data=b, params=params, timeout=self.timeout)

    def scan(self, target: str, param: str, method: str = "GET",
             params: Optional[Dict[str, str]] = None,
             body: Optional[Dict[str, str]] = None) -> VulnParam:
        params = params or {}
        body = body or {}
        if param.startswith("path:"):
            return VulnParam(parameter=param, source="path", confirmed=False)

        base = self._probe(target, param, "1", method, params, body)
        base_fp = self._fingerprint(base)
        base_time = base.elapsed.total_seconds()
        self._true_fp = base_fp

        types: List[str] = []
        db = ""
        evidence = ""
        max_lat = 0
        seen = set()

        for p in PROBES:
            if p.payload in seen:
                continue
            seen.add(p.payload)
            try:
                r = self._probe(target, param, p.payload, method, params, body)
            except requests.RequestException as exc:
                self._log(f"  probe {p.label!r} failed: {exc}")
                continue
            if self.delay:
                time.sleep(self.delay)
            latency = r.elapsed.total_seconds()
            max_lat = max(max_lat, int(latency * 1000))
            fp = self._fingerprint(r)
            hit = self._hit_db(r.text if r.text else "")

            if hit and not db:
                db = hit[0]
            if hit and p.kind not in ("time", "boolean_true", "boolean_false"):
                types.append(p.kind)
                evidence = f"DB error marker ({hit[0]}) on {p.label}"

            if p.kind == "boolean_true":
                self._true_fp = fp
            elif p.kind == "boolean_false":
                if self._true_fp and fp != self._true_fp:
                    if "boolean" not in types:
                        types.append("boolean")
                        evidence = "differential response 1=1 vs 1=2"
            elif p.kind == "time" and latency - base_time >= 1.5:
                if "time" not in types:
                    types.append("time")
                    evidence = (f"latency {int(latency*1000)}ms vs baseline "
                                f"{int(base_time*1000)}ms")

        confirmed = bool(types)
        source = "query" if method.upper() == "GET" else "body"
        return VulnParam(parameter=param, source=source, confirmed=confirmed,
                         injection_types=types, db_flavor=db,
                         evidence=evidence, latency_ms=max_lat)

    def scan_params(self, target: str, param_names: List[str], method: str = "GET",
                    params: Optional[Dict[str, str]] = None,
                    body: Optional[Dict[str, str]] = None) -> List[VulnParam]:
        results: List[VulnParam] = []
        for name in param_names:
            self._log(f"-- param: {name}")
            results.append(self.scan(target, name, method, params, body))
        return results


SCAN_APPROVAL_HINT = ("Targets must be explicitly approved. Only scan targets you "
                      "own or are authorized to test (ARCHITECTURE.md 5.5).")