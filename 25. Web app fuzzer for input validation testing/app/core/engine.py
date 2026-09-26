"""Web App Fuzzer - scan engine (discovery, planning, execution, detection)."""
from __future__ import annotations

import json
import os
import random
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional

from .detectors import detect
from .discovery import Discovery
from .framemap import module_meta
from .http_client import Session
from .models import Endpoint, Finding, FuzzCase
from .payloads import load_payloads, new_marker


@dataclass
class ScanConfig:
    url: str = ""
    auth_cookie: str = ""
    auth_header: str = ""
    extra_headers: str = ""
    max_pages: int = 10
    max_requests: int = 500
    concurrency: int = 4
    delay_ms: int = 100
    timeout: int = 15
    verify_tls: bool = True
    proxy: str = ""
    seed: int = 20260919
    modules: List[str] = field(default_factory=list)
    user_agent: str = "WebAppFuzzer/1.0 (authorized security-testing only)"
    notes: str = ""


class Engine:
    def __init__(
        self,
        config: ScanConfig,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        audit_dir: str = "",
    ) -> None:
        self.config = config
        self._on_progress = on_progress or (lambda *_: None)
        self._on_log = on_log or (lambda *_: None)
        self._on_finding = on_finding or (lambda *_: None)
        self._audit_dir = audit_dir
        self._stop = threading.Event()
        self._rng = random.Random(config.seed)
        self._findings: List[Finding] = []
        self._requests = 0
        self.run_id = f"RUN-{int(time.time() * 1000)}"
        self._started = time.time()

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    @property
    def requests(self) -> int:
        return self._requests

    def run(self) -> List[Finding]:
        session = self._build_session()
        self._audit("scan_start", {"url": self.config.url, "modules": self.config.modules})
        self._log(f"[discover] starting crawl of {self.config.url}")

        endpoints, urls = Discovery(session, max_pages=self.config.max_pages).crawl(self.config.url)
        self._log(f"[discover] {len(endpoints)} endpoints, {len(urls)} urls found")

        cases = self._plan(endpoints)
        if self.stopped:
            self._audit("scan_end", {"status": "stopped"})
            return self._findings
        self._log(f"[fuzz] {len(cases)} fuzz cases planned")

        baselines: Dict[str, tuple] = {}
        total = len(cases)
        lock = threading.Lock()
        done = [0]

        def completed() -> None:
            with lock:
                done[0] += 1
                self._requests += 1
                d = done[0]
            self._on_progress(d, total)
            time.sleep(self.config.delay_ms / 1000.0)

        def worker(case: FuzzCase) -> None:
            if self.stopped:
                return
            base = baselines.get(case.url)
            if base is None:
                raw = dict(case.params)
                raw.pop(case.param_name, None)
                base = self._send(session, case.method, case.url, raw)
                baselines[case.url] = base
            b_status, b_body, b_headers, b_time = base
            if isinstance(b_status, int) and b_status >= 500:
                self._audit("skip", {"url": case.url, "reason": "baseline 5xx"})
                return
            result = self._send(session, case.method, case.url, dict(case.params))
            self._audit_request(case, result)
            a_status, a_body, a_headers, a_time = result
            hit = detect(
                module=case.module,
                payload_id=case.payload_id,
                payload=case.payload,
                marker=case.marker,
                baseline={"status": b_status, "body": b_body or "", "headers": b_headers or {}, "time": b_time or 0.0},
                actual={"status": a_status, "body": a_body or "", "headers": a_headers or {}, "time": a_time or 0.0},
            )
            if hit:
                severity, confidence, evidence = hit
                meta = module_meta(case.module)
                finding = Finding(
                    module=case.module,
                    title=str(meta.get("title", case.module)),
                    severity=severity,
                    confidence=confidence,
                    owasp=str(meta.get("owasp", "")),
                    cwes=list(meta.get("cwes", [])),
                    nist_controls=list(meta.get("nist", [])),
                    iso_controls=list(meta.get("iso", [])),
                    ssdf_tasks=list(meta.get("ssdf", [])),
                    remediation=str(meta.get("remediation", "")),
                    evidence={**evidence, "response_status": a_status, "response_bytes": len(a_body or "")},
                    url=case.url,
                    param=case.param_name,
                    payload_id=case.payload_id,
                )
                with lock:
                    self._findings.append(finding)
                self._audit("finding", {"module": case.module, "severity": severity, "url": case.url, "param": case.param_name, "payload": case.payload_id, "confidence": confidence})
                self._on_finding(finding)
            completed()

        with ThreadPoolExecutor(max_workers=max(1, int(self.config.concurrency))) as pool:
            futs = [pool.submit(worker, c) for c in cases]
            for fut in futs:
                if self.stopped:
                    break

        self._log(f"[done] {self._requests} requests, {len(self._findings)} findings")
        self._audit("scan_end", {"status": "stopped" if self.stopped else "completed", "requests": self._requests, "findings": len(self._findings)})
        return self._findings

    def _send(self, session: Session, method: str, url: str, params: Dict[str, str]):
        if method.upper() == "GET":
            return session.request("GET", url, params=params)
        return session.request("POST", url, params=None, data=params)

    def _build_session(self) -> Session:
        cookies: Dict[str, str] = {}
        if self.config.auth_cookie and "=" in self.config.auth_cookie:
            for pair in self.config.auth_cookie.split(";"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    cookies[k.strip()] = v.strip()
        headers: Dict[str, str] = {}
        if self.config.auth_header and ":" in self.config.auth_header:
            k, _, v = self.config.auth_header.partition(":")
            headers[k.strip()] = v.strip()
        if self.config.extra_headers:
            for line in self.config.extra_headers.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers.setdefault(k.strip(), v.strip())
        return Session(
            user_agent=self.config.user_agent,
            timeout=self.config.timeout,
            verify_tls=self.config.verify_tls,
            proxy=self.config.proxy or None,
            cookies=cookies,
            extra_headers=headers,
        )

    def _plan(self, endpoints: List[Endpoint]) -> List[FuzzCase]:
        cases: List[FuzzCase] = []
        for mod in self.config.modules:
            for payload_id, template in load_payloads(mod):
                for ep in endpoints:
                    for param in ep.params:
                        marker = self._rng_marker()
                        payload = template.replace("{marker}", marker)
                        params = {p.name: p.value for p in ep.params}
                        params[param.name] = payload
                        cases.append(
                            FuzzCase(
                                module=mod,
                                payload_id=payload_id,
                                payload=payload,
                                marker=marker,
                                method=ep.method.upper() or "GET",
                                url=ep.url,
                                param_name=param.name,
                                location=param.location,
                                params=params,
                            )
                        )
                        if len(cases) >= self.config.max_requests:
                            self._log(f"[plan] capped at {self.config.max_requests} fuzz cases")
                            return cases
        return cases

    def _rng_marker(self) -> str:
        return new_marker()

    def _log(self, line: str) -> None:
        self._on_log(line)
        self._audit("log", {"line": line})

    def _audit(self, event: str, data: Dict) -> None:
        if not self._audit_dir:
            return
        try:
            os.makedirs(self._audit_dir, exist_ok=True)
            entry = {"ts": datetime.utcnow().isoformat(), "run": self.run_id, "event": event, **data}
            with open(os.path.join(self._audit_dir, "audit.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def _audit_request(self, case: FuzzCase, result) -> None:
        self._audit("request", {"module": case.module, "payload": case.payload_id, "url": case.url, "param": case.param_name, "status": result[0]})

    def summary(self) -> Dict:
        return {
            "run_id": self.run_id,
            "started": datetime.fromtimestamp(self._started).isoformat(),
            "requests": self._requests,
            "findings": len(self._findings),
            "stopped": self.stopped,
        }