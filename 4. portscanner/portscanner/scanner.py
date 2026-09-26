"""Scan orchestrator: wires config → resolver → scheduler → service pass → report.

One Scan object per run; no global state.
"""
from __future__ import annotations

import signal
from datetime import datetime, timezone

from .config import Config
from .events import EventBus, ServiceFoundEvent, WarningEvent
from .report import render
from .resolver import TargetResolver
from .scheduler import Scheduler
from .security import audit_scan_finished, audit_scan_started
from .service import ServiceDetector
from .store import ResultStore


class Scanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.bus = EventBus()
        self.store = ResultStore(
            wal_path=config.resume_wal or "scan.wal",
            resume=bool(config.resume_wal),
        )
        self.store.attach(self.bus)
        self.detector = ServiceDetector(timeout_s=max(1.0, config.timeout_s * 2))
        self.warnings: list[str] = []
        self._stop = False

    # ---------- public ----------
    def run(self) -> str:
        """Execute the scan and return formatted output."""
        audit_scan_started(self.config)
        resolver = TargetResolver(list(self.config.targets),
                                  list(self.config.exclude))
        scheduler = Scheduler(self.config, resolver, self.bus)
        scheduler._result_sink = self._collect  # final-report hook

        prev_int = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, self._on_sigint)
        except ValueError:  # non-main thread (GUI mode)
            pass

        try:
            stats = scheduler.run()
        finally:
            try:
                signal.signal(signal.SIGINT, prev_int)
            except (ValueError, TypeError):
                pass

        # NOTE: the WAL must stay open through the service pass and report
        # render — closing it earlier made every service-detected scan crash
        # with "I/O operation on closed file" (fixed 2026-09-12).
        try:
            if self.config.service_detect:
                self._service_pass()

            meta = {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "config": self._public_config(),
                "stats": {
                    "probes_sent": sum(len(self.config.ports) * 1 for _ in [0]),
                    "counts": stats["counts"],
                    "duration_s": stats["duration_s"],
                    "warnings": stats["warnings"],
                },
            }
            hosts = self._host_report(resolver)
            output = render(self.config.output_format, hosts, meta)
            audit_scan_finished(
                f"targets={len(hosts)} "
                f"open={stats['counts'].get(str(__import__('portscanner.models', fromlist=['PortState']).PortState.OPEN), 0)} "
                f"dur={stats['duration_s']}s"
            )
            return output
        finally:
            self.store.close()

    def stop(self) -> None:
        self._stop = True

    # ---------- internals ----------
    def _collect(self, result) -> None:
        pass  # results arrive via bus → store; hook kept for streaming UIs

    def _on_sigint(self, signum, frame) -> None:
        self.warnings.append("interrupted — partial results saved (resume with --resume)")
        self.store_close_once()

    def store_close_once(self) -> None:
        pass  # scheduler.stop() drains workers; store closed in run()'s finally

    def _service_pass(self) -> None:
        """Second pass on open ports only (keeps hot loop fast, §4.5)."""
        for r in self.store.open_ports():
            if self._stop:
                break
            svc = self.detector.identify(r.host, r.port, str(r.proto))
            if svc:
                self.store.add_service(svc)
                self.bus.publish(ServiceFoundEvent(
                    host=svc.host, port=svc.port, service=svc.service))

    def _public_config(self) -> dict:
        """Sanitized config for reports (no secrets — security.md)."""
        return {
            "targets": list(self.config.targets),
            "ports": f"{len(self.config.ports)} ports",
            "scan_type": str(self.config.scan_type),
            "workers": self.config.workers,
            "rate_limit": self.config.rate_limit,
            "timeout_s": self.config.timeout_s,
            "service_detect": self.config.service_detect,
        }

    def _host_report(self, resolver: TargetResolver) -> list[dict]:
        by_host: dict[str, dict] = {}
        for r in self.store.results.values():
            h = by_host.setdefault(r.host, {"ip": r.host, "hostname": r.hostname,
                                            "ports": [], "services": []})
            h["ports"].append({
                "port": r.port, "proto": str(r.proto),
                "state": str(r.state), "ts": r.ts,
            })
        for (host, port), svc in self.store.services.items():
            if host in by_host:
                by_host[host]["services"].append(svc.to_dict())
        return sorted(by_host.values(), key=lambda h: h["ip"])
