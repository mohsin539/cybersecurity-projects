"""Scheduler / concurrency engine (architecture.md §4.3, §6, §8).

Owns ALL concurrency: job generation (targets × ports), bounded worker pool,
global token-bucket rate limiting, per-host fairness caps, retries with
exponential backoff, and host-down pruning.
"""
from __future__ import annotations

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .engines import get_engine
from .events import (PortResultEvent, ScanFinished, ScanStarted, WarningEvent,
                     EventBus)
from .models import PortState, Proto, ProbeJob
from .ratelimit import BackoffPolicy, TokenBucket
from .resolver import TargetResolver

INCONCLUSIVE = {PortState.FILTERED, PortState.OPEN_FILTERED,
                PortState.CLOSED_FILTERED, PortState.UNREACHABLE}
HOST_DOWN_THRESHOLD = 12          # consecutive unreachable → prune host (§8)


class Scheduler:
    def __probes_for__(self):
        pass  # documented hook point; not used

    def __init__(self, config, resolver: TargetResolver, bus: EventBus) -> None:
        self.config = config
        self.resolver = resolver
        self.bus = bus
        self.engine = get_engine(config.scan_type.value)
        self.proto = Proto.UDP if config.scan_type == "udp" else Proto.TCP
        self.bucket = TokenBucket(config.rate_limit,
                                  burst=max(1, config.workers // 2))
        self.backoff = BackoffPolicy(config.timeout_s, config.jitter_ms)
        self.jobs: queue.Queue = queue.Queue(maxsize=config.workers * 4)  # back-pressure (§6)
        self.warnings: list[str] = []
        self._host_down: dict[str, int] = {}
        self._inflight: dict[str, int] = {}
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._start_ts = 0.0
        self.counts: dict[str, int] = {}

    # ---------- job generation (lazy, streaming) ----------
    def _generate_jobs(self) -> None:
        try:
            for target in self.resolver.expand():
                if self._stop.is_set():
                    break
                for port in self.config.ports:
                    if self._stop.is_set():
                        break
                    # per-host fairness cap: block if host has too many in-flight (§6)
                    while (not self._stop.is_set()
                           and self._inflight.get(target.ip, 0) >= self.config.per_host_cap):
                        with self._cond:
                            self._cond.wait(0.05)
                    if self._stop.is_set():
                        break
                    self.jobs.put(ProbeJob(target=target, port=port,
                                           proto=self.proto))
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"job generation error: {exc}")
            self._stop.set()
        finally:
            self.jobs.put(None)  # sentinel: generation done

    # ---------- workers ----------
    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                item = self.jobs.get(timeout=0.25)
            except queue.Empty:
                continue
            if item is None:
                self.jobs.put(None)  # re-share sentinel for other workers
                return
            job = item
            self._on_job_start(job)
            result = None
            try:
                self.bucket.acquire()
                result = self.engine.probe(job, self.config.timeout_s)
            except Exception as exc:  # noqa: BLE001 — engine crash must not kill worker
                self.warnings.append(f"probe error {job.target.ip}:{job.port}: {exc}")
                result = None
            finally:
                self._on_job_done(job)
            if result is not None:
                self._handle_result(job, result)

    def _on_job_start(self, job: ProbeJob) -> None:
        with self._cond:
            self._inflight[job.target.ip] = self._inflight.get(job.target.ip, 0) + 1

    def _on_job_done(self, job: ProbeJob) -> None:
        with self._cond:
            self._inflight[job.target.ip] -= 1
            if self._inflight[job.target.ip] <= 0:
                del self._inflight[job.target.ip]
            self._cond.notify_all()

    # ---------- result handling / state machine (§8) ----------
    def _handle_result(self, job: ProbeJob, result) -> None:
        self.counts[str(result.state)] = self.counts.get(str(result.state), 0) + 1
        settled = result.state not in INCONCLUSIVE or job.attempt >= self.config.retries
        if not settled:
            # exponential backoff, then re-enqueue (§8 RETRYING)
            threading.Timer(
                self.backoff.delay(job.attempt),
                self._retry, args=(job,),
            ).start()
            return
        if result.state == PortState.UNREACHABLE:
            self._host_down[job.target.ip] = self._host_down.get(job.target.ip, 0) + 1
        self.bus.publish(PortResultEvent(
            host=result.host, port=result.port, proto=str(result.proto),
            state=str(result.state), rtt_ms=result.rtt_ms,
        ))
        # Store write happens via bus subscriber; direct hook for final report:
        if getattr(self, "_result_sink", None):
            self._result_sink(result)

    def _retry(self, job: ProbeJob) -> None:
        if self._stop.is_set():
            return
        job.attempt += 1
        try:
            self.jobs.put(job, timeout=1.0)
        except queue.Full:
            self.warnings.append(f"retry dropped (queue full): {job.target.ip}:{job.port}")

    # ---------- lifecycle ----------
    def run(self) -> dict:
        self._start_ts = time.monotonic()
        targets = list(self.resolver.expand())  # snapshot for progress reporting
        self.bus.publish(ScanStarted(targets=len(targets),
                                     ports=len(self.config.ports),
                                     engine=self.engine.name))
        gen = threading.Thread(target=self._generate_jobs, name="jobgen", daemon=True)
        gen.start()
        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            futures = [pool.submit(self._worker) for _ in range(min(self.config.workers, 512))]
            for f in futures:
                f.result()
        gen.join(timeout=5.0)
        duration = time.monotonic() - self._start_ts
        self.bus.publish(ScanFinished(duration_s=duration, counts=self.counts,
                                      warnings=len(self.warnings)))
        return {
            "duration_s": round(duration, 2),
            "counts": self.counts,
            "warnings": self.warnings,
        }

    def stop(self) -> None:
        """Ctrl-C path: stop issuing, drain quickly, keep partial results (§10)."""
        self._stop.set()
        with self._cond:
            self._cond.notify_all()
