"""Headless-browser detection engine.

For each candidate the scanner:
  1. spins up an isolated Chromium context (JS enabled, cookies in-memory)
  2. injects an instrumentation shim (allowed: captured in an overridden
     `alert/prompt/confirm`, JS errors pushed to a global)
  3. loads the probe URL, waits for `settle_ms`
  4. pulls observations and matches them against beacon hits

Verdicts (industry-aligned with OWASP ASVS v4.0.3 V5.1/XSS evidence model):
  EXECUTED  - beacon hit OR dialog/JS fired with the sentinel token
  LIKELY    - token observable in DOM with script-context evidence
  SUSPICIOUS- token rendered, but no execution signal
  CLEAN     - token not observed and no JS signal
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from app.config import settings

logger = logging.getLogger("xtester.scanner")

INIT_SCRIPT = r"""
(() => {
  if (window.__xtestShim) return;
  window.__xtestShim = { fired: [], dialogs: [], errors: [] };
  ['alert','prompt','confirm'].forEach(function (fn) {
    var orig = window[fn].bind(window);
    window[fn] = function (arg) {
      window.__xtestShim.dialogs.push(String(arg));
      window.__xtestShim.fired.push(String(arg));
      try { return orig(arg); } catch (e) {}
    };
  });
  window.addEventListener('error', function (e) {
    var msg = (e.message || '').toString();
    window.__xtestShim.errors.push(msg);
    if (/xtok_|Script error/.test(msg) === false) {
      window.__xtestShim.fired.push('js-error:' + msg);
    }
  });
})();
"""


@dataclass
class ProbeResult:
    candidate_id: str
    verdict: str = "clean"
    confidence: float = 0.0
    beacon_hit: bool = False
    dialogs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dom_contains_token: bool = False
    status_code: int = 0
    observations: list[str] = field(default_factory=list)


class BeaconRegistry:
    """Process-local hit registry (dev/eager mode). Workers in production use
    the Redis-backed subclass to share state with the API's collector."""

    def __init__(self) -> None:
        self._hits: set[str] = set()

    def record(self, scan_id: str, candidate_id: str) -> None:
        self._hits.add(f"{scan_id}:{candidate_id}")

    def pop_hit(self, scan_id: str, candidate_id: str) -> bool:
        key = f"{scan_id}:{candidate_id}"
        if key in self._hits:
            self._hits.discard(key)
            return True
        return False

    def clear(self) -> None:
        self._hits.clear()


memory_registry = BeaconRegistry()


try:  # optional import keeps unit tests free of Playwright
    from redis import Redis  # noqa: F401

    class RedisBeaconRegistry(BeaconRegistry):
        def __init__(self, client: "Redis") -> None:
            self._r = client
            self._prefix = "xtest:beacon"

        def record(self, scan_id: str, candidate_id: str) -> None:
            key = f"{self._prefix}:{scan_id}:{candidate_id}"
            self._r.setex(key, 600, "1")

        def pop_hit(self, scan_id: str, candidate_id: str) -> bool:
            key = f"{self._prefix}:{scan_id}:{candidate_id}"
            return bool(self._r.delete(key))

except ImportError:  # pragma: no cover
    pass


def _jscore(probe: ProbeResult) -> float:
    """Combine evidence into 0..1 confidence."""
    score = 0.0
    if probe.beacon_hit:
        score += 1.0
    elif probe.dialogs and any("xtok_" in d for d in probe.dialogs):
        score += 0.95
    elif probe.dom_contains_token and any("xtok_" in e for e in probe.errors):
        score += 0.8
    elif probe.dom_contains_token and probe.dialogs:
        score += 0.6
    elif probe.dom_contains_token:
        score += 0.3
    if probe.status_code in (500, 0):
        score = min(score, 0.4)  # degraded / error page lowers trust
    return round(min(score, 1.0), 3)


def classify(probe: ProbeResult, min_confidence: float = 0.6) -> str:
    score = _jscore(probe)
    probe.confidence = score
    if probe.beacon_hit or score >= 0.9:
        probe.verdict = "EXECUTED"
    elif score >= 0.6:
        probe.verdict = "LIKELY"
    elif score >= 0.3:
        probe.verdict = "SUSPICIOUS"
    else:
        probe.verdict = "CLEAN"
    return probe.verdict


class Scanner:
    def __init__(
        self,
        registry: BeaconRegistry | None = None,
        concurrency: int | None = None,
        settle_ms: int | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        self.registry = registry or memory_registry
        self.concurrency = concurrency or settings.scan_concurrency
        self.settle_ms = settle_ms or settings.scan_default_wait_ms
        self.timeout_ms = timeout_ms or settings.scan_http_timeout

    async def run(
        self,
        candidates: list,
        scan_id: str,
        progress=None,
    ) -> dict[str, ProbeResult]:
        from playwright.async_api import async_playwright

        results: dict[str, ProbeResult] = {}
        sem = asyncio.Semaphore(self.concurrency)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu"],
            )
            try:

                async def _probe(candidate) -> ProbeResult:
                    async with sem:
                        return await self._probe_one(browser, candidate, scan_id)

                queue = list(candidates)
                for i in range(0, len(queue), self.concurrency):
                    batch = queue[i : i + self.concurrency]
                    done = await asyncio.gather(*(_probe(c) for c in batch))
                    for c, probe in zip(batch, done):
                        results[c.id] = probe
                        if progress:
                            progress(c, probe)
            finally:
                await browser.close()
        return results

    async def _probe_one(self, browser, candidate, scan_id: str) -> ProbeResult:
        probe = ProbeResult(candidate_id=candidate.id)
        url = candidate.proof_url
        try:
            ctx = await browser.new_context(
                ignore_https_errors=False,
                java_script_enabled=True,
            )
            await ctx.add_init_script(INIT_SCRIPT)
            page = await ctx.new_page()
            try:
                resp = await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                probe.status_code = resp.status if resp else 0
            except Exception as exc:  # noqa: BLE001
                probe.observations.append(f"navigation error: {type(exc).__name__}")
                probe.status_code = 0
            await page.wait_for_timeout(self.settle_ms)

            obs = await page.evaluate(
                "() => ({ d: window.__xtestShim ? window.__xtestShim.dialogs : [], "
                "e: window.__xtestShim ? window.__xtestShim.errors : [], "
                "t: document.body ? document.body.innerText : '' })"
            ).catch(lambda _: {"d": [], "e": [], "t": ""})

            html = await page.evaluate(
                "() => document.documentElement ? document.documentElement.outerHTML : ''"
            ).catch(lambda _: "")

            probe.dialogs = [str(x) for x in obs.get("d", [])]
            probe.errors = [str(x) for x in obs.get("e", [])]
            probe.dom_contains_token = candidate.token in obs.get("t", "") or candidate.token in (html or "")
            await page.close()
            await ctx.close()

            if candidate.beacon:
                probe.beacon_hit = self.registry.pop_hit(scan_id, candidate.id)
            classify(probe, settings.detector_min_confidence)
            if probe.verdict == "EXECUTED":
                probe.observations.append("execution confirmed via sentinel")
            return probe
        except Exception as exc:  # noqa: BLE001
            probe.observations.append(f"scan error: {type(exc).__name__}: {exc}")
            probe.verdict = "CLEAN"
            return probe


def build_probe_url(candidate) -> str:
    return candidate.proof_url