"""Collection engine: coordinates discovery, extraction, hashing and auditing."""
from __future__ import annotations

import os
import time
from typing import Callable, Dict, List, Optional

from sec import compliance
from sec.audit import AuditLogger
from sec.integrity import build_manifest, new_scan_id, sha256_file

from . import decrypt, extractors, paths
from .models import BrowserProfile, EvidenceItem, ScanOptions, ScanResult

Progress = Optional[Callable[[str, float], None]]

# Categories whose source is a single SQLite/JSON file worth hashing.
_HASHABLE = {"history", "downloads", "cookies", "bookmarks", "autofill",
             "logins", "search_terms"}


class Engine:
    """Runs a full read-only collection pass over selected browser profiles."""

    def __init__(self, options: ScanOptions, logger: AuditLogger,
                 progress: Progress = None):
        self.options = options
        self.log = logger
        self.progress = progress
        self._key_cache: Dict[str, tuple] = {}

    # ------------------------------------------------------------------
    def _report(self, message: str, fraction: float) -> None:
        if self.progress:
            try:
                self.progress(message, max(0.0, min(1.0, fraction)))
            except Exception:  # noqa: BLE001
                pass

    def _master_key(self, profile: BrowserProfile) -> Optional[bytes]:
        if profile.kind != "chromium" or not profile.key_file:
            return None
        cached = self._key_cache.get(profile.user_data or profile.key_file)
        if cached is None:
            key, status = decrypt.load_master_key(profile.key_file)
            cached = (key, status)
            self._key_cache[profile.user_data or profile.key_file] = cached
            if key:
                self.log.info("key.unwrapped", "Chromium master key unwrapped",
                              browser=profile.browser, status=status)
            else:
                self.log.warning("key.unavailable", "Master key unavailable",
                                 browser=profile.browser, status=status)
        return cached[0]

    # ------------------------------------------------------------------
    def discover(self) -> List[BrowserProfile]:
        self._report("Discovering browser profiles...", 0.02)
        found = paths.discover_browsers()
        self.log.info("discovery.complete", f"{len(found)} profile(s) discovered",
                      profiles=[p.label for p in found])
        return found

    # ------------------------------------------------------------------
    def run(self, profiles: Optional[List[BrowserProfile]] = None) -> ScanResult:
        scan = ScanResult(scan_id=new_scan_id(), started_at=_now_iso(),
                          operator=self.log.actor)
        t0 = time.time()

        if profiles is None:
            profiles = self.discover()
        if self.options.profile_filter:
            wanted = set(self.options.profile_filter)
            profiles = [p for p in profiles if p.label in wanted]
        scan.browsers = profiles

        self.log.notice("scan.start", "Collection started",
                        scan_id=scan.scan_id, categories=self.options.categories,
                        decrypt_secrets=self.options.decrypt_secrets,
                        profiles=[p.label for p in profiles])

        categories = [c for c in self.options.categories]
        total_steps = max(len(profiles) * max(len(categories), 1), 1)
        step = 0

        for profile in profiles:
            for category in categories:
                step += 1
                fraction = 0.05 + 0.9 * (step / total_steps)
                self._report(f"{profile.label}: {category}...", fraction)
                try:
                    records, source = self._collect(profile, category)
                except Exception as exc:  # noqa: BLE001
                    msg = f"{profile.label}/{category}: {exc}"
                    scan.errors.append(msg)
                    self.log.error("collect.error", msg)
                    continue

                if records:
                    scan.artifacts.setdefault(category, []).extend(records)
                if source:
                    self._record_evidence(scan, profile, category, source, len(records))

        self._finalise(scan, time.time() - t0)
        return scan

    # ------------------------------------------------------------------
    def _collect(self, profile: BrowserProfile, category: str):
        """Return (records, source_path) for one artifact category."""
        limit = self.options.max_records_per_category
        src = paths.artifact_path(profile, category)
        if not src:
            return [], ""

        chromium = profile.kind == "chromium"
        key = self._master_key(profile)
        dec = self.options.decrypt_secrets

        if category == "history":
            records = (extractors.extract_history_chromium(src, limit) if chromium
                       else extractors.extract_history_firefox(src, limit))
        elif category == "downloads":
            records = (extractors.extract_downloads_chromium(src, limit) if chromium
                       else extractors.extract_downloads_firefox(src, limit))
        elif category == "bookmarks":
            records = (extractors.extract_bookmarks_chromium(src) if chromium
                       else extractors.extract_bookmarks_firefox(src))
        elif category == "cookies":
            records = (extractors.extract_cookies_chromium(src, key, dec, limit) if chromium
                       else extractors.extract_cookies_firefox(src, dec, limit))
        elif category == "autofill":
            records = (extractors.extract_autofill_chromium(src, limit) if chromium
                       else extractors.extract_autofill_firefox(src, limit))
        elif category == "logins":
            records = (extractors.extract_logins_chromium(src, key, dec, limit) if chromium
                       else extractors.extract_logins_firefox(src, dec, limit))
        elif category == "search_terms":
            records = (extractors.extract_search_terms_chromium(src, limit) if chromium
                       else extractors.extract_search_terms_firefox(src, limit))
        elif category == "cache":
            records = (extractors.extract_cache_chromium(src, self.options.extract_cache_urls, limit)
                       if chromium else
                       extractors.extract_cache_firefox(src, self.options.extract_cache_urls, limit))
        else:
            return [], ""

        # Stamp provenance on every record for traceability.
        for rec in records:
            rec.setdefault("_browser", profile.browser)
            rec.setdefault("_profile", profile.profile)
        return records, src

    # ------------------------------------------------------------------
    def _record_evidence(self, scan: ScanResult, profile: BrowserProfile,
                         category: str, source: str, count: int) -> None:
        digest = ""
        if category in _HASHABLE and os.path.isfile(source):
            try:
                digest = sha256_file(source)
            except OSError as exc:
                scan.errors.append(f"hash failed for {source}: {exc}")
        elif os.path.isdir(source):
            digest = f"directory:{source}"
        item = EvidenceItem(
            category=category, source_path=source, source_sha256=digest,
            record_count=count, notes=f"{profile.label}",
        )
        scan.evidence.append(item)
        self.log.info("evidence.collected", f"{category} from {profile.label}",
                      records=count, sha256=digest[:16] + "..." if digest else "")

    # ------------------------------------------------------------------
    def _finalise(self, scan: ScanResult, elapsed: float) -> None:
        scan.finish()
        stats = {
            "profiles_scanned": len(scan.browsers),
            "categories_requested": len(self.options.categories),
            "total_records": sum(len(v) for v in scan.artifacts.values()),
            "elapsed_seconds": round(elapsed, 2),
            "per_category": {k: len(v) for k, v in scan.artifacts.items()},
        }
        scan.statistics = stats

        manifest = build_manifest(scan.evidence)
        scan.integrity = {
            "manifest": manifest,
            "compliance": compliance.assessment(),
            "audit_chain_valid": self.log.verify(),
            "audit_entries": len(self.log.entries),
        }
        self.log.notice("scan.complete", "Collection finished",
                        scan_id=scan.scan_id, records=stats["total_records"],
                        elapsed=stats["elapsed_seconds"])


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
