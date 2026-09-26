"""StaticLab analysis pipeline: orchestrates hashing -> entropy -> PE parsing -> strings -> lookups -> verdict."""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from .audit import AuditStore
from .entropy import shannon_entropy
from .hashing import hash_file, pe_derived_hashes
from .lookups import run_lookups
from .model import AnalysisResult, HashBundle, StringHit, ThreatReport
from .pe_parser import parse_pe
from .strings_extractor import extract_strings

Progress = Optional[Callable[[int, int, str], None]]  # (stage_no, total, label)


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _magic_hint(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if head[:2] == b"MZ" and head[0x3C:0x40] != b"\x00" * 4:
            return "PE executable (DOS/MZ)"
        if head[:4] == b"\x7fELF":
            return "ELF executable"
        if head[:4] == b"\xca\xfe\xba\xbe":
            return "Mach-O (universal)"
        if head[:4] == b"\xcf\xfa\xed\xfe":
            return "Mach-O 64"
        return "binary (unknown magic)"
    except OSError:
        return None


def analyze(
    file_path: str,
    config: Optional[dict] = None,
    audit: Optional[AuditStore] = None,
    progress: Progress = None,
    min_string_len: int = 4,
    lookups_enabled: Optional[list[str]] = None,
) -> AnalysisResult:
    """Run the full static pipeline and return an AnalysisResult."""
    config = config or {}
    result = AnalysisResult(
        analysis_id=f"an-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}",
        file_path=file_path,
        file_name=os.path.basename(file_path),
        file_size=os.path.getsize(file_path),
        magic_hint=_magic_hint(file_path),
        stat_created=_iso(os.path.getctime(file_path)),
        stat_modified=_iso(os.path.getmtime(file_path)),
    )
    result.stage("pipeline_start")
    progress and progress(1, 8, "Reading & hashing file (MD5/SHA1/SHA256/SHA512)")

    with open(file_path, "rb") as f:
        data = f.read()

    digests = hash_file(file_path)
    derived = pe_derived_hashes(file_path)
    result.hashes = HashBundle(
        md5=digests["md5"],
        sha1=digests["sha1"],
        sha256=digests["sha256"],
        sha512=digests["sha512"],
        imphash=derived.get("imphash"),
        authentihash=derived.get("authentihash"),
    )
    result.hashes.entropy = round(shannon_entropy(data), 4)
    result.stage("hashing")

    progress and progress(2, 8, "PE header parsing")
    pe = parse_pe(file_path)
    result.pe = pe
    result.stage("pe_headers")

    progress and progress(3, 8, "Entropy analysis")
    result.stage("entropy")

    progress and progress(4, 8, "Strings extraction")
    result.strings = extract_strings(data, min_len=min_string_len, include_unicode=True)
    result.suspicious_strings = [s for s in result.strings if s.flags][:3000]
    result.stage("strings")

    progress and progress(5, 8, "Verdict scoring (local heuristics)")
    _score_local(result, data)
    result.stage("scoring")

    progress and progress(6, 8, "Threat-intel lookups")
    if lookups_enabled:
        result.lookups = run_lookups(
            result.hashes.sha256,
            config,
            enabled=lookups_enabled,
            progress=lambda name, status: progress and progress(6, 8, f"lookup {name} {status}"),
        )
        for r in result.lookups:
            if r.score:
                _score_external(result, r)
    result.stage("lookups")

    progress and progress(7, 8, "Audit log (append-only chain)")
    if audit and result.hashes:
        detail = {
            "file": result.file_name,
            "sha256": result.hashes.sha256,
            "score": result.score,
            "verdict": result.verdict_key,
            "suspicious_strings": len([s for s in result.suspicious_strings if "suspicious" in s.flags]),
        }
        result.audit_chain_hash = audit.append(
            "analysis.complete", result.file_name, json_dumps(detail)
        )
        ok, issues = audit.verify_chain()
        result.audit_verified = ok
    result.stage("audit")

    result.finalize()
    progress and progress(8, 8, "Done")
    return result


def json_dumps(obj) -> str:
    import json

    return json.dumps(obj, default=str, sort_keys=True)


# ---------------------------------------------------------------------------
# Local heuristic scoring
# ---------------------------------------------------------------------------

_SUSPECT_IMPORTS = ("GetProcAddress", "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
                    "CreateRemoteThread", "LoadLibrary", "CryptDecrypt", "RegSetValueEx",
                    "CreateService", "ShellExecute")


def _score_local(result: AnalysisResult, data: bytes) -> None:
    pe = result.pe
    if result.hashes:
        ent = result.hashes.entropy
        if ent >= 7.4:
            result.score += 12 if ent >= 7.8 else 8
    sus = result.suspicious_strings
    n = len([s for s in sus if "suspicious" in s.flags])
    n_url = len([s for s in sus if "url" in s.flags])
    result.score += min(20, n * 3)
    result.score += min(10, n_url * 2)
    if pe and pe.valid:
        if pe.overlay_size > 0:
            result.score += 4 if not pe.overlay_pe_embedded else 12
        import_names = [f for _, funcs in pe.imports for f in funcs]
        overlap = set(import_names) & set(_SUSPECT_IMPORTS)
        result.score += min(15, len(overlap) * 3)
        ent_sections = [s.entropy for s in pe.sections]
        if ent_sections and max(ent_sections) >= 7.5 and not result.pe.is_signed:
            result.score += 6
        if not result.pe.is_signed and result.pe.is_pe:
            result.score += 3
    result.score = max(0, min(70, result.score))  # external lookups add up to +30


def _score_external(result: AnalysisResult, report: ThreatReport) -> None:
    if report.score is None:
        return
    result.score += report.score // 3  # normalize a 100 to ~33


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def strings_text(result: AnalysisResult, include_all: bool = False) -> str:
    hits = result.strings if include_all else result.suspicious_strings or result.strings[:500]
    return "".join(f"[{h.encoding}:0x{h.offset:x}] {h.value}\n" for h in hits)