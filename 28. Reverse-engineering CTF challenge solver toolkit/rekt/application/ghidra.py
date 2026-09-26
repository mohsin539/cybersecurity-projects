"""Ghidra headless bridge (ARCHITECTURE.md §3.4, M2).

Runs Ghidra's analyzeHeadless against a COPY of the sample inside the job
scratch dir, with the ExportDecomp post-script. Consent-gated at the GUI
(JobKind.GHIDRA); audited; hard timeout; never modifies the original sample.

Ghidra location resolution order:
  1. REKT_GHIDRA_HOME env var (install root containing support/analyzeHeadless*)
  2. --ghidra-home passed via GUI picker
No download happens in v1.0 (offline-first, A10): the user installs Ghidra.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "backends" / "ghidra_scripts" / "ExportDecomp.java"
_FUNC_SEP = re.compile(r"^// ==== (.+?) @ (0x[0-9a-fA-F]+)\s*$", re.M)
MAX_DECOMP_CHARS = 2 * 1024 * 1024


@dataclass
class GhidraHome:
    root: Path

    def analyzer(self) -> Path:
        ext = ".bat" if sys.platform == "win32" else ""
        return self.root / "support" / f"analyzeHeadless{ext}"


def find_ghidra() -> GhidraHome | None:
    """Locate a local Ghidra install (env var only — no network, A10)."""
    root = os.environ.get("REKT_GHIDRA_HOME", "")
    if root and (Path(root) / "support").exists():
        return GhidraHome(Path(root))
    return None


def find_ghidra_from_path(path: str) -> GhidraHome | None:
    """Validate a user-supplied Ghidra install root (GUI picker or env)."""
    if not path:
        return find_ghidra()
    root = Path(path)
    if (root / "support").exists():
        return GhidraHome(root)
    return None


def build_command(home: GhidraHome, project_dir: Path, sample_copy: Path,
                  out_c: Path) -> list[str]:
    """argv list — no shell (OWASP A03). Auditable/inspectable."""
    return [
        str(home.analyzer()),
        str(project_dir), "rekt_job",          # project location + name
        "-import", str(sample_copy),
        "-scriptPath", str(_SCRIPT.parent),
        "-postScript", "ExportDecomp.java", str(out_c),
        "-deleteProject",
    ]


def run_headless(home: GhidraHome, sample_copy: Path, scratch: Path,
                 timeout_s: int = 600) -> tuple[bool, str, list[dict]]:
    """Run Ghidra headless. Returns (ok, decompiled_text, function_index)."""
    out_c = scratch / "decomp.c"
    project_dir = scratch / "ghidra_proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    cmd = build_command(home, project_dir, sample_copy, out_c)
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell
            cmd, capture_output=True, timeout=timeout_s,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except subprocess.TimeoutExpired:
        return False, f"ghidra exceeded {timeout_s}s — killed", []
    except OSError as e:
        return False, f"ghidra launch failed: {e}", []
    if proc.returncode != 0 or not out_c.exists():
        tail = (proc.stderr or b"")[-800:].decode("utf-8", "replace")
        return False, f"ghidra failed rc={proc.returncode}: {tail}", []
    text = out_c.read_text(encoding="utf-8", errors="replace")[:MAX_DECOMP_CHARS]
    index = [{"name": m.group(1), "addr": m.group(2)}
             for m in _FUNC_SEP.finditer(text)]
    return True, text, index
