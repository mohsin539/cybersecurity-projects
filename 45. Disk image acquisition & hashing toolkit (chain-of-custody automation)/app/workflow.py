#!/usr/bin/env python3
"""Case workflow orchestration.

A case folder is a self-contained, portable evidence pack:

    <case_dir>/
      case.chainofcustody.json        # signed, tamper-evident ledger
      evidence_caseId_<exhibit>.dd    # raw bit image (or E01/AFF4 in certified build)
      evidence_manifest.json          # canonical JSON evidence manifest
      SHA256SUMS                      # POSIX digest file
      hash_manifest.csv
      hash_manifest.xlsx
      forensic_report.pdf             # signed court-style PDF
      chain_of_custody_report.pdf     # custody visual

All acquisition flows create/sign a custody event automatically, so the
platform is 'chain-of-custody automation' out of the box.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .config import (CUSTODY_NAME, CUSTODY_PDF_NAME, EXPORT_CSV_NAME,
                     EXPORT_XLSX_NAME, MANIFEST_NAME, RAW_EXT,
                     REPORT_PDF_NAME, SHA256SUMS_NAME, VERSION)
from .custody import Ledger, machine_id
from .imaging import acquire_image, fmt_size, list_physical_drives, verify_image
from .reports import (build_forensic_pdf, write_csv, write_json, write_sha256sums,
                      write_xlsx)


def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name or "evidence")


class Case:
    def __init__(self, case_dir: str, case_id: str, case_name: str,
                 examiner: str, role: str, org: str, passphrase: str):
        self.dir = case_dir
        self.case_id = case_id
        self.case_name = case_name
        self.examiner = examiner
        self.role = role
        self.org = org
        self.ledger: Ledger = None
        os.makedirs(case_dir, exist_ok=True)
        self.ledger = Ledger.create_new(
            os.path.join(case_dir, CUSTODY_NAME), case_id, case_name,
            examiner, role, org, passphrase)

    def key(self, passphrase: str) -> bytes:
        from .custody import derive_key
        salt = bytes.fromhex(self.ledger.meta["pbkdf2"]["salt_hex"])
        m_ = self.ledger.meta
        if machine_id() != m_["machine_id"]:
            raise ValueError("Ledger was created on a different machine.")
        key = derive_key(passphrase, salt, m_["pbkdf2"]["iterations"])
        from .custody import key_fingerprint
        if key_fingerprint(key) != m_["key_fingerprint"]:
            raise ValueError("Passphrase does not match this case ledger.")
        return key

    # -- acquisition --------------------------------------------------------
    def acquire(self, source: str, filename: Optional[str] = None,
                algorithms: Iterable[str] = ("sha256", "sha3_256"),
                passphrase: str = "",
                writeblocker_confirmed: bool = True,
                progress_cb=None, cancel_cb=None) -> Dict[str, Any]:
        key = self.key(passphrase)
        if filename is None:
            base = sanitize(os.path.basename(source.rstrip("/\\").replace("\\", "_")))
            filename = f"evidence_{self.case_id}_{base}.{RAW_EXT}"
        target = os.path.join(self.dir, filename)

        digests, nbytes, elapsed, src_size = acquire_image(
            source, target, algorithms=algorithms,
            progress_cb=progress_cb, cancel_cb=cancel_cb)

        self.ledger.append(
            "acquisition_completed",
            f"Bit-for-bit acquisition of {source} → {filename} "
            f"({fmt_size(src_size)})",
            key, exhibit=filename,
            detail={"source": source, "size_bytes": nbytes, "elapsed_sec": round(elapsed, 3),
                    "write_blocker_engaged": writeblocker_confirmed,
                    "algorithms": list(digests), "hashes": digests,
                    "read_only_source": True})

        manifest = self.build_manifest(filename, source, digests, nbytes,
                                       src_size, elapsed)
        self._export_machine_formats(manifest, digests, filename)
        return {"manifest": manifest, "digests": digests,
                "bytes": nbytes, "elapsed": elapsed}

    # -- verification -------------------------------------------------------
    def verify_exhibit(self, filename: str, algorithms: Iterable[str],
                       expected_hashes: Dict[str, str],
                       passphrase: str = "",
                       progress_cb=None, cancel_cb=None) -> Tuple[bool, Dict]:
        key = self.key(passphrase)
        match, digests, mismatches = verify_image(
            os.path.join(self.dir, filename), expected_hashes,
            progress_cb=progress_cb, cancel_cb=cancel_cb)
        self.ledger.append(
            "verification" + ("_pass" if match else "_fail"),
            f"Re-hash of {filename}: {'MATCH (unmodified)' if match else 'MISMATCH: ' + ','.join(mismatches)}",
            key, exhibit=filename,
            detail={"match": match, "mismatches": mismatches,
                    "algorithm": next(iter(algorithms)), "hashes": digests})
        return match, digests

    # -- custody actions -----------------------------------------------------
    def custody(self, action: str, description: str, passphrase: str,
                exhibit: Optional[str] = None) -> Dict[str, Any]:
        key = self.key(passphrase)
        return self.ledger.append(action, description, key, exhibit=exhibit)

    def timeline(self):
        return self.ledger.timeline()

    def audit(self, passphrase: str) -> Tuple[bool, List[str]]:
        return self.ledger.verify(passphrase)

    # -- reporting ------------------------------------------------------------
    def build_manifest(self, filename, source, hashes, nbytes, src_size,
                       elapsed) -> Dict[str, Any]:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        ht = {k: v for k, v in hashes.items()}
        manifest = {
            "schema": f"{'DIHT'}-1.0",
            "tool": {"name": "Disk Image Acquisition & Hashing Toolkit",
                     "version": VERSION, "build": "portable"},
            "case_id": self.case_id,
            "case_name": self.case_name,
            "generated_utc": now,
            "meta": {
                "case": self.case_id,
                "examiner": self.examiner,
                "role": self.role,
                "organization": self.org,
                "machine_id": machine_id(),
                "evidence": filename,
            },
            "evidence": [{
                "exhibit": filename,
                "source_device": source,
                "size_bytes": nbytes,
                "size_display": fmt_size(nbytes),
                "source_size_bytes": src_size or 0,
                "elapsed_sec": round(elapsed, 3),
                "acquired_utc": now,
                "hashes": ht,
                "authoritative": [a for a in ("sha256", "sha3_256") if a in ht],
                "verification": {"algorithm": "pending", "match": None,
                                 "timestamp": None},
            }],
            "custody": self.timeline(),
            "signatures": self._signature_block(),
        }
        return manifest

    def _signature_block(self):
        fp = self.ledger.meta.get("key_fingerprint", "-")
        return {"manifest_fingerprint": fp, "signing_mechanism": "HMAC-SHA256 (PBKDF2 key)"}

    def _export_machine_formats(self, manifest, digests, filename):
        write_json(os.path.join(self.dir, MANIFEST_NAME), manifest)
        write_sha256sums(os.path.join(self.dir, SHA256SUMS_NAME),
                         {filename: digests.get("sha256", "")})
        rows = [{"exhibit": filename, "algorithm": a, "digest": d,
                 "size_bytes": manifest["evidence"][0]["size_bytes"],
                 "source": manifest["evidence"][0]["source_device"],
                 "acquired_utc": manifest["generated_utc"],
                 "case_id": self.case_id, "tool": "DIHT", "tool_version": VERSION}
                for a, d in digests.items()]
        write_csv(os.path.join(self.dir, EXPORT_CSV_NAME), rows)
        write_xlsx(os.path.join(self.dir, EXPORT_XLSX_NAME), manifest)

    def ensure_reports(self) -> List[str]:
        manifest = self.load_manifest()
        files = []
        files.append(build_forensic_pdf(os.path.join(self.dir, REPORT_PDF_NAME), manifest))

        # custody visual report
        self._build_custody_pdf(os.path.join(self.dir, CUSTODY_PDF_NAME), manifest)
        files.append(CUSTODY_PDF_NAME)
        return files

    def _build_custody_pdf(self, path, manifest):
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm,
                                rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm)
        story = [Paragraph("Chain of Custody — Signed Timeline", styles["Title"])]
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Case <b>{manifest['case_id']}</b> — {manifest['case_name']} · "
            f"Examiner: {manifest['meta'].get('examiner','-')}", styles["BodyText"]))
        story.append(Spacer(1, 8))
        hdr = ["#", "Timestamp (UTC)", "Action", "Description", "Exhibit", "Actor"]
        rows = [hdr]
        for i, ev in enumerate(manifest["custody"], 1):
            rows.append([str(i), ev["ts"], ev["action"], ev["description"],
                         ev.get("exhibit") or "-", ev["actor"]])
        t = Table(rows, colWidths=[8 * mm, 40 * mm, 32 * mm, 64 * mm, 24 * mm, 26 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ]))
        story.append(t)
        doc.build(story)

    def load_manifest(self) -> Dict[str, Any]:
        with open(os.path.join(self.dir, MANIFEST_NAME), "r", encoding="utf-8") as f:
            return json.load(f)


# --------------------------------------------------------------------------
def open_case(case_dir: str, case_id: str, case_name: str, examiner: str,
              role: str, org: str, passphrase: str) -> Case:
    """Resume an existing case (ledger present) or create a fresh one."""
    ledger_path = os.path.join(case_dir, CUSTODY_NAME)
    if os.path.exists(ledger_path):
        c = Case.__new__(Case)
        c.dir, c.case_id, c.case_name = case_dir, case_id, case_name
        c.examiner, c.role, c.org = examiner, role, org
        c.ledger = Ledger.load(ledger_path)
        if c.ledger.meta["case_id"] != case_id:
            raise ValueError("Case ID does not match ledger metadata.")
        return c
    return Case(case_dir, case_id, case_name, examiner, role, org, passphrase)