import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EvidenceRecord:
    def __init__(self, exhibit_id: str, source: str, description: str, path: str = ""):
        self.uid = now_iso().replace(":", "").replace("-", "") + os.urandom(2).hex()
        self.exhibit_id = exhibit_id
        self.source = source
        self.description = description
        self.path = path
        self.sha256 = ""
        self.size = 0
        self.acquired_at = now_iso()
        self.status = "acquired"

    def hash_if_missing(self, base: Path) -> None:
        p = base / self.path if self.path else None
        if p and p.exists() and not self.sha256:
            self.sha256 = sha256_file(p)
            self.size = p.stat().st_size

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "exhibit_id": self.exhibit_id,
            "source": self.source,
            "description": self.description,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "acquired_at": self.acquired_at,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceRecord":
        r = cls(d["exhibit_id"], d["source"], d["description"], d.get("path", ""))
        r.uid = d["uid"]
        r.sha256 = d.get("sha256", "")
        r.size = d.get("size", 0)
        r.acquired_at = d.get("acquired_at", "")
        r.status = d.get("status", "acquired")
        return r


class Case:
    def __init__(self, case_id: str, root: Path, title: str = "", description: str = "", examiner: str = ""):
        self.id = case_id
        self.root = Path(root)
        self.manifest = self.root / "manifest.json"
        self.title = title
        self.description = description
        self.examiner = examiner
        self.opened_at = now_iso()
        self.evidence: list[EvidenceRecord] = []
        self.zones: dict[str, str] = {
            "intake": "open",
            "acquisition": "pending",
            "extraction": "pending",
            "analysis": "pending",
            "reporting": "pending",
            "audit": "pending",
        }
        self.reports: list[dict] = []

    # -- persistence ---------------------------------------------------
    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        data = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "examiner": self.examiner,
            "opened_at": self.opened_at,
            "zones": self.zones,
            "evidence": [e.to_dict() for e in self.evidence],
            "reports": self.reports,
        }
        self.manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self) -> "Case":
        data = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.title = data.get("title", "")
        self.description = data.get("description", "")
        self.examiner = data.get("examiner", "")
        self.opened_at = data.get("opened_at", "")
        self.zones = dict(data.get("zones", self.zones))
        self.evidence = [EvidenceRecord.from_dict(d) for d in data.get("evidence", [])]
        self.reports = data.get("reports", [])
        return self

    @classmethod
    def open_existing(cls, root: Path) -> "Case":
        case_id = Path(root).name
        c = cls(case_id, root)
        return c.load()

    # -- lifecycle -----------------------------------------------------
    def set_zone(self, zone: str, status: str) -> None:
        self.zones[zone] = status

    def add_evidence(self, rec: EvidenceRecord) -> None:
        self.evidence.append(rec)

    def add_report(self, name: str, relpath: str) -> None:
        self.reports.append({"name": name, "path": relpath, "created_at": now_iso(), "sha256": ""})

    def hash_report(self, index: int) -> None:
        base = self.root
        rp = base / self.reports[index]["path"]
        if rp.exists():
            self.reports[index]["sha256"] = sha256_file(rp)

    def sub(self, *parts: str) -> Path:
        p = self.root.joinpath(*parts)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def acquisition_dir(self) -> Path:
        return self.sub("acquisition")

    @property
    def logical_dir(self) -> Path:
        return self.sub("logical")

    @property
    def reports_dir(self) -> Path:
        return self.sub("reports")

    @property
    def inventory_path(self) -> Path:
        return self.root / "inventory.json"

    @property
    def summary(self) -> dict:
        total = sum(e.size for e in self.evidence)
        return {
            "case_id": self.id,
            "title": self.title,
            "exhibits": len(self.evidence),
            "total_bytes": total,
            "zones": self.zones,
        }