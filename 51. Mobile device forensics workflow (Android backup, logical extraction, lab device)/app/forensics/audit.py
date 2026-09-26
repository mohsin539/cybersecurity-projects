import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditJournal:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _count(self) -> int:
        n = 0
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    n += 1
        return n

    def _head(self) -> str:
        if self.path.exists():
            last = None
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last = json.loads(line)
            if last:
                return last["hash"]
        return GENESIS

    def append(self, actor: str, zone: str, action: str, detail: str = "") -> dict:
        prev = self._head()
        ts = _now()
        entry = {
            "n": self._count(),
            "ts": ts,
            "actor": actor,
            "zone": zone,
            "action": action,
            "detail": detail,
            "prev": prev,
        }
        canonical = json.dumps(
            {k: entry[k] for k in ("ts", "actor", "zone", "action", "detail")},
            sort_keys=True,
            separators=(",", ":"),
        )
        entry["hash"] = hashlib.sha256(f"{prev}|{ts}|{canonical}".encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def read(self) -> list[dict]:
        out = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.append(json.loads(line))
        return out

    def entries_for(self, case_id: str) -> list[dict]:
        return [e for e in self.read() if case_id in e.get("detail", "")]

    def verify(self) -> list[tuple[int, bool, str]]:
        results = []
        prev = GENESIS
        for i, e in enumerate(self.read()):
            canonical = json.dumps(
                {k: e[k] for k in ("ts", "actor", "zone", "action", "detail")},
                sort_keys=True,
                separators=(",", ":"),
            )
            expect = hashlib.sha256(f"{e['prev']}|{e['ts']}|{canonical}".encode("utf-8")).hexdigest()
            problems = []
            if e["prev"] != prev:
                problems.append("link broken (prev mismatch)")
            if e["hash"] != expect:
                problems.append("hash mismatch")
            ok = not problems
            results.append((e["n"], ok, ", ".join(problems) if problems else "OK"))
            prev = e["hash"]
        return results

    def export(self, target: Path) -> Path:
        data = {"journal": self.read(), "integrity": "sha256_hash_chain"}
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return target