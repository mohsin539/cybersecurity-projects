import datetime
import os
import sys
from pathlib import Path


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def default_vault() -> Path:
    return app_base_dir() / "evidence_vault"


def ensure_vault(vault: Path) -> None:
    (vault / "cases").mkdir(parents=True, exist_ok=True)
    (vault / "journal").mkdir(parents=True, exist_ok=True)
    (vault / "keys").mkdir(parents=True, exist_ok=True)
    (vault / "exports").mkdir(parents=True, exist_ok=True)


def case_root(vault: Path, case_id: str) -> Path:
    return vault / "cases" / case_id


def signing_key_path(vault: Path) -> Path:
    return vault / "keys" / "signing.key"


def signing_key(vault: Path) -> bytes:
    p = signing_key_path(vault)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_bytes(os.urandom(32))
    return p.read_bytes()


def next_case_id(vault: Path) -> str:
    year = datetime.date.today().year
    folder = vault / "cases"
    n = 1
    while (folder / f"CSE-{year}-{n:04d}").exists():
        n += 1
    return f"CSE-{year}-{n:04d}"