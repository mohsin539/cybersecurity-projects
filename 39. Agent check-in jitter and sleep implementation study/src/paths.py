"""Portable runtime paths (ISO 27001 / least-privilege design).

* No writes to Program Files, no registry usage.
* Per-user data dir: %LOCALAPPDATA%\\AgentJitterStudy (overridable by
  AGENTSTUDY_DATA_DIR env var - useful in locked-down environments).
* Delete-on-crash safe: single owner process, WAL sqlite not used.
"""
from __future__ import annotations

import os

APP_DIR_NAME = "AgentJitterStudy"


def data_dir() -> str:
    override = os.environ.get("AGENTSTUDY_DATA_DIR")
    if override:
        return os.path.abspath(override)
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, APP_DIR_NAME)


def out_dir() -> str:
    d = os.path.join(data_dir(), "out")
    os.makedirs(d, exist_ok=True)
    return d


def audit_log_path() -> str:
    d = data_dir()
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "audit.log")


def log_dir() -> str:
    d = os.path.join(data_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return d