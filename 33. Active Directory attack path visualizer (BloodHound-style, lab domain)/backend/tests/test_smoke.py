"""Smoke: portable launcher module loads and env defaults apply."""
from __future__ import annotations

import importlib
import os


def test_run_module_sets_lab_defaults():
    if "SG_JWT_SECRET" in os.environ:
        del os.environ["SG_JWT_SECRET"]
    if "SG_ENVIRONMENT" in os.environ:
        del os.environ["SG_ENVIRONMENT"]
    import run  # backend/run.py on path via tests cwd

    importlib.reload(run)
    assert os.environ.get("SG_ENVIRONMENT") == "lab"
    assert len(os.environ.get("SG_JWT_SECRET", "")) >= 32
