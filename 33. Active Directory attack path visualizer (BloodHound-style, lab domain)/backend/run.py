"""Portable launcher for SentinelGraph (exe / single-command lab runs).

- Lab profile: binds loopback only, docs enabled, in-memory graph.
- Generates a fresh per-run JWT session secret unless one is provided,
  so tokens never survive process restarts (portable-mode posture).
"""
from __future__ import annotations

import os
import secrets

os.environ.setdefault("SG_ENVIRONMENT", "lab")
os.environ.setdefault("SG_JWT_SECRET", secrets.token_urlsafe(48))


def main() -> None:
    import uvicorn

    from app.main import app  # noqa: import after env for clean settings

    host = os.environ.get("SG_HOST", "127.0.0.1")
    port = int(os.environ.get("SG_PORT", "8000"))
    print(f"SentinelGraph running at http://{host}:{port}  (Ctrl+C to stop)")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
