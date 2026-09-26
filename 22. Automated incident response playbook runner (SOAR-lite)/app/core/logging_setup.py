"""Structured logging bootstrap."""
from __future__ import annotations

import logging
import sys

from app.config import settings


def setup_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(handler)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)