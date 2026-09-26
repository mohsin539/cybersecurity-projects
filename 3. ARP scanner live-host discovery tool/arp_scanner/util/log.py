"""Logging setup. All log output goes to stderr so stdout stays clean for
results (per archetecture.md §14). GUI mirrors events into its audit pane via
a dedicated handler in arp_scanner.gui."""

from __future__ import annotations

import logging
import sys

_configured = False


def setup_logging(verbosity: int = 0) -> logging.Logger:
    """Configure root logger to stderr. verbosity 0=INFO, 1=DEBUG, -1=WARNING."""
    global _configured
    level = logging.DEBUG if verbosity >= 1 else (logging.INFO if verbosity >= 0 else logging.WARNING)
    logger = logging.getLogger("arp_scanner")
    if _configured:
        logger.setLevel(level)
        return logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _configured = True
    return logger