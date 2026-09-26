"""Port scanner package — see architecture.md for the design reference."""
__version__ = "1.0.0"

from .config import Config, ScanType, validate
from .models import PortState, Proto
from .scanner import Scanner

__all__ = ["Config", "ScanType", "validate", "Scanner", "PortState", "Proto"]
