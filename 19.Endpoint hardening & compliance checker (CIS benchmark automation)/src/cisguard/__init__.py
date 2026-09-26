"""CISGuard — read-only CIS Benchmark assessment for Windows endpoints.

Hexagonal architecture (ports & adapters): the domain core never imports
winreg/subprocess/Qt. Windows collectors are adapters behind ports.
Assessment is STRICTLY READ-ONLY — remediation is out of scope by design.
"""

__version__ = "0.1.0"
APP_NAME = "CISGuard"
