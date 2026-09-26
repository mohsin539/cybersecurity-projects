from arp_scanner.core.config import ScannerConfig
from arp_scanner.core.engine import run_scan
from arp_scanner.security.guard import PermissionDenied

cfg = ScannerConfig(target="192.168.56.1", interface="auto", timeout=0.3, retries=0)
try:
    result = run_scan(cfg)
    print(f"SCAN RESULT: hosts={len(result.hosts)} via {result.interface}")
except PermissionDenied as exc:
    print(f"PRIVILEGE-DENIED (expected without admin): {exc}")
except Exception as exc:
    print(f"OTHER: {type(exc).__name__}: {exc}")