"""ETW + hook-engine extension point (architecture §5.1, roadmap v1.1).

Real-time capture is intentionally NOT wired in v1.0:
- Windows Sandbox / Hyper-V runner provisioning requires elevation and is a
  deliberate, explicit analyst action.
- The native shim (Rust/C++ ETW consumer + IAT/EAT inline hooks on MinHook)
  is built as a sidecar DLL at a later milestone.

This module documents the contract the native shim will satisfy so
`CaptureRunner` can consume live events identically to trace replay.
"""

import threading
import time
from dataclasses import dataclass, field


@dataclass
class EtwContract:
    provider_guids: list[str] = field(default_factory=lambda: [
        "{318A8A8D-1C0A-4C7F-8C33-4B48A12E1CAB}",  # (extensible example)
    ])
    min_hook_dlls: list[str] = field(default_factory=lambda: [
        "ntdll.dll", "kernel32.dll", "advapi32.dll", "ws2_32.dll",
        "user32.dll", "wininet.dll",
    ])
    sink: str = "named_pipe://acsuv_capture"


class LiveCaptureBridge:
    """Placeholder: receives ordered dict-events from the native shim."""

    def __init__(self, store, policy, redaction) -> None:
        self.store = store
        self.policy = policy
        self.redaction = redaction
        self.running = False
        self._lock = threading.Lock()

    def start(self, session_id: str) -> None:
        raise NotImplementedError(
            "Live ETW capture ships in v1.1. Use offline replay (Menu > Capture > Replay trace)."
        )

    def stop(self) -> None:
        self.running = False