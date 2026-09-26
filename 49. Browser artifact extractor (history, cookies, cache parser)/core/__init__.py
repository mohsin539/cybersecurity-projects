"""Core extraction engine for the Browser Artifact Extractor.

Modules
-------
paths       : Locate installed browsers and their profile directories.
models      : Data models shared across the engine.
decrypt     : DPAPI / AES-GCM decryption for Chromium secrets.
extractors  : Read-only parsers for history, cookies, cache, downloads, etc.
engine      : Orchestrates a full collection run.
"""

__all__ = ["paths", "models", "decrypt", "extractors", "engine"]
__version__ = "1.0.0"
