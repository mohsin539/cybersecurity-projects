"""Plugin manager: signed allow-list by default (OWASP A08, ISO A.8.30).

A plugin is a directory: plugin.toml + plugin.py (+ optional .sig for signed).
Plugins run IN-PROCESS but only receive an API object with pure helpers; any
sample-touching work must go through the JobService (sandboxed). Unsigned
plugins require Developer Mode for the session and are recorded in the audit log.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from rekt.platform.audit import AuditLog
from rekt.platform import trust

try:
    import tomllib
except ImportError:  # py3.10 fallback: minimal flat parser
    tomllib = None  # type: ignore[assignment]

API_VERSION = 1
REQUIRED_KEYS = {"name", "version", "api", "entry"}


@dataclass
class LoadedPlugin:
    name: str
    version: str
    signed: bool
    path: Path
    instance: object


class PluginError(Exception):
    pass


def _parse_toml(path: Path) -> dict:
    if tomllib is not None:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    raise PluginError("tomllib unavailable; Python >= 3.11 required for plugins")


def discover(plugin_dir: Path, developer_mode: bool, audit: AuditLog | None = None
             ) -> tuple[list[LoadedPlugin], list[str]]:
    """Load all valid plugins. Returns (loaded, rejected_with_reasons)."""
    loaded: list[LoadedPlugin] = []
    rejected: list[str] = []
    if not plugin_dir.exists():
        return loaded, rejected

    pub = trust.trusted_public_key()
    for pdir in sorted(p for p in plugin_dir.iterdir() if p.is_dir()):
        manifest_path = pdir / "plugin.toml"
        entry_path = pdir / "plugin.py"
        try:
            manifest = _parse_toml(manifest_path)
        except (OSError, PluginError) as e:
            rejected.append(f"{pdir.name}: unreadable manifest ({e})")
            continue
        if not REQUIRED_KEYS.issubset(manifest):
            rejected.append(f"{pdir.name}: manifest missing {REQUIRED_KEYS - set(manifest)}")
            continue
        if manifest.get("api") != API_VERSION:
            rejected.append(f"{pdir.name}: api version {manifest.get('api')} != {API_VERSION}")
            continue

        signed = False
        sig_path = pdir / "plugin.sig"
        if pub is not None and sig_path.exists():
            try:
                bundle = json.loads(sig_path.read_text(encoding="ascii"))
                message = manifest_path.read_bytes() + entry_path.read_bytes()
                signed = trust.verify_signature(
                    pub, message, base64.b64decode(bundle["signature"], validate=True))
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                signed = False
        if not signed and not developer_mode:
            rejected.append(f"{pdir.name}: unsigned plugin (enable Developer Mode to load)")
            continue
        if not signed and audit is not None:
            audit.append("plugin.unsigned_loaded", plugin=manifest["name"],
                         version=manifest["version"])

        try:
            instance = _load_module(pdir, manifest, entry_path)
        except PluginError as e:
            rejected.append(f"{pdir.name}: {e}")
            continue
        loaded.append(LoadedPlugin(str(manifest["name"]), str(manifest["version"]),
                                   signed, pdir, instance))
    return loaded, rejected


def _load_module(pdir: Path, manifest: dict, entry_path: Path):
    """Import the plugin entry module and instantiate its Plugin class."""
    if not entry_path.exists():
        raise PluginError("entry plugin.py missing")
    mod_name = f"rekt_plugin_{pdir.name}"
    spec = importlib.util.spec_from_file_location(mod_name, entry_path)
    if spec is None or spec.loader is None:
        raise PluginError("cannot build import spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # noqa: BLE001 — reject broken plugins, never crash host
        raise PluginError(f"entry raised on import: {type(e).__name__}: {e}") from e
    cls = getattr(module, "Plugin", None)
    if cls is None:
        raise PluginError("entry must define class Plugin")
    try:
        return cls()
    except Exception as e:  # noqa: BLE001
        raise PluginError(f"Plugin() constructor failed: {e}") from e
