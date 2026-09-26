"""Discover installed browsers and their profile directories.

The locator is deliberately conservative: it only *reads* directory listings and
``profiles.ini`` files. It never executes browser binaries and never writes into
a profile directory (ISO 27001 A.8.3 / NIST SP 800-86 evidence preservation).
"""
from __future__ import annotations

import configparser
import os
import sys
from typing import Dict, List

from .models import BrowserProfile

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = not (IS_WINDOWS or IS_MAC)

HOME = os.path.expanduser("~")


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path)).replace("/", os.sep)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


# ---------------------------------------------------------------------------
# Chromium-family definitions
# ---------------------------------------------------------------------------
# Each entry maps a browser name to its "User Data" root per platform.
CHROMIUM_ROOTS: Dict[str, Dict[str, str]] = {
    "Chrome": {
        "win": r"%LOCALAPPDATA%\Google\Chrome\User Data",
        "mac": "~/Library/Application Support/Google/Chrome",
        "linux": "~/.config/google-chrome",
    },
    "Chrome Beta": {
        "win": r"%LOCALAPPDATA%\Google\Chrome Beta\User Data",
        "mac": "~/Library/Application Support/Google/Chrome Beta",
        "linux": "~/.config/google-chrome-beta",
    },
    "Edge": {
        "win": r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
        "mac": "~/Library/Application Support/Microsoft Edge",
        "linux": "~/.config/microsoft-edge",
    },
    "Brave": {
        "win": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
        "mac": "~/Library/Application Support/BraveSoftware/Brave-Browser",
        "linux": "~/.config/BraveSoftware/Brave-Browser",
    },
    "Opera": {
        "win": r"%APPDATA%\Opera Software\Opera Stable",
        "mac": "~/Library/Application Support/com.operasoftware.Opera",
        "linux": "~/.config/opera",
    },
    "Opera GX": {
        "win": r"%APPDATA%\Opera Software\Opera GX Stable",
        "mac": "~/Library/Application Support/com.operasoftware.OperaGX",
        "linux": "~/.config/opera-gx",
    },
    "Vivaldi": {
        "win": r"%LOCALAPPDATA%\Vivaldi\User Data",
        "mac": "~/Library/Application Support/Vivaldi",
        "linux": "~/.config/vivaldi",
    },
    "Chromium": {
        "win": r"%LOCALAPPDATA%\Chromium\User Data",
        "mac": "~/Library/Application Support/Chromium",
        "linux": "~/.config/chromium",
    },
    "Yandex": {
        "win": r"%LOCALAPPDATA%\Yandex\YandexBrowser\User Data",
        "mac": "~/Library/Application Support/Yandex/YandexBrowser",
        "linux": "~/.config/yandex-browser",
    },
    "Whale": {
        "win": r"%LOCALAPPDATA%\Naver\Naver Whale\User Data",
        "mac": "~/Library/Application Support/Naver/Whale",
        "linux": "~/.config/naver-whale",
    },
    "Arc": {
        "win": r"%LOCALAPPDATA%\Packages\TheBrowserCompany.Arc_*\LocalCache\Local\Arc",
        "mac": "~/Library/Application Support/Arc",
        "linux": "",
    },
}

# Artifact file names inside a Chromium profile directory.
CHROMIUM_ARTIFACTS = {
    "history": ["History"],
    "downloads": ["History"],           # downloads live in the same DB
    "bookmarks": ["Bookmarks"],
    "cookies": ["Network/Cookies", "Cookies"],
    "cache": ["Cache/Cache_Data", "Cache", "Code Cache"],
    "autofill": ["Web Data"],
    "logins": ["Login Data"],
    "search_terms": ["History"],
    "shortcuts": ["Shortcuts"],
    "sessions": ["Sessions"],
    "preferences": ["Preferences"],
    "extension_cookies": ["Network/Cookies"],
}

FIREFOX_ROOTS = {
    "win": r"%APPDATA%\Mozilla\Firefox",
    "mac": "~/Library/Application Support/Firefox",
    "linux": "~/.mozilla/firefox",
}

FIREFOX_ARTIFACTS = {
    "history": ["places.sqlite"],
    "downloads": ["places.sqlite"],
    "bookmarks": ["places.sqlite"],
    "cookies": ["cookies.sqlite"],
    "cache": ["cache2"],
    "autofill": ["formhistory.sqlite"],
    "logins": ["logins.json"],
    "search_terms": ["places.sqlite", "formhistory.sqlite"],
    "sessions": ["sessionstore-backups", "sessionstore.jsonlz4"],
}

# Chromium artifact file names whose evidence hash should never be skipped.
_HASH_ARTIFACTS = {"History", "Cookies", "Bookmarks", "Web Data", "Login Data",
                   "places.sqlite", "cookies.sqlite", "formhistory.sqlite",
                   "logins.json", "Preferences"}


def _platform_key() -> str:
    if IS_WINDOWS:
        return "win"
    if IS_MAC:
        return "mac"
    return "linux"


def _chromium_profiles(user_data: str) -> List[str]:
    """Return profile directory names inside a Chromium *User Data* folder."""
    if not os.path.isdir(user_data):
        return []
    names = []
    for entry in sorted(os.listdir(user_data)):
        full = os.path.join(user_data, entry)
        if not os.path.isdir(full):
            continue
        if entry in ("Default", "Guest Profile", "System Profile"):
            names.append(entry)
        elif entry.startswith("Profile "):
            names.append(entry)
    return names


def _map_artifacts(root: str, spec: Dict[str, List[str]]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for category, candidates in spec.items():
        for rel in candidates:
            candidate = os.path.join(root, *rel.split("/"))
            if os.path.exists(candidate):
                found[category] = candidate
                break
    return found


def _discover_chromium() -> List[BrowserProfile]:
    pk = _platform_key()
    profiles: List[BrowserProfile] = []
    env = {"LOCALAPPDATA": _env("LOCALAPPDATA"), "APPDATA": _env("APPDATA")}

    for browser, roots in CHROMIUM_ROOTS.items():
        raw = roots.get(pk, "")
        if not raw:
            continue
        raw = raw.replace("%LOCALAPPDATA%", env["LOCALAPPDATA"]).replace("%APPDATA%", env["APPDATA"])
        root = _expand(raw)
        if "*" in root:
            # Expand a single-level wildcard (e.g. Arc packages path).
            import glob
            matches = glob.glob(root)
            root = matches[0] if matches else root
        if not os.path.isdir(root):
            continue

        key_file = None
        local_state = os.path.join(root, "Local State")
        if os.path.isfile(local_state):
            key_file = local_state

        profile_names = _chromium_profiles(root) or ["Default"]
        for name in profile_names:
            pdir = os.path.join(root, name, "User Data") if os.path.basename(root) == name else os.path.join(root, name)
            # Opera stores artifacts directly in the root, not under a profile.
            if not os.path.isdir(pdir):
                pdir = root
            available = _map_artifacts(pdir, CHROMIUM_ARTIFACTS)
            if not available:
                continue
            profiles.append(BrowserProfile(
                browser=browser, profile=name, root=pdir, kind="chromium",
                user_data=root, key_file=key_file, available=available,
            ))
    return profiles


def _firefox_profiles() -> List[tuple]:
    """Return (profile_name, path) tuples discovered via profiles.ini."""
    root = _expand(FIREFOX_ROOTS[_platform_key()])
    result = []
    ini_path = os.path.join(root, "profiles.ini")
    if os.path.isfile(ini_path):
        parser = configparser.ConfigParser()
        try:
            parser.read(ini_path, encoding="utf-8", errors="ignore")
        except Exception:
            parser = None
        if parser:
            for section in parser.sections():
                if not section.lower().startswith("profile"):
                    continue
                name = parser.get(section, "Name", fallback=section)
                rel = parser.get(section, "Path", fallback="")
                is_relative = parser.getint(section, "IsRelative", fallback=1)
                if not rel:
                    continue
                path = os.path.join(root, rel) if is_relative else _expand(rel)
                result.append((name, path))
    if not result:
        base = os.path.join(root, "Profiles")
        if os.path.isdir(base):
            for name in sorted(os.listdir(base)):
                p = os.path.join(base, name)
                if os.path.isdir(p):
                    result.append((name, p))
    return result


def _discover_firefox() -> List[BrowserProfile]:
    profiles: List[BrowserProfile] = []
    for name, path in _firefox_profiles():
        if not os.path.isdir(path):
            continue
        available = _map_artifacts(path, FIREFOX_ARTIFACTS)
        if not available:
            continue
        profiles.append(BrowserProfile(
            browser="Firefox", profile=name, root=path, kind="firefox",
            user_data=os.path.dirname(path),
            key_file=os.path.join(path, "key4.db") if os.path.isfile(os.path.join(path, "key4.db")) else None,
            available=available,
        ))
    return profiles


def discover_browsers() -> List[BrowserProfile]:
    """Return every browser profile reachable on the current host."""
    profiles = _discover_chromium()
    profiles.extend(_discover_firefox())
    profiles.sort(key=lambda p: (p.browser.lower(), p.profile.lower()))
    return profiles


def artifact_path(profile: BrowserProfile, category: str) -> str:
    """Return the on-disk path for a category, or an empty string."""
    return profile.available.get(category, "")
