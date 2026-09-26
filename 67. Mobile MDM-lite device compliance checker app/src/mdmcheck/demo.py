"""Deterministic demo telemetry used for offline demos and onboarding devices."""
from __future__ import annotations

import hashlib
import random
from typing import Any

from .model import telemetry_sample

ANDROID_MODELS = [
    ("Google", "Pixel 7"), ("Samsung", "Galaxy S22"), ("Xiaomi", "Redmi Note 12"),
    ("OnePlus", "OnePlus 10 Pro"), ("Motorola", "Moto G52"),
]
IOS_MODELS = [("Apple", "iPhone 14"), ("Apple", "iPhone 13"), ("Apple", "iPhone SE (3rd gen)")]

ANDROID_BUNDLES = [
    "com.google.android.gms", "com.android.chrome", "com.microsoft.office.outlook",
    "com.microsoft.teams", "com.slack", "org.torproject.android",
    "com.example.roguespy", "com.mxtech.videoplayer.ad", "com.spotify.music",
    "com.google.android.apps.maps", "com.whatsapp",
]
IOS_BUNDLES = [
    "com.apple.mobilesafari", "com.microsoft.office.outlook", "com.tinyspeck.chatlyio",
    "com.apple.mobileslideshow", "com.apple.Maps", "com.example.roguespy",
]


def _seed(device_id: str, salt: str) -> random.Random:
    h = hashlib.sha256((device_id + salt).encode()).hexdigest()
    return random.Random(int(h[:8], 16))


def demo_telemetry(device_id: str, platform: str) -> dict:
    """Build a plausible device profile. Deterministic per device id."""
    rng = _seed(device_id, "demo-v1")
    t: dict[str, Any] = telemetry_sample()

    if platform == "android":
        brand, model = ANDROID_MODELS[rng.randrange(len(ANDROID_MODELS))]
        t["os"]["version"] = rng.choice(["11.0", "12.0", "12.1", "13.0", "14.0"])
        sdk = {"11.0": 30, "12.0": 31, "12.1": 32, "13.0": 33, "14.0": 34}[t["os"]["version"]]
        t["os"]["sdk"] = sdk
        t["hardware"] = {"brand": brand, "model": model, "serial": device_id[:8].upper()}
        pool = ANDROID_BUNDLES[:]
        # anyone can have the forbidden apps
        for banned in ["org.torproject.android", "com.example.roguespy", "com.mxtech.videoplayer.ad"]:
            if rng.random() < 0.22:
                pool.append(banned)
        t["apps"]["installed"] = rng.sample(pool, rng.randint(6, len(pool)))
        t["security"] = {
            "rooted": rng.random() < 0.12,
            "unknown_sources": rng.random() < 0.18,
            "encryption": rng.random() > 0.08,
            "screen_lock": rng.random() > 0.10,
            "play_protect": rng.random() > 0.12,
            "side_loading": rng.random() < 0.15,
            "biometric": rng.random() > 0.15,
        }
    else:
        brand, model = IOS_MODELS[rng.randrange(len(IOS_MODELS))]
        t["os"]["version"] = rng.choice(["14.8", "15.0", "15.7", "16.0", "17.0"])
        t["os"]["sdk"] = 0
        t["hardware"] = {"brand": brand, "model": model, "serial": device_id[:8].upper()}
        if rng.random() < 0.22:
            t["apps"]["installed"] = rng.sample(IOS_BUNDLES, rng.randint(4, len(IOS_BUNDLES)))
        else:
            t["apps"]["installed"] = [a for a in rng.sample(IOS_BUNDLES, rng.randint(4, len(IOS_BUNDLES))) if a != "com.example.roguespy"]
        t["security"] = {
            "rooted": False,
            "jailbreak": rng.random() < 0.10,
            "unknown_sources": False,
            "encryption": rng.random() > 0.05,
            "screen_lock": rng.random() > 0.08,
            "play_protect": True,
            "side_loading": rng.random() < 0.10,
            "biometric": rng.random() > 0.12,
        }
    t["network"] = {"vpn": rng.random() < 0.10, "geofenced": True}
    t["agent"] = {"version": "1.0.0", "uptime_sec": rng.randint(3000, 900000)}
    return t


def demo_batch() -> dict:
    devices = [
        ("Florence-Android", "android", "BYOD"),
        ("Marcus-iPhone", "ios", "Corp"),
        ("Aisha-S10", "android", "Corp"),
        ("Dev-Emulator-A", "android", "Dev"),
        ("Liam-iPad", "ios", "Sales"),
        ("Sofia-Note", "android", "BYOD"),
    ]
    names = [d[0] for d in devices]
    platforms = {"android": "android", "ios": "ios"}
    return {
        "devices": [
            {
                "id": f"demo-{i + 1:02d}",
                "name": name,
                "platform": platforms[pf],
                "department": dep,
                "model": demo_telemetry(f"demo-{i + 1:02d}", platforms[pf])["hardware"]["model"],
            }
            for i, (name, pf, dep) in enumerate(devices)
        ],
        "name_lookup": dict(zip(names, [f"demo-{i + 1:02d}" for i in range(len(names))])),
    }