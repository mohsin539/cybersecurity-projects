"""Colour themes for the desktop GUI (light + dark, high contrast)."""

from __future__ import annotations

LIGHT = {
    "bg": "#f4f6fa",
    "panel": "#ffffff",
    "fg": "#1b2430",
    "muted": "#5b6b7b",
    "frame": "#d8dee9",
    "accent": "#1769aa",
    "accent_fg": "#ffffff",
    "danger": "#b3261e",
    "ok": "#1c7c3c",
    "text_bg": "#ffffff",
    "input": "#ffffff",
}

DARK = {
    "bg": "#101522",
    "panel": "#1a2233",
    "fg": "#dbe4f0",
    "muted": "#8a98ab",
    "frame": "#2b3750",
    "accent": "#3b82f6",
    "accent_fg": "#ffffff",
    "danger": "#ff6b6b",
    "ok": "#4ade80",
    "text_bg": "#0c111c",
    "input": "#0c111c",
}

# Entity -> highlight colour. Matches classification bands:
# CRITICAL (red), HIGH (orange), MEDIUM (amber), LOW (blue), SAFE (green).
ENTITY_COLORS = {
    "SSN": "#e05555",
    "CREDIT_CARD": "#e05555",
    "API_KEY": "#e05555",
    "AUTH_TOKEN": "#e05555",
    "EMAIL": "#f08c3a",
    "PHONE": "#f08c3a",
    "PASSWORD": "#f08c3a",
    "PASSPORT": "#f08c3a",
    "DRIVER_LICENSE": "#f08c3a",
    "HEALTH_RECORD": "#f08c3a",
    "IP_ADDRESS": "#e5c14a",
    "NAME": "#e5c14a",
    "DATE_OF_BIRTH": "#e5c14a",
    "DOB": "#e5c14a",
    "COORDINATES": "#e5c14a",
    "LOCATION": "#e5c14a",
    "MAC_ADDRESS": "#e5c14a",
    "URL": "#6ea8fe",
    "TIMESTAMP": "#6ea8fe",
    "VERSION": "#6ea8fe",
    "DEVICE_ID": "#6ea8fe",
    "SAFE": "#5cb85c",
}


def entity_color(entity_type: str) -> str:
    return ENTITY_COLORS.get(entity_type, "#9b9bf0")
