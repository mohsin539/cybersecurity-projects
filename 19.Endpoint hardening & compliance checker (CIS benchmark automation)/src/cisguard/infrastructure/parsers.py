"""Parsers: raw command output -> observed scalar for the evaluator."""

from __future__ import annotations

import re


def parse(spec_parse: str, output: str) -> str:
    out = output or ""
    if spec_parse == "verbatim":
        return out.strip()[:120] or "(empty)"
    if spec_parse == "min_pass_len":
        return _net_accounts(out, "Minimum password length")
    if spec_parse == "max_pass_age":
        return _net_accounts(out, "Maximum password age")
    if spec_parse == "password_hist_len":
        return _net_accounts(out, "Password history length")
    if spec_parse == "lockout_duration":
        return _net_accounts(out, "Lockout duration")
    if spec_parse == "lockout_threshold":
        return _net_accounts(out, "Lockout threshold")
    if spec_parse == "lockout_reset":
        return _net_accounts(out, "Lockout observation window")
    if spec_parse == "complexity":
        m = re.search(r"Password complexity requirements:\s*(\w+)", out)
        return m.group(1) if m else "(not found)"
    if spec_parse == "reversible":
        m = re.search(r"Store passwords using reversible encryption:\s*(\w+)", out)
        return m.group(1) if m else "(not found)"
    if spec_parse == "bitlocker_protection":
        m = re.search(r"Protection Status:\s*(\w+)", out)
        return {"ProtectionOn": "On", "On": "On", "ProtectionOff": "Off"}.get(m.group(1), m.group(1)) if m else "(not found)"
    if spec_parse == "psv2_state":
        m = re.search(r"(Enabled|Disabled)", out, re.IGNORECASE)
        return m.group(1).title() if m else "(not found)"
    return out.strip()[:120] or "(empty)"


def _net_accounts(output: str, field: str) -> str:
    # `net accounts` labels carry optional unit suffixes: "(days)", "(minutes)".
    m = re.search(re.escape(field) + r"(\s*\([^)]*\))?\s*:\s*([\w-]+)", output)
    return m.group(2) if m else "(not found)"
