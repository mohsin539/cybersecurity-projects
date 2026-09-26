"""ScanService tests using in-memory collectors (deterministic, no OS access)."""

from __future__ import annotations

import pytest

from cisguard.application.scan_service import ScanService
from cisguard.domain.models import Status
from cisguard.infrastructure.test_collectors import (
    FakeAuditpol, FakeCommands, FakeDefender, FakeRegistry, FakeServices, FakeSystem,
)

NET_OUT = (
    "Password history length:              24\n"
    "Maximum password age (days):          42\n"
    "Minimum password length:              14\n"
    "Password complexity requirements:     Yes\n"
    "Store passwords using reversible encryption: No\n"
    "Lockout threshold:                    5\n"
    "Lockout duration (minutes):           30\n"
    "Lockout observation window (minutes): 30"
)


@pytest.fixture()
def hardened_scan():
    reg = FakeRegistry({
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\EventLog\Security", "MaxSize"): 196608,
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\EventLog\Application", "MaxSize"): 32768,
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\EventLog\System", "MaxSize"): 32768,
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash"): 1,
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM"): 1,
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous"): 1,
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"): 5,
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse"): 1,
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature"): 1,
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"): 1,
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken"): 1,
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop"): 1,
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin"): 2,
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"): 255,
        ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"): 1,
        ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"): 0,
    })
    services = FakeServices({"Spooler": "Stopped", "RemoteRegistry": "Disabled",
                             "SSDPSRV": "Disabled", "upnphost": "Disabled",
                             "W32Time": "Running", "MpsSvc": "Running", "Fax": "NotFound"})
    commands = FakeCommands({("net", "accounts"): NET_OUT,
                             ("manage-bde", "-status", "C:"): "Protection Status: ProtectionOn",
                             ("powershell", "-NoProfile", "-Command",
                              "(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue).State"): "Disabled",
                             ("cmd", "/c", "ver"): "Microsoft Windows [Version 10.0.22631.4317]"})
    auditpol = FakeAuditpol({
        "Credential Validation": {"Success": True, "Failure": True},
        "Logon": {"Success": True, "Failure": True},
        "Account Lockout": {"Success": False, "Failure": True},
        "Other Logon/Logoff Events": {"Success": True, "Failure": False},
        "Process Creation": {"Success": True, "Failure": False},
        "Registry": {"Success": True, "Failure": False},
        "Security Group Management": {"Success": True, "Failure": False},
        "User Account Management": {"Success": True, "Failure": True},
        "Removable Storage": {"Success": True, "Failure": True},
        "Security State Change": {"Success": True, "Failure": False},
        "Security System Extension": {"Success": True, "Failure": False},
        "System Integrity": {"Success": True, "Failure": True},
    })
    defender = FakeDefender({"DisableRealtimeMonitoring": "0", "DisableBehaviorMonitoring": "0",
                             "DisableScriptScanning": "0", "MAPSReporting": "1",
                             "PUAProtection": "1"})
    svc = ScanService(reg, services, commands, auditpol, defender, FakeSystem())
    return svc


def test_hardened_endpoint_scores_perfect(hardened_scan):
    record = hardened_scan.scan()
    s = record.summary
    assert s.total == len(record.results)
    assert s.errors == 0, "fixtures cover every collector path"
    assert s.failed == 0
    assert s.score == 100.0


def test_every_result_has_evidence(hardened_scan):
    record = hardened_scan.scan()
    for r in record.results:
        assert r.evidence.source and r.observed


def test_failing_registry_value_is_reported(hardened_scan):
    hardened_scan._registry._values[("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash")] = 0
    record = hardened_scan.scan()
    r = next(x for x in record.results if x.control_id == "5.1.1")
    assert r.status == Status.FAIL
    assert r.observed == "0"


def test_missing_service_reported_not_found(hardened_scan):
    hardened_scan._services._states.pop("Spooler")
    record = hardened_scan.scan()
    r = next(x for x in record.results if x.control_id == "4.1.1")
    assert r.status == Status.PASS  # NotFound is acceptable for Spooler


def test_auditpol_expected_shape(hardened_scan):
    hardened_scan._auditpol._state["Process Creation"] = {"Success": False, "Failure": False}
    record = hardened_scan.scan()
    r = next(x for x in record.results if x.control_id == "2.2.1")
    assert r.status == Status.FAIL
