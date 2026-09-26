"""NIST SP 800-53 Rev.5 security and privacy controls.

Source: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

A curated catalogue of controls relevant to red team findings, tagged with
their control family and NIST CSF v2.0 function (GV/ID/PR/DE/RS/RC).
"""

from __future__ import annotations

from ..models.framework import FrameworkControl

# (control id, name, CSF function)
_NIST_CONTROLS = [
    ("AC-2", "Account Management", "PR"),
    ("AC-3", "Access Enforcement", "PR"),
    ("AC-4", "Information Flow Enforcement", "PR"),
    ("AC-5", "Separation of Duties", "PR"),
    ("AC-6", "Least Privilege", "PR"),
    ("AC-7", "Unsuccessful Logon Attempts", "PR"),
    ("AC-8", "System Use Notification", "PR"),
    ("AC-17", "Remote Access", "PR"),
    ("AC-20", "Use of External Systems", "PR"),
    ("AT-2", "Literacy Training and Awareness", "PR"),
    ("AT-3", "Role-Based Training", "PR"),
    ("AU-3", "Content of Audit Records", "DE"),
    ("AU-6", "Audit Record Review, Analysis, and Reporting", "DE"),
    ("AU-9", "Protection of Audit Information", "PR"),
    ("AU-12", "Audit Record Generation", "DE"),
    ("AU-16", "Cross-Organizational Auditing", "DE"),
    ("CA-7", "Continuous Monitoring", "DE"),
    ("CM-6", "Configuration Settings", "PR"),
    ("CM-7", "Least Functionality", "PR"),
    ("CM-8", "System Component Inventory", "ID"),
    ("CM-11", "User-Installed Software", "ID"),
    ("CP-10", "System Recovery and Reconstitution", "RC"),
    ("IA-2", "Identification and Authentication (Organizational Users)", "PR"),
    ("IA-5", "Authenticator Management", "PR"),
    ("IA-8", "Identification and Authentication (Non-Organizational Users)", "PR"),
    ("IA-11", "Re-authentication", "PR"),
    ("IR-4", "Incident Handling", "RS"),
    ("IR-5", "Incident Monitoring", "RS"),
    ("IR-8", "Incident Response Plan", "RS"),
    ("PL-8", "Security and Privacy Architectures", "PR"),
    ("RA-3", "Risk Assessment", "ID"),
    ("RA-5", "Vulnerability Monitoring and Scanning", "ID"),
    ("SA-9", "External System Services", "PR"),
    ("SA-10", "Developer Configuration Management", "PR"),
    ("SA-11", "Developer Testing and Evaluation", "PR"),
    ("SC-5", "Denial of Service Protection", "PR"),
    ("SC-7", "Boundary Protection", "PR"),
    ("SC-8", "Transmission Confidentiality and Integrity", "PR"),
    ("SC-13", "Cryptographic Protection", "PR"),
    ("SC-20", "Secure Name/Address Resolution Service (Authoritative Source)", "PR"),
    ("SC-23", "Session Authenticity", "PR"),
    ("SC-24", "Fail in Known State", "PR"),
    ("SC-28", "Protection of Information at Rest", "PR"),
    ("SC-28(1)", "Protection of Information at Rest: Cryptographic Protection", "PR"),
    ("SI-2", "Flaw Remediation", "PR"),
    ("SI-3", "Malicious Code Protection", "PR"),
    ("SI-4", "System Monitoring", "DE"),
    ("SI-7", "Software, Firmware, and Information Integrity", "PR"),
    ("SI-10", "Information Input Validation", "PR"),
    ("SI-11", "Error Handling", "PR"),
    ("SI-12", "Information Management and Retention", "ID"),
    ("SI-16", "Memory Protection", "PR"),
    ("SR-3", "Supply Chain Categorization", "ID"),
    ("SR-11", "Component Authenticity", "PR"),
]

NIST_FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "PL": "Planning",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

NIST_CSF_FUNCTIONS = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

NIST_CONTROLS = [
    FrameworkControl(
        framework="NIST SP 800-53 Rev.5",
        code=code,
        name=name,
        family=NIST_FAMILIES.get(code.split("-")[0], "General"),
        description=f"{name} ({code})",
        reference_url="https://csrc.nist.gov/Projects/risk-management/sp800-53-controls",
        related=(csf,),
    )
    for code, name, csf in _NIST_CONTROLS
]

NIST_BY_ID = {control.code: control for control in NIST_CONTROLS}


def nist_control(code: str) -> FrameworkControl:
    return NIST_BY_ID[code]