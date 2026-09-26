"""ISO/IEC 27001:2022 Annex A controls.

Source: https://www.iso.org/standard/27001 and ISO/IEC 27002:2022 mapping.

Annex A of the 2022 revision groups controls into four themes:
Organizational (A.5.x), People (A.6.x), Physical (A.7.x) and
Technological (A.8.x).
"""

from __future__ import annotations

from ..models.framework import FrameworkControl

ISO_THEMES = {
    "A5": "Organizational",
    "A6": "People",
    "A7": "Physical",
    "A8": "Technological",
}

_ISO_CONTROLS = [
    ("A.5.1", "Policies for information security"),
    ("A.5.3", "Segregation of duties"),
    ("A.5.15", "Access control"),
    ("A.5.16", "Identity management"),
    ("A.5.17", "Authentication information"),
    ("A.5.18", "Access rights"),
    ("A.5.23", "Cloud services security"),
    ("A.5.24", "Information security incident management planning and preparation"),
    ("A.5.25", "Assessment and decision on information security events"),
    ("A.5.26", "Response to information security incidents"),
    ("A.5.27", "Learning from information security incidents"),
    ("A.5.28", "Collection of evidence"),
    ("A.5.31", "Legal, statutory, regulatory and contractual requirements"),
    ("A.5.33", "Protection of records"),
    ("A.5.36", "Compliance with policies, rules and standards for information security"),
    ("A.5.37", "Documented operating procedures"),
    ("A.6.3", "Information security awareness, education and training"),
    ("A.6.8", "Reporting information security events"),
    ("A.7.2", "Physical entry"),
    ("A.7.9", "Protection against physical and environmental threats"),
    ("A.7.10", "Supporting utilities"),
    ("A.8.2", "Privileged access rights"),
    ("A.8.3", "Limitation of information access"),
    ("A.8.4", "Access to source code"),
    ("A.8.5", "Secure authentication"),
    ("A.8.6", "Capacity management"),
    ("A.8.8", "Management of technical vulnerabilities"),
    ("A.8.9", "Configuration management"),
    ("A.8.10", "Information deletion"),
    ("A.8.11", "Data masking"),
    ("A.8.12", "Prevention of data leakage"),
    ("A.8.13", "Information backup"),
    ("A.8.15", "Logging"),
    ("A.8.16", "Monitoring activities"),
    ("A.8.17", "Clock synchronization"),
    ("A.8.19", "Installation of software on operational systems"),
    ("A.8.20", "Networks security"),
    ("A.8.21", "Security of network services"),
    ("A.8.22", "Segregation of networks"),
    ("A.8.23", "Web filtering"),
    ("A.8.24", "Use of cryptography"),
    ("A.8.25", "Secure development life cycle"),
    ("A.8.26", "Application security requirements"),
    ("A.8.27", "Secure system architecture and engineering principles"),
    ("A.8.28", "Secure coding"),
    ("A.8.29", "Security testing in development and acceptance"),
    ("A.8.30", "Outsourced development"),
    ("A.8.31", "Separation of development, test and production environments"),
    ("A.8.32", "Change management"),
]

ISO_CONTROLS = [
    FrameworkControl(
        framework="ISO/IEC 27001:2022",
        code=code,
        name=name,
        family=ISO_THEMES.get(code.split(".")[0], "Organizational"),
        description=f"{name} ({code})",
        reference_url="https://www.iso.org/standard/27001",
    )
    for code, name in _ISO_CONTROLS
]

ISO_BY_ID = {control.code: control for control in ISO_CONTROLS}


def iso_control(code: str) -> FrameworkControl:
    return ISO_BY_ID[code]