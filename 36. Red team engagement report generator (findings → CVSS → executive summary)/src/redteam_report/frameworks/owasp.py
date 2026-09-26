"""OWASP Top 10 (2021) application-security risk categories.

Source: https://owasp.org/Top10/
"""

from __future__ import annotations

from ..models.framework import FrameworkControl

OWASP_TOP_10_2021 = [
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A01",
        name="Broken Access Control",
        family="Access Control",
        description=(
            "Restrictions are not correctly enforced, enabling users to act "
            "outside their intended permissions, access unauthorized functions "
            "or data, escalate privileges, or perform forced browsing and IDOR."
        ),
        reference_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A02",
        name="Cryptographic Failures",
        family="Cryptography",
        description=(
            "Failures related to cryptography — missing or weak encryption, "
            "insecure key management, cleartext transmission or storage of "
            "sensitive data and non-compliant use of algorithms."
        ),
        reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A03",
        name="Injection",
        family="Input Validation",
        description=(
            "Untrusted data is interpreted as part of a command or query "
            "(SQL, NoSQL, OS command, LDAP, expression language) and executed "
            "with unintended privileges."
        ),
        reference_url="https://owasp.org/Top10/A03_2021-Injection/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A04",
        name="Insecure Design",
        family="Design / Architecture",
        description=(
            "Missing or ineffective design and architecture controls, "
            "threat modelling gaps and insecure business logic that allows "
            "abuse of expected behaviour."
        ),
        reference_url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A05",
        name="Security Misconfiguration",
        family="Configuration Management",
        description=(
            "Insecure defaults, open cloud storage, unnecessary features, "
            "default accounts, verbose errors and incomplete hardening of the "
            "technology stack."
        ),
        reference_url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A06",
        name="Vulnerable and Outdated Components",
        family="Supply Chain / Dependencies",
        description=(
            "Use of components (libraries, runtimes, packages, sub-systems) "
            "with known vulnerabilities, end-of-life software, or components "
            "not patched to a supported state."
        ),
        reference_url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A07",
        name="Identification and Authentication Failures",
        family="Identity & Access Management",
        description=(
            "Broken authentication, weak password policy, credential stuffing, "
            "session fixation, missing MFA and insecure session management."
        ),
        reference_url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A08",
        name="Software and Data Integrity Failures",
        family="Software & Data Integrity",
        description=(
            "Code and infrastructure that fail to protect against integrity "
            "violations — insecure deserialization, untrusted CI/CD pipelines, "
            "unsigned updates and lack of integrity verification."
        ),
        reference_url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A09",
        name="Security Logging and Monitoring Failures",
        family="Logging & Monitoring",
        description=(
            "Insufficient logging, detection, monitoring and active response, "
            "enabling attacks to go unnoticed and preventing post-incident forensics."
        ),
        reference_url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ),
    FrameworkControl(
        framework="OWASP Top 10 2021",
        code="A10",
        name="Server-Side Request Forgery (SSRF)",
        family="Server-Side Request Forgery",
        description=(
            "Server-side application fetches a remote resource supplied by the "
            "attacker without validation, allowing access to internal services, "
            "cloud metadata and internal networks."
        ),
        reference_url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
]

OWASP_BY_ID = {control.code: control for control in OWASP_TOP_10_2021}


def owasp_control(code: str) -> FrameworkControl:
    code = code.split(":")[0]  # accept "A01:2021" style input
    return OWASP_BY_ID[code]