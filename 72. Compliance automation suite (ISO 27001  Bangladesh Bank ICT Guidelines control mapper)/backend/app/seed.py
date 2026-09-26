"""Seed data — frameworks, canonical controls, cross-framework mappings, demo assets."""
import hashlib
from datetime import datetime, timedelta, timezone

from .database import Base, SessionLocal, engine, naive_utcnow
from .models import (
    Asset, Control, ControlMapping, Evidence, EvidenceLink, Framework, RiskPoint,
    ScanResult, Setting, User, RemediationTicket,
)
from .security import hash_password
from .engines.risk import risk_tier

FRAMEWORKS = [
    {"code": "ISO27001", "name": "ISO/IEC 27001", "version": "2022",
     "publisher": "International Organization for Standardization", "cadence": "Annual Audit + Continuous"},
    {"code": "BBICT2015", "name": "Bangladesh Bank ICT Guidelines", "version": "2015",
     "publisher": "Bangladesh Bank (BB)", "cadence": "Quarterly F&R + Annual"},
    {"code": "NISTCSF", "name": "NIST Cybersecurity Framework", "version": "2.0",
     "publisher": "NIST", "cadence": "Continuous"},
    {"code": "OWASP2021", "name": "OWASP Top 10", "version": "2021",
     "publisher": "OWASP Foundation", "cadence": "Each Release / CI"},
]

ISO_CONTROLS = [
    ("A.5.1", "Policies for information security", "POLICY", "MUST"),
    ("A.5.2", "Information security roles and responsibilities", "GOVERNANCE", "MUST"),
    ("A.5.7", "Threat intelligence", "THREAT_INTEL", "SHOULD"),
    ("A.5.9", "Inventory of information and other associated assets", "ASSET_INVENTORY", "MUST"),
    ("A.5.10", "Acceptable use of information and other associated assets", "ACCEPTABLE_USE", "MUST"),
    ("A.5.15", "Access control", "ACCESS_CONTROL", "MUST"),
    ("A.5.24", "Planning and preparation of information security incident management", "INCIDENT", "MUST"),
    ("A.5.30", "ICT readiness for business continuity", "BCM", "MUST"),
    ("A.6.3", "Information security awareness, education and training", "TRAINING", "MUST"),
    ("A.7.4", "Physical security monitoring", "PHYSICAL", "SHOULD"),
    ("A.8.2", "Assignment of access rights", "ACCESS_CONTROL", "MUST"),
    ("A.8.5", "Secure authentication", "IDENTITY", "MUST"),
    ("A.8.8", "Management of technical vulnerabilities", "VULNERABILITY", "MUST"),
    ("A.8.9", "Configuration management", "CONFIGURATION", "SHOULD"),
    ("A.8.15", "Logging", "LOG_AND_MONITOR", "MUST"),
    ("A.8.16", "Monitoring activities", "LOG_AND_MONITOR", "MUST"),
    ("A.8.20", "Networks security", "NETWORK", "MUST"),
    ("A.8.24", "Use of cryptography", "CRYPTOGRAPHY", "MUST"),
    ("A.8.28", "Secure coding", "SECURE_CODING", "MUST"),
    ("A.8.34", "Protection of information systems during audit testing", "AUDIT", "SHOULD"),
]

BB_CONTROLS = [
    ("CH-01", "BOD & Senior Management oversight", "GOVERNANCE", "MUST"),
    ("CH-02", "ICT strategic planning", "GOVERNANCE", "MUST"),
    ("CH-03", "Risk management framework", "RISK_MANAGEMENT", "MUST"),
    ("CH-06", "Outsourcing & third-party ICT risk", "VENDOR_RISK", "MUST"),
    ("CH-08", "ICT procurement & vendor management", "VENDOR_RISK", "SHOULD"),
    ("CH-12", "Network, systems & application security", "NETWORK", "MUST"),
    ("CH-14", "Information security operations", "LOG_AND_MONITOR", "MUST"),
    ("CH-15", "Physical & environmental security", "PHYSICAL", "MUST"),
    ("CH-16", "Access control & identity management", "ACCESS_CONTROL", "MUST"),
    ("CH-17", "Human resources security", "TRAINING", "MUST"),
    ("CH-18", "Business continuity & disaster recovery management", "BCM", "MUST"),
    ("CH-19", "Incident management", "INCIDENT", "MUST"),
    ("CH-27", "Cyber incident response plan", "INCIDENT", "MUST"),
    ("CH-31", "E-banking & digital channel security", "SECURE_CODING", "MUST"),
]

NIST_CONTROLS = [
    ("GV.RM-01", "Risk management strategy established", "RISK_MANAGEMENT", "MUST"),
    ("ID.AM-01", "Inventory of physical and logical assets", "ASSET_INVENTORY", "MUST"),
    ("PR.AC-01", "Identities and credentials managed", "IDENTITY", "MUST"),
    ("PR.DS-01", "Data-at-rest protected", "DATA_PROTECTION", "MUST"),
    ("PR.DS-06", "Integrity checking mechanisms", "DATA_PROTECTION", "MUST"),
    ("PR.AT-01", "Personnel provided awareness & training", "TRAINING", "MUST"),
    ("PR.PT-04", "Networks & communications secured", "NETWORK", "MUST"),
    ("DE.CM-01", "Network monitored for anomalies", "LOG_AND_MONITOR", "MUST"),
    ("RS.RP-01", "Response plan executed during events", "INCIDENT", "MUST"),
    ("RC.RP-01", "Recovery plan executed during/after events", "BCM", "MUST"),
    ("RA-5", "Vulnerability monitoring & scanning", "VULNERABILITY", "MUST"),
    ("SC-13", "Cryptographic protection", "CRYPTOGRAPHY", "MUST"),
]

OWASP_CONTROLS = [
    ("A01:2021", "Broken Access Control", "ACCESS_CONTROL", "MUST"),
    ("A02:2021", "Cryptographic Failures", "CRYPTOGRAPHY", "MUST"),
    ("A03:2021", "Injection", "SECURE_CODING", "MUST"),
    ("A04:2021", "Insecure Design", "SECURE_CODING", "MUST"),
    ("A05:2021", "Security Misconfiguration", "CONFIGURATION", "MUST"),
    ("A06:2021", "Vulnerable and Outdated Components", "VULNERABILITY", "MUST"),
    ("A07:2021", "Identification and Authentication Failures", "IDENTITY", "MUST"),
    ("A08:2021", "Software and Data Integrity Failures", "DATA_PROTECTION", "MUST"),
    ("A09:2021", "Security Logging and Monitoring Failures", "LOG_AND_MONITOR", "MUST"),
    ("A10:2021", "Server-Side Request Forgery", "SECURE_CODING", "MUST"),
]

MAPPING_HINTS = {
    "POLICY": [("BBICT2015", "CH-01"), ("NISTCSF", "GV.RM-01")],
    "GOVERNANCE": [("BBICT2015", "CH-02")],
    "ASSET_INVENTORY": [("NISTCSF", "ID.AM-01")],
    "ACCESS_CONTROL": [("BBICT2015", "CH-16"), ("NISTCSF", "PR.AC-01"), ("OWASP2021", "A01:2021")],
    "IDENTITY": [("BBICT2015", "CH-16"), ("NISTCSF", "PR.AC-01"), ("OWASP2021", "A07:2021")],
    "VULNERABILITY": [("BBICT2015", "CH-12"), ("NISTCSF", "RA-5"), ("OWASP2021", "A06:2021")],
    "CONFIGURATION": [("BBICT2015", "CH-12"), ("OWASP2021", "A05:2021")],
    "LOG_AND_MONITOR": [("BBICT2015", "CH-14"), ("NISTCSF", "DE.CM-01"), ("OWASP2021", "A09:2021")],
    "NETWORK": [("BBICT2015", "CH-12"), ("NISTCSF", "PR.PT-04")],
    "CRYPTOGRAPHY": [("BBICT2015", "CH-14"), ("NISTCSF", "SC-13"), ("OWASP2021", "A02:2021")],
    "SECURE_CODING": [("BBICT2015", "CH-31"), ("OWASP2021", "A03:2021")],
    "TRAINING": [("BBICT2015", "CH-17"), ("NISTCSF", "PR.AT-01")],
    "BCM": [("BBICT2015", "CH-18"), ("NISTCSF", "RC.RP-01")],
    "INCIDENT": [("BBICT2015", "CH-19"), ("NISTCSF", "RS.RP-01")],
    "THREAT_INTEL": [("BBICT2015", "CH-03")],
    "RISK_MANAGEMENT": [("BBICT2015", "CH-03"), ("NISTCSF", "GV.RM-01")],
    "VENDOR_RISK": [("BBICT2015", "CH-08")],
    "PHYSICAL": [("BBICT2015", "CH-15")],
    "DATA_PROTECTION": [("BBICT2015", "CH-14"), ("NISTCSF", "PR.DS-01"), ("OWASP2021", "A08:2021")],
}

ASSETS = [
    ("Core Banking System (CBS)", "DB", "PRODUCTION", "RESTRICTED", "Head of IT", 5.0),
    ("Internet Banking Portal", "WEB_APP", "PRODUCTION", "RESTRICTED", "Head of Digital", 5.0),
    ("Customer API Gateway", "API", "PRODUCTION", "RESTRICTED", "Head of Digital", 4.5),
    ("Mobile Banking App Backend", "API", "PRODUCTION", "CONFIDENTIAL", "Head of Mobile", 4.5),
    ("Network Perimeter (Firewall)", "NETWORK", "PRODUCTION", "RESTRICTED", "CISO", 5.0),
    ("Internal HR Systems", "WEB_APP", "INTERNAL", "CONFIDENTIAL", "Head of HR", 3.0),
    ("SWIFT Connectivity", "NETWORK", "PRODUCTION", "RESTRICTED", "Treasury", 5.0),
    ("Dev/CI Pipeline", "ENDPOINT", "DEVELOPMENT", "INTERNAL", "DevOps Lead", 3.5),
]

SCAN_FINDINGS = [
    ("Internet Banking Portal", "OWASP_ZAP", "DAST", "SQL Injection in login endpoint", "CRITICAL", 9.1),
    ("Internet Banking Portal", "OWASP_ZAP", "DAST", "Stored XSS in transaction notes", "HIGH", 7.4),
    ("Customer API Gateway", "OWASP_ZAP", "DAST", "Broken object-level authorization (IDOR)", "HIGH", 7.8),
    ("Mobile Banking App Backend", "SEMGREP", "SAST", "Hard-coded API key in source", "HIGH", 7.5),
    ("Core Banking System (CBS)", "NESSUS", "INFRA", "TLS 1.0 enabled on legacy port", "MEDIUM", 5.2),
    ("Network Perimeter (Firewall)", "CHECKOV", "CSPM", "Security group allows 0.0.0.0/0 to 3306", "HIGH", 7.0),
    ("Dev/CI Pipeline", "TRIVY", "SCA", "Outdated Node 16 image (CVE-2024)", "MEDIUM", 6.5),
    ("Internal HR Systems", "OWASP_ZAP", "DAST", "Missing security headers (CSP)", "LOW", 3.1),
]

USERS = [
    ("admin", "admin@bank.local", "Super Admin", "SUPER_ADMIN", "Admin@12345"),
    ("ciso", "ciso@bank.local", "Chief Information Security Officer", "CISO", "Ciso@12345"),
    ("auditor", "auditor@bank.local", "External Auditor", "ASSESSOR", "Audit@12345"),
    ("owner", "control.owner@bank.local", "Control Owner (Head of IT)", "CONTROL_OWNER", "Owner@12345"),
    ("regulator", "bb.ict@bb.org.bd", "Bangladesh Bank Examiner", "REGULATOR", "Regul@12345"),
]

EVIDENCE_SAMPLES = [
    ("KMS Encryption Policy (A.8.24 / PR.DS-1)", "POLICY", "AWS KMS", ["A.8.24", "A.8.5", "CH-14", "PR.DS-01", "A02:2021"]),
    ("Annual Pentest Report 2026", "SCAN_REPORT", "Nessus", ["A.8.8", "CH-12", "RA-5", "A06:2021"]),
    ("IAM Role Baseline Export", "CONFIG_BASELINE", "AWS IAM", ["A.8.2", "CH-16", "PR.AC-01", "A01:2021"]),
    ("SIEM Log Retention Policy", "LOG_EXPORT", "OpenSearch", ["A.8.15", "CH-14", "DE.CM-01", "A09:2021"]),
    ("Secure SDLC Code Review Report", "SCAN_REPORT", "Semgrep", ["A.8.28", "CH-31", "A03:2021", "A04:2021"]),
    ("DR Test Sign-off (RTO 2h)", "AUDIT", "BCM Office", ["A.5.30", "CH-18", "RC.RP-01"]),
]

RISKS = [
    ("SQL Injection exposure on internet banking", "CRITICAL", 5, 5, 9.1, "OPEN"),
    ("IDOR on customer API gateway", "HIGH", 4, 5, 7.8, "OPEN"),
    ("Broad network egress to database tier", "HIGH", 4, 4, 7.0, "OPEN"),
    ("Legacy TLS 1.0 allowed on ageing endpoints", "MEDIUM", 3, 3, 5.2, "MITIGATING"),
    ("API key hard-code in mobile backend", "HIGH", 4, 4, 7.5, "OPEN"),
    ("Missing CSP headers on HR portal", "LOW", 2, 2, 3.1, "ACCEPTED"),
]


def seed(force: bool = False):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Framework).count() > 0 and not force:
            print("Database already seeded. Use force=True to re-seed.")
            return
        if force:
            Base.metadata.drop_all(bind=engine)
            Base.metadata.create_all(bind=engine)

        fw_map = {}
        for f in FRAMEWORKS:
            fw = Framework(**f)
            db.add(fw)
            fw_map[f["code"]] = fw
        db.commit()

        ctrl_by_fw_code = {}
        for fw_code, controls, ctrl_def in (
            ("ISO27001", ISO_CONTROLS, None), ("BBICT2015", BB_CONTROLS, None),
            ("NISTCSF", NIST_CONTROLS, None), ("OWASP2021", OWASP_CONTROLS, None),
        ):
            for code, title, category, intent in controls:
                c = Control(framework_id=fw_map[fw_code].id, code=code, title=title,
                            category=category, intent=intent, owner="TBD",
                            implementation_status="NOT_ASSESSED")
                db.add(c)
        db.commit()

        index = {fw_code: {c.code: c for c in db.query(Control).filter(
            Control.framework_id == fw_map[fw_code].id).all()} for fw_code in fw_map}

        for src_fw_code in ("ISO27001", "OWASP2021"):
            for src_code, src_ctrl in index[src_fw_code].items():
                for target_fw, target_code in MAPPING_HINTS.get(src_ctrl.category, []):
                    target_ctrl = index.get(target_fw, {}).get(target_code)
                    if target_ctrl and src_ctrl.id != target_ctrl.id:
                        exists = db.query(ControlMapping).filter(
                            ControlMapping.source_id == src_ctrl.id,
                            ControlMapping.target_id == target_ctrl.id).first()
                        if not exists:
                            db.add(ControlMapping(
                                source_id=src_ctrl.id, target_id=target_ctrl.id,
                                map_type="EQUIVALENT",
                                rationale=f"Canonical category '{src_ctrl.category}' equivalence"))
        db.commit()

        for username, email, display, role, pwd in USERS:
            db.add(User(username=username, email=email, display_name=display,
                        role=role, password_hash=hash_password(pwd), mfa_enabled=True))
        db.commit()

        asset_map = {}
        for name, atype, env, cls, owner, crit in ASSETS:
            a = Asset(name=name, asset_type=atype, environment=env, classification=cls,
                      owner=owner, criticality=crit)
            db.add(a)
            asset_map[name] = a
        db.commit()

        for asset_name, scanner, ftype, title, severity, cvss in SCAN_FINDINGS:
            db.add(ScanResult(asset_id=asset_map[asset_name].id, scanner=scanner,
                              finding_type=ftype, title=title, severity=severity,
                              cvss=cvss, status="OPEN"))
        db.commit()

        all_controls = {c.code: c for c in db.query(Control).all()}
        ev_hashes = []
        for title, atype, source, codes in EVIDENCE_SAMPLES:
            chain_input = hashlib.sha256(f"{title}|{source}".encode()).hexdigest()
            ev_hashes.append(chain_input)
        prev = hashlib.sha256(b"VAULT_GENESIS").hexdigest()
        now = naive_utcnow()
        for idx, (title, atype, source, codes) in enumerate(EVIDENCE_SAMPLES):
            chain_hash = hashlib.sha256(
                f"{idx + 1}|{title}|{atype}|{ev_hashes[idx]}|{now.isoformat()}|{prev}".encode()).hexdigest()
            ev = Evidence(
                title=title, artefact_type=atype, source_system=source,
                description=f"Seed evidence for {', '.join(codes)}",
                mime_type="text/plain", file_size=1024, sha256=ev_hashes[idx],
                chain_hash=chain_hash, uploaded_by="ciso", worm_locked=True,
                retention_days=365, created_at=now,
            )
            db.add(ev)
            db.commit()
            db.refresh(ev)
            for code in codes:
                ctrl = all_controls.get(code)
                if ctrl:
                    link = EvidenceLink(evidence_id=ev.id, control_id=ctrl.id, linked_by="ciso")
                    db.add(link)
            prev = chain_hash
        db.commit()

        for title, tier, like, impact, cvss, status in RISKS:
            db.add(RiskPoint(
                title=title, likelihood=like, impact=impact, cvss=cvss,
                raw_score=round((like * impact / 25) * 0.6 + (cvss / 10) * 0.4, 3),
                residual_score=round((like * impact / 25) * 0.6 * 0.8 + (cvss / 10) * 0.4, 3),
                tier=tier, status=status,
            ))
        db.commit()

        for t in db.query(RiskPoint).filter(RiskPoint.tier.in_(["CRITICAL", "HIGH"]),
                                            RiskPoint.status == "OPEN").all():
            sla = {"CRITICAL": 24, "HIGH": 72}[t.tier]
            db.add(RemediationTicket(
                risk_id=t.id, title=f"Remediate: {t.title}",
                description="Auto-escalated during seed.", priority=t.tier,
                sla_hours=sla, due_at=now + timedelta(hours=sla), status="OPEN"))
        db.commit()

        db.add(Setting(key="platform.name", value="Compliance Automation Suite v1.0.0"))
        db.add(Setting(key="schema.version", value="1"))
        db.add(Setting(key="seed_created_at", value=now.isoformat()))
        db.commit()

        print(f"Seeded: {db.query(Framework).count()} frameworks, "
              f"{db.query(Control).count()} controls, "
              f"{db.query(Asset).count()} assets, "
              f"{db.query(Evidence).count()} evidence, "
              f"{db.query(RiskPoint).count()} risks, "
              f"{db.query(User).count()} users.")
    finally:
        db.close()


if __name__ == "__main__":
    seed(force=False)