"""Settings page: data dir, retention, redaction toggle, format policy,
portable mode info. All changes are audit-logged."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout,
    QWidget,
)

from .widgets import section_title


class SettingsPage(QWidget):
    def __init__(self, win) -> None:
        super().__init__()
        self.win = win
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(14)

        title = QLabel("Settings & Policy")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        svc = self.win.services
        lay.addWidget(section_title("Runtime"))
        info = QLabel(
            f"Policy:        {svc.policy.config_version}\n"
            f"Policy hash:   {svc.policy.snapshot_hash[:24]}…\n"
            f"Data dir:      {svc.config.data_dir}\n"
            f"Events/session cap: {svc.policy.max_events_per_session:,}\n"
            f"Timeout:       {svc.policy.capture_timeout_seconds}s\n"
            f"Retention:     {svc.policy.retention_days} days\n"
            f"Allowed formats: {', '.join(svc.policy.allowed_export_formats)}"
        )
        info.setStyleSheet("background:#111a2c; border:1px solid #233454; border-radius:10px;"
                           "padding:14px; color:#cbd5e1;")
        info.setObjectName("card")
        lay.addWidget(info)

        lay.addWidget(section_title("Security controls"))
        self.redact = QCheckBox("Redact PII / secrets in API args before persist")
        self.redact.setChecked(svc.policy.redact_pii)
        self.sign = QCheckBox("Sign generated reports (Ed25519, v1.2 rollout)")
        self.sign.setChecked(svc.policy.sign_reports)
        self.aud = QCheckBox("Audit logging enabled (append-only)")
        self.aud.setChecked(svc.policy.audit_enabled)
        for w in (self.redact, self.sign, self.aud):
            lay.addWidget(w)

        btn = QPushButton("Save policy changes")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._save)
        lay.addWidget(btn)

        lay.addStretch(1)
        lay.addWidget(section_title("About"))
        about = QLabel(
            "ACSV v1.0.0 — Portable API call sequence visualizer.\n"
            "Security: ISO27001:2022 · NIST CSF 2.0/SP 800-53 · OWASP Top 10 2021.\n"
            "Offline-first. No telemetry. Samples are never executed on the host."
        )
        about.setStyleSheet("color:#64748b; font-size:11px;")
        lay.addWidget(about)

    def _save(self) -> None:
        svc = self.win.services
        if self.redact.isChecked() != svc.policy.redact_pii:
            svc.record("SETTINGS_CHANGE", {"redact_pii": self.redact.isChecked()})
        if self.sign.isChecked() != svc.policy.sign_reports:
            svc.record("SETTINGS_CHANGE", {"sign_reports": self.sign.isChecked()})
        if self.aud.isChecked() != svc.policy.audit_enabled:
            svc.record("SETTINGS_CHANGE", {"audit_enabled": self.aud.isChecked()})
        QMessageBox.information(
            self, "Saved",
            "Viewer toggles stored in the audit log.\n"
            "Persistent policy must be edited in policies/default.toml then restarted."
        )