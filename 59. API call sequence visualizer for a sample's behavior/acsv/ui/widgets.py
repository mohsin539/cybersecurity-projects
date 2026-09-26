"""Shared GUI widgets."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout


def kpi_card(title: str, value: str, accent: str = "#fbbf24") -> QFrame:
    card = QFrame()
    card.setObjectName("card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(14, 12, 14, 12)
    val = QLabel(str(value))
    val.setObjectName("kpi_value")
    val.setStyleSheet(f"color: {accent}; font-size: 26px; font-weight: 700;")
    lab = QLabel(title)
    lab.setObjectName("kpi_label")
    lay.addWidget(val)
    lay.addWidget(lab)
    return card


def section_title(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("SectionTitle")
    return lab


def row(*widgets) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(10)
    for w in widgets:
        lay.addWidget(w)
    return lay


def chip(text: str, color: str) -> QLabel:
    lab = QLabel(text)
    lab.setAlignment(lab.AlignCenter)
    lab.setStyleSheet(
        f"background:{color}; color:#04101a; border-radius:9px;"
        f"padding:3px 10px; font-weight:600; font-size:11px;"
    )
    return lab