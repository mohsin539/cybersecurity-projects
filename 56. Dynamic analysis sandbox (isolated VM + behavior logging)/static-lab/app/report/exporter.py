"""Export an AnalysisResult to HTML / JSON / plain text."""

from __future__ import annotations

import html as htmlmod
import json
from typing import Optional

from ..core.model import AnalysisResult
from .template import render_html

_VERDICT_COLORS = {"clean": "#2ea043", "suspicious": "#e08a00", "malicious": "#d1242f", "malicious_hc": "#8c1a22"}


def export_json(result: AnalysisResult, pretty: bool = True) -> str:
    d = result.to_dict()
    return json.dumps(d, indent=2, default=str) if pretty else json.dumps(d, default=str)


def export_txt(result: AnalysisResult) -> str:
    line = "-" * 58
    out = [line, "StaticLab v1.0 - Static Analysis Report (TXT)", line]
    out.append(f"Analysis ID: {result.analysis_id}")
    out.append(f"File: {result.file_path}")
    out.append(f"Size: {result.file_size:,} bytes")
    out.append(f"Magic hint: {result.magic_hint or 'n/a'}")
    out.append(f"Verdict: {result.verdict_label} (score {result.score}/100)")
    if result.hashes:
        out.append("Hashes:")
        out.append(f"  MD5     {result.hashes.md5}")
        out.append(f"  SHA-1   {result.hashes.sha1}")
        out.append(f"  SHA-256 {result.hashes.sha256}")
        out.append(f"  SHA-512 {result.hashes.sha512}")
        out.append(f"  imphash {result.hashes.imphash or '-'}")
        out.append(f"  entropy {result.hashes.entropy:.4f} bits/byte")
    if result.pe and result.pe.is_pe:
        pe = result.pe
        out.append(f"PE: {pe.magic} machine={pe.machine} sections={pe.number_of_sections}")
        out.append(f"    entry={pe.entry_point:#x} image_base={pe.image_base:#x} subsystem={pe.subsystem}")
        out.append(f"    dll={pe.is_dll} driver={pe.is_driver} signed={pe.is_signed}")
        out.append(f"    cert_present={pe.certificate_present} overlay={pe.overlay_size} bytes")
        for s in pe.sections:
            out.append(f"    sect {s.name}: entropy {s.entropy:.3f} size {s.raw_size}")
    for rep in result.lookups:
        out.append(f"[lookup:{rep.provider}] status={rep.status} score={rep.score} msg={rep.message}")
    out.append(f"Threat url: {result.tls_url}")
    if result.audit_chain_hash:
        out.append(f"Audit chain: {result.audit_chain_hash}")
        out.append(f"Audit verified: {result.audit_verified}")
    out.append(line)
    return "\n".join(out)


def _esc(v: Optional[str]) -> str:
    return htmlmod.escape(str(v), quote=True) if v is not None else "&mdash;"


def export_html(result: AnalysisResult, extra: Optional[str] = None) -> str:
    """Render the attractive, self-contained HTML report (no external assets)."""
    vcolor = _VERDICT_COLORS.get(result.verdict_key, "#888")
    h = result.hashes
    pe = result.pe if (result.pe and result.pe.is_pe) else None

    hashes_rows = ""
    if h:
        for label, val in (
            ("MD5", h.md5),
            ("SHA-1", h.sha1),
            ("SHA-256", h.sha256),
            ("SHA-512", h.sha512),
            ("imphash", h.imphash),
            ("Authentihash", h.authentihash),
        ):
            hashes_rows += f"<tr><td>{_esc(label)}</td><td class='mono'>{_esc(val) or '&mdash;'}</td></tr>"

    pe_rows = ""
    if pe:
        props = [
            ("Format", f"{_esc(pe.magic)} ({'DLL' if pe.is_dll else 'EXE'}{' driver' if pe.is_driver else ''})"),
            ("Machine", pe.machine),
            ("Sections", str(pe.number_of_sections)),
            ("Timestamp", pe.timestamp),
            ("Entry Point", f"0x{pe.entry_point:X}" if pe.entry_point else "&mdash;"),
            ("Image Base", f"0x{pe.image_base:X}" if pe.image_base else "&mdash;"),
            ("Subsystem", pe.subsystem),
            ("DLL Characteristics", pe.dll_characteristics),
            ("Cert Table", "present" if pe.certificate_present else "absent"),
            ("Signed (pefile)", "yes" if pe.is_signed else "no"),
            ("Overlay Size", f"{pe.overlay_size:,} bytes" + ("  <span class=warn>&#9888;</span> embedded PE!" if pe.overlay_pe_embedded else "")),
            ("Linker Version", pe.linker_version or "&mdash;"),
            ("Debug Info", pe.debug_type or "none"),
            ("TLS Callbacks", str(pe.tls_callbacks)),
        ]
        pe_rows = "".join(
            f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in props if v
        )
        if pe.warnings:
            pe_rows += "".join(
                f"<tr><td>warn</td><td class='warn'>{_esc(w)}</td></tr>" for w in pe.warnings[:6]
            )

    sections_rows = ""
    if pe:
        for s in pe.sections:
            color = "#2ea043" if s.entropy < 6.5 else "#e08a00" if s.entropy < 7.4 else "#d1242f"
            sections_rows += (
                f"<tr><td>{_esc(s.name)}</td><td>0x{s.virtual_address:X}</td>"
                f"<td>{s.virtual_size:,}</td><td>{s.raw_size:,}</td>"
                f"<td style='color:{color};font-weight:600'>{s.entropy:.3f}</td>"
                f"<td class='mono'>{_esc(s.sha256[:16])}&#8230;</td></tr>"
            )

    if pe:
        imports_rows = ""
        for dll, funcs in pe.imports[:60]:
            imports_rows += f"<tr><td>{_esc(dll)}</td><td class='mono'>{_esc(', '.join(funcs[:24]))}</td></tr>"
    else:
        imports_rows = f"<tr><td colspan=2>{_esc(result.magic_hint or 'not a PE')}</td></tr>"

    sus_rows = ""
    for s in (result.suspicious_strings or result.strings[:400])[:400]:
        flags = " ".join(f"<span class='chip'>{f}</span>" for f in s.flags[:4])
        sus_rows += f"<tr><td class='mono'>0x{s.offset:X}</td><td>{_esc(s.encoding)}</td><td>{_esc(s.value[:200])}</td><td>{flags}</td></tr>"

    lu_cards = ""
    for r in result.lookups:
        badge = {"no_key": "<span class='chip warn'>no key</span>", "error": "<span class='chip err'>error</span>"}.get(r.status, "")
        link = f"<a href='{_esc(r.url)}' target=_blank>{_esc(r.url)}</a>" if r.url else "&mdash;"
        score_c = "#2ea043" if (r.score or 0) < 20 else "#e08a00" if (r.score or 0) < 60 else "#d1242f"
        lu_cards += (
            f"<div class='card'><div class='card-title'>{_esc(r.provider)} {badge}</div>"
            f"<div class='mono'>{_esc(r.sha256[:16])}&#8230;</div>"
            f"<div>status: {_esc(r.status)}</div>"
            f"<div style='color:{score_c}'>score: {r.score or 0}/100</div>"
            f"<div>{_esc(r.message)}</div><div class='small'>{link}</div></div>"
        )

    audit_html = ""
    if result.audit_chain_hash:
        ok = bool(result.audit_verified)
        audit_html = (
            f"<tr><td>Audit Chain Hash</td><td class='mono'>{_esc(result.audit_chain_hash)}</td></tr>"
            f"<tr><td>Chain Verified</td><td>{'<span class=chip-ok>VERIFIED</span>' if ok else '<span class=chip-err>FAILED</span>'}</td></tr>"
        )

    extra_html = extra or ""
    return render_html(
        verdict=result.verdict_label,
        verdict_color=vcolor,
        score=result.score,
        analysis_id=result.analysis_id,
        file_path=result.file_path,
        file_name=result.file_name,
        file_size=result.file_size,
        magic_hint=result.magic_hint or "&mdash;",
        hashes_rows=hashes_rows,
        pe_rows=pe_rows,
        sections_rows=sections_rows,
        imports_rows=imports_rows,
        suspicious_rows=sus_rows,
        string_count=len(result.strings),
        lookup_cards=lu_cards,
        audit_html=audit_html,
        extra=extra_html,
    )