from __future__ import annotations

from typing import Any, Optional

from .intake import read_quarantined
from .models import RESULT_SCHEMA_VERSION, Sample, StaticFindings
from .staticanalyzer import file_entropy, printable_prefix

# architecture.md section 7: Encryption Pattern Study Module.
# All heuristics are statistical/structural. No cryptographic claims of exact
# algorithm; every inference carries an explicit confidence and source.

NO_SIGNATURE = "no-encryption-signature"
FULL_FILE = "full-file-encryption"
FORMAT_PRESERVING = "format-preserving-encryption"
HIGH_ENTROPY = "high-entropy-payload"


def _classify_pattern(entropy: float, hr: float, printable: bool) -> tuple[str, float]:
    if entropy >= 7.8 and hr >= 0.92:
        conf = min(0.97, 0.75 + (entropy - 7.8) * 0.35 + (hr - 0.92) * 0.4)
        return FULL_FILE, round(conf, 3)
    if entropy >= 7.0 and hr >= 0.6:
        conf = min(0.88, 0.5 + (entropy - 7.0) * 0.2)
        return HIGH_ENTROPY, round(conf, 3)
    if hr >= 0.35 and printable:
        conf = 0.55 + (hr - 0.35) * 0.4
        return FORMAT_PRESERVING, round(min(conf, 0.85), 3)
    if entropy < 6.0:
        return NO_SIGNATURE, 0.9
    return NO_SIGNATURE, 0.55


def _guess_algorithm(static: StaticFindings, pattern: str) -> dict[str, Any]:
    if pattern == NO_SIGNATURE:
        return {"guess": "not-applicable", "confidence": 0.9, "source": ["static"]}
    hints = [h for h in static.crypto_imports if h in ("RSA", "AES", "CHACHA", "OPENSSL", "CRYPTOAPI")]
    if hints and static.pe_info.get("is_pe"):
        guess = " / ".join(hints[:3]).lower()
        return {"guess": guess + "-family (suspected)", "confidence": 0.45, "source": ["import-hints"]}
    if hints:
        return {"guess": hints[0].lower() + "-family (suspected)", "confidence": 0.35, "source": ["string-hints"]}
    return {
        "guess": "statistical (symmetric block-cipher output consistent)",
        "confidence": 0.3,
        "source": ["entropy-model"],
    }


def _key_handling(static: StaticFindings) -> dict[str, Any]:
    low = " ".join(i.lower() for i in static.crypto_imports + static.ransom_indicators)
    if "rsa" in low or "publickey" in low or "importkey" in low:
        return {"pattern": "hybrid-asymmetric-envelope (suspected)",
                "note": "embedded public-key usage implied by observed strings"}
    if "cryptgenkey" in low or "generatekey" in low:
        return {"pattern": "on-host key generation (suspected)",
                "note": "key material likely session-scoped"}
    return {"pattern": "unknown", "note": "no key-handling hints observed"}


def _evidence_analysis(static: StaticFindings, evidence_path: Optional[str]) -> tuple[dict[str, Any], float]:
    """Compare suspect (quarantined) vs evidence original when supplied."""
    if not evidence_path:
        return {
            "evidence_mode": "single-file-static",
            "files_touched": None,
            "on_device_source": "not-observed (non-executing workbench)",
        }, 0.0
    try:
        with open(evidence_path, "rb") as f:
            ev = f.read()
    except OSError:
        return {"evidence_mode": "error-reading-evidence", "files_touched": None}, 0.0

    ev_ent = file_entropy(ev)
    delta = static.entropy - ev_ent
    boost = 0.0
    if ev_ent < 7.0 and delta >= 1.5:
        boost = 0.15
        strategy = "rewrite / encryption of original content"
    elif static.entropy >= 7.5:
        boost = 0.08
        strategy = "high-entropy suspect vs lower-entropy original"
    else:
        strategy = "comparable entropy - weak evidence"
    return {
        "evidence_mode": "original-vs-suspect pair",
        "files_touched": "pair (original + suspect)",
        "original_entropy": round(ev_ent, 4),
        "suspect_entropy": round(static.entropy, 4),
        "entropy_delta": round(delta, 4),
        "observed_strategy": strategy,
    }, boost


def build_fingerprint(sample: Sample, static: StaticFindings,
                      evidence_path: Optional[str] = None) -> dict[str, Any]:
    data = read_quarantined(sample)
    ent = static.entropy
    hr = static.block_high_entropy_ratio
    printable = printable_prefix(data)

    pattern, base_conf = _classify_pattern(ent, hr, printable)
    algo = _guess_algorithm(static, pattern)
    keys = _key_handling(static)
    cov, ev_boost = _evidence_analysis(static, evidence_path)

    indicator_text = " ".join(static.ransom_indicators).lower()
    note_present = any(k in indicator_text for k in
                       ("ransom", "bitcoin", "recover your files", "decrypt", "wallet", "unlock"))
    ransom_note = {
        "present": bool(note_present),
        "confidence": 0.7 if note_present else 0.9,
        "note_indicators": static.ransom_indicators[:6],
    }

    if pattern == NO_SIGNATURE:
        overall = 0.95 * base_conf
    else:
        overall = 0.55 * base_conf + 0.22 * min(algo["confidence"] + 0.1, 0.8) \
            + 0.08 * ransom_note["confidence"] + 0.2 * ev_boost
        overall = min(overall, 0.97)

    risk_flag = pattern != NO_SIGNATURE and overall >= 0.55

    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "sample": {
            "sha256": sample.sha256,
            "original_name": sample.original_name,
            "size": sample.size,
            "magic_hex": sample.magic_hex,
            "magic_hint": sample.magic_hint,
        },
        "environment": {
            "mode": "portable-workbench",
            "execution": False,
            "execution_note": "non-executing: no sample was launched",
            "static_signature_version": "1.0",
        },
        "pattern": {
            "class": pattern,
            "entropy_bits_per_byte": round(ent, 4),
            "high_entropy_block_ratio": round(hr, 4),
            "printable_header": printable,
            "block_size_hint_bytes": 8192,
        },
        "algorithm": algo,
        "key_handling": keys,
        "coverage": cov,
        "ransom_note": ransom_note,
        "confidence_overall": round(overall, 3),
        "risk_flag": bool(risk_flag),
        "summary": _summary_text(pattern, overall, note_present),
    }


def _summary_text(pattern: str, confidence: float, note_present: bool) -> str:
    label = {
        NO_SIGNATURE: "no strong encryption-consistent signal",
        FULL_FILE: "full-file encryption signature",
        HIGH_ENTROPY: "high-entropy encrypted payload",
        FORMAT_PRESERVING: "format-preserving encryption signature",
    }[pattern]
    note = "ransom-note indicators present" if note_present else "no ransom-note indicators"
    return f"{label} (confidence {confidence:.2f}); {note}."