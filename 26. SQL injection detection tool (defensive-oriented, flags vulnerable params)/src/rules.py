"""Layer 1 - Signature / Rule Engine corpus.

Modeled on ARCHITECTURE.md section 6.1. Each rule is a compiled regex with
compliance metadata (CWE, OWASP, injection type, DB flavor, FP risk).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern


@dataclass(frozen=True)
class Rule:
    rid: str
    name: str
    pattern: str
    weight: float              # contribution to fused score (0..1)
    injection_type: str        # error | boolean | union | time | stacked | oob | generic
    db_flavor: str
    cwe: str
    owasp: str
    fp_risk: str               # low | medium | high
    description: str

    @property
    def compiled(self) -> Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE)


# Tautologies / boolean conditions
_R = [
    Rule("R-0001", "tautology-or-1=1",
         r"\bOR\s+[\w'.()`\"=]+\s*=\s*[\w'.()`\"=]+",
         0.85, "boolean", "ANY", "CWE-89", "A03", "medium",
         "'OR x=y' boolean primitive. Strong signal only with SQL context."),
    Rule("R-0002", "contradiction-and-1=2",
         r"\bAND\s+[\w'.()`\"=]+\s*=\s*[\w'.()`\"=]+",
         0.80, "boolean", "ANY", "CWE-89", "A03", "medium",
         "'AND x=y' boolean primitive used in differential probing."),
    Rule("R-0003", "quoted-tautology",
         r"'\s*OR\s+['\w.]+\s*=\s*['\w.]+\s*--",
         0.95, "boolean", "ANY", "CWE-89", "A03", "low",
         "Classic ' OR 1=1 -- comment-terminated boolean bypass."),
    Rule("R-0004", "literal-compare",
         r"\b\d+\s*=\s*\d+\b",
         0.55, "boolean", "ANY", "CWE-89", "A03", "high",
         "Numeric equality (1=1) - high FP in natural text; weighted low."),
    # Union-based
    Rule("R-0011", "union-select",
         r"\bUNION\s+(?:ALL\s+)?SELECT\b",
         0.98, "union", "ANY", "CWE-89", "A03", "low",
         "UNION SELECT column-retrieval primitive."),
    Rule("R-0012", "union-select-null",
         r"\bUNION\s+(?:ALL\s+)?SELECT\s+(?:NULL\s*,?\s*)+NULL\b",
         0.99, "union", "ANY", "CWE-89", "A03", "low",
         "UNION SELECT NULL NULL - column-count discovery."),
    Rule("R-0013", "order-by-column-probe",
         r"\bORDER\s+BY\s+\d+",
         0.70, "union", "ANY", "CWE-89", "A03", "medium",
         "ORDER BY n column-count probing (usually preceded by error)."),
    Rule("R-0014", "group-by-concat",
         r"\bGROUP\s+BY\s+\d+",
         0.60, "union", "ANY", "CWE-89", "A03", "medium",
         "GROUP BY n probing variant."),
    # Comments / comment markers (obfuscation pyjamas amplifier)
    Rule("R-0021", "comment-marker",
         r"(?:--[^\r\n]*|\#|/\*.*?\*/)",
         0.65, "generic", "ANY", "CWE-89", "A03", "high",
         "SQL comment marker. Weighted high-FP; usually combined with other hits."),
    Rule("R-0022", "inline-comment-in-keyword",
         r"\b\w+/\*.*?\*/\w+\b",
         0.90, "generic", "ANY", "CWE-89", "A03", "low",
         "Interleaved comment inside a keyword (sel/**/ect)."),
    Rule("R-0023", "mysql-hint-comment",
         r"/\*![\w\s]+\*/",
         0.95, "generic", "MySQL", "CWE-89", "A03", "low",
         "MySQL version-hint comment - obfuscation/privilege trick."),
    # DB keywords commonly used in extraction
    Rule("R-0031", "information-schema",
         r"\binformation_schema\b",
         0.85, "generic", "ANY", "CWE-89", "A03", "medium",
         "Schema-metadata table used in data exfiltration."),
    Rule("R-0032", "version-var",
         r"@@(?:version|version_compile_os|global\.version)",
         0.92, "generic", "MySQL", "CWE-89", "A03", "low",
         "MySQL global version variables."),
    Rule("R-0033", "db-name-fn",
         r"\b(?:DB_NAME|CURRENT_DATABASE|DATABASE)\s*\(",
         0.80, "generic", "ANY", "CWE-89", "A03", "medium",
         "Database-identity functions."),
    Rule("R-0034", "concat-char-probe",
         r"\bCONCAT\s*\(|\bCHAR\s*\(\s*\d+\s*(?:,\s*\d+\s*)*\)|\bCONVERT\s*\([^)]*\),?",
         0.78, "generic", "ANY", "CWE-89", "A03", "medium",
         "CONCAT/CHAR/CONVERT expression primitives."),
    Rule("R-0035", "select-from",
         r"\bSELECT\b.{0,40}\bFROM\b",
         0.82, "generic", "ANY", "CWE-89", "A03", "medium",
         "SELECT...FROM data-retrieval structure."),
    Rule("R-0036", "into-outfile",
         r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b",
         0.98, "generic", "MySQL", "CWE-89", "A03", "low",
         "INTO OUTFILE/DUMPFILE - file-write exfiltration."),
    Rule("R-0037", "load-file",
         r"\bLOAD_FILE\s*\(",
         0.97, "oob", "MySQL", "CWE-89", "A03", "low",
         "LOAD_FILE - server-file read primitive."),
    Rule("R-0038", "xp-cmdshell",
         r"\bxp_cmdshell\b",
         0.99, "oob", "MSSQL", "CWE-89", "A03", "low",
         "xp_cmdshell - command execution."),
    Rule("R-0039", "utl-http",
         r"\bUTL_HTTP\b|\bSYS_EXEC\b",
         0.97, "oob", "Oracle", "CWE-89", "A03", "low",
         "Oracle out-of-band primitives."),
    # Time-based blind primitives
    Rule("R-0041", "mysql-sleep",
         r"\bSLEEP\s*\(\s*\d+\s*\)",
         0.97, "time", "MySQL", "CWE-89", "A03", "low",
         "MySQL SLEEP(n) - time-based blind marker."),
    Rule("R-0042", "benchmark",
         r"\bBENCHMARK\s*\([^)]*\)",
         0.97, "time", "MySQL", "CWE-89", "A03", "low",
         "MySQL BENCHMARK(n,expr) CPU-delay marker."),
    Rule("R-0043", "pg-sleep",
         r"\bpg_sleep\s*\([^)]*\)",
         0.97, "time", "PostgreSQL", "CWE-89", "A03", "low",
         "PostgreSQL pg_sleep(n) delay marker."),
    Rule("R-0044", "waitfor-delay",
         r"\bWAITFOR\s+DELAY\s+['\"][^'\"]+['\"]",
         0.98, "time", "MSSQL", "CWE-89", "A03", "low",
         "MSSQL WAITFOR DELAY 'hh:mm:ss' marker."),
    Rule("R-0045", "dbms-lock",
         r"\bDBMS_LOCK\.SLEEP\b|\bdbms_pipe\b",
         0.97, "time", "Oracle", "CWE-89", "A03", "low",
         "Oracle DBMS_LOCK.SLEEP delay marker."),
    # Stacked query delimiters
    Rule("R-0051", "stacked-query-delim",
         r"(?:;|['\"]\s*;)\s*(?:SELECT|UPDATE|DELETE|INSERT|CREATE|DROP|ALTER)\s+\w+",
         0.93, "stacked", "ANY", "CWE-89", "A03", "low",
         "Semicolon-led second statement (stacked query)."),
    # Error-trigger primitives
    Rule("R-0061", "unterminated-quote-err",
         r"\w['\"](?:\s*(?:--|#|;)|\s*$)|[0-9a-z_]['\"]\s*(?:OR|AND|UNION|FROM|WHERE|SELECT)\b",
         0.60, "error", "ANY", "CWE-89", "A03", "medium",
         "Word-adjacent quote that breaks string context (1', admin' OR ...)."),
    Rule("R-0062", "round-expr",
         r"-(?:\d+|\w+\s*\()\s*AND\s*\w+",
         0.75, "error", "ANY", "CWE-89", "A03", "medium",
         "Arithmetic rounding construct (e.g. -1 AND 2) used by sqlmap."),
    Rule("R-0063", "numeric-math-operator-gap",
         r"\d+\s*(?:\+|\-)\s*\(?SELECT",
         0.92, "generic", "ANY", "CWE-89", "A03", "low",
         "arithmetic operator directly chaining a SELECT."),
    # LIKE wildcard abuse
    Rule("R-0071", "like-metachar",
         r"\bLIKE\s+['\"]?%",
         0.70, "generic", "ANY", "CWE-89", "A03", "medium",
         "LIKE '%%' constructs in unexpected params."),
    # XML/encoding-agnostic PERCENT / unicode escapes
    Rule("R-0072", "percent-char3-hex",
         r"%(?:2[0-9A-Fa-f]|3[0-9A-Fa-f]|4[0-9A-Fa-f]|5[0-9A-Fa-f]|6[0-9A-Fa-f]|7[0-9A-Fa-f])%",
         0.35, "generic", "ANY", "CWE-89", "A03", "high",
         "Percent-encoded ASCII triple - evasion indicator; low weight standalone."),
    # OS command / DB function spills
    Rule("R-0073", "dual-table",
         r"\bFROM\s+DUAL\b",
         0.80, "generic", "Oracle", "CWE-89", "A03", "low",
         "Oracle DUAL pseudo-table reference."),
    Rule("R-0074", "union-select-intofiles-char",
         r"\bCHAR\s*\(\s*0x[0-9A-Fa-f]+",
         0.90, "union", "ANY", "CWE-89", "A03", "low",
         "CHAR(0x...) hex-blob union payload."),
]

RULES: List[Rule] = _R
_RULES_COMPILED: List = []


def compiled_rules():
    if not _RULES_COMPILED:
        for r in RULES:
            _RULES_COMPILED.append((r, r.compiled))
    return _RULES_COMPILED