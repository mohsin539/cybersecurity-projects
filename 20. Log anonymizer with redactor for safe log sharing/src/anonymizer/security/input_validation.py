"""Input validation and sanitization (OWASP A03 Injection, A04 Insecure Design).

Rejects malformed/malicious inputs before they reach the pipeline:
  - Size limits
  - Null-byte and control-character rejection
  - Log format validation
  - Max detection request size
"""

import re
from dataclasses import dataclass

MAX_LOG_LINE_LENGTH = 100_000
MAX_LINES_PER_BATCH = 100_000
MAX_DEPTH_NESTED = 50

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
NULL_BYTE_RE = re.compile(r"\\x00|%00|\\\\u0000")


@dataclass
class ValidationError(Exception):
    code: str = "INVALID_INPUT"
    detail: str = ""
    field: str = ""


class InputValidator:
    """Validates raw log input against hard constraints."""

    def __init__(
        self,
        max_line_length: int = MAX_LOG_LINE_LENGTH,
        max_batch_size: int = MAX_LINES_PER_BATCH,
    ):
        self.max_line_length = max_line_length
        self.max_batch_size = max_batch_size

    def validate_line(self, line: str, field_name: str = "log_line") -> str:
        """Validate a single log line; returns the safe line or raises."""
        if not isinstance(line, str):
            raise ValidationError("TYPE_ERROR", "Log line must be a string", field_name)
        if not line.strip():
            raise ValidationError("EMPTY", "Log line cannot be empty", field_name)
        if len(line) > self.max_line_length:
            raise ValidationError(
                "MAX_LENGTH", f"Log line exceeds {self.max_line_length} chars", field_name
            )
        if NULL_BYTE_RE.search(line):
            raise ValidationError("NULL_BYTE", "Null byte sequences are rejected", field_name)
        if CONTROL_CHAR_RE.search(line):
            raise ValidationError("CONTROL_CHAR", "Control characters are rejected", field_name)
        if "\n" in line:
            raise ValidationError("LINE_BREAK", "Log line must not contain line breaks", field_name)
        return line

    def validate_batch(self, lines: list, field_name: str = "log_lines") -> list:
        """Validate a batch; returns validated lines."""
        if not isinstance(lines, list):
            raise ValidationError("TYPE_ERROR", "Batch must be a list", field_name)
        if not lines:
            raise ValidationError("EMPTY_BATCH", "Batch cannot be empty", field_name)
        if len(lines) > self.max_batch_size:
            raise ValidationError(
                "MAX_BATCH", f"Batch exceeds {self.max_batch_size} lines", field_name
            )
        return [self.validate_line(l, field_name) for l in lines]

    def sanitize_metadata(self, request_headers: dict) -> dict:
        """Filter proxy-controlled headers (SSRF/header-injection protection)."""
        BLOCKED_HEADERS = {
            "x-forwarded-for",
            "x-forwarded-host",
            "x-real-ip",
            "x-amzn-*",
            "forwarded",
            "host",
            "content-length",
        }
        return {
            k: v
            for k, v in request_headers.items()
            if k.lower() not in BLOCKED_HEADERS and not k.startswith("x-amzn-")
        }
