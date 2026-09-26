"""Intake / PE parsing / path-safety tests."""

from __future__ import annotations

import pytest

from acsv.intake import parse_pe_meta, safe_join


class TestPE:
    def test_not_pe(self, tmp_path):
        f = tmp_path / "text.txt"
        f.write_text("hello")
        m = parse_pe_meta(f)
        assert m["is_pe"] is False

    def test_real_pe(self):
        import sys
        py = __import__("sys").executable
        from pathlib import Path
        m = parse_pe_meta(Path(py))
        assert m["is_pe"] is True
        assert m["machine"] in ("x64", "x86", "ARM64", "ARM")


class TestPathSafety:
    def test_safe_join(self, tmp_path):
        out = safe_join(tmp_path, "ok\\nested.txt")
        assert str(out).startswith(str(tmp_path.resolve()))
        assert out == (tmp_path / "ok" / "nested.txt").resolve()

    def test_zip_slip_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            safe_join(tmp_path, "..\\..\\evil.txt")