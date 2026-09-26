"""Core module tests (stdlib unittest, no network)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import SecretVault  # noqa: E402
from app.core import entropy, hashing  # noqa: E402
from app.core.audit import AuditStore  # noqa: E402
from app.core.model import verdict_from_score  # noqa: E402
from app.core.pe_parser import parse_pe  # noqa: E402
from app.core.pipeline import analyze  # noqa: E402
from app.core.strings_extractor import extract_strings  # noqa: E402


class EntropyTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(entropy.shannon_entropy(b""), 0.0)

    def test_high_entropy(self):
        data = os.urandom(4096)
        self.assertGreater(entropy.shannon_entropy(data), 7.0)

    def test_low_entropy(self):
        self.assertLess(entropy.shannon_entropy(b"A" * 4096), 0.1)


class HashingTests(unittest.TestCase):
    def test_known_vectors(self):
        import hashlib as hl

        d = b"hello staticlab"
        digests = {
            "md5": hl.md5(d).hexdigest(),
            "sha1": hl.sha1(d).hexdigest(),
            "sha256": hl.sha256(d).hexdigest(),
            "sha512": hl.sha512(d).hexdigest(),
        }
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(d)
            path = f.name
        try:
            out = hashing.hash_file(path)
            self.assertEqual(out, digests)
        finally:
            os.unlink(path)


class StringsTests(unittest.TestCase):
    def test_ascii_and_unicode(self):
        # realistic layout: ASCII run, zero-pad, then aligned UTF-16LE (PE-style)
        data = b"MZ\x00" + b"HelloWorld\x00\x00\x00" + "WideStr".encode("utf-16le") + b"\x00\x00rest"
        hits = extract_strings(data, min_len=4)
        values = [h.value for h in hits]
        self.assertIn("HelloWorld", values)
        self.assertIn("WideStr", values)

    def test_url_flag(self):
        hits = extract_strings(b"get http://evil.example/x?token=1", min_len=4)
        urls = [h for h in hits if "url" in h.flags]
        self.assertTrue(any("http" in h.value for h in urls))


class VerdictTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(verdict_from_score(5)[0], "clean")
        self.assertEqual(verdict_from_score(30)[0], "suspicious")
        self.assertEqual(verdict_from_score(55)[0], "malicious")
        self.assertEqual(verdict_from_score(90)[0], "malicious_hc")


class AuditTests(unittest.TestCase):
    def test_chain_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            store = AuditStore(os.path.join(d, "audit.db"), os.urandom(32))
            store.append("test.action", "file.bin", {"x": 1})
            h1 = store.last_hash()
            store.append("test.action", "file2.bin", {"x": 2})
            ok, issues = store.verify_chain()
            self.assertTrue(ok, issues)
            # tamper: modify a payload directly via sqlite
            import sqlite3

            conn = sqlite3.connect(os.path.join(d, "audit.db"))
            conn.execute("UPDATE audit_chain SET payload='tampered' WHERE chain_hash=?", (h1,))
            conn.commit()
            conn.close()
            ok, issues = store.verify_chain()
            self.assertFalse(ok)
            store.close()


class PeParserTests(unittest.TestCase):
    def test_python_exe_is_pe(self):
        path = sys.executable  # python.exe is a real PE
        if not path.lower().endswith((".exe", ".dll")):
            self.skipTest("interpreter not an .exe/.dll")
        info = parse_pe(path)
        self.assertTrue(info.is_pe, info.warnings)
        self.assertGreater(info.number_of_sections, 0)

    def test_not_pe(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
            f.write(b"not an executable at all")
            path = f.name
        try:
            info = parse_pe(path)
            self.assertFalse(info.is_pe)
        finally:
            os.unlink(path)


class PipelineTests(unittest.TestCase):
    def test_analysis_mock_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"MZ" + os.urandom(64))
            path = f.name
        try:
            with tempfile.TemporaryDirectory() as d:
                store = AuditStore(os.path.join(d, "audit.db"), os.urandom(32))
                r = analyze(path, audit=store, lookups_enabled=[])
                self.assertTrue(r.hashes.sha256)
                self.assertIsNotNone(r.audit_chain_hash)
                self.assertTrue(r.audit_verified)
                store.close()
        finally:
            os.unlink(path)


class VaultTests(unittest.TestCase):
    def test_roundtrip_on_windows(self):
        import ctypes

        if not (os.name == "nt" and hasattr(ctypes, "windll")):
            self.skipTest("DPAPI not available")
        with tempfile.TemporaryDirectory() as d:
            v = SecretVault(os.path.join(d, "secrets.bin"))
            v.set("virustotal", "abc123")
            v2 = SecretVault(os.path.join(d, "secrets.bin"))
            self.assertEqual(v2.get("virustotal"), "abc123")


if __name__ == "__main__":
    unittest.main(verbosity=2)