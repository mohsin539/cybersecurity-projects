from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from timeline_builder.security.audit import AuditLogger, verify_audit_chain
from timeline_builder.security.crypto import is_encryption_available, seal_bytes, unseal_bytes
from timeline_builder.security.hashing import sha256_bytes, sha256_file
from timeline_builder.security.validation import ValidationError, ensure_within, sanitize_filename, validate_source_path


class HashingTests(unittest.TestCase):
    def test_sha256_bytes(self):
        self.assertEqual(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_sha256_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(b"abc")
            self.assertEqual(sha256_file(path), sha256_bytes(b"abc"))


class ValidationTests(unittest.TestCase):
    def test_null_byte_rejected(self):
        with self.assertRaises(ValidationError):
            validate_source_path("bad\x00path", must_exist=False)

    def test_missing_path_rejected(self):
        with self.assertRaises(ValidationError):
            validate_source_path("definitely-not-here-12345", must_exist=True)

    def test_ensure_within_blocks_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            with self.assertRaises(ValidationError):
                ensure_within(base, base / ".." / "escape")

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename('a<b>c:d"e/f'), "a_b_c_d_e_f")
        self.assertEqual(sanitize_filename(""), "artifact")


class AuditChainTests(unittest.TestCase):
    def test_chain_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(path, actor="tester")
            logger.log("test.start", target="x")
            logger.log("test.step", target="y", value=1)
            ok, message = verify_audit_chain(path)
            self.assertTrue(ok, message)
            self.assertIn("2 records", message)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.log("a")
            logger.log("b")
            lines = path.read_text(encoding="utf-8").splitlines()
            lines[1] = lines[1].replace('"action":"a"', '"action":"evil"')
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ok, _message = verify_audit_chain(path)
            self.assertFalse(ok)


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self):
        if not is_encryption_available():
            self.skipTest("cryptography not installed")
        blob = seal_bytes(b"case data", "s3cret-passphrase")
        self.assertEqual(unseal_bytes(blob, "s3cret-passphrase"), b"case data")

    def test_wrong_password(self):
        if not is_encryption_available():
            self.skipTest("cryptography not installed")
        blob = seal_bytes(b"case data", "right")
        with self.assertRaises(Exception):
            unseal_bytes(blob, "wrong")


if __name__ == "__main__":
    unittest.main()
