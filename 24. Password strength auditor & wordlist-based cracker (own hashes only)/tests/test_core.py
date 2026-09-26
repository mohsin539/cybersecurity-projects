import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core import auditor, cracker, hashes, ntlm, report, wordlists
from src.compat import workspace


class TestNtlm(unittest.TestCase):
    def test_md4_vectors(self):
        self.assertEqual(ntlm._md4_digest(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(ntlm._md4_digest(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")

    def test_ntlm_vector(self):
        self.assertEqual(ntlm.ntlm_hex("password"), "8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(ntlm.ntlm_hex("Password"), "a4f49c406510bdcab6824ee7c30fd852")


class TestIdentify(unittest.TestCase):
    def test_lengths(self):
        self.assertEqual(hashes.identify_token("5f4dcc3b5aa765d61d8327deb882cf99"), ["MD5", "NTLM"])
        self.assertEqual(
            hashes.identify_token("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"), ["SHA1"]
        )
        self.assertEqual(
            hashes.identify_token("8c897605a993c244e2ffee897e5e5676e9562c26e28d9a63d7aa9b03aed3a423"),
            ["SHA256"],
        )

    def test_salted(self):
        t = hashes.identify_line("5f4dcc3b5aa765d61d8327deb882cf99:mysalt")
        self.assertEqual(t["salt"], "mysalt")

    def test_modular(self):
        self.assertEqual(hashes.identify_token("$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxmZk4MJu7xW1Q6N7xYQ9Fv9Jli")[0], "bcrypt")

    def test_force32(self):
        t = hashes.identify_line("a4f49c406510bdcab6824ee7c30fd852", force32="NTLM")
        self.assertEqual(t["algos"], ["NTLM"])

    def test_compute_matches_hmac(self):
        self.assertEqual(
            hashes.compute("MD5", "password"),
            hashlib.md5(b"password").hexdigest(),
        )
        self.assertEqual(
            hashes.compute("SHA512", "password"),
            hashlib.sha512(b"password").hexdigest(),
        )


class TestCracker(unittest.TestCase):
    def _targets(self):
        targets = [
            hashes.identify_line("8846f7eaee8fb117ad06bdd830b7586c", force32="NTLM"),
            hashes.identify_line(hashlib.md5(b"password").hexdigest(), force32="MD5"),
            hashes.identify_line(hashlib.sha256(b"letmein").hexdigest()),
        ]
        for i, t in enumerate(targets, 1):
            t["pos"] = i
        return targets

    def test_wordlist(self):
        crk = cracker.Cracker(self._targets(), workers=2)
        stats = crk.run("wordlist", words=["password", "letmein", "123456"])
        self.assertEqual(len(stats["found_map"]), 3)
        self.assertEqual(stats["found_map"][hashlib.sha256(b"letmein").hexdigest()]["candidate"], "letmein")

    def test_rules(self):
        targets = [hashes.identify_line(hashlib.md5(b"Password1").hexdigest(), force32="MD5")]
        targets[0]["pos"] = 1
        crk = cracker.Cracker(targets, workers=2)
        stats = crk.run("rules", words=["password"])
        self.assertEqual(stats["found_map"][hashlib.md5(b"Password1").hexdigest()]["candidate"], "Password1")

    def test_mask(self):
        targets = [hashes.identify_line(hashlib.md5(b"0007").hexdigest(), force32="MD5")]
        targets[0]["pos"] = 1
        crk = cracker.Cracker(targets, workers=2)
        stats = crk.run("mask", charset="0123456789", min_len=4, max_len=4)
        self.assertIn(hashlib.md5(b"0007").hexdigest(), stats["found_map"])

    def test_mask_guard(self):
        md5_x = hashlib.md5(b"x").hexdigest()
        target = hashes.identify_line(md5_x, force32="MD5")
        target["pos"] = 1
        crk = cracker.Cracker([target], workers=2)
        stats = crk.run("mask", charset="0123456789abcdef", min_len=10, max_len=10)
        self.assertIn("error", stats)

    def test_salted(self):
        token = hashes.compute("MD5", "abc123", salt="pepper")
        targets = [{"token": token, "algos": ["MD5"], "salt": "pepper", "pos": 1}]
        crk = cracker.Cracker(targets, workers=2)
        stats = crk.run("wordlist", words=["abc123"])
        self.assertEqual(stats["found_map"][token]["candidate"], "abc123")

    def test_stop(self):
        targets = self._targets()
        crk = cracker.Cracker(targets, workers=2)
        crk.stop()
        stats = crk.run("mask", charset="0123456789", min_len=4, max_len=4)
        self.assertIn("attempted", stats)


class TestAuditor(unittest.TestCase):
    def test_nist_min_length(self):
        r = auditor.analyze("short", blocklist=None)
        self.assertEqual(r["checks"][0], ("Length >= 8 (NIST SP 800-63B minimum)", False))

    def test_blocklist(self):
        r = auditor.analyze("password", blocklist=wordlists.common_blocklist())
        self.assertTrue(r["blocked"])
        self.assertLessEqual(r["score"], 10)

    def test_strong_password(self):
        r = auditor.analyze("Tr0ub4dor&3-Xy!!k9")
        self.assertGreaterEqual(r["score"], 80)
        self.assertTrue(r["checks"][0][1])

    def test_duration(self):
        self.assertIn("s", auditor.format_duration(0.5))
        self.assertIn("d", auditor.format_duration(5 * 86400))


class TestWorkspace(unittest.TestCase):
    def test_attest_and_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = workspace.Workspace(tmp)
            self.assertFalse(ws.attested())
            ws.attest("tester")
            self.assertTrue(ws.attested())
            ws.audit("attack_completed", detail="mock")
            ws.audit("report_generated", detail="mock2")
            ok, count = ws.verify_chain()
            self.assertTrue(ok)
            self.assertEqual(count, 3)
            path = os.path.join(tmp, "audit.jsonl")
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"seq": 999, "ts": "x", "event": "tampered"}) + "\n")
            ok, _ = ws.verify_chain()
            self.assertFalse(ok)
            ws.wipe()
            self.assertFalse(ws.attested())

    def test_bundle_roundtrip(self):
        if not workspace.bundle_available():
            self.skipTest("DPAPI not available on this OS")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.pwg")
            workspace.save_bundle(path, json.dumps({"k": "v"}).encode())
            data = workspace.load_bundle(path)
            self.assertEqual(json.loads(data.decode()), {"k": "v"})


class TestReport(unittest.TestCase):
    def test_html_watermark(self):
        meta = {"operator": "alice", "session_id": "ws-abc", "scope": "OWN / AUTHORIZED DATA ONLY"}
        summary = {"targets": 2, "cracked": 1, "unresolved": 1, "scope": "OWN"}
        items = [
            {"pos": 1, "token": "aaaa", "algos": ["NTLM"], "salt": "", "candidate": ""},
            {"pos": 2, "token": "bbbb", "algos": ["MD5"], "salt": "", "candidate": "secret1"},
        ]
        doc = report.build_html(meta, summary, items)
        self.assertIn("alice", doc)
        self.assertIn("OWN", doc)
        self.assertIn("secret1", doc)

    def test_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.csv")
            report.write_csv(path, [{"pos": 1, "token": "a", "algos": ["MD5"], "salt": "", "candidate": "x"}])
            with open(path, "r", encoding="utf-8-sig") as fh:
                content = fh.read()
            self.assertIn("x", content)


class TestWordlist(unittest.TestCase):
    def test_load_guards_and_blocklist(self):
        block = wordlists.common_blocklist()
        self.assertIn("password", block)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write("one\none\ntwo\n\x00bad\n\n\n")
            path = fh.name
        try:
            words = wordlists.load_wordlist(path)
            self.assertEqual(words, ["one", "two"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)