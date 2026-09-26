"""Unit + smoke tests (architecture.md §15).

Run: py -m unittest discover -s tests -v
"""
from __future__ import annotations

import socket
import threading
import unittest

from portscanner import report, security
from portscanner.config import ConfigError, parse_ports, validate
from portscanner.models import PortState
from portscanner.resolver import TargetResolver
from portscanner.scanner import Scanner


class TestConfig(unittest.TestCase):
    def test_parse_ports_ranges_and_profiles(self):
        self.assertEqual(parse_ports("22,80,443"), (22, 80, 443))
        self.assertEqual(parse_ports("80-83"), (80, 81, 82, 83))
        self.assertIn(443, parse_ports("top100"))
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_parse_ports_rejects_garbage(self):
        for bad in ("0", "65536", "abc", "80-70", ";;", ""):
            with self.assertRaises(ConfigError):
                parse_ports(bad)

    def test_validate_rejects_bad_targets(self):
        with self.assertRaises(ConfigError):
            validate(["10.0.0.1; rm -rf /"], "80")
        with self.assertRaises(ConfigError):
            validate([], "80")
        with self.assertRaises(ConfigError):
            validate(["example.com"], "80", scan_type="teleport")

    def test_raw_scan_requires_authorization(self):
        with self.assertRaises(ConfigError):
            validate(["127.0.0.1"], "80", scan_type="syn", authorized=False)


class TestSecurity(unittest.TestCase):
    def test_sanitize_strips_terminal_escapes(self):
        evil = b"\x1b]0;pwned\x07hello \x1b[31mred"
        out = security.sanitize_text(evil)
        self.assertNotIn("\x1b", out)
        self.assertIn("hello", out)

    def test_authorization_gate_denies_non_interactive(self):
        ok = security.authorization_gate(["93.184.216.34"], interactive=False, yes=False)
        self.assertFalse(ok)

    def test_authorization_gate_allows_private_scope(self):
        ok = security.authorization_gate(["127.0.0.1"], interactive=False, yes=False)
        self.assertTrue(ok)

    def test_safe_output_path_blocks_traversal(self):
        from pathlib import Path
        with self.assertRaises(ValueError):
            security.safe_output_path("C:/Windows/system32/evil.txt", Path.cwd())


class TestResolver(unittest.TestCase):
    def test_cidr_expansion_dedupe(self):
        r = TargetResolver(["127.0.0.1", "127.0.0.0/30"], [])
        targets = list(r.expand())
        ips = [t.ip for t in targets]
        self.assertEqual(len(ips), len(set(ips)))
        self.assertIn("127.0.0.1", ips)
        self.assertIn("127.0.0.2", ips)


class _FixtureServer:
    """Binds accept / refuse / drop ports on loopback (architecture.md §15)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.port_open = self.sock.getsockname()[1]
        self.sock.listen(8)
        self._thr = threading.Thread(target=self._serve, daemon=True)
        self._thr.start()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port_closed = s.getsockname()[1]
        s.close()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
                c.close()
            except OSError:
                return

    def close(self):
        self.sock.close()


class TestSmokeScan(unittest.TestCase):
    def test_connect_scan_loopback(self):
        fx = _FixtureServer()
        try:
            cfg = validate(
                targets=["127.0.0.1"],
                ports_spec=f"{fx.port_open},{fx.port_closed}",
                scan_type="connect",
                workers=8,
                timeout_s=0.5,
                retries=0,
                service_detect=False,
                output_format="json",
                authorized=True,
            )
            out = Scanner(cfg).run()
            self.assertIn('"schema_version": 1', out)
            self.assertIn('"state": "open"', out)
            self.assertIn(str(fx.port_open), out)
            # refused port: closed on stock stacks; filtered when RST-suppressed
            self.assertRegex(out, r'"state": "(closed|filtered)"')
        finally:
            fx.close()


class TestReport(unittest.TestCase):
    def test_all_formatters_render(self):
        hosts = [{"ip": "127.0.0.1", "hostname": "", "ports": [
            {"port": 80, "proto": "tcp", "state": "open", "ts": 0}],
            "services": [{"port": 80, "proto": "tcp", "service": "http",
                          "product": "", "version": "", "banner": "",
                          "confidence": 0.9, "tls": None}]}]
        meta = {"stats": {"probes_sent": 1, "counts": {"open": 1}, "duration_s": 0.1}}
        for fmt in ("table", "json", "jsonl", "csv", "greppable"):
            out = report.render(fmt, hosts, meta)
            self.assertIsInstance(out, str)
            self.assertTrue(out.strip())


if __name__ == "__main__":
    unittest.main()
