"""Domain-layer test suite (architecture.md section 10).

Run with:  py -m unittest discover -s tests -v
"""
from __future__ import annotations

import unittest

from domain import (Err, Ok, VLSMRequirement, broadcast_of, cidr_for_hosts,
                    cidr_to_mask, classify, describe, ip_from_octets,
                    is_private, mask_to_cidr, network_of, parse_cidr,
                    parse_ipv4, parse_netmask, parse_prefix, plan_vlsm,
                    total_addresses, usable_hosts)
from domain.formatter import format_binary_mask, format_hex_ip


class TestResult(unittest.TestCase):
    def test_ok_map_and_unwrap(self) -> None:
        self.assertEqual(Ok(3).map(lambda x: x * 2).unwrap(), 6)
        self.assertTrue(Ok(3).is_ok())
        self.assertFalse(Ok(3).is_err())

    def test_err_map_is_noop(self) -> None:
        r = Err("bad").map(lambda x: x * 2)
        self.assertTrue(r.is_err())
        self.assertEqual(r.error, "bad")


class TestParser(unittest.TestCase):
    def test_valid_ips(self) -> None:
        for text, expected in [("192.168.10.77", 0xC0A80A4D),
                               ("0.0.0.0", 0),
                               ("255.255.255.255", 0xFFFFFFFF),
                               (" 10.0.0.1 ", 0x0A000001)]:
            with self.subTest(text=text):
                r = parse_ipv4(text)
                self.assertTrue(r.is_ok(), msg=str(r))
                self.assertEqual(r.unwrap(), expected)

    def test_invalid_ips(self) -> None:
        for text in ["256.1.1.1", "10.0.0", "10.0.0.1.1", "",
                     "a.b.c.d", "10.0.0.-1", "01.2.3.4", "10.0.0.999"]:
            with self.subTest(text=text):
                self.assertTrue(parse_ipv4(text).is_err(), msg=str(text))

    def test_parse_ipv4_none_is_error(self) -> None:
        self.assertTrue(parse_ipv4(None).is_err())


class TestCidrParsing(unittest.TestCase):
    def test_valid_cidr(self) -> None:
        for text, expected in [("24", 24), ("/24", 24), (" 0 ", 0), ("32", 32)]:
            with self.subTest(text=text):
                r = parse_cidr(text)
                self.assertTrue(r.is_ok())
                self.assertEqual(r.unwrap(), expected)

    def test_invalid_cidr(self) -> None:
        for text in ["33", "-1", "abc", "", "1.2"]:
            with self.subTest(text=text):
                self.assertTrue(parse_cidr(text).is_err())

    def test_parse_prefix_accepts_mask(self) -> None:
        r = parse_prefix("255.255.255.192")
        self.assertTrue(r.is_ok())
        self.assertEqual(r.unwrap(), 26)

    def test_parse_prefix_accepts_cidr(self) -> None:
        r = parse_prefix("/26")
        self.assertTrue(r.is_ok())
        self.assertEqual(r.unwrap(), 26)

    def test_netmask_valid(self) -> None:
        r = parse_netmask("255.255.255.0")
        self.assertTrue(r.is_ok())
        self.assertEqual(r.unwrap(), 24)

    def test_netmask_rejects_non_contiguous(self) -> None:
        self.assertTrue(parse_netmask("255.0.255.0").is_err())


class TestCoreMath(unittest.TestCase):
    def test_known_answer_192_168_10_77_26(self) -> None:
        ip = ip_from_octets(192, 168, 10, 77)
        info = describe(ip, 26)
        self.assertEqual(info.network, "192.168.10.64")
        self.assertEqual(info.broadcast, "192.168.10.127")
        self.assertEqual(info.first_host, "192.168.10.65")
        self.assertEqual(info.last_host, "192.168.10.126")
        self.assertEqual(info.subnet_mask, "255.255.255.192")
        self.assertEqual(info.wildcard_mask, "0.0.0.63")
        self.assertEqual(info.total_addresses, 64)
        self.assertEqual(info.usable_hosts, 62)
        self.assertEqual(info.ip_class, "C")
        self.assertTrue(info.is_private)
        self.assertEqual(info.binary_mask, "11111111.11111111.11111111.11000000")
        self.assertEqual(info.hex_ip, "0xC0A80A4D")

    def test_slash31_rfc3021(self) -> None:
        info = describe(ip_from_octets(10, 0, 0, 4), 31)
        self.assertEqual(info.first_host, "10.0.0.4")
        self.assertEqual(info.last_host, "10.0.0.5")
        self.assertEqual(info.usable_hosts, 2)

    def test_slash32_host_route(self) -> None:
        info = describe(ip_from_octets(203, 0, 113, 7), 32)
        self.assertEqual(info.network, "203.0.113.7")
        self.assertEqual(info.first_host, "203.0.113.7")
        self.assertEqual(info.last_host, "203.0.113.7")
        self.assertEqual(info.usable_hosts, 1)
        self.assertEqual(info.total_addresses, 1)

    def test_mask_roundtrip_all_33_masks(self) -> None:
        for cidr in range(33):
            self.assertEqual(mask_to_cidr(cidr_to_mask(cidr)), cidr)

    def test_ordering_property(self) -> None:
        ip = ip_from_octets(172, 16, 3, 9)
        for cidr in range(0, 33):
            self.assertLessEqual(network_of(ip, cidr), ip)
            self.assertLessEqual(ip, broadcast_of(ip, cidr))

    def test_classify(self) -> None:
        cases = {10: "A", 130: "B", 200: "C", 228: "D", 245: "E"}
        for octet, cls in cases.items():
            self.assertEqual(classify(ip_from_octets(octet, 1, 1, 1)), cls)

    def test_private_ranges(self) -> None:
        self.assertTrue(is_private(ip_from_octets(10, 1, 2, 3)))
        self.assertTrue(is_private(ip_from_octets(172, 20, 0, 1)))
        self.assertTrue(is_private(ip_from_octets(192, 168, 5, 5)))
        self.assertFalse(is_private(ip_from_octets(8, 8, 8, 8)))
        self.assertTrue(is_private(ip_from_octets(127, 0, 0, 1)))
        self.assertTrue(is_private(ip_from_octets(169, 254, 9, 9)))

    def test_cidr_for_hosts_table(self) -> None:
        cases = {1: 30, 2: 30, 3: 29, 6: 29, 7: 28, 62: 26, 63: 25, 64: 25,
                 100: 25, 126: 25, 127: 24, 1000: 22, 50000: 16}
        for hosts, cidr in cases.items():
            with self.subTest(hosts=hosts):
                self.assertEqual(cidr_for_hosts(hosts), cidr)
                self.assertGreaterEqual(usable_hosts(cidr), hosts)

    def test_cidr_for_hosts_edges(self) -> None:
        self.assertEqual(cidr_for_hosts(0), 32)
        self.assertEqual(cidr_for_hosts(2 ** 31), 0)


class TestVLSM(unittest.TestCase):
    def test_golden_class_c_office(self) -> None:
        base = ip_from_octets(192, 168, 1, 0)
        plan_r = plan_vlsm(base, 24, [
            VLSMRequirement("Sales", 50),
            VLSMRequirement("Engineering", 25),
            VLSMRequirement("Guest WiFi", 10),
        ])
        self.assertTrue(plan_r.is_ok())
        plan = plan_r.unwrap()
        self.assertEqual([s.cidr for s in plan.subnets], [26, 27, 28])
        nets = [s.network for s in plan.subnets]
        self.assertEqual(nets, ["192.168.1.0", "192.168.1.64", "192.168.1.96"])
        self.assertEqual(plan.subnets[0].first_host, "192.168.1.1")
        self.assertEqual(plan.subnets[0].last_host, "192.168.1.62")
        self.assertEqual(plan.failures, ())
        self.assertEqual(plan.gaps, ())
        # 64 + 32 + 16 = 112 of 256 addresses; leftover 192.168.1.112-.255
        self.assertEqual(plan.used_percent, 43.75)
        self.assertEqual(plan.leftover_start, ip_from_octets(192, 168, 1, 112))
        self.assertEqual(plan.leftover_end, ip_from_octets(192, 168, 1, 255))

    def test_no_overlap_and_in_bounds(self) -> None:
        base = ip_from_octets(10, 0, 0, 0)
        plan_r = plan_vlsm(base, 16, [
            VLSMRequirement("A", 500), VLSMRequirement("B", 100),
            VLSMRequirement("C", 55), VLSMRequirement("D", 2),
            VLSMRequirement("E", 2), VLSMRequirement("F", 120),
        ])
        self.assertTrue(plan_r.is_ok())
        plan = plan_r.unwrap()
        ranges = sorted((s.start, s.end) for s in plan.subnets)
        for (_, e1), (s2, _) in zip(ranges, ranges[1:]):
            self.assertLess(e1, s2)          # strict separation, no overlap
        for start, end in ranges:
            self.assertGreaterEqual(start, plan.base_network)
            self.assertLessEqual(end, plan.base_network + total_addresses(16) - 1)

    def test_larger_than_base_fails_but_others_alloc(self) -> None:
        base = ip_from_octets(192, 168, 1, 0)
        plan_r = plan_vlsm(base, 26, [
            VLSMRequirement("TooBig", 500),
            VLSMRequirement("Small", 5),
        ])
        self.assertTrue(plan_r.is_ok())
        plan = plan_r.unwrap()
        self.assertEqual(len(plan.failures), 1)
        self.assertEqual(plan.failures[0].name, "TooBig")
        self.assertEqual(len(plan.subnets), 1)
        self.assertIn("larger than base", plan.failures[0].reason)

    def test_overflow_fails_last_requirement(self) -> None:
        base = ip_from_octets(192, 168, 1, 0)
        plan_r = plan_vlsm(base, 24, [
            VLSMRequirement("A", 100), VLSMRequirement("B", 100),
            VLSMRequirement("C", 5),
        ])
        self.assertTrue(plan_r.is_ok())
        plan = plan_r.unwrap()
        self.assertEqual(len(plan.subnets), 2)
        self.assertEqual(len(plan.failures), 1)
        self.assertEqual(plan.failures[0].name, "C")
        self.assertIn("left in the base network", plan.failures[0].reason)

    def test_descending_allocation_and_alignment(self) -> None:
        base = 0x0A000000  # 10.0.0.0/24
        plan_r = plan_vlsm(base, 24, [VLSMRequirement("tiny", 2),
                                      VLSMRequirement("big", 64)])
        self.assertTrue(plan_r.is_ok())
        plan = plan_r.unwrap()
        # Largest first: big -> /25 at 10.0.0.0, tiny -> /30 at 10.0.0.128.
        self.assertEqual([s.name for s in plan.subnets], ["big", "tiny"])
        self.assertEqual(plan.subnets[0].network, "10.0.0.0")
        self.assertEqual(plan.subnets[0].cidr, 25)
        self.assertEqual(plan.subnets[1].network, "10.0.0.128")
        self.assertEqual(plan.subnets[1].cidr, 30)
        # Descending power-of-two blocks always land aligned: no gaps ever.
        self.assertEqual(plan.gaps, ())

    def test_exact_fit_zero_leftover(self) -> None:
        base = 0x0A000000
        plan_r = plan_vlsm(base, 24, [VLSMRequirement("A", 100),
                                      VLSMRequirement("B", 100)])
        self.assertTrue(plan_r.is_ok())
        plan = plan_r.unwrap()
        self.assertIsNone(plan.leftover_start)
        self.assertEqual(plan.used_percent, 100.0)

    def test_stable_sort_keeps_input_order_for_ties(self) -> None:
        base = 0x0A000000
        plan_r = plan_vlsm(base, 24, [VLSMRequirement("first", 10),
                                      VLSMRequirement("second", 10)])
        plan = plan_r.unwrap()
        self.assertEqual([s.name for s in plan.subnets], ["first", "second"])

    def test_empty_requirements_rejected(self) -> None:
        self.assertTrue(plan_vlsm(0x0A000000, 24, []).is_err())

    def test_bad_base_cidr_rejected(self) -> None:
        self.assertTrue(plan_vlsm(0x0A000000, 33,
                                  [VLSMRequirement("A", 5)]).is_err())


class TestFormatter(unittest.TestCase):
    def test_binary_mask(self) -> None:
        self.assertEqual(format_binary_mask(26),
                         "11111111.11111111.11111111.11000000")
        self.assertEqual(format_binary_mask(0), "00000000.00000000.00000000.00000000")
        self.assertEqual(format_binary_mask(32),
                         "11111111.11111111.11111111.11111111")

    def test_hex(self) -> None:
        self.assertEqual(format_hex_ip(0xC0A80A4D), "0xC0A80A4D")


if __name__ == "__main__":
    unittest.main()
