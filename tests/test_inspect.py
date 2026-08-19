"""Zero-dependency tests for Phase 1 packet inspection (stdlib unittest)."""

from __future__ import annotations

import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from nids.inspect import format_summary, summarize, tcp_flags_str


class TcpFlagsTest(unittest.TestCase):
    def test_single_and_combined_flags(self):
        self.assertEqual(tcp_flags_str(0x02), "S")
        self.assertEqual(tcp_flags_str(0x10), "A")
        self.assertEqual(tcp_flags_str(0x12), "SA")
        self.assertEqual(tcp_flags_str(0x00), "")


class SummarizeTest(unittest.TestCase):
    def test_tcp(self):
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(
            src="192.168.1.10", dst="192.168.1.20"
        ) / TCP(sport=50000, dport=22, flags="S")
        info = summarize(pkt)
        self.assertEqual(info["proto"], "TCP")
        self.assertEqual(info["src"], "192.168.1.10")
        self.assertEqual(info["dst"], "192.168.1.20")
        self.assertEqual(info["src_port"], 50000)
        self.assertEqual(info["dst_port"], 22)
        self.assertEqual(info["tcp_flags"], "S")
        self.assertEqual(info["src_mac"], "00:11:22:33:44:55")

    def test_udp(self):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        info = summarize(pkt)
        self.assertEqual(info["proto"], "UDP")
        self.assertEqual(info["src_port"], 5353)
        self.assertEqual(info["dst_port"], 53)
        self.assertIsNone(info["tcp_flags"])

    def test_icmp(self):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / ICMP()
        info = summarize(pkt)
        self.assertEqual(info["proto"], "ICMP")
        self.assertIsNone(info["src_port"])
        self.assertIsNone(info["dst_port"])

    def test_arp(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            psrc="192.168.1.1", pdst="192.168.1.10", op=1
        )
        info = summarize(pkt)
        self.assertEqual(info["proto"], "ARP")
        self.assertEqual(info["src"], "192.168.1.1")
        self.assertEqual(info["dst"], "192.168.1.10")


class FormatTest(unittest.TestCase):
    def test_tcp_line_contains_ports_and_flags(self):
        pkt = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
            sport=50000, dport=22, flags="S"
        )
        line = format_summary(summarize(pkt))
        self.assertIn("192.168.1.10:50000", line)
        self.assertIn("192.168.1.20:22", line)
        self.assertIn("[S]", line)


if __name__ == "__main__":
    unittest.main()
