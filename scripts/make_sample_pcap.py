"""Generate a small synthetic pcap for Phase 1 testing.

Builds a mixed capture so the decoder is exercised against every layer we
care about: ARP, ICMP, a TCP handshake, UDP, and a short port scan (the scan
will matter again in Phase 3).

Output: data/pcaps/sample.pcap  (gitignored; regenerate any time).

Run:  python scripts/make_sample_pcap.py
"""

from __future__ import annotations

import time
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "data" / "pcaps" / "sample.pcap"

# Hosts with stable MACs so the output is easy to read.
GATEWAY = ("192.168.1.1", "00:00:0c:9f:f0:01")
HOST_A = ("192.168.1.10", "00:11:22:33:44:55")
HOST_B = ("192.168.1.20", "aa:bb:cc:dd:ee:ff")
DNS = ("192.168.1.53", "00:aa:00:bb:00:cc")
SCANNER = ("192.168.1.99", "66:77:88:99:aa:bb")

# Ports the scanner touches — clearly more than a normal host would in ~2s.
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 3306, 3389, 5432, 8080,
]


def l2(src: tuple[str, str], dst: tuple[str, str]):
    return Ether(src=src[1], dst=dst[1])


def main() -> None:
    base = time.time()
    packets: list[Packet] = []

    def add(pkt: Packet, offset: float) -> None:
        pkt.time = base + offset  # spread timestamps out realistically
        packets.append(pkt)

    # 1. ARP: who has 192.168.1.10?
    add(l2(GATEWAY, ("0.0.0.0", "ff:ff:ff:ff:ff:ff"))
        / ARP(psrc=GATEWAY[0], pdst=HOST_A[0], op=1), 0.0)

    # 2. ICMP echo request/reply.
    add(l2(HOST_A, DNS) / IP(src=HOST_A[0], dst="8.8.8.8") / ICMP(), 0.2)
    add(l2(DNS, HOST_A) / IP(src="8.8.8.8", dst=HOST_A[0]) / ICMP(type=0), 0.3)

    # 3. TCP handshake: A opens SSH to B.
    add(l2(HOST_A, HOST_B) / IP(src=HOST_A[0], dst=HOST_B[0])
        / TCP(sport=50000, dport=22, flags="S"), 1.0)
    add(l2(HOST_B, HOST_A) / IP(src=HOST_B[0], dst=HOST_A[0])
        / TCP(sport=22, dport=50000, flags="SA"), 1.1)
    add(l2(HOST_A, HOST_B) / IP(src=HOST_A[0], dst=HOST_B[0])
        / TCP(sport=50000, dport=22, flags="A"), 1.2)

    # 4. UDP: a DNS query.
    add(l2(HOST_A, DNS) / IP(src=HOST_A[0], dst=DNS[0])
        / UDP(sport=5353, dport=53), 2.0)

    # 5. Port scan: one host hits many ports on B in ~2 seconds.
    for i, port in enumerate(SCAN_PORTS):
        add(l2(SCANNER, HOST_B) / IP(src=SCANNER[0], dst=HOST_B[0])
            / TCP(sport=60000, dport=port, flags="S"), 3.0 + i * 0.1)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT_PATH), packets)
    print(f"Wrote {len(packets)} packets to {OUT_PATH}")


if __name__ == "__main__":
    main()
