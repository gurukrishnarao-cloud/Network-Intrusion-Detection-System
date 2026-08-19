"""Phase 1 — packet inspection.

Decode a Scapy packet into a small, plain dict of the fields we care about:
timestamp, MACs, IPs, protocol, ports, size and TCP flags.

``summarize`` is the single source of truth the later phases (feature
extraction, detection) will consume, so it's kept layer-agnostic and
dependency-free beyond Scapy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

# TCP flag bits -> single-letter names (F S R P A U E C), tcpdump-style order.
_TCP_FLAGS = (
    (0x01, "F"),  # FIN
    (0x02, "S"),  # SYN
    (0x04, "R"),  # RST
    (0x08, "P"),  # PSH
    (0x10, "A"),  # ACK
    (0x20, "U"),  # URG
    (0x40, "E"),  # ECE
    (0x80, "C"),  # CWR
)

# IP protocol numbers -> names we care about. Anything else shows as a number.
_PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def tcp_flags_str(flags: int) -> str:
    """Render a TCP flags bitmask as e.g. ``S``, ``SA``, ``A``."""
    return "".join(letter for bit, letter in _TCP_FLAGS if flags & bit)


def summarize(pkt: Packet) -> Dict[str, Optional[object]]:
    """Decode one packet into a flat dict of interesting fields."""
    info: Dict[str, Optional[object]] = {
        "time": None,
        "size": len(pkt),
        "src_mac": None,
        "dst_mac": None,
        "src": None,
        "dst": None,
        "proto": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
    }

    # Capture timestamp is attached by the reader; hand-built packets lack it.
    ts = getattr(pkt, "time", None)
    if ts is not None:
        info["time"] = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(
            timespec="milliseconds"
        )

    if Ether in pkt:
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    # Link-level addressing for the three cases we care about.
    if ARP in pkt:
        info["src"] = pkt[ARP].psrc
        info["dst"] = pkt[ARP].pdst
        info["proto"] = "ARP"
    elif IP in pkt:
        info["src"] = pkt[IP].src
        info["dst"] = pkt[IP].dst
        info["proto"] = _PROTO_NAMES.get(pkt[IP].proto, str(pkt[IP].proto))
    elif IPv6 in pkt:
        info["src"] = pkt[IPv6].src
        info["dst"] = pkt[IPv6].dst
        info["proto"] = _PROTO_NAMES.get(pkt[IPv6].nh, str(pkt[IPv6].nh))

    # Transport layer.
    if TCP in pkt:
        info["proto"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["tcp_flags"] = tcp_flags_str(pkt[TCP].flags)
    elif UDP in pkt:
        info["proto"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport
    elif ICMP in pkt:
        info["proto"] = "ICMP"

    return info


def format_summary(info: Dict[str, Optional[object]]) -> str:
    """Render a summary dict as a single readable line."""
    t = info["time"]
    clock = t[11:23] if isinstance(t, str) and len(t) >= 23 else (t or "-")

    if info["proto"] == "ARP":
        return (
            f"[{clock}] ARP   {info['src']} ({info['src_mac']}) "
            f"-> {info['dst']} ({info['dst_mac']})"
        )

    src = (
        f"{info['src']}:{info['src_port']}"
        if info["src_port"] is not None
        else str(info["src"])
    )
    dst = (
        f"{info['dst']}:{info['dst_port']}"
        if info["dst_port"] is not None
        else str(info["dst"])
    )

    flags = f" [{info['tcp_flags']}]" if info["tcp_flags"] else ""
    return f"[{clock}] {info['proto']:<5} {src} -> {dst}{flags} len={info['size']}"
