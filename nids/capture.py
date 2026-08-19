"""Phase 1 — packet capture.

Offline pcap/pcapng reading for now. Live sniffing (Scapy ``sniff``) will be
added later; it requires root / ``CAP_NET_RAW`` and is kept out of this module
so the rest of the pipeline is agnostic to where packets come from.
"""

from __future__ import annotations

from typing import Iterator, List, Optional

from scapy.packet import Packet
from scapy.utils import PcapReader


def iter_packets(path: str, limit: Optional[int] = None) -> Iterator[Packet]:
    """Stream packets from a pcap/pcapng file one at a time.

    Streaming keeps memory use flat even for large captures, unlike ``rdpcap``
    which loads the whole file at once.
    """
    with PcapReader(str(path)) as reader:
        for index, pkt in enumerate(reader):
            if limit is not None and index >= limit:
                break
            yield pkt


def read_pcap(path: str, limit: Optional[int] = None) -> List[Packet]:
    """Read a whole pcap/pcapng file into memory (fine for small files)."""
    return list(iter_packets(path, limit=limit))
