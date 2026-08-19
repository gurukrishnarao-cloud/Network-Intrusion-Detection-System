"""CLI entry point: ``python -m nids``.

Phase 1 usage:
    python -m nids --pcap data/pcaps/sample.pcap
    python -m nids --pcap data/pcaps/sample.pcap --limit 5 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .capture import iter_packets
from .inspect import format_summary, summarize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="Network Intrusion Detection System — Phase 1: capture & inspect",
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="path to a pcap/pcapng file "
        "(generate one with scripts/make_sample_pcap.py)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="only inspect the first N packets",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one JSON object per packet (for later phases)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    count = 0
    for pkt in iter_packets(args.pcap, limit=args.limit):
        info = summarize(pkt)
        if args.json:
            print(json.dumps(info, default=str))
        else:
            print(format_summary(info))
        count += 1

    print(f"\nInspected {count} packets from {args.pcap}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
