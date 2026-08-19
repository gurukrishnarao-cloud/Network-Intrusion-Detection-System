# Network Intrusion Detection System

A rule-based (then ML-assisted) network intrusion detection system, built
incrementally.

```
Network Traffic → Packet Capture → Feature Extraction → Detection Engine
      → Normal / Suspicious? → Alert → Investigation / Logging → Dashboard
```

## Roadmap

| Phase | What | Status |
|-------|------|--------|
| 1 | Packet capture & inspection (Scapy) | ✅ done |
| 2 | Feature extraction & analysis (Pandas) | next |
| 3 | Rule-based detection engine | — |
| 4 | Alerting & logging | — |
| 5 | Machine learning (sklearn) | — |
| 6 | Dashboard | — |

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Phase 1 — capture & inspect packets

Generate a synthetic sample capture (ARP, ICMP, TCP handshake, UDP, and a
short port scan):

```bash
.venv/bin/python scripts/make_sample_pcap.py
```

Inspect it:

```bash
# human-readable, one line per packet
.venv/bin/python -m nids --pcap data/pcaps/sample.pcap

# first N packets only
.venv/bin/python -m nids --pcap data/pcaps/sample.pcap --limit 5

# one JSON object per packet (feeds later phases)
.venv/bin/python -m nids --pcap data/pcaps/sample.pcap --json
```

Each packet reports: timestamp, source/destination MAC and IP, protocol,
source/destination port, packet size, and TCP flags.

Run the tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

> Live sniffing (`sniff()`) needs root / `CAP_NET_RAW`, so Phase 1 uses
> offline pcap files here. Live capture is added on a machine with privileges.

## Layout

```
nids/            # the package
  capture.py     #   offline pcap reading (live sniff comes later)
  inspect.py     #   packet -> field dict + pretty printer
  __main__.py    #   CLI (python -m nids)
scripts/         # helpers (pcap generation)
tests/           # unit tests
data/pcaps/      # captures (gitignored — regenerate)
```
