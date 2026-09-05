#!/usr/bin/env python3
"""pcap -> labeled CSV in the per-flow model's EXACT schema.

Why this exists
---------------
The trained model consumes CICFlowMeter *forward-direction* features (see
``src/recon_detector/features.py``).  Zeek's conn.log does not compute them, so
we compute them ourselves, straight from the packets, and — unlike CIC-IDS-2017
— we ALSO keep ``src_ip``/``dst_ip``/``dst_port``/``timestamp`` so the dataset
supports a source-disjoint / time-ordered split (fixing the leakage caveat in
models/metadata.json).

Strict one-way discipline
-------------------------
A "flow" here is keyed by the ORDERED 5-tuple (src, dst, sport, dport, proto).
We only ever read the forward direction: the reverse tuple B->A is a *different*
flow and never contributes to a forward flow's features. Nothing here needs a
handshake, an ACK, or any response. This mirrors the passive data-diode model.

Output columns = the 17 approved features (exact CIC names) + identity/time
columns + Label.

Usage
-----
    python pcap_to_cic.py --pcap scan.pcap   --label PortScan --out scan.csv
    python pcap_to_cic.py --pcap benign.pcap --label BENIGN   --out benign.csv
    # then concatenate the per-pcap CSVs into one dataset.
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from scapy.all import PcapReader, IP, IPv6, TCP, UDP

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from recon_detector.features import APPROVED_FEATURES  # noqa: E402
IDENTITY_COLS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol"]

FlowKey = Tuple[str, str, int, int, str]


class Flow:
    __slots__ = ("first_ts", "times", "lengths", "hdr_lens", "psh", "urg",
                 "init_win", "act_data", "min_seg", "proto")

    def __init__(self, proto: str):
        self.first_ts: float = 0.0
        self.times: List[float] = []      # per forward packet arrival time
        self.lengths: List[int] = []      # per forward packet payload length
        self.hdr_lens: int = 0            # sum of L3+L4 header bytes (forward)
        self.psh: int = 0
        self.urg: int = 0
        self.init_win: int = -1           # TCP window of the FIRST forward pkt
        self.act_data: int = 0            # forward pkts carrying payload
        self.min_seg: int = -1            # min L4 header size (forward)
        self.proto: str = proto


def _std(xs: List[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    m = sum(xs) / n
    return math.sqrt(sum((x - m) ** 2 for x in xs) / n)  # population std (CIC)


def extract(pcap_path: str) -> Dict[FlowKey, Flow]:
    flows: Dict[FlowKey, Flow] = {}
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if IP in pkt:
                ip = pkt[IP]; src, dst = ip.src, ip.dst; l3_hdr = ip.ihl * 4
            elif IPv6 in pkt:
                ip = pkt[IPv6]; src, dst = ip.src, ip.dst; l3_hdr = 40
            else:
                continue

            if TCP in pkt:
                l4 = pkt[TCP]; proto = "TCP"
            elif UDP in pkt:
                l4 = pkt[UDP]; proto = "UDP"
            else:
                continue

            sport, dport = int(l4.sport), int(l4.dport)
            key: FlowKey = (src, dst, sport, dport, proto)
            ts = float(pkt.time)

            f = flows.get(key)
            if f is None:
                f = Flow(proto)
                f.first_ts = ts
                flows[key] = f

            payload_len = len(l4.payload)
            f.times.append(ts)
            f.lengths.append(payload_len)

            if proto == "TCP":
                l4_hdr = l4.dataofs * 4 if l4.dataofs else 20
                flags = int(l4.flags)
                if flags & 0x08:  # PSH
                    f.psh += 1
                if flags & 0x20:  # URG
                    f.urg += 1
                if f.init_win < 0:
                    f.init_win = int(l4.window)
            else:
                l4_hdr = 8  # UDP header

            f.hdr_lens += l3_hdr + l4_hdr
            if f.min_seg < 0 or l4_hdr < f.min_seg:
                f.min_seg = l4_hdr
            if payload_len > 0:
                f.act_data += 1
    return flows


def features_for(f: Flow) -> Dict[str, float]:
    times = sorted(f.times)
    iats = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    lengths = f.lengths
    return {
        "Total Fwd Packets": float(len(lengths)),
        "Total Length of Fwd Packets": float(sum(lengths)),
        "Fwd Packet Length Max": float(max(lengths)) if lengths else 0.0,
        "Fwd Packet Length Min": float(min(lengths)) if lengths else 0.0,
        "Fwd Packet Length Mean": float(sum(lengths) / len(lengths)) if lengths else 0.0,
        "Fwd Packet Length Std": _std([float(x) for x in lengths]),
        "Fwd IAT Total": float(sum(iats)),
        "Fwd IAT Mean": float(sum(iats) / len(iats)) if iats else 0.0,
        "Fwd IAT Std": _std(iats),
        "Fwd IAT Max": float(max(iats)) if iats else 0.0,
        "Fwd IAT Min": float(min(iats)) if iats else 0.0,
        "Fwd PSH Flags": float(f.psh),
        "Fwd URG Flags": float(f.urg),
        "Fwd Header Length": float(f.hdr_lens),
        "Init_Win_bytes_forward": float(f.init_win if f.init_win >= 0 else -1),
        "act_data_pkt_fwd": float(f.act_data),
        "min_seg_size_forward": float(f.min_seg if f.min_seg >= 0 else 0),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="pcap -> labeled CIC-schema CSV (forward-only)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--label", required=True, help="PortScan or BENIGN")
    ap.add_argument("--scan-type", default="benign",
                    help="benign|vertical|horizontal|slow|mixed (per-category ground truth)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    flows = extract(a.pcap)
    cols = IDENTITY_COLS + APPROVED_FEATURES + ["Label", "Scan_Type"]
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for (src, dst, sport, dport, proto), f in flows.items():
            row = {
                "timestamp": round(f.first_ts, 6),
                "src_ip": src, "dst_ip": dst, "dst_port": dport, "protocol": proto,
                "Label": a.label, "Scan_Type": a.scan_type,
            }
            row.update(features_for(f))
            w.writerow(row)
    print(f"[pcap_to_cic] {a.pcap}: {len(flows)} forward flows -> {a.out} "
          f"(Label={a.label} Scan_Type={a.scan_type})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
