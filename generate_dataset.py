#!/usr/bin/env python3
"""Generate synthetic one-way network traffic datasets with exact class & scan-type ratios.

Target Ratios (specified by user):
  - 72% BENIGN (normal single-client traffic + benign high-fanout CDN/update traffic)
  - 28% PORTSCAN:
      - 9% Vertical Scans (one source -> many ports on a single target)
      - 5% Horizontal Scans (one source -> many hosts on a single port)
      - 8% Slow Scans (stealthy scans spread across distinct time windows)
      - 6% Mixed Scans (one source -> many hosts AND many ports)

The script generates realistic, multi-IP, multi-port traffic with the exact 17 forward-only
CIC features required by the RandomForest model.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from recon_detector.features import APPROVED_FEATURES  # noqa: E402

IDENTITY_COLS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol"]
COMMON_PORTS = [80, 443, 22, 53, 25, 110, 143, 993, 995, 3306, 5432, 8080, 8443]


def _std(xs: List[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    m = sum(xs) / n
    return math.sqrt(sum((x - m) ** 2 for x in xs) / n)


def _benign_flow_features(rng: random.Random) -> Dict[str, float]:
    """Features for a normal, payload-carrying benign client flow."""
    pkts = float(rng.randint(6, 45))
    lengths = [float(rng.randint(100, 1460)) for _ in range(int(pkts))]
    # Inter-arrival times (active flow)
    dur = rng.uniform(0.1, 4.0)
    iats = [dur / pkts * rng.uniform(0.5, 1.5) for _ in range(int(pkts) - 1)]

    return {
        "Total Fwd Packets": pkts,
        "Total Length of Fwd Packets": float(sum(lengths)),
        "Fwd Packet Length Max": float(max(lengths)),
        "Fwd Packet Length Min": float(min(lengths)),
        "Fwd Packet Length Mean": float(sum(lengths) / pkts),
        "Fwd Packet Length Std": _std(lengths),
        "Fwd IAT Total": dur,
        "Fwd IAT Mean": float(sum(iats) / len(iats)) if iats else 0.0,
        "Fwd IAT Std": _std(iats),
        "Fwd IAT Max": float(max(iats)) if iats else 0.0,
        "Fwd IAT Min": float(min(iats)) if iats else 0.0,
        "Fwd PSH Flags": float(rng.randint(1, 4)),
        "Fwd URG Flags": 0.0,
        "Fwd Header Length": float(pkts * rng.choice([40, 52])),
        "Init_Win_bytes_forward": float(rng.choice([64240, 65535, 29200, 14600])),
        "act_data_pkt_fwd": float(max(pkts - 2, 1)),
        "min_seg_size_forward": float(rng.choice([20, 32])),
    }


def _scan_flow_features(rng: random.Random, is_slow: bool = False) -> Dict[str, float]:
    """Features for a scan probe: tiny, 1-2 packets, 0 payload bytes."""
    pkts = 1.0 if rng.random() > 0.1 else 2.0
    lengths = [0.0] * int(pkts)
    dur = rng.uniform(0.0001, 0.005) if pkts > 1 else 0.0
    iats = [dur] if pkts > 1 else []

    return {
        "Total Fwd Packets": pkts,
        "Total Length of Fwd Packets": 0.0,
        "Fwd Packet Length Max": 0.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": 0.0,
        "Fwd Packet Length Std": 0.0,
        "Fwd IAT Total": dur,
        "Fwd IAT Mean": dur if iats else 0.0,
        "Fwd IAT Std": 0.0,
        "Fwd IAT Max": dur if iats else 0.0,
        "Fwd IAT Min": dur if iats else 0.0,
        "Fwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Fwd Header Length": float(pkts * 40),
        "Init_Win_bytes_forward": float(rng.choice([1024, 2048, 64240, 0])),
        "act_data_pkt_fwd": 0.0,
        "min_seg_size_forward": 20.0,
    }


def generate_dataset(
    n_flows: int = 10000,
    seed: int = 42,
    p_benign: float = 0.72,
    p_vertical: float = 0.09,
    p_horizontal: float = 0.05,
    p_slow: float = 0.08,
    p_mixed: float = 0.06,
) -> List[Dict]:
    rng = random.Random(seed)

    # Compute exact row counts
    n_b = int(round(n_flows * p_benign))
    n_v = int(round(n_flows * p_vertical))
    n_h = int(round(n_flows * p_horizontal))
    n_s = int(round(n_flows * p_slow))
    n_m = n_flows - (n_b + n_v + n_h + n_s)

    flows: List[Dict] = []
    base_ts = 1725400000.0

    # 1. BENIGN TRAFFIC (72%)
    # Multiple client IPs and subnets accessing legitimate servers
    benign_subnets = [f"192.168.{net}" for net in range(1, 15)]
    server_subnets = [f"10.0.{net}" for net in range(1, 8)] + [f"172.16.{net}" for net in range(1, 5)]

    t = base_ts
    for i in range(n_b):
        t += rng.uniform(0.01, 0.25)
        src = f"{rng.choice(benign_subnets)}.{rng.randint(2, 250)}"
        dst = f"{rng.choice(server_subnets)}.{rng.randint(2, 250)}"
        dport = rng.choice(COMMON_PORTS)

        row = {
            "timestamp": round(t, 6),
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "protocol": "TCP",
            "Label": "BENIGN",
            "Scan_Type": "benign",
        }
        row.update(_benign_flow_features(rng))
        flows.append(row)

    total_duration = max(t - base_ts, 600.0)

    # 2. VERTICAL SCANS (9%)
    # Multiple attacker IPs targeting many ports on individual victim hosts
    v_attackers = [f"45.33.32.{i}" for i in range(10, 25)]
    v_victims = [f"10.0.1.{i}" for i in range(10, 30)]

    remaining_v = n_v
    while remaining_v > 0:
        burst_size = min(remaining_v, rng.randint(25, 60))
        remaining_v -= burst_size
        atk = rng.choice(v_attackers)
        vic = rng.choice(v_victims)
        ports = rng.sample(range(1, 65535), burst_size)
        t_burst = base_ts + rng.uniform(5.0, total_duration - 30.0)
        for p in ports:
            t_burst += rng.uniform(0.005, 0.04)
            row = {
                "timestamp": round(t_burst, 6),
                "src_ip": atk,
                "dst_ip": vic,
                "dst_port": p,
                "protocol": "TCP",
                "Label": "PortScan",
                "Scan_Type": "vertical",
            }
            row.update(_scan_flow_features(rng))
            flows.append(row)

    # 3. HORIZONTAL SCANS (5%)
    # Multiple attacker IPs targeting a single port across entire subnets
    h_attackers = [f"185.220.101.{i}" for i in range(5, 20)]
    h_target_ports = [445, 3389, 22, 80, 8080, 23, 21]

    remaining_h = n_h
    while remaining_h > 0:
        sweep_size = min(remaining_h, rng.randint(30, 70))
        remaining_h -= sweep_size
        atk = rng.choice(h_attackers)
        port = rng.choice(h_target_ports)
        t_sweep = base_ts + rng.uniform(10.0, total_duration - 30.0)
        for j in range(sweep_size):
            t_sweep += rng.uniform(0.005, 0.04)
            vic = f"10.0.{j // 254 + 1}.{(j % 254) + 1}"
            row = {
                "timestamp": round(t_sweep, 6),
                "src_ip": atk,
                "dst_ip": vic,
                "dst_port": port,
                "protocol": "TCP",
                "Label": "PortScan",
                "Scan_Type": "horizontal",
            }
            row.update(_scan_flow_features(rng))
            flows.append(row)

    # 4. SLOW SCANS (8%)
    # Multiple attacker IPs probing targets with time gaps (e.g. 1 probe every 12-25s)
    # persisting across rolling windows
    s_attackers = [f"198.51.100.{i}" for i in range(1, 12)]
    s_victims = [f"10.0.2.{i}" for i in range(1, 20)]

    remaining_s = n_s
    while remaining_s > 0:
        session_size = min(remaining_s, rng.randint(15, 30))
        remaining_s -= session_size
        atk = rng.choice(s_attackers)
        vic = rng.choice(s_victims)
        ports = rng.sample(range(1, 65535), session_size)
        t_slow = base_ts + rng.uniform(0.0, max(total_duration - (session_size * 25.0), 10.0))
        for p in ports:
            t_slow += rng.uniform(12.0, 25.0)  # Slow rate: 12-25s per probe
            row = {
                "timestamp": round(t_slow, 6),
                "src_ip": atk,
                "dst_ip": vic,
                "dst_port": p,
                "protocol": "TCP",
                "Label": "PortScan",
                "Scan_Type": "slow",
            }
            row.update(_scan_flow_features(rng, is_slow=True))
            flows.append(row)

    # 5. MIXED SCANS (6%)
    # Attackers probing many ports across many hosts (strobe / distributed reconnaissance)
    m_attackers = [f"203.0.113.{i}" for i in range(1, 10)]

    remaining_m = n_m
    while remaining_m > 0:
        m_hosts = rng.randint(8, 15)
        m_ports_per_host = rng.randint(4, 8)
        batch = min(remaining_m, m_hosts * m_ports_per_host)
        remaining_m -= batch
        atk = rng.choice(m_attackers)
        target_ports = rng.sample(range(1, 65535), m_ports_per_host)
        t_m = base_ts + rng.uniform(15.0, total_duration - 30.0)

        added = 0
        for h_idx in range(m_hosts):
            vic = f"172.16.{h_idx + 1}.{rng.randint(1, 100)}"
            for p in target_ports:
                if added >= batch:
                    break
                t_m += rng.uniform(0.01, 0.05)
                row = {
                    "timestamp": round(t_m, 6),
                    "src_ip": atk,
                    "dst_ip": vic,
                    "dst_port": p,
                    "protocol": "TCP",
                    "Label": "PortScan",
                    "Scan_Type": "mixed",
                }
                row.update(_scan_flow_features(rng))
                flows.append(row)
                added += 1

    # Sort all flows chronologically by timestamp
    flows.sort(key=lambda r: r["timestamp"])
    return flows


def main():
    parser = argparse.ArgumentParser(description="Generate dataset with exact class & scan type ratios")
    parser.add_argument("--n-flows", type=int, default=10000, help="Total flows to generate (default: 10000)")
    parser.add_argument("--out-dir", default="dataset_custom", help="Output directory for CSV files")
    parser.add_argument("--split", type=float, default=0.70, help="Train split ratio (default: 0.70)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print(f"[*] Generating {args.n_flows} flows with:")
    print("    - 72% BENIGN")
    print("    - 28% PORTSCAN (9% Vertical, 5% Horizontal, 8% Slow, 6% Mixed)")

    flows = generate_dataset(n_flows=args.n_flows, seed=args.seed)

    cols = IDENTITY_COLS + APPROVED_FEATURES + ["Label", "Scan_Type"]

    full_csv = out / "custom_dataset.csv"
    with open(full_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(flows)

    # Time-ordered train/test split
    cut = int(len(flows) * args.split)
    train_flows = flows[:cut]
    test_flows = flows[cut:]

    with open(out / "train.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(train_flows)

    with open(out / "test.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(test_flows)

    # Print summary breakdown
    def counts_of(sub_flows):
        by_label = {}
        by_type = {}
        for f in sub_flows:
            lbl = f["Label"]
            st = f["Scan_Type"]
            by_label[lbl] = by_label.get(lbl, 0) + 1
            by_type[st] = by_type.get(st, 0) + 1
        return by_label, by_type

    full_lbl, full_type = counts_of(flows)
    print("\n[✓] Generated Dataset Summary:")
    print(f"    Total Rows: {len(flows)}")
    print(f"    Class Breakdown: {full_lbl}")
    for st, cnt in sorted(full_type.items()):
        pct = (cnt / len(flows)) * 100
        print(f"      - {st:12s}: {cnt:5d} ({pct:5.2f}%)")

    print(f"\n[✓] Wrote files:")
    print(f"    - {full_csv} ({len(flows)} rows)")
    print(f"    - {out / 'train.csv'} ({len(train_flows)} rows)")
    print(f"    - {out / 'test.csv'} ({len(test_flows)} rows)")


if __name__ == "__main__":
    main()

