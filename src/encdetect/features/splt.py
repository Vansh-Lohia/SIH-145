"""Sequence of Packet Lengths and Times (SPLT) — shape/timing features (CLAUDE.md §6.2).

Per session, first N packets, each (size, direction, inter_arrival_ms). Two consumers:
  - summary_stats(): tabular features for the LightGBM baseline.
  - raw_sequence(): fixed-length (size, direction, iat) array for the 1D-CNN.

Highest-priority family: survives ECH, TLS 1.3, everything (CLAUDE.md §3).
Ref: Anderson & McGrew (Cisco), "Identifying Encrypted Malware Traffic with Contextual
Flow Data". N is tunable — 20 vs 30 is an open item (CLAUDE.md §11).
"""
from __future__ import annotations

import math
from dataclasses import dataclass

DEFAULT_N = 20  # first N packets; §11 open item: compare 20 vs 30

# A burst = consecutive packets in the same direction; an idle gap = IAT above this (ms).
IDLE_GAP_MS = 1000.0


@dataclass
class Packet:
    size: int
    direction: int      # +1 = up (client->server), -1 = down (server->client)
    inter_arrival_ms: float


def _stats(values: list[float], prefix: str) -> dict[str, float]:
    if not values:
        return {f"{prefix}_{k}": 0.0 for k in ("mean", "std", "min", "max")}
    n = len(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    return {
        f"{prefix}_mean": mean,
        f"{prefix}_std": math.sqrt(var),
        f"{prefix}_min": min(values),
        f"{prefix}_max": max(values),
    }


def summary_stats(packets: list[Packet]) -> dict[str, float]:
    """Tabular SPLT summary for the LightGBM baseline.

    Returns mean/std/min/max of sizes and IATs, up:down packet & byte ratios, burst count,
    idle-gap count, packet count, and total duration.
    """
    feats: dict[str, float] = {}
    sizes = [p.size for p in packets]
    iats = [p.inter_arrival_ms for p in packets]

    feats.update(_stats([float(s) for s in sizes], "size"))
    feats.update(_stats(iats, "iat"))

    up_pkts = [p for p in packets if p.direction > 0]
    down_pkts = [p for p in packets if p.direction < 0]
    up_bytes = sum(p.size for p in up_pkts)
    down_bytes = sum(p.size for p in down_pkts)

    feats["pkt_count"] = float(len(packets))
    feats["up_pkt_count"] = float(len(up_pkts))
    feats["down_pkt_count"] = float(len(down_pkts))
    feats["updown_pkt_ratio"] = len(up_pkts) / (len(down_pkts) + 1)
    feats["updown_byte_ratio"] = up_bytes / (down_bytes + 1)
    feats["total_bytes"] = float(up_bytes + down_bytes)

    # bursts: number of maximal same-direction runs
    burst_count = 0
    prev_dir = 0
    for p in packets:
        if p.direction != prev_dir:
            burst_count += 1
            prev_dir = p.direction
    feats["burst_count"] = float(burst_count)

    feats["idle_gap_count"] = float(sum(1 for i in iats if i > IDLE_GAP_MS))
    feats["duration_ms"] = float(sum(iats))
    return feats


def raw_sequence(packets: list[Packet], n: int = DEFAULT_N) -> list[tuple[int, int, float]]:
    """Fixed-length (size, direction, iat) sequence for the 1D-CNN.

    Truncated to the first N packets and right-padded with zero packets so every session
    yields an n x 3 array.
    """
    seq = [(p.size, p.direction, p.inter_arrival_ms) for p in packets[:n]]
    if len(seq) < n:
        seq.extend([(0, 0, 0.0)] * (n - len(seq)))
    return seq


SUMMARY_FEATURE_NAMES = [
    "size_mean", "size_std", "size_min", "size_max",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "pkt_count", "up_pkt_count", "down_pkt_count",
    "updown_pkt_ratio", "updown_byte_ratio", "total_bytes",
    "burst_count", "idle_gap_count", "duration_ms",
]
