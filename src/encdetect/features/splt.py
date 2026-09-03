"""Sequence of Packet Lengths and Times (SPLT) — shape/timing features (CLAUDE.md §6.2).

Per session, first N packets, each (size, direction, inter_arrival_ms). Two consumers:
  - summary_stats(): mean/std/min/max of sizes & IATs, up:down packet & byte ratios,
    burst count, idle-gap count, duration -> LightGBM baseline.
  - raw_sequence(): the (size, direction, iat) array -> 1D-CNN.

Highest-priority family: survives ECH, TLS 1.3, everything.
Ref: Anderson & McGrew (Cisco), "Identifying Encrypted Malware Traffic with Contextual
Flow Data". N is tunable — test 20 vs 30 (CLAUDE.md open items §11).

STUB — Build Order step 2 (stats) / step 3 (raw sequence).
"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_N = 20  # first N packets; §11 open item: compare 20 vs 30


@dataclass
class Packet:
    size: int
    direction: int      # +1 = up (client->server), -1 = down
    inter_arrival_ms: float


def summary_stats(packets: list[Packet]) -> dict[str, float]:
    """Tabular SPLT summary for the LightGBM baseline. STUB."""
    raise NotImplementedError("SPLT summary — Build Order step 2")


def raw_sequence(packets: list[Packet], n: int = DEFAULT_N) -> list[tuple[int, int, float]]:
    """Fixed-length (size, direction, iat) sequence for the 1D-CNN. STUB."""
    raise NotImplementedError("SPLT sequence — Build Order step 3")
