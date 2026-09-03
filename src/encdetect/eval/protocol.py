"""Splitters enforcing the evaluation rules (CLAUDE.md §7).

The splitters are the guardrail against the environment artifact that collapsed our DGA
module (recall 95.6% -> ~0% under held-out-family test). They operate on group labels
(`pcap`, `family`, `environment`) carried through the whole pipeline from the labels
sidecar (CLAUDE.md §8).

STUB — Build Order step 2.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def split_by_capture_file(records: list[dict[str, Any]]) -> tuple[list, list]:
    """Ensure no flows from one pcap land in both train and test (rule 1). STUB."""
    raise NotImplementedError("Capture-file split — Build Order step 2")


def leave_one_family_out(records: list[dict[str, Any]]) -> Iterator[tuple[list, list, str]]:
    """Yield (train, test, held_out_family). The HEADLINE protocol (rule 2). STUB."""
    raise NotImplementedError("Leave-one-family-out — Build Order step 2")


def temporal_split(records: list[dict[str, Any]], cutoff_ts: float) -> tuple[list, list]:
    """Older -> train, newer -> test (rule 3). STUB."""
    raise NotImplementedError
