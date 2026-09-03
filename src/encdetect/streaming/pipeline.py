"""Asyncio sliding-window streaming pipeline (CLAUDE.md §2.4, §4, Build Order step 6).

Maintains per-session state keyed by flow 5-tuple, fires a decision at min(first N packets,
session close), emits schema-conformant alerts, and measures p99 latency.

STUB — Build Order step 6.
"""
from __future__ import annotations

import asyncio
from typing import Any

DECISION_PACKET_COUNT = 20      # first N packets (CLAUDE.md §4; §11: test 20 vs 30)
TARGET_P99_LATENCY_S = 30.0


class SessionState:
    """Accumulates packets/handshake for one flow until a decision fires. STUB."""

    def __init__(self, flow_key: tuple) -> None:
        self.flow_key = flow_key
        self.packets: list[Any] = []
        self.decided = False


async def run_pipeline(source) -> None:
    """Consume records, update session state, emit alerts. STUB."""
    raise NotImplementedError("Streaming pipeline — Build Order step 6")


def _flow_key(record: dict[str, Any]) -> tuple:
    return (
        record.get("src_ip"), record.get("src_port"),
        record.get("dst_ip"), record.get("dst_port"),
        record.get("proto"),
    )
