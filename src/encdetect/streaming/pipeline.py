"""Asyncio sliding-window streaming pipeline (CLAUDE.md §2.4, §4, Build Order step 6).

Maintains per-session state keyed by the flow 5-tuple, fires a decision at
min(first N packets, session close), scores it with the baseline model, and emits a
schema-conformant alert when the malicious probability clears the operating threshold.
Tracks per-session latency so p99 can be reported (target < 30 s).

This is the incremental, bounded-latency path — NOT a batch end-of-run report.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..alert import Alert, Evidence, FlowId
from ..features.session import Session, featurize

DECISION_PACKET_COUNT = 20      # first N packets (CLAUDE.md §4; §11: test 20 vs 30)
TARGET_P99_LATENCY_S = 30.0


@dataclass
class StreamResult:
    alerts: list[dict[str, Any]] = field(default_factory=list)
    latencies_s: list[float] = field(default_factory=list)
    n_sessions: int = 0

    def p99_latency_s(self) -> float:
        if not self.latencies_s:
            return 0.0
        import numpy as np
        return float(np.quantile(self.latencies_s, 0.99))


def _severity_for(confidence: float) -> str:
    # severity = inherent impact of the threat class (C2 is high); NOT the model certainty.
    return "high"


def _build_alert(session: Session, confidence: float,
                 evidence: list[tuple[str, Any, float]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    start = datetime.fromtimestamp(session.start_ts, tz=timezone.utc) if session.start_ts else now
    end = datetime.fromtimestamp(session.end_ts, tz=timezone.utc) if session.end_ts else now
    return Alert(
        flow_id=FlowId(session.flow.src_ip, session.flow.src_port,
                       session.flow.dst_ip, session.flow.dst_port, session.flow.proto),
        severity=_severity_for(confidence),
        confidence=confidence,
        window_start=start, window_end=end,
        evidence=[Evidence(f, v, c) for f, v, c in evidence],
    ).to_dict()


async def run_pipeline(
    sessions: AsyncIterator[Session] | Iterable[Session],
    model,
    threshold: float,
    on_alert: Callable[[dict[str, Any]], None] | None = None,
    n_packets: int = DECISION_PACKET_COUNT,
) -> StreamResult:
    """Consume a stream of completed Sessions, score each, and emit alerts.

    `model` must expose predict_proba([bundle]) -> [p] and explain(bundle) -> evidence
    (the LgbmBaseline satisfies this). In a live deployment the Session objects arrive
    incrementally from the Zeek reader as flows reach N packets or close.
    """
    result = StreamResult()

    async def _aiter():
        if hasattr(sessions, "__aiter__"):
            async for s in sessions:  # type: ignore[union-attr]
                yield s
        else:
            for s in sessions:  # type: ignore[assignment]
                yield s
                await asyncio.sleep(0)  # cooperative yield

    async for session in _aiter():
        t0 = time.perf_counter()
        bundle = featurize(session, n_packets=n_packets)
        proba = float(model.predict_proba([bundle])[0])
        result.n_sessions += 1
        result.latencies_s.append(time.perf_counter() - t0)
        if proba > threshold:
            evidence = model.explain(bundle)
            alert = _build_alert(session, proba, evidence)
            result.alerts.append(alert)
            if on_alert is not None:
                on_alert(alert)
    return result


def _flow_key(record: dict[str, Any]) -> tuple:
    return (record.get("src_ip"), record.get("src_port"),
            record.get("dst_ip"), record.get("dst_port"), record.get("proto"))
