"""Input and output data contracts for the reconnaissance detector.

These dataclasses define the boundary with the (future) common ingestion /
feature-extraction layer and the common alert-scoring layer.  The detector
consumes :class:`FlowRecord` and emits :class:`DetectionResult`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def parse_timestamp(value: Any) -> float:
    """Normalize a timestamp to epoch seconds (float).

    Accepts epoch numbers (int/float) or ISO-8601 strings.  A missing value is
    an error: temporal state is meaningless without a time.
    """
    if value is None:
        raise ValueError("record is missing 'timestamp'")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        # plain numeric string
        try:
            return float(s)
        except ValueError:
            pass
        # ISO-8601 (allow trailing 'Z')
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    raise ValueError(f"unsupported timestamp type: {type(value)!r}")


@dataclass
class FlowRecord:
    """A single observed-direction flow record (A -> B only).

    The minimal contract is ``timestamp, src_ip, dst_ip, dst_port, protocol,
    packet_count, byte_count, flow_duration``.  Additional observed-direction
    statistics (matching approved CIC feature names) may be supplied in
    ``features`` and, when present, are used by the per-flow model.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    packet_count: float = 1.0
    byte_count: float = 0.0
    flow_duration: float = 0.0
    features: Dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlowRecord":
        return cls(
            timestamp=parse_timestamp(d.get("timestamp")),
            src_ip=str(d["src_ip"]),
            dst_ip=str(d["dst_ip"]),
            dst_port=int(d.get("dst_port", 0)),
            protocol=str(d.get("protocol", "TCP")).upper(),
            packet_count=float(d.get("packet_count", 1.0)),
            byte_count=float(d.get("byte_count", 0.0)),
            flow_duration=float(d.get("flow_duration", 0.0)),
            features={k: float(v) for k, v in (d.get("features") or {}).items()},
        )


@dataclass
class DetectionResult:
    """Structured detection result handed to the common alert-scoring layer."""

    detected: bool
    threat_class: str
    scan_type: str
    score: float
    timestamp: float
    source: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=_json_default)


def _json_default(o: Any) -> Any:
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)
