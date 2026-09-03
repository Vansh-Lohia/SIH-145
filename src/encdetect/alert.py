"""Alert construction against the frozen shared schema (CLAUDE.md §5).

Keep this the single place alerts are built so every field stays schema-conformant.
`severity` (inherent impact) and `confidence` (model certainty) are DIFFERENT fields;
never conflate them.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import DETECTOR_ID

THREAT_CLASS = "encrypted_malware"
MITRE_TECHNIQUE = "T1071.001"  # Application Layer Protocol: Web Protocols


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()


@dataclass
class FlowId:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str  # "tcp" | "udp"

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
        }


@dataclass
class Evidence:
    feature: str
    value: Any
    contribution: float


@dataclass
class Alert:
    flow_id: FlowId
    severity: str          # inherent impact: low|medium|high|critical
    confidence: float      # model certainty 0..1
    window_start: datetime
    window_end: datetime
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": str(uuid.uuid4()),
            "timestamp": _iso(datetime.now(timezone.utc)),
            "detector": DETECTOR_ID,
            "flow_id": self.flow_id.to_dict(),
            "threat_class": THREAT_CLASS,
            "mitre_technique": MITRE_TECHNIQUE,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 4),
            "window": {"start": _iso(self.window_start), "end": _iso(self.window_end)},
            "evidence": [
                {"feature": e.feature, "value": e.value, "contribution": e.contribution}
                for e in self.evidence
            ],
        }
