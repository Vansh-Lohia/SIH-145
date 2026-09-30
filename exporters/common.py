"""Unified alert schema shared by all six SimpleX detectors.

Each detector branch emits its own native output format. The exporters in this folder
adapt those outputs into ONE schema so a single dashboard (and later a single fusion /
correlation layer) can consume every detector the same way.

`severity` is the inherent impact of the threat class; `confidence` is the detector's own
certainty. They are independent fields and must never be derived from each other.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / ".sources"
OUT_DIR = ROOT / "data" / "raw"

THREATS = {
    "encrypted_malware":  {"label": "Malware in Encrypted Sessions", "mitre": "T1573",
                           "mitre_name": "Encrypted Channel", "severity": "high"},
    "botnet_c2":          {"label": "Botnet C2 Beaconing", "mitre": "T1071",
                           "mitre_name": "Application Layer Protocol", "severity": "high"},
    "dga":                {"label": "DGA Domain", "mitre": "T1568.002",
                           "mitre_name": "Domain Generation Algorithms", "severity": "medium"},
    "dns_tunnelling":     {"label": "DNS Tunnelling", "mitre": "T1071.004",
                           "mitre_name": "Application Layer Protocol: DNS", "severity": "high"},
    "port_scan":          {"label": "Reconnaissance / Port Scan", "mitre": "T1046",
                           "mitre_name": "Network Service Discovery", "severity": "medium"},
    "data_exfiltration":  {"label": "Data Exfiltration", "mitre": "T1048",
                           "mitre_name": "Exfiltration Over Alternative Protocol",
                           "severity": "critical"},
    "volumetric_ddos":    {"label": "Volumetric / Protocol DDoS", "mitre": "T1498",
                           "mitre_name": "Network Denial of Service", "severity": "high"},
}

# Where the evidence came from. Shown on every alert in the dashboard.
DATA_KINDS = {
    "real": "Real capture",
    "lab": "Lab-captured traffic",
    "synthetic": "Synthetic scenario",
}


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def make_alert(*, detector: str, threat: str, confidence: float, captured_ts: float | None,
               evidence: list[dict[str, Any]], dataset: str, kind: str,
               src_ip: str | None = None, src_port: int | None = None,
               dst_ip: str | None = None, dst_port: int | None = None,
               proto: str | None = None, entity: str | None = None,
               summary: str = "", severity: str | None = None) -> dict[str, Any]:
    t = THREATS[threat]
    assert kind in DATA_KINDS, kind
    return {
        "alert_id": str(uuid.uuid4()),
        "detector": detector,
        "threat_class": threat,
        "threat_label": t["label"],
        "mitre_technique": t["mitre"],
        "mitre_name": t["mitre_name"],
        "severity": severity or t["severity"],
        "confidence": round(max(0.0, min(1.0, float(confidence))), 4),
        "flow_id": {"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                    "dst_port": dst_port, "proto": proto},
        "entity": entity,
        "summary": summary,
        "evidence": evidence,
        "captured_at": iso(captured_ts),
        "source": {"dataset": dataset, "kind": kind},
    }


def write(name: str, alerts: list[dict[str, Any]]) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a) + "\n")
    print(f"{name}: {len(alerts)} alerts -> {path.relative_to(ROOT)}")
    return path
