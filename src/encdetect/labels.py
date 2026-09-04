"""Label sidecar loading + application (CLAUDE.md §8).

Every capture carries a `labels.jsonl` sidecar, one JSON object per line:

    {"pcap":"run_07.pcap","start_ts":0,"end_ts":0,"src_ip":"","dst_ip":"",
     "label":"benign|malicious","family":"","environment":""}

A rule matches a session when each *specified* selector matches (empty selector = wildcard):
  - src_ip / dst_ip: exact IP match (either direction is checked, since a "src" in the
    sidecar may be the infected host regardless of who opened the TLS connection)
  - start_ts / end_ts: session start falls in the window (0/absent end = open-ended)

The most specific matching rule wins (more non-empty selectors = more specific). `family` and
`environment` are carried onto the session so the evaluation splitters can use them
(leave-one-family-out, by-environment). Sessions matching no rule take `default_label`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .features.session import Session


@dataclass
class LabelRule:
    label: str = ""
    family: str = ""
    environment: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    start_ts: float = 0.0
    end_ts: float = 0.0
    pcap: str = ""

    @property
    def specificity(self) -> int:
        return sum(bool(x) for x in (self.src_ip, self.dst_ip)) + \
            (1 if self.end_ts else 0)

    def matches(self, s: Session) -> bool:
        ips = {s.flow.src_ip, s.flow.dst_ip}
        if self.src_ip and self.src_ip not in ips:
            return False
        if self.dst_ip and self.dst_ip not in ips:
            return False
        if self.start_ts and s.start_ts and s.start_ts < self.start_ts:
            return False
        if self.end_ts and s.start_ts and s.start_ts > self.end_ts:
            return False
        return True


def load_labels(path: str | Path) -> list[LabelRule]:
    rules: list[LabelRule] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        d: dict[str, Any] = json.loads(line)
        rules.append(LabelRule(
            label=d.get("label", ""), family=d.get("family", ""),
            environment=d.get("environment", ""),
            src_ip=d.get("src_ip", "") or "", dst_ip=d.get("dst_ip", "") or "",
            start_ts=float(d.get("start_ts", 0) or 0),
            end_ts=float(d.get("end_ts", 0) or 0),
            pcap=d.get("pcap", ""),
        ))
    return rules


def apply_labels(sessions: list[Session], rules: list[LabelRule],
                 default_label: str = "") -> list[Session]:
    """Attach label/family/environment to each session from the best-matching rule."""
    for s in sessions:
        best: LabelRule | None = None
        for r in rules:
            if r.matches(s) and (best is None or r.specificity > best.specificity):
                best = r
        if best is not None:
            s.label = best.label
            s.family = best.family
            s.environment = best.environment
        elif default_label:
            s.label = default_label
    return sessions
