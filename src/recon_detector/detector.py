"""The reconnaissance / port-scan detector.

Ties the three evidence sources together (spec sections 18, 40):

    per-flow ML evidence  +  source-level fan-out  +  temporal persistence

into a single score in ``[0, 1]`` and a structured :class:`DetectionResult`.
Source-level behavioural evidence is weighted more heavily than any single
suspicious flow.  All heuristic weights and thresholds live in
:class:`DetectorConfig` so they are explicit and their sensitivity can be
evaluated.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .behavior import BehaviorTracker, WindowFeatures
from .model import CompositeFlowScorer, FlowScorer, HeuristicFlowScorer, MLFlowScorer
from .schemas import DetectionResult, FlowRecord

THREAT_CLASS = "reconnaissance_port_scan"


def _saturate(value: float, scale: float) -> float:
    """Map ``[0, inf)`` to ``[0, 1)`` with a soft knee at ``scale``."""
    if scale <= 0:
        return 0.0
    return 1.0 - math.exp(-max(value, 0.0) / scale)


@dataclass
class DetectorConfig:
    """All tunable knobs.  Defaults are documented starting points, not
    universal constants -- evaluate sensitivity (spec sections 8, 18, 22)."""

    window_seconds: float = 60.0
    state_ttl: float = 600.0

    # Score-fusion weights (must sum to 1.0).  Behaviour (scan-like fan-out +
    # persistence) deliberately outweighs the per-flow term, which acts mainly
    # as a "is scan-like flow shape present at all" confirmation.
    w_flow: float = 0.20
    w_fanout: float = 0.55
    w_persistence: float = 0.25

    # Fan-out saturation scales (a "knee" number of scan-like pairs / windows).
    fanout_pair_scale: float = 20.0
    persistence_scale: float = 3.0

    # Detection gate.
    detection_threshold: float = 0.6
    min_observed_flows: int = 8           # burst path: flows in recent window
    min_persistence_override: int = 2     # slow path: distinct suspicious windows
    min_slow_scan_pairs: int = 10         # slow path: cumulative scan-like pairs

    # Scan-type classification thresholds (documented; evaluated in synthetic tests).
    min_ports_vertical: int = 6
    min_hosts_horizontal: int = 6
    mixed_host_min: int = 4
    mixed_port_min: int = 4

    # Per-flow scan-likeness threshold used to compute scan_like_flow_ratio.
    scan_like_score_threshold: float = 0.5
    small_flow_packet_threshold: float = 3.0

    def normalized_weights(self) -> "tuple[float, float, float]":
        total = self.w_flow + self.w_fanout + self.w_persistence
        if total <= 0:
            return (0.0, 0.0, 0.0)
        return (self.w_flow / total, self.w_fanout / total, self.w_persistence / total)


class ReconDetector:
    """Incremental, single-source reconnaissance detector.

    Usage::

        det = ReconDetector()                 # heuristic scorer, no model file
        det = ReconDetector.from_model_dir("models")   # with trained model
        result = det.process(record_dict_or_FlowRecord)
    """

    def __init__(
        self,
        flow_scorer: Optional[FlowScorer] = None,
        config: Optional[DetectorConfig] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.flow_scorer: FlowScorer = flow_scorer or HeuristicFlowScorer()
        self.tracker = BehaviorTracker(
            window_seconds=self.config.window_seconds,
            state_ttl=self.config.state_ttl,
            small_flow_packet_threshold=self.config.small_flow_packet_threshold,
            scan_like_score_threshold=self.config.scan_like_score_threshold,
        )

    @classmethod
    def from_model_dir(
        cls, model_dir: Union[str, Path], config: Optional[DetectorConfig] = None
    ) -> "ReconDetector":
        scorer = CompositeFlowScorer(ml=MLFlowScorer.load(model_dir))
        return cls(flow_scorer=scorer, config=config)

    # --- main entry point -------------------------------------------------
    def process(self, record: Union[FlowRecord, Dict[str, Any]]) -> DetectionResult:
        if not isinstance(record, FlowRecord):
            record = FlowRecord.from_dict(record)

        flow_score = float(self.flow_scorer.score(record))

        state, feats = self.tracker.observe(
            src_ip=record.src_ip,
            ts=record.timestamp,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
            packet_count=record.packet_count,
            byte_count=record.byte_count,
            scan_score=flow_score,
        )

        # Mark this window as "active" for persistence whenever the current
        # flow is itself scan-like.  This is what lets slow scans accumulate
        # persistence across windows without any single burst.  Benign large
        # flows are not scan-like and never mark a window.
        if flow_score >= self.config.scan_like_score_threshold:
            state.mark_window(record.timestamp)
            feats = state.window_features(record.timestamp)  # refresh persistence

        score, components = self._fuse(feats)
        scan_type = self._classify_scan_type(feats)
        detected = self._decide(score, feats)

        evidence: Dict[str, Any] = {
            "window_seconds": feats.window_seconds,
            "observed_flows": feats.observed_flows,
            "unique_destination_hosts": feats.unique_destination_hosts,
            "unique_destination_ports": feats.unique_destination_ports,
            "unique_destination_pairs": feats.unique_destination_pairs,
            "attempts_per_second": round(feats.attempts_per_second, 4),
            "destination_host_entropy": round(feats.destination_host_entropy, 4),
            "destination_port_entropy": round(feats.destination_port_entropy, 4),
            "destination_pair_entropy": round(feats.destination_pair_entropy, 4),
            "small_flow_ratio": round(feats.small_flow_ratio, 4),
            "scan_like_flow_ratio": round(feats.scan_like_flow_ratio, 4),
            "mean_flow_scan_score": round(feats.mean_flow_scan_score, 4),
            "max_flow_scan_score": round(feats.max_flow_scan_score, 4),
            "persistence": feats.persistence,
            "ports_per_host": round(feats.ports_per_host, 4),
            "recent_window_flows": feats.recent_window_flows,
            "scan_like_hosts": feats.scan_like_hosts,
            "scan_like_ports": feats.scan_like_ports,
            "scan_like_pairs": feats.scan_like_pairs,
            "score_components": {k: round(v, 4) for k, v in components.items()},
        }

        return DetectionResult(
            detected=detected,
            threat_class=THREAT_CLASS if detected else "none",
            scan_type=scan_type if detected else "unknown",
            score=round(score, 4),
            timestamp=record.timestamp,
            source=record.src_ip,
            evidence=evidence,
        )

    def expire_state(self, now: float) -> int:
        return self.tracker.expire(now)

    @property
    def active_sources(self) -> int:
        return self.tracker.active_sources

    # --- score fusion -----------------------------------------------------
    def _fuse(self, f: WindowFeatures) -> "tuple[float, Dict[str, float]]":
        w_flow, w_fanout, w_persist = self.config.normalized_weights()

        # (1) Per-flow evidence: confirms scan-like flow *shape* is present.
        #     Uses max scan score (is there a clear probe?) plus the mean over
        #     scan-like flows.  It cannot by itself drive a detection -- fan-out
        #     and persistence gate that.
        flow_evidence = 0.5 * f.max_flow_scan_score + 0.5 * f.mean_flow_scan_score

        # (2) Fan-out evidence: distinct (host, port) pairs reached by *scan-like*
        #     flows.  Restricting to scan-like flows is what makes this survive
        #     camouflage and, crucially, ignore benign high fan-out -- browsers,
        #     CDNs, updates produce large flows that are not scan-like, so they
        #     contribute zero here (spec section 19).
        fanout_evidence = _saturate(f.scan_like_pairs, self.config.fanout_pair_scale)

        # (3) Temporal persistence: suspicious activity across multiple windows.
        persistence_evidence = _saturate(f.persistence, self.config.persistence_scale)

        score = (
            w_flow * flow_evidence
            + w_fanout * fanout_evidence
            + w_persist * persistence_evidence
        )
        score = float(min(max(score, 0.0), 1.0))
        return score, {
            "flow_evidence": flow_evidence,
            "fanout_evidence": fanout_evidence,
            "persistence_evidence": persistence_evidence,
        }

    # --- scan-type classification ----------------------------------------
    def _classify_scan_type(self, f: WindowFeatures) -> str:
        c = self.config
        # Classify using scan-like fan-out only, so benign destinations mixed in
        # (camouflage) do not distort the vertical/horizontal decision.
        hosts = f.scan_like_hosts
        ports = f.scan_like_ports

        high_ports = ports >= c.min_ports_vertical
        high_hosts = hosts >= c.min_hosts_horizontal
        mixed = hosts >= c.mixed_host_min and ports >= c.mixed_port_min

        # Vertical: many ports on one / few hosts.
        vertical = high_ports and hosts <= max(2, c.mixed_host_min - 1)
        # Horizontal: many hosts on one / few ports.
        horizontal = high_hosts and ports <= max(2, c.mixed_port_min - 1)

        if mixed and not (vertical or horizontal):
            return "mixed"
        if vertical and horizontal:
            return "mixed"
        if vertical:
            return "vertical"
        if horizontal:
            return "horizontal"
        if mixed:
            return "mixed"
        return "unknown"

    # --- detection gate ---------------------------------------------------
    def _decide(self, score: float, f: WindowFeatures) -> bool:
        if score < self.config.detection_threshold:
            return False
        # Two independent evidence paths must be satisfied for a detection:
        #   burst path  -- enough scan-like flows in the recent window; or
        #   slow  path  -- suspicious activity persisted across multiple windows
        #                  AND enough cumulative scan-like pairs to rule out
        #                  merely sparse benign traffic (spec section 10).
        burst = (
            f.recent_window_flows >= self.config.min_observed_flows
            and f.scan_like_pairs >= self.config.min_observed_flows
        )
        slow = (
            f.persistence >= self.config.min_persistence_override
            and f.scan_like_pairs >= self.config.min_slow_scan_pairs
        )
        return burst or slow
