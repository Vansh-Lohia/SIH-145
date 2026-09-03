"""Per-flow scan classifier.

The per-flow model answers a narrow question: *how scan-like is this single
observed-direction flow?*  It never decides on its own that a source is
scanning -- that is the behavioural layer's job (see spec section 7).

Two interchangeable scorers implement the same ``score(record) -> float``
interface:

* :class:`HeuristicFlowScorer` -- a dependency-free default that flags the
  classic scan signature (very small, near-payload-free flows).  It lets the
  detector run out of the box and keeps tests fast.
* :class:`MLFlowScorer` -- a trained ``RandomForestClassifier`` over the
  approved observed-direction feature list.

The output is called a *scan score* in ``[0, 1]``, not a probability, because
no calibration is performed (spec sections 7 and 37).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Protocol

import numpy as np

from .features import APPROVED_FEATURES, assert_features_are_one_way, vectorize_record
from .schemas import FlowRecord


class FlowScorer(Protocol):
    """Anything that can assign a scan score to a single flow."""

    def score(self, record: FlowRecord) -> float:  # pragma: no cover - protocol
        ...


@dataclass
class HeuristicFlowScorer:
    """Deterministic fallback scorer -- no training required.

    Port scans (SYN/connect/UDP probes) show up as tiny flows: one or a few
    forward packets carrying essentially no application payload.  This scorer
    maps that shape to a high score and is monotonic / bounded in ``[0, 1]``.
    """

    max_scan_packets: float = 4.0
    max_scan_bytes_per_packet: float = 16.0

    def score(self, record: FlowRecord) -> float:
        pkts = max(record.packet_count, 0.0)
        byts = max(record.byte_count, 0.0)
        # Feature 1: few packets -> more scan-like.
        pkt_term = np.exp(-max(pkts - 1.0, 0.0) / self.max_scan_packets)
        # Feature 2: little/no payload per packet -> more scan-like.
        bpp = byts / pkts if pkts else 0.0
        byte_term = np.exp(-bpp / self.max_scan_bytes_per_packet)
        return float(np.clip(0.5 * pkt_term + 0.5 * byte_term, 0.0, 1.0))


@dataclass
class MLFlowScorer:
    """Trained RandomForest scorer over approved observed-direction features."""

    model: object
    feature_list: List[str]
    medians: Dict[str, float] = field(default_factory=dict)
    scan_class_index: int = 1
    metadata: Dict[str, object] = field(default_factory=dict)

    def score(self, record: FlowRecord) -> float:
        row = vectorize_record(
            self.feature_list,
            record.features,
            record.packet_count,
            record.byte_count,
            record.flow_duration,
            self.medians,
        )
        x = np.asarray(row, dtype=float).reshape(1, -1)
        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
        proba = self.model.predict_proba(x)[0]
        return float(np.clip(proba[self.scan_class_index], 0.0, 1.0))

    # --- persistence ------------------------------------------------------
    def save(self, model_dir: str | Path) -> None:
        import joblib

        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, model_dir / "per_flow_model.joblib")
        (model_dir / "feature_list.json").write_text(
            json.dumps(self.feature_list, indent=2)
        )
        meta = dict(self.metadata)
        meta["medians"] = self.medians
        meta["scan_class_index"] = self.scan_class_index
        (model_dir / "metadata.json").write_text(json.dumps(meta, indent=2, default=str))

    @classmethod
    def load(cls, model_dir: str | Path) -> "MLFlowScorer":
        import joblib

        model_dir = Path(model_dir)
        model = joblib.load(model_dir / "per_flow_model.joblib")
        feature_list = json.loads((model_dir / "feature_list.json").read_text())
        assert_features_are_one_way(feature_list)
        meta = json.loads((model_dir / "metadata.json").read_text())
        medians = meta.get("medians", {})
        scan_idx = int(meta.get("scan_class_index", 1))
        return cls(
            model=model,
            feature_list=feature_list,
            medians=medians,
            scan_class_index=scan_idx,
            metadata=meta,
        )


@dataclass
class CompositeFlowScorer:
    """Use the ML scorer only when the record genuinely carries enough of the
    approved features; otherwise fall back to the heuristic.

    Rationale (spec sections 7, 16): the trained model expects the full
    observed-direction CIC feature vector.  The *minimal* streaming contract
    (``packet_count`` / ``byte_count`` / ``flow_duration``) does not carry those
    columns, and imputing 14 of 17 features from global medians produces an
    out-of-distribution vector the model reads unreliably.  So we only trust the
    ML score when the ingestion layer supplied at least ``min_features`` real
    features; below that the deterministic heuristic is more honest.
    """

    ml: "MLFlowScorer"
    heuristic: HeuristicFlowScorer = field(default_factory=HeuristicFlowScorer)
    min_features: int = 5

    def score(self, record: FlowRecord) -> float:
        provided = sum(1 for f in self.ml.feature_list if f in (record.features or {}))
        if provided >= self.min_features:
            return self.ml.score(record)
        return self.heuristic.score(record)


def train_per_flow_model(
    X: np.ndarray,
    y: np.ndarray,
    feature_list: Optional[List[str]] = None,
    medians: Optional[Dict[str, float]] = None,
    n_estimators: int = 100,
    max_depth: Optional[int] = None,
    random_state: int = 42,
    class_labels: Optional[List[str]] = None,
    metadata: Optional[Dict[str, object]] = None,
) -> MLFlowScorer:
    """Train a RandomForest per-flow scorer.

    ``y`` is expected to be binary with ``1`` = scan / positive class.  Kept
    intentionally small (no large hyperparameter search, spec section 22).
    """
    from sklearn.ensemble import RandomForestClassifier

    feature_list = feature_list or list(APPROVED_FEATURES)
    assert_features_are_one_way(feature_list)

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    clf.fit(X, y)
    # Locate the positive (scan) class column in predict_proba output.
    classes = list(clf.classes_)
    scan_index = classes.index(1) if 1 in classes else len(classes) - 1

    meta = dict(metadata or {})
    meta.setdefault("class_labels", class_labels or ["benign", "scan"])
    meta.setdefault("n_estimators", n_estimators)
    meta.setdefault("random_state", random_state)
    return MLFlowScorer(
        model=clf,
        feature_list=feature_list,
        medians=medians or {},
        scan_class_index=scan_index,
        metadata=meta,
    )
