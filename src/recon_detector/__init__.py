"""recon_detector -- passive, one-way reconnaissance / port-scan detector.

Public API::

    from recon_detector import ReconDetector, DetectorConfig
    from recon_detector import FlowRecord, DetectionResult

    det = ReconDetector()                          # heuristic per-flow scorer
    det = ReconDetector.from_model_dir("models")   # trained per-flow model
    result = det.process(record)                   # -> DetectionResult
"""

from .schemas import FlowRecord, DetectionResult, parse_timestamp
from .detector import ReconDetector, DetectorConfig, THREAT_CLASS
from .model import (
    HeuristicFlowScorer,
    MLFlowScorer,
    CompositeFlowScorer,
    train_per_flow_model,
)
from .behavior import BehaviorTracker, SourceState, WindowFeatures
from .features import APPROVED_FEATURES

__version__ = "0.1.0"

__all__ = [
    "FlowRecord",
    "DetectionResult",
    "parse_timestamp",
    "ReconDetector",
    "DetectorConfig",
    "THREAT_CLASS",
    "HeuristicFlowScorer",
    "MLFlowScorer",
    "CompositeFlowScorer",
    "train_per_flow_model",
    "BehaviorTracker",
    "SourceState",
    "WindowFeatures",
    "APPROVED_FEATURES",
    "__version__",
]
