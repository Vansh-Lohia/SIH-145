"""Approved observed-direction feature set for the per-flow scan classifier.

This module is the *single source of truth* for which CICFlowMeter/CICIDS
columns the supervised model is allowed to consume.

Design rules (see spec sections 12-15):

* Only forward / observed-direction flow-shape features are used.
* No backward (`Bwd*`) features, no ratios, no bidirectional totals, and no
  flag counts that could aggregate reverse-direction packets.
* `Destination Port` is deliberately *excluded* from the ML feature vector.
  Its raw numeric value acts as a weak identity that a tree model can memorise
  for this particular capture; instead it is used purely as a behavioural key
  (vertical fan-out) in :mod:`recon_detector.behavior`.
* `Flow Duration` and any `*/s` rate columns are excluded from the ML vector
  because their exact semantics span both directions of the flow.

Each feature is also given a mapping from the *minimal* normalized streaming
record (``packet_count`` / ``byte_count`` / ``flow_duration``) so the same model
can score production records that carry fewer fields.  Missing features are
imputed from training medians stored in the model metadata.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

# --- Approved feature list (order matters; persisted with the model) ---------
APPROVED_FEATURES: List[str] = [
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Init_Win_bytes_forward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
]

# Substrings that must NEVER appear in an approved feature name.  Used by the
# one-way constraint tests to prove no reverse-direction leakage crept in.
FORBIDDEN_SUBSTRINGS: List[str] = [
    "Bwd",
    "Backward",
    "Down/Up",
    "Ratio",
    "SYN",
    "RST",
    "ACK Flag",
    "FIN Flag",
    "Bulk Rate",  # bidirectional bulk statistics
]


def assert_features_are_one_way(features: List[str]) -> None:
    """Raise ``ValueError`` if any feature name looks reverse-direction-derived."""
    for name in features:
        for bad in FORBIDDEN_SUBSTRINGS:
            if bad.lower() in name.lower():
                raise ValueError(
                    f"Feature {name!r} contains forbidden substring {bad!r}; "
                    "it may depend on reverse-direction traffic."
                )


# --- Mapping from the minimal normalized record to approved features ---------
# Only a handful of approved features can be derived from the minimal contract
# (packet_count / byte_count / flow_duration).  The rest are imputed from
# training medians.  This is intentional and documented: when a production
# record carries only minimal fields the per-flow score is weaker and the
# behavioural layer carries proportionally more weight.
def _mean_fwd_len(pkts: float, byts: float) -> float:
    return byts / pkts if pkts else 0.0


_MINIMAL_DERIVATIONS: Dict[str, Callable[[float, float, float], float]] = {
    "Total Fwd Packets": lambda pkts, byts, dur: pkts,
    "Total Length of Fwd Packets": lambda pkts, byts, dur: byts,
    "Fwd Packet Length Mean": lambda pkts, byts, dur: _mean_fwd_len(pkts, byts),
    "Fwd Packet Length Max": lambda pkts, byts, dur: _mean_fwd_len(pkts, byts),
    "Fwd IAT Total": lambda pkts, byts, dur: dur,
    "act_data_pkt_fwd": lambda pkts, byts, dur: max(pkts - 1, 0) if byts > 0 else 0.0,
}


def vectorize_record(
    features: List[str],
    explicit: Optional[Dict[str, float]],
    packet_count: float,
    byte_count: float,
    flow_duration: float,
    medians: Optional[Dict[str, float]] = None,
) -> List[float]:
    """Build a feature vector for one flow record.

    Precedence for each feature: an explicitly supplied value, then a value
    derived from the minimal record, then the training median (or 0.0).
    """
    explicit = explicit or {}
    medians = medians or {}
    row: List[float] = []
    for name in features:
        if name in explicit and explicit[name] is not None:
            row.append(float(explicit[name]))
        elif name in _MINIMAL_DERIVATIONS:
            row.append(float(_MINIMAL_DERIVATIONS[name](packet_count, byte_count, flow_duration)))
        else:
            row.append(float(medians.get(name, 0.0)))
    return row
