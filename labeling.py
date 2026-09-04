"""
labeling.py
===========
Assigns the final training label to a window, following the label
strategy agreed earlier in this project:

  POSITIVE : every flow in the window is 'positive_candidate' (CC/IRC/P2P
             -tagged Botnet label) AND the window's own inter-arrival
             CoV is below PERIODICITY_COV_THRESHOLD (empirical
             periodicity confirmation — label evidence alone is not
             sufficient, see the label-audit discussion).
  NEGATIVE : every flow in the window is 'normal' (From-Normal-*).
             Regardless of whether the window looks periodic — a
             periodic-but-benign window is still a negative example,
             since teaching the model to tolerate benign periodicity is
             the whole point of including it.
  EXCLUDED : anything else (mixed labels within the window, excluded
             Botnet sub-categories, background, or a window whose flows
             are 'positive_candidate' but that fails the periodicity
             check). Excluded windows are never used for training; they
             go into a separate stress-test bucket for evaluation.

PERIODICITY_COV_THRESHOLD is a placeholder, not a validated number —
see the flag below and the config module docstring.
"""

from __future__ import annotations
from typing import Dict, Optional

import pandas as pd

# NOT YET EMPIRICALLY VALIDATED — starting point only. Must be checked
# against the actual inter-arrival distribution of confirmed CC-tagged
# conversations once real timestamps are available (flagged repeatedly
# in the methodology discussion; do not treat this as tuned).
PERIODICITY_COV_THRESHOLD = 0.5

POSITIVE = "positive"
NEGATIVE = "negative"
EXCLUDED = "excluded"


def label_window(flows: pd.DataFrame, inter_arrival_cov: float) -> str:
    buckets = set(flows["label_bucket"].unique())

    if buckets == {"positive_candidate"}:
        if inter_arrival_cov < PERIODICITY_COV_THRESHOLD:
            return POSITIVE
        return EXCLUDED  # label evidence present but periodicity check failed

    if buckets == {"normal"}:
        return NEGATIVE

    return EXCLUDED
