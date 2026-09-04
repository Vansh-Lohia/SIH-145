"""
dataset_builder.py
===================
Orchestrates windowing.py + features.py + labeling.py into a single flat
DataFrame: one row per generated window, with feature columns, the
assigned label, and metadata needed later for scenario-based splitting
and latency reporting.

This is the ONLY module that combines those three stages — training and
evaluation code should consume its output and never call windowing/
features/labeling directly, so the leakage-relevant logic stays in one
auditable place.
"""

from __future__ import annotations
from typing import List

import pandas as pd

from config import WindowConfig, WINDOW_CFG
from windowing import generate_windows, Window
from features import compute_window_features, FEATURE_NAMES
from labeling import label_window, EXCLUDED


def build_window_dataset(df_preprocessed: pd.DataFrame,
                          cfg: WindowConfig = WINDOW_CFG) -> pd.DataFrame:
    """df_preprocessed: output of preprocessing.preprocess().
    Returns a DataFrame with columns: FEATURE_NAMES + ['label',
    'scenario', 'conv_key', 'window_start', 'window_end', 'n_flows'].
    Rows with label == 'excluded' ARE included (needed for the
    stress-test evaluation bucket) — filter them out explicitly before
    training, not before returning from this function.
    """
    windows: List[Window] = generate_windows(df_preprocessed, cfg)

    rows = []
    for w in windows:
        feats = compute_window_features(w)
        lbl = label_window(w.flows, feats["inter_arrival_cov"])
        row = dict(feats)
        row["label"] = lbl
        row["scenario"] = w.conv_key[0]
        row["conv_key"] = w.conv_key
        row["window_start"] = w.window_start
        row["window_end"] = w.window_end
        row["n_flows"] = w.n_flows
        rows.append(row)

    if not rows:
        return pd.DataFrame(columns=FEATURE_NAMES + [
            "label", "scenario", "conv_key", "window_start", "window_end", "n_flows"
        ])

    return pd.DataFrame(rows)
