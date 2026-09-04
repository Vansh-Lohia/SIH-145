"""
splitting.py
============
Explicit scenario-based train/validation/test split — deliberately NOT a
random row-level or window-level split, per the leakage discussion
earlier in this project (random splits let the model memorise
per-scenario/per-family fingerprints rather than learning generalisable
periodicity behaviour).

Scenario assignment is grouped by malware family (see config.SplitConfig)
so a family never straddles the split.
"""

from __future__ import annotations
from typing import Tuple

import pandas as pd

from config import SplitConfig, SPLIT_CFG


def _scenario_in(scenario: str, prefixes: tuple) -> bool:
    return any(scenario.startswith(p) for p in prefixes)


def scenario_split(df: pd.DataFrame,
                    cfg: SplitConfig = SPLIT_CFG
                    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split a window-level DataFrame (must have a 'scenario' column) into
    (train, val, test) by scenario membership. Rows whose scenario matches
    none of the configured prefixes are dropped (with a warning) rather
    than silently included somewhere.
    """
    train_mask = df["scenario"].apply(lambda s: _scenario_in(s, cfg.train_scenarios))
    val_mask = df["scenario"].apply(lambda s: _scenario_in(s, cfg.val_scenarios))
    test_mask = df["scenario"].apply(lambda s: _scenario_in(s, cfg.test_scenarios))

    unmatched = ~(train_mask | val_mask | test_mask)
    if unmatched.any():
        bad_scenarios = sorted(df.loc[unmatched, "scenario"].unique())
        print(f"[splitting] WARNING: {unmatched.sum()} rows from scenarios "
              f"{bad_scenarios} matched no split configuration and are being "
              f"dropped. Update config.SplitConfig if these scenarios should "
              f"be included.")

    return (df.loc[train_mask].reset_index(drop=True),
            df.loc[val_mask].reset_index(drop=True),
            df.loc[test_mask].reset_index(drop=True))


def report_split_sizes(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame) -> None:
    for name, part in [("train", train), ("val", val), ("test", test)]:
        if len(part) == 0:
            print(f"[splitting] {name}: 0 rows")
            continue
        counts = part["label"].value_counts().to_dict()
        print(f"[splitting] {name}: {len(part)} windows, label counts = {counts}, "
              f"scenarios = {sorted(part['scenario'].unique())}")
