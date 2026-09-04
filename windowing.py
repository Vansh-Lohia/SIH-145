"""
windowing.py
============
Groups preprocessed flows into conversations and generates chronological,
overlapping, leakage-safe sliding windows per conversation.

Conversation key: (scenario, src_addr, dst_addr, dport, proto)
  - scenario is included so two different CTU-13 captures never get
    merged into one timeline just because of coincidental IP/port reuse.
  - sport is deliberately EXCLUDED from the key (ephemeral per-connection
    port; grouping by it would fragment one real conversation into many
    spurious single-flow ones — see the windowing-design discussion).

Leakage rule (enforced here, not just documented): a window ending at
`window_end` only ever includes flows with start_time < window_end.
Windows are built by iterating scenario+conversation groups sorted by
start_time and stepping forward in time — flows are never looked up
out of chronological order.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Iterator

import pandas as pd
import numpy as np

from config import WindowConfig, WINDOW_CFG


CONV_KEY_COLS = ["scenario", "src_addr", "dst_addr", "dport", "proto"]


@dataclass
class Window:
    conv_key: tuple
    window_start: pd.Timestamp
    window_end: pd.Timestamp
    flows: pd.DataFrame          # the flows in [window_start, window_end)
    src_addr_all_dests: pd.DataFrame  # ALL of this source host's flows up
                                       # to window_end, across every
                                       # destination (needed for the
                                       # destination-concentration
                                       # features in features.py) —
                                       # still leakage-safe: filtered to
                                       # start_time < window_end below.

    @property
    def n_flows(self) -> int:
        return len(self.flows)


def _generate_windows_for_conversation(
    conv_key: tuple,
    conv_flows: pd.DataFrame,
    host_flows: pd.DataFrame,
    cfg: WindowConfig,
) -> Iterator[Window]:
    """conv_flows: flows for this exact conv_key, sorted by start_time.
    host_flows: ALL flows for this conv's src_addr (any destination),
    sorted by start_time — used only to compute destination-concentration
    context per window, filtered to the leakage-safe cutoff inside the
    loop.
    """
    if conv_flows.empty:
        return

    t0 = conv_flows["start_time"].iloc[0]
    t_last = conv_flows["start_time"].iloc[-1]
    window_len = pd.Timedelta(seconds=cfg.window_seconds)
    step = pd.Timedelta(seconds=cfg.step_seconds)

    window_start = t0
    # stop once the window start would be beyond the last observed flow
    while window_start <= t_last:
        window_end = window_start + window_len

        mask = (conv_flows["start_time"] >= window_start) & \
               (conv_flows["start_time"] < window_end)
        flows_in_window = conv_flows.loc[mask]

        if len(flows_in_window) >= cfg.min_flows_for_prediction:
            host_mask = host_flows["start_time"] < window_end
            host_ctx = host_flows.loc[host_mask]
            yield Window(
                conv_key=conv_key,
                window_start=window_start,
                window_end=window_end,
                flows=flows_in_window.reset_index(drop=True),
                src_addr_all_dests=host_ctx,
            )
        window_start = window_start + step


def generate_windows(df: pd.DataFrame, cfg: WindowConfig = WINDOW_CFG) -> List[Window]:
    """Main entry point. df must already be preprocess()-ed (has
    normalised columns, is sorted by start_time).
    """
    for col in CONV_KEY_COLS:
        if col not in df.columns:
            raise ValueError(f"generate_windows: missing conversation-key column {col!r}")

    windows: List[Window] = []

    # Pre-group by (scenario, src_addr) once, since host-level context
    # (used for destination-concentration features) is shared across all
    # conv_keys with the same source host within a scenario.
    host_groups = {k: v.sort_values("start_time")
                   for k, v in df.groupby(["scenario", "src_addr"])}

    conv_groups = df.groupby(CONV_KEY_COLS)
    for conv_key, conv_flows in conv_groups:
        conv_flows = conv_flows.sort_values("start_time")
        scenario, src_addr = conv_key[0], conv_key[1]
        host_flows = host_groups[(scenario, src_addr)]
        windows.extend(
            _generate_windows_for_conversation(conv_key, conv_flows, host_flows, cfg)
        )
    return windows
