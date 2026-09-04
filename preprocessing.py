"""
preprocessing.py
=================
Cleans a raw loaded DataFrame into a normalised schema and attaches the
label-taxonomy bucket derived from the audited CTU-13 label strings.

Does NOT do any windowing, grouping, or feature computation — this
module produces a flow-level table with one row per flow, ready for
windowing.py to consume.
"""

from __future__ import annotations
import re
from typing import Optional

import pandas as pd
import numpy as np

from config import (
    REQUIRED_COLUMNS, POSITIVE_LABEL_PATTERNS, EXCLUDED_BOTNET_PATTERNS,
    NORMAL_LABEL_PATTERN, BACKGROUND_LABEL_PATTERN, BOTNET_LABEL_PATTERN,
)

# Common CTU-13 / Argus column name aliases -> normalised name
_COLUMN_ALIASES = {
    "starttime": "start_time", "start_time": "start_time",
    "srcaddr": "src_addr", "src_addr": "src_addr",
    "sport": "sport",
    "dstaddr": "dst_addr", "dst_addr": "dst_addr",
    "dport": "dport",
    "proto": "proto",
    "dur": "dur",
    "state": "state",
    "stos": "stos", "dtos": "dtos",
    "totpkts": "tot_pkts", "tot_pkts": "tot_pkts",
    "totbytes": "tot_bytes", "tot_bytes": "tot_bytes",
    "srcbytes": "src_bytes", "src_bytes": "src_bytes",
    "label": "label",
    "scenario": "scenario",
    "dir": "dir",
}

# Canonical Argus state families (collapses the ~230 raw state strings
# seen in the audit into a small, interpretable vocabulary). Anything
# unmatched falls into "OTHER".
_STATE_CANON_RULES = [
    (re.compile(r"^CON$"), "ESTABLISHED"),
    (re.compile(r"^S_RA$|^SRPA"), "ESTABLISHED"),
    (re.compile(r"^FSPA_FSPA$|^FSPA_FSA$|^FSA_FSA$|^FSRPA"), "CLOSED_NORMAL"),
    (re.compile(r"^S_$|^S_SA$|^SR_"), "ATTEMPT_HALF_OPEN"),
    (re.compile(r"^INT$"), "INTERRUPTED"),
    (re.compile(r"^URP$|^URH$"), "UDP"),
    (re.compile(r"^PA_PA$|^SPA_SPA$"), "SHORT_ACK_EXCHANGE"),
]


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename raw columns to the internal normalised schema (case-insensitive)."""
    rename_map = {}
    for col in df.columns:
        key = col.strip().lower()
        if key in _COLUMN_ALIASES:
            rename_map[col] = _COLUMN_ALIASES[key]
    out = df.rename(columns=rename_map)
    return out


def validate_schema(df: pd.DataFrame) -> None:
    """Raise a clear error if required columns are missing, instead of
    failing deep inside windowing with a confusing KeyError.
    """
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            "Input data is missing required column(s): "
            f"{missing}. This pipeline requires re-sourced CTU-13 data "
            "with StartTime/SrcAddr/Sport/DstAddr/Dport restored — see "
            "the module docstring in config.py. The originally audited "
            "parquet sample for this project did NOT include these "
            "columns and cannot be used directly."
        )


def canonicalize_state(state: Optional[str]) -> str:
    if state is None or (isinstance(state, float) and np.isnan(state)):
        return "MISSING"
    s = str(state).strip()
    for pattern, canon in _STATE_CANON_RULES:
        if pattern.search(s):
            return canon
    return "OTHER"


def bucket_label(label: Optional[str]) -> str:
    """Classify a raw CTU-13 label string into one of:
      'positive_candidate' : CC/IRC/P2P tagged Botnet flow (label evidence
                              for beaconing; still needs the empirical
                              periodicity check applied at window-labeling time)
      'excluded_botnet'    : Botnet-labelled but non-beaconing behaviour
                              (Attempt/SPAM/Ad/ICMP/DNS) - held out, never
                              forced into positive or negative
      'normal'             : From-Normal-* traffic (negative candidate)
      'background'         : Background traffic (weak ground truth; not
                              used for training labels, only evaluation)
      'other_botnet'       : Botnet-labelled, not matching any of the
                              above sub-rules (rare; treated like
                              excluded_botnet by default)
    """
    if label is None or (isinstance(label, float) and np.isnan(label)):
        return "unknown"
    l = str(label)

    if re.search(BACKGROUND_LABEL_PATTERN, l, re.IGNORECASE):
        return "background"
    if re.search(NORMAL_LABEL_PATTERN, l, re.IGNORECASE):
        return "normal"
    if re.search(BOTNET_LABEL_PATTERN, l, re.IGNORECASE):
        for pat in POSITIVE_LABEL_PATTERNS:
            if re.search(pat, l):
                return "positive_candidate"
        for pat in EXCLUDED_BOTNET_PATTERNS:
            if re.search(pat, l):
                return "excluded_botnet"
        return "other_botnet"
    return "unknown"


def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    """Full preprocessing pass: normalise columns, validate schema, parse
    dtypes, canonicalise state, bucket labels. Returns a clean flow-level
    DataFrame sorted by (conversation key components are added later in
    windowing.py) start_time.
    """
    df = normalise_columns(df)
    validate_schema(df)

    df = df.copy()
    df["start_time"] = pd.to_datetime(df["start_time"], errors="coerce")
    df["dur"] = pd.to_numeric(df["dur"], errors="coerce")
    df["tot_pkts"] = pd.to_numeric(df["tot_pkts"], errors="coerce")
    df["tot_bytes"] = pd.to_numeric(df["tot_bytes"], errors="coerce")
    df["src_bytes"] = pd.to_numeric(df["src_bytes"], errors="coerce")
    df["dport"] = df["dport"].astype(str)
    df["sport"] = df["sport"].astype(str)
    df["proto"] = df["proto"].astype(str).str.strip().str.lower()

    n_bad_time = df["start_time"].isna().sum()
    if n_bad_time:
        df = df[df["start_time"].notna()].copy()

    df["state_canon"] = df["state"].apply(canonicalize_state)
    df["label_bucket"] = df["label"].apply(bucket_label)

    if "scenario" not in df.columns:
        df["scenario"] = "unknown_scenario"

    df = df.sort_values("start_time").reset_index(drop=True)
    return df
