"""
features.py
===========
Computes a practical baseline subset of the full feature inventory
(temporal periodicity, inter-arrival, destination concentration,
port/protocol consistency, volume/packet, statistical) for a single
Window object.

Deliberately excludes any raw IP or raw destination-port identity as a
feature value (requirement 3 from the baseline spec) — IPs/ports are
only ever used to derive counts/ratios/booleans, never passed through
as categorical identity. See FEATURE_NAMES for the exact model input
vector and the docstring at the bottom for the leakage rationale.
"""

from __future__ import annotations
from typing import Dict

import numpy as np
import pandas as pd

from windowing import Window

# Ordered list of feature names == the model's input vector. Keeping
# this as an explicit list (rather than "whatever columns end up in the
# DataFrame") makes it obvious exactly what the model sees.
FEATURE_NAMES = [
    # --- 1. temporal periodicity ---
    "inter_arrival_cov",
    "autocorr_peak_strength",
    # --- 2. inter-arrival ---
    "inter_arrival_mean",
    "inter_arrival_median",
    "inter_arrival_range",
    "missed_beacon_ratio",
    "inter_arrival_skew",
    # --- 3. destination concentration (host-level, leakage-safe: counts only) ---
    "host_distinct_dest_count",
    "host_top_dest_share",
    # --- 4. port/protocol consistency ---
    "dest_port_is_wellknown",
    "conv_state_consistency",
    # --- 5. volume/packet ---
    "bytes_mean", "bytes_cov",
    "pkts_mean", "pkts_cov",
    "dur_mean", "dur_cov",
    "src_byte_asymmetry_mean",
    # --- misc window metadata (not fed to the model, kept for evaluation/latency) ---
]

_WELLKNOWN_PORTS = {"80", "443", "53", "22", "21", "25", "110", "143", "3389"}


def _safe_cov(x: np.ndarray) -> float:
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    if len(x) < 2 or x.mean() == 0:
        return 0.0
    return float(x.std(ddof=1) / abs(x.mean()))


def _safe_mean(x: np.ndarray) -> float:
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    return float(x.mean()) if len(x) else 0.0


def _inter_arrival_seconds(flows: pd.DataFrame) -> np.ndarray:
    ts = flows["start_time"].sort_values().values.astype("datetime64[ns]")
    if len(ts) < 2:
        return np.array([])
    deltas = np.diff(ts).astype("timedelta64[s]").astype(float)
    return deltas


def _autocorr_peak(inter_arrivals: np.ndarray, n_lags: int = 5) -> float:
    """Cheap, dependency-light periodicity proxy: autocorrelation of the
    inter-arrival sequence itself (not a full binned time-series
    autocorrelation / Lomb-Scargle — that is flagged in the feature
    inventory as a follow-up, non-streaming, per-window-trigger
    computation). Here we treat the inter-arrival series as a sequence
    and measure how strongly consecutive intervals correlate with each
    other at small lags — a genuinely periodic beacon has near-constant
    intervals, so this correlates strongly; jittery/random traffic does not.
    Returns the max |autocorrelation| over lags 1..min(n_lags, len-1),
    or 0.0 if there isn't enough data.
    """
    x = inter_arrivals
    n = len(x)
    if n < 3:
        return 0.0
    x = x - x.mean()
    denom = np.sum(x ** 2)
    if denom == 0:
        return 1.0  # perfectly constant intervals -> perfectly periodic
    max_lag = min(n_lags, n - 1)
    peaks = []
    for lag in range(1, max_lag + 1):
        num = np.sum(x[:-lag] * x[lag:])
        peaks.append(abs(num / denom))
    return float(max(peaks)) if peaks else 0.0


def _skew(x: np.ndarray) -> float:
    x = np.asarray(x, dtype=float)
    if len(x) < 3:
        return 0.0
    m = x.mean()
    s = x.std(ddof=0)
    if s == 0:
        return 0.0
    return float(np.mean(((x - m) / s) ** 3))


def compute_window_features(window: Window) -> Dict[str, float]:
    flows = window.flows
    inter_arrivals = _inter_arrival_seconds(flows)

    # --- 1. temporal periodicity ---
    cov = _safe_cov(inter_arrivals) if len(inter_arrivals) else 0.0
    autocorr_peak = _autocorr_peak(inter_arrivals)

    # --- 2. inter-arrival ---
    ia_mean = _safe_mean(inter_arrivals)
    ia_median = float(np.median(inter_arrivals)) if len(inter_arrivals) else 0.0
    ia_range = float(inter_arrivals.max() - inter_arrivals.min()) if len(inter_arrivals) else 0.0
    if len(inter_arrivals) and ia_mean > 0:
        missed = np.sum(inter_arrivals > 2 * ia_mean)
        missed_ratio = float(missed / len(inter_arrivals))
    else:
        missed_ratio = 0.0
    ia_skew = _skew(inter_arrivals)

    # --- 3. destination concentration (host-level context, leakage-safe) ---
    host_ctx = window.src_addr_all_dests
    dest_keys = host_ctx[["dst_addr", "dport", "proto"]].apply(tuple, axis=1)
    distinct_dest_count = int(dest_keys.nunique())
    if len(dest_keys):
        top_share = float(dest_keys.value_counts(normalize=True).iloc[0])
    else:
        top_share = 0.0

    # --- 4. port/protocol consistency ---
    dport_vals = flows["dport"].astype(str)
    dest_port_wellknown = float(dport_vals.isin(_WELLKNOWN_PORTS).mean()) if len(dport_vals) else 0.0
    state_counts = flows["state_canon"].value_counts(normalize=True)
    state_consistency = float(state_counts.iloc[0]) if len(state_counts) else 0.0

    # --- 5. volume / packet ---
    bytes_mean = _safe_mean(flows["tot_bytes"].values)
    bytes_cov = _safe_cov(flows["tot_bytes"].values)
    pkts_mean = _safe_mean(flows["tot_pkts"].values)
    pkts_cov = _safe_cov(flows["tot_pkts"].values)
    dur_mean = _safe_mean(flows["dur"].values)
    dur_cov = _safe_cov(flows["dur"].values)
    tot_b = flows["tot_bytes"].replace(0, np.nan)
    asym = (flows["src_bytes"] / tot_b).replace([np.inf, -np.inf], np.nan)
    asym_mean = _safe_mean(asym.values)

    return {
        "inter_arrival_cov": cov,
        "autocorr_peak_strength": autocorr_peak,
        "inter_arrival_mean": ia_mean,
        "inter_arrival_median": ia_median,
        "inter_arrival_range": ia_range,
        "missed_beacon_ratio": missed_ratio,
        "inter_arrival_skew": ia_skew,
        "host_distinct_dest_count": float(distinct_dest_count),
        "host_top_dest_share": top_share,
        "dest_port_is_wellknown": dest_port_wellknown,
        "conv_state_consistency": state_consistency,
        "bytes_mean": bytes_mean, "bytes_cov": bytes_cov,
        "pkts_mean": pkts_mean, "pkts_cov": pkts_cov,
        "dur_mean": dur_mean, "dur_cov": dur_cov,
        "src_byte_asymmetry_mean": asym_mean,
    }
