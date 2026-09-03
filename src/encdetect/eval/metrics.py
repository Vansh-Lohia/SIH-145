"""Security-relevant metrics (CLAUDE.md §7).

Report format for EVERY experiment:
    split_type | TPR@0.1%FPR | precision | recall | F1 | alerts/hr | p99 latency

Log the random-split and leave-one-family-out numbers SIDE BY SIDE; the gap is itself a
finding. Never report balanced accuracy or accuracy alone — real traffic is ~99.9% benign.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def tpr_at_fixed_fpr(y_true, y_score, fpr: float = 0.001) -> tuple[float, float]:
    """True-positive rate at a fixed low FPR (default 0.1%).

    Returns (tpr, threshold). The threshold is the score cut that yields <= `fpr` on the
    negatives; if no positive threshold achieves it, returns the strictest available.
    """
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    neg = y_score[y_true == 0]
    pos = y_score[y_true == 1]
    if len(neg) == 0 or len(pos) == 0:
        return 0.0, 1.0
    # threshold = the (1 - fpr) quantile of negative scores => at most `fpr` false positives.
    threshold = float(np.quantile(neg, 1.0 - fpr))
    tpr = float(np.mean(pos > threshold))
    return tpr, threshold


def precision_recall_f1(y_true, y_score, threshold: float) -> tuple[float, float, float]:
    y_true = np.asarray(y_true).astype(int)
    pred = (np.asarray(y_score, dtype=float) > threshold).astype(int)
    tp = int(np.sum((pred == 1) & (y_true == 1)))
    fp = int(np.sum((pred == 1) & (y_true == 0)))
    fn = int(np.sum((pred == 0) & (y_true == 1)))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def alerts_per_hour(y_score, threshold: float, duration_hours: float) -> float:
    """Alert volume at the chosen operating point (rule 5)."""
    if duration_hours <= 0:
        return 0.0
    n_alerts = int(np.sum(np.asarray(y_score, dtype=float) > threshold))
    return n_alerts / duration_hours


@dataclass
class ExperimentRow:
    split_type: str
    tpr_at_0p1_fpr: float
    precision: float
    recall: float
    f1: float
    alerts_per_hr: float
    p99_latency_s: float

    HEADER = "split_type            | TPR@0.1%FPR | precision | recall |   F1   | alerts/hr | p99 lat(s)"

    def format_row(self) -> str:
        return (
            f"{self.split_type:<21} |   {self.tpr_at_0p1_fpr:>7.4f}   |  "
            f"{self.precision:>6.4f}  | {self.recall:>6.4f} | {self.f1:>6.4f} | "
            f"{self.alerts_per_hr:>8.1f}  |  {self.p99_latency_s:>6.3f}"
        )


def evaluate(y_true, y_score, split_type: str, duration_hours: float,
             p99_latency_s: float = 0.0, fpr: float = 0.001) -> ExperimentRow:
    """Build a full report row at the fixed-FPR operating point."""
    tpr, threshold = tpr_at_fixed_fpr(y_true, y_score, fpr=fpr)
    precision, recall, f1 = precision_recall_f1(y_true, y_score, threshold)
    aph = alerts_per_hour(y_score, threshold, duration_hours)
    return ExperimentRow(split_type, tpr, precision, recall, f1, aph, p99_latency_s)
