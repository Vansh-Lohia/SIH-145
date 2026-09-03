"""Security-relevant metrics (CLAUDE.md §7).

Report format for EVERY experiment:
    split_type | TPR@0.1%FPR | precision | recall | F1 | alerts/hr | p99 latency

Log the random-split and leave-one-family-out numbers SIDE BY SIDE; the gap is itself a
finding. Never report balanced accuracy or accuracy alone. Real traffic is ~99.9% benign.

STUB — Build Order step 2.
"""
from __future__ import annotations

from dataclasses import dataclass


def tpr_at_fixed_fpr(y_true, y_score, fpr: float = 0.001) -> float:
    """True-positive rate at a fixed low FPR (default 0.1%). STUB."""
    raise NotImplementedError("TPR@FPR — Build Order step 2")


def alerts_per_hour(y_score, threshold: float, duration_hours: float) -> float:
    """Alert volume at the chosen operating point. STUB."""
    raise NotImplementedError


@dataclass
class ExperimentRow:
    split_type: str
    tpr_at_0p1_fpr: float
    precision: float
    recall: float
    f1: float
    alerts_per_hr: float
    p99_latency_s: float

    def format_row(self) -> str:
        return (
            f"{self.split_type} | {self.tpr_at_0p1_fpr:.4f} | {self.precision:.4f} | "
            f"{self.recall:.4f} | {self.f1:.4f} | {self.alerts_per_hr:.1f} | "
            f"{self.p99_latency_s:.2f}"
        )
