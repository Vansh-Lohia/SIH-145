"""
evaluate.py
===========
Computes the required metric set (Precision, Recall, F1, PR-AUC,
Confusion Matrix, False Positive Rate) for a trained model against a
window-level dataset, plus a detection-latency report derived from the
window design (not a separately-measured runtime benchmark — see the
docstring on `latency_report`).
"""

from __future__ import annotations
from dataclasses import dataclass, asdict

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score, average_precision_score,
    confusion_matrix,
)

from config import WindowConfig
from train import TrainedModel, predict_proba


@dataclass
class EvalResult:
    n_windows: int
    n_positive: int
    n_negative: int
    precision: float
    recall: float
    f1: float
    pr_auc: float
    false_positive_rate: float
    tn: int
    fp: int
    fn: int
    tp: int
    threshold: float

    def as_dict(self):
        return asdict(self)


def evaluate(trained: TrainedModel, df: pd.DataFrame, threshold: float = 0.5) -> EvalResult:
    """df must contain only rows with label in {'positive','negative'} —
    the confirmed, non-excluded evaluation set. For the separate
    stress-test bucket (excluded windows), use `score_stress_bucket`
    instead, which reports a positive-rate rather than classification
    metrics (there is no ground-truth label to score against).
    """
    eval_df = df[df["label"].isin(["positive", "negative"])].copy()
    if eval_df.empty:
        raise ValueError("evaluate(): no positive/negative-labelled rows in df")

    y_true = (eval_df["label"] == "positive").astype(int).values
    y_prob = predict_proba(trained, eval_df)
    y_pred = (y_prob >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return EvalResult(
        n_windows=len(eval_df),
        n_positive=int(y_true.sum()),
        n_negative=int(len(y_true) - y_true.sum()),
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, zero_division=0)),
        pr_auc=float(average_precision_score(y_true, y_prob)),
        false_positive_rate=float(fpr),
        tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
        threshold=threshold,
    )


def score_stress_bucket(trained: TrainedModel, df: pd.DataFrame,
                         threshold: float = 0.5) -> dict:
    """Score the 'excluded' windows (ambiguous Botnet sub-categories:
    Attempt/SPAM/Ad/ICMP/DNS, and Background traffic) — there is no
    trustworthy binary ground truth here, so we report the model's
    positive-flag RATE on this traffic as a proxy false-positive-risk
    indicator, broken down where possible by the original label bucket
    of the windows' flows, rather than computing precision/recall.
    """
    stress_df = df[df["label"] == "excluded"].copy()
    if stress_df.empty:
        return {"n_windows": 0, "flagged_rate": None, "by_original_bucket": {}}

    y_prob = predict_proba(trained, stress_df)
    flagged = (y_prob >= threshold)
    return {
        "n_windows": len(stress_df),
        "flagged_rate": float(flagged.mean()),
    }


def print_eval_result(name: str, result: EvalResult) -> None:
    print(f"\n=== {name} ===")
    print(f"  windows: {result.n_windows}  (positive={result.n_positive}, "
          f"negative={result.n_negative})")
    print(f"  threshold: {result.threshold}")
    print(f"  Precision: {result.precision:.4f}")
    print(f"  Recall:    {result.recall:.4f}")
    print(f"  F1:        {result.f1:.4f}")
    print(f"  PR-AUC:    {result.pr_auc:.4f}")
    print(f"  FPR:       {result.false_positive_rate:.4f}")
    print(f"  Confusion matrix [tn={result.tn}, fp={result.fp}, "
          f"fn={result.fn}, tp={result.tp}]")


# ---------------------------------------------------------------------------
# Latency reporting
# ---------------------------------------------------------------------------
def latency_report(cfg: WindowConfig, dataset_df: pd.DataFrame = None) -> dict:
    """Detection latency under this window design has two components:

    1. Step latency (design-level, exact): a conversation's window is only
       re-evaluated every `step_seconds`, so in the worst case a pattern
       that becomes detectable right after a window boundary waits up to
       `step_seconds` before the next scoring opportunity.
    2. Minimum-evidence latency (data-dependent): a conversation cannot
       receive ANY prediction until it has accumulated
       `min_flows_for_prediction` flows — this is reported empirically
       below as the observed time-to-N-flows across the dataset's
       conversations, since it depends on the conversation's own beacon
       interval, not just the window config.

    Total near-real-time detection bound ≈ time-to-min-flows + step_seconds
    (+ unavoidable flow-export latency from the traffic capture layer,
    which this offline dataset cannot measure — flagged, not estimated).
    """
    report = {
        "window_seconds": cfg.window_seconds,
        "step_seconds": cfg.step_seconds,
        "min_flows_for_prediction": cfg.min_flows_for_prediction,
        "step_latency_seconds_worst_case": cfg.step_seconds,
    }

    if dataset_df is not None and len(dataset_df):
        # time-to-first-prediction per conversation: window_end - window_start
        # of each conversation's FIRST generated window is a lower bound on
        # how long that conversation had to be observed before any
        # prediction was possible.
        first_windows = (dataset_df.sort_values("window_start")
                          .groupby("conv_key", as_index=False)
                          .first())
        time_to_first = (first_windows["window_end"] - first_windows["window_start"]).dt.total_seconds()
        report["time_to_first_prediction_seconds"] = {
            "mean": float(time_to_first.mean()),
            "median": float(time_to_first.median()),
            "p90": float(time_to_first.quantile(0.90)),
        }

    return report


def print_latency_report(report: dict) -> None:
    print("\n=== Detection latency (design-derived) ===")
    print(f"  window length:        {report['window_seconds']}s")
    print(f"  step size:             {report['step_seconds']}s  "
          f"(worst-case additional wait for next scoring opportunity)")
    print(f"  min flows required:     {report['min_flows_for_prediction']}")
    if "time_to_first_prediction_seconds" in report:
        t = report["time_to_first_prediction_seconds"]
        print(f"  observed time-to-first-prediction (this dataset): "
              f"mean={t['mean']:.1f}s, median={t['median']:.1f}s, p90={t['p90']:.1f}s")
    print("  NOTE: excludes flow-export latency from the capture layer "
          "(Argus/NetFlow only finalises a flow record on completion or "
          "timeout) — real deployment latency = the above + that export "
          "delay, which cannot be measured from this offline dataset.")
