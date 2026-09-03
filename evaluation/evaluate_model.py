"""Offline supervised evaluation of the per-flow model (spec sections 23, 25).

Reports precision / recall / F1 / confusion matrix / ROC-AUC / PR-AUC on a
stratified holdout split, and prints the leakage caveat prominently.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import numpy as np

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))  # so `training.train` is importable

from recon_detector.model import MLFlowScorer  # noqa: E402


def run_evaluation(
    dataset: Optional[str] = None,
    model_dir: str = "models",
    test_size: float = 0.3,
    max_rows: Optional[int] = None,
    random_state: int = 42,
    out: Optional[str] = None,
) -> dict:
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score,
        precision_score, recall_score, roc_auc_score, average_precision_score,
    )
    # reuse the same preparation as training for consistency
    from training.train import load_and_prepare, locate_dataset

    scorer = MLFlowScorer.load(model_dir)
    ds = locate_dataset(dataset)
    X, y, _medians, info = load_and_prepare(ds, scorer.feature_list, max_rows=max_rows)

    # Reproduce the same split as training so we score the true holdout.
    _, X_te, _, y_te = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    proba = scorer.model.predict_proba(X_te)[:, scorer.scan_class_index]
    pred = (proba >= 0.5).astype(int)

    metrics = {
        "n_test": int(len(y_te)),
        "class_distribution": {"benign": int((y_te == 0).sum()),
                               "scan": int((y_te == 1).sum())},
        "precision": float(precision_score(y_te, pred, zero_division=0)),
        "recall": float(recall_score(y_te, pred, zero_division=0)),
        "f1": float(f1_score(y_te, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_te, proba)) if len(set(y_te)) > 1 else None,
        "pr_auc": float(average_precision_score(y_te, proba)) if len(set(y_te)) > 1 else None,
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
        "leakage_caveat": (
            "Stratified RANDOM split on a dataset without src/time keys; these "
            "numbers do NOT equal real-world streaming performance."
        ),
    }
    print("=== Offline supervised benchmark (per-flow model) ===")
    print(classification_report(y_te, pred, labels=[0, 1], target_names=["benign", "scan"], zero_division=0))
    print(f"roc_auc={metrics['roc_auc']} pr_auc={metrics['pr_auc']}")
    print(f"confusion_matrix (rows=true benign/scan): {metrics['confusion_matrix']}")
    print("NOTE:", metrics["leakage_caveat"])

    if out:
        Path(out).write_text(json.dumps(metrics, indent=2))
        print(f"wrote {out}")
    return metrics


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    run_evaluation(a.dataset, a.model_dir, a.test_size, a.max_rows, a.random_state, a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
