"""Reproducible training pipeline for the per-flow scan classifier.

Steps (spec section 22):
  1. locate dataset            5. remove invalid values     9. save feature list
  2. inspect columns           6. train model              10. save metadata
  3. inspect labels            7. evaluate model           11. reproducible inference
  4. validate selected features 8. save model artifact

Only approved observed-direction features are used (see
``recon_detector.features.APPROVED_FEATURES``).  ``Destination Port`` is
intentionally NOT a model feature; it is a behavioural key.

Leakage caveat (spec section 25): the CIC CSV has no source-IP / timestamp
columns, so we cannot do a source- or time-disjoint split.  We use a stratified
random split and state explicitly that the resulting offline metrics do NOT
prove real-world streaming performance.
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

# Make the src-layout package importable when run from the repo root.
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from recon_detector.features import APPROVED_FEATURES, assert_features_are_one_way  # noqa: E402
from recon_detector.model import train_per_flow_model  # noqa: E402

DATASET_CANDIDATES = [
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "~/Downloads/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "~/Downloads/archive/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

POSITIVE_LABELS = {"portscan", "port scan", "scan"}


def locate_dataset(explicit: Optional[str] = None) -> Path:
    candidates = ([explicit] if explicit else []) + DATASET_CANDIDATES
    for c in candidates:
        p = Path(c).expanduser()
        if p.exists():
            return p
    raise FileNotFoundError(
        "Could not locate the CIC PortScan CSV. Pass --dataset PATH. Tried: "
        + ", ".join(str(Path(c).expanduser()) for c in candidates)
    )


def load_and_prepare(
    dataset: Path,
    feature_list: List[str],
    max_rows: Optional[int] = None,
) -> "tuple[np.ndarray, np.ndarray, Dict[str, float], Dict]":
    import pandas as pd

    assert_features_are_one_way(feature_list)
    df = pd.read_csv(dataset, nrows=max_rows, low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    # inspect labels
    label_col = "Label" if "Label" in df.columns else df.columns[-1]
    raw_labels = df[label_col].astype(str).str.strip()
    label_counts = raw_labels.value_counts().to_dict()

    missing = [f for f in feature_list if f not in df.columns]
    if missing:
        raise KeyError(f"dataset is missing approved features: {missing}")

    X_df = df[feature_list].apply(pd.to_numeric, errors="coerce")
    # remove invalid values: inf -> nan, then drop rows that are all-nan; fill rest
    X_df = X_df.replace([np.inf, -np.inf], np.nan)
    medians = X_df.median(numeric_only=True).fillna(0.0).to_dict()
    X_df = X_df.fillna(medians)

    y = raw_labels.str.lower().isin(POSITIVE_LABELS).astype(int).to_numpy()
    if len(np.unique(y)) < 2:
        raise ValueError(
            f"Dataset contains only 1 class ({label_counts}). Supervised binary classification "
            "requires both BENIGN and PortScan flows to learn a decision boundary. "
            "Please ensure benign traffic was captured and processed."
        )

    info = {
        "n_rows": int(len(df)),
        "label_column": label_col,
        "label_counts": {str(k): int(v) for k, v in label_counts.items()},
        "positive_rate": float(y.mean()),
        "columns_total": int(df.shape[1]),
    }
    return X_df.to_numpy(dtype=float), y, {k: float(v) for k, v in medians.items()}, info


def run_training(
    dataset: Optional[str] = None,
    model_dir: str = "models",
    test_size: float = 0.3,
    n_estimators: int = 100,
    max_rows: Optional[int] = None,
    random_state: int = 42,
    feature_list: Optional[List[str]] = None,
) -> Dict:
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score,
        precision_score, recall_score, roc_auc_score, average_precision_score,
    )

    feature_list = feature_list or list(APPROVED_FEATURES)
    ds = locate_dataset(dataset)
    print(f"[train] dataset: {ds}")
    X, y, medians, info = load_and_prepare(ds, feature_list, max_rows=max_rows)
    print(f"[train] rows={info['n_rows']} positive_rate={info['positive_rate']:.4f} "
          f"labels={info['label_counts']}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    scorer = train_per_flow_model(
        X_tr, y_tr,
        feature_list=feature_list,
        medians=medians,
        n_estimators=n_estimators,
        random_state=random_state,
        metadata={
            "dataset": str(ds),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "test_size": test_size,
            "n_train": int(len(y_tr)),
            "n_test": int(len(y_te)),
            "label_info": info,
            "leakage_caveat": (
                "CIC CSV lacks src/dst IP and timestamp columns; this is a "
                "stratified RANDOM split. Offline metrics do NOT prove "
                "real-world streaming performance (spec section 25)."
            ),
            "excluded_by_design": {
                "Destination Port": "used as behavioural key, not an ML identity",
                "Flow Duration / */s": "bidirectional semantics",
                "*Bwd* / ratios / flag counts": "reverse-direction dependent",
            },
            "python": platform.python_version(),
        },
    )

    # evaluate on holdout
    proba = scorer.model.predict_proba(X_te)[:, scorer.scan_class_index]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "precision": float(precision_score(y_te, pred, zero_division=0)),
        "recall": float(recall_score(y_te, pred, zero_division=0)),
        "f1": float(f1_score(y_te, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_te, proba)) if len(set(y_te)) > 1 else None,
        "pr_auc": float(average_precision_score(y_te, proba)) if len(set(y_te)) > 1 else None,
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
    }
    print("[train] holdout metrics:")
    print(classification_report(y_te, pred, labels=[0, 1], target_names=["benign", "scan"], zero_division=0))
    print(f"[train] roc_auc={metrics['roc_auc']} pr_auc={metrics['pr_auc']}")

    # feature importances (transparency)
    importances = dict(sorted(
        zip(feature_list, scorer.model.feature_importances_.tolist()),
        key=lambda kv: kv[1], reverse=True,
    ))
    scorer.metadata["holdout_metrics"] = metrics
    scorer.metadata["feature_importances"] = importances

    out = Path(model_dir)
    scorer.save(out)
    (out / "training_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[train] saved model + feature_list + metadata to {out}/")
    print(f"[train] top features: {list(importances)[:5]}")
    return metrics


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Train the per-flow scan classifier")
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--n-estimators", type=int, default=100)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--random-state", type=int, default=42)
    a = ap.parse_args()
    run_training(a.dataset, a.model_dir, a.test_size, a.n_estimators,
                 a.max_rows, a.random_state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
