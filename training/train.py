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
columns, so we cannot do a true source- or time-disjoint split. However, the
dataset is ~25% exact-duplicate rows (72,353 / 286,467 in the PortScan CSV) --
a plain random split lets near-identical flows land on both sides, inflating
holdout metrics. We instead group rows by their exact feature-vector fingerprint
(duplicate/near-duplicate flows always land entirely in train or entirely in
test) and split on those groups with ``StratifiedGroupKFold``. This does not
fully substitute for a source/time-disjoint split, but it removes the specific,
measured leakage source that exists in this dataset.
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


def group_disjoint_folds(X: np.ndarray, y: np.ndarray, test_size: float, random_state: int):
    """Yield (train_idx, test_idx) folds where rows sharing an identical
    feature-vector fingerprint (exact/near-duplicate flows) always land
    entirely on one side.

    Plain ``train_test_split`` on this dataset lets duplicate flows leak across
    train/test (spec section 25 caveat). Grouping by fingerprint before
    splitting removes that leakage even without a source-IP/timestamp column
    -- but this dataset has a handful of *enormous* fingerprint groups (two
    single flow shapes each account for >25% of all rows), so a single
    arbitrary fold can silo an entire scan "shape" out of training or into
    test by chance. We therefore run every fold, not just one, and the caller
    reports mean/std across them instead of trusting one split.
    """
    from sklearn.model_selection import StratifiedGroupKFold

    _, groups, group_counts = np.unique(X, axis=0, return_inverse=True, return_counts=True)
    n_groups = int(groups.max()) + 1
    n_splits = max(2, round(1.0 / test_size))
    n_splits = min(n_splits, n_groups)
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    dup_rows = int(len(X) - n_groups)
    split_info = {
        "method": "StratifiedGroupKFold cross-validation on feature-vector fingerprint groups",
        "n_groups": n_groups,
        "duplicate_rows_removed_from_leakage": dup_rows,
        "duplicate_row_fraction": float(dup_rows / len(X)) if len(X) else 0.0,
        "n_splits": n_splits,
        "largest_group_sizes": sorted(group_counts.tolist(), reverse=True)[:5],
    }
    return list(splitter.split(X, y, groups=groups)), split_info


def run_training(
    dataset: Optional[str] = None,
    model_dir: str = "models",
    test_size: float = 0.3,
    n_estimators: int = 100,
    max_rows: Optional[int] = None,
    random_state: int = 42,
    feature_list: Optional[List[str]] = None,
) -> Dict:
    from sklearn.metrics import (
        f1_score, precision_score, recall_score,
        roc_auc_score, average_precision_score,
    )

    feature_list = feature_list or list(APPROVED_FEATURES)
    ds = locate_dataset(dataset)
    print(f"[train] dataset: {ds}")
    X, y, medians, info = load_and_prepare(ds, feature_list, max_rows=max_rows)
    print(f"[train] rows={info['n_rows']} positive_rate={info['positive_rate']:.4f} "
          f"labels={info['label_counts']}")

    folds, split_info = group_disjoint_folds(X, y, test_size=test_size, random_state=random_state)
    print(f"[train] group-disjoint CV: {split_info['n_groups']} unique flow fingerprints, "
          f"{split_info['duplicate_rows_removed_from_leakage']} duplicate rows "
          f"({split_info['duplicate_row_fraction']:.1%}) kept out of cross-fold leakage, "
          f"largest groups={split_info['largest_group_sizes']}")

    # Cross-validate across every fold rather than trusting one arbitrary split:
    # this dataset has a couple of enormous fingerprint groups (see
    # largest_group_sizes above), so which fold a given giant group lands in
    # can swing a single-split holdout wildly. Mean/std across folds is the
    # honest number.
    fold_metrics: List[Dict] = []
    for fold_i, (train_idx, test_idx) in enumerate(folds):
        X_tr, X_te = X[train_idx], X[test_idx]
        y_tr, y_te = y[train_idx], y[test_idx]
        if len(np.unique(y_tr)) < 2 or len(np.unique(y_te)) < 2:
            continue  # degenerate fold (all one class on one side); skip
        fold_scorer = train_per_flow_model(
            X_tr, y_tr, feature_list=feature_list, medians=medians,
            n_estimators=n_estimators, random_state=random_state,
        )
        proba = fold_scorer.model.predict_proba(X_te)[:, fold_scorer.scan_class_index]
        pred = (proba >= 0.5).astype(int)
        fold_metrics.append({
            "fold": fold_i,
            "n_train": int(len(y_tr)),
            "n_test": int(len(y_te)),
            "precision": float(precision_score(y_te, pred, zero_division=0)),
            "recall": float(recall_score(y_te, pred, zero_division=0)),
            "f1": float(f1_score(y_te, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_te, proba)),
            "pr_auc": float(average_precision_score(y_te, proba)),
        })
        print(f"[train] fold {fold_i}: precision={fold_metrics[-1]['precision']:.4f} "
              f"recall={fold_metrics[-1]['recall']:.4f} f1={fold_metrics[-1]['f1']:.4f} "
              f"roc_auc={fold_metrics[-1]['roc_auc']:.4f}")

    def _mean_std(key: str) -> Dict[str, float]:
        vals = [m[key] for m in fold_metrics]
        return {"mean": float(np.mean(vals)), "std": float(np.std(vals))}

    cv_metrics = {
        "n_folds_evaluated": len(fold_metrics),
        "precision": _mean_std("precision"),
        "recall": _mean_std("recall"),
        "f1": _mean_std("f1"),
        "roc_auc": _mean_std("roc_auc"),
        "pr_auc": _mean_std("pr_auc"),
        "per_fold": fold_metrics,
    }
    print(f"[train] group-disjoint CV summary over {len(fold_metrics)} folds: "
          f"precision={cv_metrics['precision']['mean']:.4f}+/-{cv_metrics['precision']['std']:.4f} "
          f"recall={cv_metrics['recall']['mean']:.4f}+/-{cv_metrics['recall']['std']:.4f} "
          f"f1={cv_metrics['f1']['mean']:.4f}+/-{cv_metrics['f1']['std']:.4f}")

    # Final deployed model is fit on ALL available data -- CV above is only to
    # honestly estimate generalization, not to hold back production training data.
    final_scorer = train_per_flow_model(
        X, y,
        feature_list=feature_list,
        medians=medians,
        n_estimators=n_estimators,
        random_state=random_state,
        metadata={
            "dataset": str(ds),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "test_size": test_size,
            "label_info": info,
            "split_info": split_info,
            "leakage_caveat": (
                "CIC CSV lacks src/dst IP and timestamp columns, so this is not a "
                "true source- or time-disjoint split -- offline metrics still do NOT "
                "prove real-world streaming performance (spec section 25). Metrics ARE "
                "from feature-vector-fingerprint GROUP-disjoint cross-validation "
                "(StratifiedGroupKFold, all folds evaluated), which removes the measured "
                f"duplicate-row leakage ({split_info['duplicate_row_fraction']:.1%} of rows) "
                "that a plain random split let leak across train/test. Cross-validating "
                "every fold (rather than one split) also revealed that a couple of "
                "single flow shapes each span >25% of all rows -- a single split can "
                "silo an entire shape out of training by chance; the per-fold spread in "
                "cv_metrics reflects that instability honestly instead of hiding it."
            ),
            "excluded_by_design": {
                "Destination Port": "used as behavioural key, not an ML identity",
                "Flow Duration / */s": "bidirectional semantics",
                "*Bwd* / ratios / flag counts": "reverse-direction dependent",
            },
            "python": platform.python_version(),
        },
    )
    final_scorer.metadata["cv_metrics"] = cv_metrics

    # feature importances (transparency), from the final production model
    importances = dict(sorted(
        zip(feature_list, final_scorer.model.feature_importances_.tolist()),
        key=lambda kv: kv[1], reverse=True,
    ))
    final_scorer.metadata["feature_importances"] = importances

    out = Path(model_dir)
    final_scorer.save(out)
    (out / "training_metrics.json").write_text(json.dumps(cv_metrics, indent=2))
    print(f"[train] saved model (trained on all {len(y)} rows) + feature_list + metadata to {out}/")
    print(f"[train] top features: {list(importances)[:5]}")
    return cv_metrics


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
