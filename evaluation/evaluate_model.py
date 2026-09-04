"""Offline supervised evaluation of the per-flow model (spec sections 23, 25).

Reports the group-disjoint cross-validated precision / recall / F1 / ROC-AUC /
PR-AUC that ``training/train.py`` computed and saved alongside the model.

This does NOT re-derive a holdout split itself: the saved model is trained on
*all* available rows (see ``training/train.py``), so there is no data left
that the model hasn't seen -- re-evaluating against any fresh split of the
same dataset would score the model on its own training data. The honest
generalization estimate is the cross-validated ``cv_metrics`` produced during
training, before the final fit; this script just surfaces it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def run_evaluation(model_dir: str = "models", out: Optional[str] = None) -> dict:
    meta_path = Path(model_dir) / "metadata.json"
    metadata = json.loads(meta_path.read_text())
    cv_metrics = metadata.get("cv_metrics")
    if cv_metrics is None:
        raise KeyError(
            f"{meta_path} has no 'cv_metrics' -- this model was trained before "
            "the group-disjoint cross-validation was added; retrain with "
            "training/train.py to get an evaluable model."
        )

    print("=== Group-disjoint cross-validated benchmark (per-flow model) ===")
    print(f"folds evaluated: {cv_metrics['n_folds_evaluated']}")
    for key in ("precision", "recall", "f1", "roc_auc", "pr_auc"):
        m = cv_metrics[key]
        print(f"{key:10s} mean={m['mean']:.4f} std={m['std']:.4f}")
    print("NOTE:", metadata.get("leakage_caveat", ""))

    if out:
        Path(out).write_text(json.dumps(cv_metrics, indent=2))
        print(f"wrote {out}")
    return cv_metrics


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    run_evaluation(a.model_dir, a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
