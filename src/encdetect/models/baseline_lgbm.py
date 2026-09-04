"""LightGBM baseline on tabular features (CLAUDE.md §4, Build Order step 2).

Built FIRST. Evaluate under leave-one-family-out (CLAUDE.md §7) — that number is the
headline, even if it's bad. Produces SHAP contributions for the alert `evidence` field.

The JA4 fingerprint is used as a FEATURE via count/target encoding — never as a lookup key
(CLAUDE.md §6.1). Malware mimics browser fingerprints, so a JA4 blocklist would be a
signature system wearing an ML hat.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ..features.session import FeatureBundle, TABULAR_FEATURE_NAMES


@dataclass
class Ja4TargetEncoder:
    """Smoothed target encoding of the JA4 hash (fit on TRAIN only, to avoid leakage)."""
    prior: float = 0.0
    smoothing: float = 10.0
    table: dict[str, float] = field(default_factory=dict)

    def fit(self, ja4s: list[str], y: np.ndarray) -> "Ja4TargetEncoder":
        y = np.asarray(y, dtype=float)
        self.prior = float(y.mean()) if len(y) else 0.0
        sums: dict[str, float] = {}
        counts: dict[str, int] = {}
        for h, label in zip(ja4s, y):
            sums[h] = sums.get(h, 0.0) + label
            counts[h] = counts.get(h, 0) + 1
        self.table = {
            h: (sums[h] + self.smoothing * self.prior) / (counts[h] + self.smoothing)
            for h in sums
        }
        return self

    def transform(self, ja4s: list[str]) -> np.ndarray:
        return np.array([self.table.get(h, self.prior) for h in ja4s], dtype=float)


class LgbmBaseline:
    """LightGBM gradient-boosted trees on the tabular + JA4-encoded features."""

    def __init__(self, params: dict[str, Any] | None = None) -> None:
        self.params = params or {
            "objective": "binary",
            "n_estimators": 300,
            "learning_rate": 0.05,
            "num_leaves": 31,
            "min_child_samples": 20,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
            "verbosity": -1,
            "n_jobs": -1,
        }
        self.model = None
        self.encoder = Ja4TargetEncoder()
        self.feature_names = TABULAR_FEATURE_NAMES + ["ja4_target_enc"]
        self._explainer = None

    # --- matrix construction ---
    def _matrix(self, bundles: list[FeatureBundle], ja4_enc: np.ndarray) -> np.ndarray:
        rows = []
        for b, enc in zip(bundles, ja4_enc):
            row = [float(b.tabular.get(name, 0.0)) for name in TABULAR_FEATURE_NAMES]
            row.append(float(enc))
            rows.append(row)
        return np.asarray(rows, dtype=float)

    @staticmethod
    def _labels(bundles: list[FeatureBundle]) -> np.ndarray:
        return np.array([1 if b.label == "malicious" else 0 for b in bundles], dtype=int)

    # --- training / inference ---
    def fit(self, bundles: list[FeatureBundle]) -> "LgbmBaseline":
        import lightgbm as lgb

        y = self._labels(bundles)
        self.encoder.fit([b.ja4 for b in bundles], y)
        X = self._matrix(bundles, self.encoder.transform([b.ja4 for b in bundles]))
        self.model = lgb.LGBMClassifier(**self.params)
        # Fit without feature_name so later predict() on raw ndarrays stays warning-free;
        # we track names ourselves in self.feature_names for reporting/SHAP.
        self.model.fit(X, y)
        self._explainer = None
        return self

    def predict_proba(self, bundles: list[FeatureBundle]) -> np.ndarray:
        X = self._matrix(bundles, self.encoder.transform([b.ja4 for b in bundles]))
        return self.model.predict_proba(X)[:, 1]

    # --- explainability (alert evidence) ---
    def explain(self, bundle: FeatureBundle, top_k: int = 4) -> list[tuple[str, Any, float]]:
        """Return top-k (feature, value, SHAP contribution) for one session's alert evidence.

        Falls back to tree gain-weighted contributions if SHAP is unavailable.
        """
        enc = self.encoder.transform([bundle.ja4])
        X = self._matrix([bundle], enc)
        raw = {**bundle.tabular, "ja4_target_enc": float(enc[0])}
        try:
            import shap

            if self._explainer is None:
                self._explainer = shap.TreeExplainer(self.model)
            sv = self._explainer.shap_values(X)
            vals = sv[1][0] if isinstance(sv, list) else np.asarray(sv)[0]
        except Exception:
            imp = np.asarray(self.model.feature_importances_, dtype=float)
            imp = imp / (imp.sum() + 1e-9)
            vals = imp * X[0]

        ranked = sorted(
            zip(self.feature_names, vals), key=lambda t: abs(t[1]), reverse=True
        )[:top_k]
        return [(name, raw.get(name, 0.0), round(float(c), 4)) for name, c in ranked]

    def save(self, path: str) -> None:
        import joblib

        joblib.dump({"model": self.model, "encoder": self.encoder,
                     "params": self.params}, path)

    @classmethod
    def load(cls, path: str) -> "LgbmBaseline":
        import joblib

        blob = joblib.load(path)
        obj = cls(blob["params"])
        obj.model = blob["model"]
        obj.encoder = blob["encoder"]
        return obj
