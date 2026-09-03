"""LightGBM baseline on tabular features (CLAUDE.md §4, Build Order step 2).

Build this FIRST. Evaluate under leave-one-family-out (CLAUDE.md §7) — that number is the
headline, even if it's bad. Produce SHAP contributions for the alert `evidence` field.

STUB.
"""
from __future__ import annotations

from typing import Any


class LgbmBaseline:
    def __init__(self, params: dict[str, Any] | None = None) -> None:
        self.params = params or {}
        self.model = None

    def fit(self, X, y) -> "LgbmBaseline":
        raise NotImplementedError("LightGBM baseline — Build Order step 2")

    def predict_proba(self, X):
        raise NotImplementedError

    def explain(self, X):
        """Return per-sample SHAP contributions for the alert `evidence` field."""
        raise NotImplementedError

    def save(self, path: str) -> None:
        raise NotImplementedError

    @classmethod
    def load(cls, path: str) -> "LgbmBaseline":
        raise NotImplementedError
