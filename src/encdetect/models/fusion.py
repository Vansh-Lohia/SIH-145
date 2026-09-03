"""Fusion of baseline + sequence model (CLAUDE.md §4, Build Order step 4).

Two candidate strategies (§11 open item): average the two scores, or concat the CNN
embedding into the GBM feature matrix. Only used after both models work independently.
"""
from __future__ import annotations

import numpy as np


def average_scores(gbm_proba, cnn_proba, weight: float = 0.5) -> np.ndarray:
    """Weighted average of the two probabilities. weight = weight on the GBM."""
    g = np.asarray(gbm_proba, dtype=float)
    c = np.asarray(cnn_proba, dtype=float)
    return weight * g + (1.0 - weight) * c


def embedding_concat_features(tabular_X, cnn_embeddings) -> np.ndarray:
    """Concatenate CNN embeddings onto the tabular matrix for a fused GBM."""
    return np.hstack([np.asarray(tabular_X, dtype=float),
                      np.asarray(cnn_embeddings, dtype=float)])
