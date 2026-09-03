"""Fusion of baseline + sequence model (CLAUDE.md §4, Build Order step 4).

Two candidate strategies (§11 open item): concat the CNN embedding into the GBM, or
average the two scores. Only build this after both models work independently.

STUB.
"""
from __future__ import annotations


def average_scores(gbm_proba, cnn_proba, weight: float = 0.5):
    raise NotImplementedError("Fusion — Build Order step 4")


def embedding_concat_features(tabular_X, cnn_embeddings):
    raise NotImplementedError
